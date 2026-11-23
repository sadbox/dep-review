package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/sadbox/dep-review/internal/allow"
)

// TextFormat describes Chunk.Text, in words the model can be given. It is
// part of this package's contract with whoever writes the prompt: every
// chunk follows it, whatever the artifact's publisher wrote.
const TextFormat = `The text is a list of changed files. Each chunk stands alone.
A line that starts with "==" was written by the gate. "== file: PATH (...)" starts a file and says whether it was added or changed, and whether only part of it is shown. A file that continues in another chunk is marked "[part N]" there and here. No other line starts with "==".
A line that starts with "@@" starts a hunk, as in a unified diff.
Every other line is the file's own text behind one marker character: "+" for a line added, "-" for a line removed, a space for an unchanged line of context, "\" for git's note about a missing final newline.
A line that starts with "~" continues the line above it, which was too long to keep in one piece; the character after "~" repeats that line's marker.
"<0xNN>" and "<U+XXXX>" stand for one control, invisible or direction-changing character that was in the file at that place. Carriage returns are shown that way unless they end a line.`

const (
	// minChunkBytes is the smallest chunk Prepare accepts. Below it a
	// file header alone may not fit.
	minChunkBytes = 256
	// maxBudgetBytes is the most text Prepare accepts Limits for, chunk
	// size times chunks: far more than any model reads, and about what
	// one process should hold.
	maxBudgetBytes = 256 << 20
	// maxRemovedListed is how many removed paths are named.
	maxRemovedListed = 200
	// partReserve is room kept in a split file's header for " [part N]".
	partReserve = 24
	// minFragment is the least room worth starting a line in when it
	// has to be cut anyway.
	minFragment = 32
	// keepWhole is the share of a chunk (one in keepWhole) up to which a
	// file is never cut in two: it starts the next chunk instead. Larger
	// files are cut at the chunk's end, so that at most that share of a
	// chunk is ever left empty.
	keepWhole = 8
)

// packer fills chunks with sections, in the order they are added.
type packer struct {
	size int      // most bytes in one chunk
	max  int      // most chunks
	done []string // the chunks that are full
	cur  []byte   // the chunk being filled
}

// used is how many chunks there are, counting the one being filled.
func (p *packer) used() int {
	if len(p.cur) > 0 {
		return len(p.done) + 1
	}
	return len(p.done)
}

func (p *packer) flush() {
	if len(p.cur) > 0 {
		p.done = append(p.done, string(p.cur))
		p.cur = nil
	}
}

// add appends one section: its header line and its body, whole lines.
//
// A section goes into the chunk being filled when it fits there. A small
// one that does not starts the next chunk. Any other is cut where the
// chunk ends and goes on in the next, under the same header: chunks are
// filled to the end, and at most one file is cut at each chunk's end.
//
// add reports false, and changes nothing, when the section does not fit
// in the chunks that are left.
func (p *packer) add(header string, body []string) bool {
	n := len(header) + 1
	for _, b := range body {
		n += len(b)
	}
	switch {
	case n <= p.size-len(p.cur):
		if len(p.cur) == 0 && len(p.done) >= p.max {
			return false
		}
		p.whole(header, body)
		return true
	case n <= p.size/keepWhole:
		if p.used() >= p.max {
			return false
		}
		p.flush()
		p.whole(header, body)
		return true
	}

	// The longest line that fits a chunk of its own under the header.
	// With too little of it, cutting makes no sense.
	longest := p.size - len(header) - partReserve - 1
	if longest < minFragment || len(header)+partReserve > p.size/2 {
		return false
	}
	// More bytes than all the room that is left: no need to try.
	if n > (p.max-len(p.done))*p.size-len(p.cur) {
		return false
	}
	// Cut on a copy, so that a section that turns out not to fit leaves
	// no trace. Appending to t.done never writes over an element of
	// p.done.
	t := packer{size: p.size, max: p.max, done: p.done, cur: append([]byte(nil), p.cur...)}
	t.split(header, body, longest)
	if t.used() > t.max {
		return false
	}
	*p = t
	return true
}

// whole writes a section into the chunk being filled.
func (p *packer) whole(header string, body []string) {
	p.cur = append(p.cur, header...)
	p.cur = append(p.cur, '\n')
	for _, b := range body {
		p.cur = append(p.cur, b...)
	}
}

// split writes a section line by line from where the chunk being filled
// stands. When a chunk is full it starts the next and repeats the header
// there, since each chunk is read on its own; the pieces are numbered.
//
// Pieces end at line ends. A line longer than longest, which fits no
// chunk, is cut at a character boundary; what follows the cut starts with
// "~" and the line's own first character (its "+", "-" or space). No line
// of a diff starts with "~", so a continuation cannot be mistaken for, or
// forged by, the file's text.
func (p *packer) split(header string, body []string, longest int) {
	part := 0  // pieces opened so far
	lines := 0 // lines written into the open piece
	at := 0    // where in p.cur the open piece's header starts
	open := func() {
		at = len(p.cur)
		part++
		p.cur = fmt.Appendf(p.cur, "%s [part %d]\n", header, part)
		lines = 0
	}
	next := func() {
		if lines == 0 {
			// Only the header went into this chunk: take it back.
			p.cur = p.cur[:at]
			part--
		}
		p.flush()
		open()
	}
	open()
	for _, hunk := range body {
		for line := range strings.Lines(hunk) {
			line = strings.TrimSuffix(line, "\n")
			continued := "~" + line[:min(1, len(line))]
			for {
				room := p.size - len(p.cur) - 1
				if len(line) <= room {
					p.cur = append(p.cur, line...)
					p.cur = append(p.cur, '\n')
					lines++
					break
				}
				if len(line) <= longest || room < minFragment {
					// It fits the next chunk whole, or there is too
					// little left here to start it.
					next()
					continue
				}
				cut := room
				for cut > 0 && !utf8.RuneStart(line[cut]) {
					cut--
				}
				if cut == 0 {
					cut = room // not UTF-8 here; escaped text always is
				}
				p.cur = append(p.cur, line[:cut]...)
				p.cur = append(p.cur, '\n')
				lines++
				line = continued + line[cut:]
				next()
			}
		}
	}
	if part == 1 {
		// It went into one chunk after all: there is no part to number.
		numbered := at + len(header)
		p.cur = append(p.cur[:numbered], p.cur[numbered+len(" [part 1]"):]...)
	}
}

// chunks returns what was packed.
func (p *packer) chunks() []Chunk {
	p.flush()
	out := make([]Chunk, len(p.done))
	for i, text := range p.done {
		out[i] = Chunk{Index: i, Text: text}
	}
	return out
}

// assemble packs the sections into chunks within lim and settles what
// the read amounts to.
//
// When everything fits, everything is sent, in path order, and the read
// is full unless some changed file was not text. When it does not fit,
// the read is partial and what is sent is the targeted read of spec
// section 7: first whole files that carry no generated-code marker, then,
// from every file not sent whole, the hunks with a marker on an added
// line. Whatever is not sent whole is listed as unread.
func assemble(pair Pair, sections []section, unread []unreadFile, removed []string, lim Limits) Prepared {
	p := &packer{size: lim.ChunkBytes, max: lim.MaxChunks}
	fits := true
	for _, s := range sections {
		if !p.add(s.header, s.hunks) {
			fits = false
			break
		}
	}
	if !fits {
		p = &packer{size: lim.ChunkBytes, max: lim.MaxChunks}
		whole := make([]bool, len(sections))
		for i, s := range sections {
			whole[i] = !s.generated && p.add(s.header, s.hunks)
		}
		for i, s := range sections {
			if whole[i] {
				continue
			}
			unread = append(unread, unreadFile{s.path, s.file})
			var picked []string
			for _, h := range s.hunks {
				if marked(h) {
					picked = append(picked, h)
				}
			}
			if len(picked) == 0 {
				continue
			}
			header := s.header + fmt.Sprintf(" [only hunks with a marker: %d of %d]", len(picked), len(s.hunks))
			if p.add(header, picked) {
				continue
			}
			// Not all of them fit: as many as do, one at a time.
			for _, h := range picked {
				p.add(s.header+" [only hunks with a marker: one of several]", []string{h})
			}
		}
	}
	// Removed files are named when there is room. They are not changed
	// or added files, so leaving the list out does not make the read
	// partial.
	if len(removed) > 0 {
		p.add(removedNote(removed))
	}

	out := Prepared{
		Pair:   pair,
		Chunks: p.chunks(),
		Unread: []Unread{},
		State:  allow.ReadFull,
	}
	sort.Slice(unread, func(i, j int) bool { return unread[i].path < unread[j].path })
	for _, u := range unread {
		out.Unread = append(out.Unread, Unread{
			Path:   escapeLine(u.path),
			Size:   u.file.size,
			SHA256: hex.EncodeToString(u.file.sum[:]),
		})
	}
	if len(out.Unread) > 0 {
		out.State = allow.ReadPartial
	}
	out.Key = contentKey(out)
	return out
}

// removedNote is the gate's list of files that exist only in the old
// artifact. Their content is not shown: the model judges what was added.
func removedNote(removed []string) (header string, body []string) {
	header = fmt.Sprintf("== removed: %d files of the old version are gone (their text is not shown)", len(removed))
	for i, p := range removed {
		if i == maxRemovedListed {
			body = append(body, fmt.Sprintf("==   and %d more\n", len(removed)-i))
			break
		}
		body = append(body, "==   "+escapeLine(p)+"\n")
	}
	return header, body
}

// contentKey is the hash a verdict is stored under. It covers the chunk
// set and everything else that decides what a verdict for those chunks
// means: which update it is, with the hashes it was bound to, what was
// left unread, and the read state. Two updates whose chunks are equal but
// where one also changed a binary file must not share a verdict, and
// neither may two updates that both have no chunk at all.
//
// Nothing in it depends on the pull request, the repository or the
// machine, so the same update prepared again gives the same key.
func contentKey(p Prepared) string {
	h := sha256.New()
	field := func(s string) {
		// Length first, so no two lists of fields hash alike.
		fmt.Fprintf(h, "%d:", len(s))
		io.WriteString(h, s)
	}
	field("dep-review artifact read v1")
	field(p.Pair.Ecosystem)
	field(p.Pair.Name)
	field(p.Pair.From)
	field(p.Pair.To)
	for _, ref := range []Ref{p.Pair.Old, p.Pair.New} {
		field(string(ref.Kind))
		field(ref.Name)
		field(ref.Version)
		field(ref.Hash)
	}
	field(string(p.State))
	field(fmt.Sprint(len(p.Unread)))
	for _, u := range p.Unread {
		field(u.Path)
		field(fmt.Sprint(u.Size))
		field(u.SHA256)
	}
	field(fmt.Sprint(len(p.Chunks)))
	for _, c := range p.Chunks {
		field(c.Text)
	}
	return hex.EncodeToString(h.Sum(nil))
}

package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/sadbox/dep-review/internal/allow"
)

const (
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

// add appends one section: its header line and its body, whole lines. A
// section goes into the chunk being filled when it fits there. A small
// one that does not starts the next chunk. Any other is cut where the
// chunk ends and goes on in the next, under the same header.
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
// section 7: first whole files in path order, bundles left out, then,
// from every file not sent whole, the hunks with a marker on an added
// line. Whatever is not sent whole is listed as unread. Nothing a
// publisher writes into a file moves it between the two.
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
			whole[i] = !s.bundle && p.add(s.header, s.hunks)
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
	// Removed files are named, not shown. Without the note the model is
	// not told that files went away, so a note that does not fit makes the
	// read partial, with nothing in Unread to show for it.
	untold := len(removed) > 0 && !p.add(removedNote(removed))

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
	if len(out.Unread) > 0 || untold {
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
// neither may two updates that both have no chunk at all. Nothing in it
// depends on the pull request, the repository or the machine.
func contentKey(p Prepared) string {
	// Named fields in a fixed order; JSON's quoting keeps two fields from
	// running into each other. Every string here is escaped text or of a
	// checked ASCII shape, so none is the invalid UTF-8 that JSON would
	// fold into one replacement character.
	b, err := json.Marshal(struct {
		Format string
		Pair   Pair
		State  allow.ReadState
		Unread []Unread
		Chunks []Chunk
	}{"dep-review artifact read v2", p.Pair, p.State, p.Unread, p.Chunks})
	if err != nil {
		// Strings and integers only. A key over nothing would be one key
		// for every read, so this is never passed over.
		panic(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

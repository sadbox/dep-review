package artifact

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/sadbox/dep-review/internal/allow"
)

func TestPackerKeepsASectionInOneChunk(t *testing.T) {
	p := &packer{size: 100, max: 3}
	body := func(n int) []string { return []string{strings.Repeat("x", n-1) + "\n"} }
	// 10 + 40 bytes, then 10 + 30: 90 in the first chunk.
	if !p.add("== file a", body(40)) || !p.add("== file b", body(30)) {
		t.Fatal("two small sections did not fit")
	}
	// 10 + 30 more would be 130: it goes to the next chunk whole.
	if !p.add("== file c", body(30)) {
		t.Fatal("a section that fits a chunk of its own was refused")
	}
	chunks := p.chunks()
	if len(chunks) != 2 || !strings.HasPrefix(chunks[1].Text, "== file c\n") || strings.Contains(chunks[0].Text, "file c") {
		t.Errorf("chunks: %+v", chunks)
	}
	for i, c := range chunks {
		if c.Index != i || len(c.Text) > 100 {
			t.Errorf("chunk %d: index %d, %d bytes", i, c.Index, len(c.Text))
		}
	}
}

func TestPackerRefusesWhatDoesNotFitAndChangesNothing(t *testing.T) {
	p := &packer{size: 100, max: 2}
	line := []string{strings.Repeat("x", 59) + "\n"}
	if !p.add("== a", line) || !p.add("== b", line) {
		t.Fatal("two chunks' worth did not fit in two chunks")
	}
	before := fmt.Sprint(p.done, string(p.cur))
	if p.add("== c", line) {
		t.Error("a third chunk's worth fit in two chunks")
	}
	if p.add("== d", []string{strings.Repeat("y\n", 400)}) {
		t.Error("a section larger than everything that is left was added")
	}
	if after := fmt.Sprint(p.done, string(p.cur)); after != before {
		t.Errorf("a refused section changed the chunks:\n%s\n%s", before, after)
	}
	// Something small still fits behind b.
	if !p.add("== e", []string{"z\n"}) {
		t.Error("a small section no longer fits")
	}
	if got := len(p.chunks()); got != 2 {
		t.Errorf("%d chunks, want 2", got)
	}
}

func TestPackerNoChunksNoRoom(t *testing.T) {
	p := &packer{size: 100, max: 0}
	if p.add("== a", []string{"x\n"}) {
		t.Error("added a section with no chunk allowed")
	}
}

// A small file is never cut in two: it starts the next chunk. A larger
// one is cut where the chunk ends, so chunks are filled.
func TestPackerCutsOnlyLargeSections(t *testing.T) {
	p := &packer{size: 1000, max: 10}
	lines := func(n int) []string { return []string{strings.Repeat("+123456789\n", n)} }
	p.add("== file: a (added)", lines(80)) // 899 bytes
	// 100 bytes do not fit in the 101 left with its header; an eighth
	// of a chunk is 125, so it is kept whole.
	p.add("== file: small (added)", lines(9))
	// 900 bytes do not fit either, and are cut.
	p.add("== file: large (added)", lines(80))
	chunks := p.chunks()
	if len(chunks) != 3 {
		t.Fatalf("%d chunks, want 3", len(chunks))
	}
	if !strings.HasPrefix(chunks[1].Text, "== file: small (added)\n") {
		t.Errorf("the small file was cut or moved:\n%s", chunks[1].Text)
	}
	if !strings.Contains(chunks[1].Text, "== file: large (added) [part 1]\n") || !strings.HasPrefix(chunks[2].Text, "== file: large (added) [part 2]\n") {
		t.Errorf("the large file was not cut at the chunk's end:\n%s\n-----\n%s", chunks[1].Text, chunks[2].Text)
	}
	if len(chunks[1].Text) < 1000-11 {
		t.Errorf("the second chunk was left at %d of 1000 bytes", len(chunks[1].Text))
	}
}

// unsplit undoes the cutting of one section: it drops the numbered
// headers and joins continuation lines back on.
func unsplit(chunks []Chunk, header string) string {
	var out strings.Builder
	for _, line := range strings.Split(strings.TrimSuffix(text(Prepared{Chunks: chunks}), "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, header+" [part "):
		case strings.HasPrefix(line, "~"):
			out.WriteString(line[2:])
		default:
			if out.Len() > 0 {
				out.WriteByte('\n')
			}
			out.WriteString(line)
		}
	}
	return out.String() + "\n"
}

func TestSplit(t *testing.T) {
	const header = "== file: big.js (changed)"
	hunk1 := "@@ -1,2 +1,3 @@\n" + strings.Repeat("+a line of ordinary length\n", 30)
	// One line far longer than a chunk, with characters of 2, 3 and 4
	// bytes so that a cut in the middle of one would show.
	long := "+" + strings.Repeat("x"+u(0xE9)+u(0x65E5)+u(0x1F642), 200)
	hunk2 := "@@ -9 +10,2 @@\n" + long + "\n-short\n"
	for _, size := range []int{256, 300, 511, 1000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			p := &packer{size: size, max: 1000}
			if !p.add(header, []string{hunk1, hunk2}) {
				t.Fatal("did not fit")
			}
			chunks := p.chunks()
			if len(chunks) < 2 {
				t.Fatalf("%d chunks", len(chunks))
			}
			total := 0
			for i, c := range chunks {
				total += len(c.Text)
				if len(c.Text) > size {
					t.Errorf("chunk %d is %d bytes, over %d", i, len(c.Text), size)
				}
				if !utf8.ValidString(c.Text) {
					t.Errorf("chunk %d is cut inside a character", i)
				}
				if !strings.HasSuffix(c.Text, "\n") {
					t.Errorf("chunk %d does not end at a line end", i)
				}
				// Every chunk says which file it is in and which part.
				if want := fmt.Sprintf("%s [part %d]\n", header, i+1); !strings.HasPrefix(c.Text, want) {
					t.Errorf("chunk %d starts %q, want %q", i, c.Text[:min(len(c.Text), 40)], want)
				}
			}
			if got := unsplit(chunks, header); got != hunk1+hunk2 {
				t.Errorf("the pieces do not add up to the section:\n%q\nwant\n%q", got, hunk1+hunk2)
			}
			// Each continuation says which line it continues: "~" and
			// the marker of the long line.
			if all := text(Prepared{Chunks: chunks}); !strings.Contains(all, "\n~+") || strings.Contains(all, "\n~-") {
				t.Errorf("continuation lines are not marked \"~+\"")
			}
			// Chunks are filled: no more of them than the text needs,
			// give or take the room a line end leaves.
			if most := total/(size-size/4) + 1; len(chunks) > most {
				t.Errorf("%d chunks for %d bytes in chunks of %d", len(chunks), total, size)
			}
		})
	}
}

// A file that is cut starts in what is left of the chunk being filled.
func TestSplitStartsInTheCurrentChunk(t *testing.T) {
	p := &packer{size: 1000, max: 3}
	p.add("== file: a (added)", []string{strings.Repeat("+123456789\n", 40)}) // 459 bytes
	body := strings.Repeat("+abcdefghi\n", 120)                               // 1200 bytes
	if !p.add("== file: b (added)", []string{body}) {
		t.Fatal("did not fit")
	}
	chunks := p.chunks()
	if len(chunks) != 2 {
		t.Fatalf("%d chunks, want 2: the second file starts in the first chunk", len(chunks))
	}
	if !strings.Contains(chunks[0].Text, "\n== file: b (added) [part 1]\n+abcdefghi\n") || !strings.HasPrefix(chunks[1].Text, "== file: b (added) [part 2]\n") {
		t.Errorf("chunks:\n%s\n-----\n%s", chunks[0].Text, chunks[1].Text)
	}
	if n := strings.Count(chunks[0].Text+chunks[1].Text, "+abcdefghi\n"); n != 120 {
		t.Errorf("%d of 120 lines", n)
	}
}

// When the cut would leave only the header in a chunk, the header goes
// with the text, and a file that then fits in one chunk is not numbered.
func TestSplitLeavesNoLoneHeader(t *testing.T) {
	p := &packer{size: 1000, max: 3}
	p.add("== file: a (added)", []string{strings.Repeat("+123456789\n", 85)}) // 954 bytes
	line := "+" + strings.Repeat("b", 400) + "\n"
	if !p.add("== file: b (added)", []string{line, line}) {
		t.Fatal("did not fit")
	}
	chunks := p.chunks()
	if len(chunks) != 2 || strings.Contains(chunks[0].Text, "file: b") {
		t.Fatalf("chunks:\n%s\n-----\n%s", chunks[0].Text, chunks[1].Text)
	}
	if want := "== file: b (added)\n" + line + line; chunks[1].Text != want {
		t.Errorf("second chunk:\n%s\nwant:\n%s", chunks[1].Text, want)
	}
}

func TestSplitNeedsRoomBesideTheHeader(t *testing.T) {
	header := "== file: " + strings.Repeat("d/", 100) + "x.js (changed)"
	p := &packer{size: 256, max: 100}
	if p.add(header, []string{strings.Repeat("+x\n", 500)}) {
		t.Errorf("cut a section whose header fills the chunk:\n%s", text(Prepared{Chunks: p.chunks()}))
	}
	if p.used() != 0 {
		t.Error("the refused section left something behind")
	}
}

// No chunk is ever larger than the budget, and there are never more
// chunks than allowed, whatever the sizes.
func TestChunksStayWithinLimits(t *testing.T) {
	oldFiles := map[string]string{}
	newFiles := map[string]string{}
	for i := range 12 {
		name := fmt.Sprintf("src/f%02d.js", i)
		oldFiles[name] = strings.Repeat(fmt.Sprintf("old line %d\n", i), 5*i+1)
		newFiles[name] = strings.Repeat(fmt.Sprintf("new line %d with require('x%d')\n", i, i), 7*i+1)
	}
	newFiles["long.js"] = strings.Repeat("0123456789", 300) + "\n"
	newFiles["wide.js"] = strings.Repeat(u(0x1F642), 500) + "\n"
	p, f := npmPair(t, oldFiles, newFiles)
	r := newReader(t, f)
	for _, lim := range []Limits{
		{ChunkBytes: 256, MaxChunks: 1}, {ChunkBytes: 256, MaxChunks: 7}, {ChunkBytes: 257, MaxChunks: 1000},
		{ChunkBytes: 400, MaxChunks: 3}, {ChunkBytes: 1000, MaxChunks: 2}, {ChunkBytes: 1000, MaxChunks: 40},
		{ChunkBytes: 5000, MaxChunks: 1}, {ChunkBytes: 5000, MaxChunks: 4}, {ChunkBytes: 100000, MaxChunks: 1},
	} {
		t.Run(fmt.Sprintf("%dx%d", lim.ChunkBytes, lim.MaxChunks), func(t *testing.T) {
			got, err := r.Prepare(t.Context(), p, lim)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Chunks) > lim.MaxChunks {
				t.Errorf("%d chunks, limit %d", len(got.Chunks), lim.MaxChunks)
			}
			for i, c := range got.Chunks {
				if len(c.Text) > lim.ChunkBytes {
					t.Errorf("chunk %d is %d bytes, limit %d", i, len(c.Text), lim.ChunkBytes)
				}
				if c.Index != i || c.Text == "" || !utf8.ValidString(c.Text) || !strings.HasPrefix(c.Text, "== ") {
					t.Errorf("chunk %d: index %d, valid UTF-8 %v, starts %q", i, c.Index, utf8.ValidString(c.Text), c.Text[:min(len(c.Text), 20)])
				}
			}
			// Full means every file is there in full; partial means
			// some file is listed as unread.
			t.Logf("state %s, %d chunks, %d unread", got.State, len(got.Chunks), len(got.Unread))
			switch got.State {
			case allow.ReadFull:
				if len(got.Unread) != 0 {
					t.Errorf("full with unread files %v", unreadPaths(got))
				}
				for i := range 12 {
					if n := strings.Count(text(got), fmt.Sprintf("+new line %d with", i)); n != 7*i+1 {
						t.Errorf("full, but file %d shows %d of its %d new lines", i, n, 7*i+1)
					}
				}
			case allow.ReadPartial:
				if len(got.Unread) == 0 {
					t.Error("partial with no unread file")
				}
			default:
				t.Errorf("state %q", got.State)
			}
		})
	}
}

// A file larger than one chunk is still read in full when the chunks
// allowed can hold it: it is split, not dropped.
func TestOversizeFileIsSplitNotDropped(t *testing.T) {
	var b strings.Builder
	for i := range 2000 {
		fmt.Fprintf(&b, "line %d of the new file\n", i)
	}
	got := prepareNPM(t, map[string]string{"a.js": "x\n"}, map[string]string{"a.js": "x\n", "big.js": b.String()}, Limits{ChunkBytes: 4096, MaxChunks: 20})
	if got.State != allow.ReadFull || len(got.Unread) != 0 {
		t.Fatalf("state %q, unread %v", got.State, unreadPaths(got))
	}
	if len(got.Chunks) < 10 {
		t.Errorf("%d chunks for a file of %d bytes", len(got.Chunks), b.Len())
	}
	all := text(got)
	for i := range 2000 {
		if !strings.Contains(all, fmt.Sprintf("+line %d of the new file\n", i)) {
			t.Fatalf("line %d is missing", i)
		}
	}
	for i, c := range got.Chunks {
		if want := fmt.Sprintf("== file: big.js (added) [part %d]\n", i+1); !strings.HasPrefix(c.Text, want) {
			t.Errorf("chunk %d starts %q", i, strings.SplitN(c.Text, "\n", 2)[0])
		}
	}
}

// numbered is n lines "prefix 0", "prefix 1", ...
func numbered(prefix string, n int) []string {
	lines := make([]string, n)
	for i := range lines {
		lines[i] = fmt.Sprintf("%s %d", prefix, i)
	}
	return lines
}

// The targeted read, when the diff does not fit: whole files first, in
// path order, then only the hunks with a marker. A file that says it was
// generated is a file like any other: what a publisher writes into it
// does not move it out of the first pass.
func TestTargetedRead(t *testing.T) {
	generatedOld := append([]string{"// @generated by a bundler"}, numbered("generated", 400)...)
	generatedNew := append([]string{}, generatedOld...)
	generatedNew[51] = "const cp = require('child_process')"
	generatedNew[201] = "generated but harmless change"
	generatedNew[351] = "fetch('https://203.0.113.9/x')"
	for i := 100; i < 110; i++ {
		generatedNew[i] = fmt.Sprintf("renamed %d %s", i, strings.Repeat("y", 30))
	}

	// Too large for what is left once the files before it are in.
	plainOld := numbered("plain", 3000)
	plainNew := append([]string{}, plainOld...)
	for i := 0; i < 3000; i += 10 {
		plainNew[i] = fmt.Sprintf("plain changed %d %s", i, strings.Repeat("z", 20))
	}
	plainNew[1505] = "eval(atob(payload))"
	plainNew[2505] = "const net = require('net')"

	join := func(lines []string) string { return strings.Join(lines, "\n") + "\n" }
	oldFiles := map[string]string{
		"dist/gen.js":  join(generatedOld),
		"lib/plain.js": join(plainOld),
		"src/main.js":  "export const a = 1\n",
		"README.md":    "# demo\n",
	}
	newFiles := map[string]string{
		"dist/gen.js":  join(generatedNew),
		"lib/plain.js": join(plainNew),
		"src/main.js":  "export const a = 2\n",
		"README.md":    "# demo\n\nNow with more.\n",
		"zz/quiet.js":  "// Code generated by protoc. DO NOT EDIT.\nexport const quiet = 1\n",
	}
	lim := Limits{ChunkBytes: 4096, MaxChunks: 2}
	got := prepareNPM(t, oldFiles, newFiles, lim)

	if got.State != allow.ReadPartial {
		t.Fatalf("state %q, want partial", got.State)
	}
	all := text(got)
	// Whole: every file that fits, in path order, the two that say they
	// are generated among them. Not whole: the one that is too big.
	wantStart := "== file: README.md (changed)\n@@ -1 +1,3 @@\n # demo\n+\n+Now with more.\n" +
		"== file: dist/gen.js (changed)\n@@ "
	if !strings.HasPrefix(all, wantStart) {
		t.Errorf("the text starts\n%.400s\nwant\n%s", all, wantStart)
	}
	if want := []string{"lib/plain.js"}; !reflect.DeepEqual(unreadPaths(got), want) {
		t.Errorf("unread %v, want %v", unreadPaths(got), want)
	}
	for _, want := range []string{
		"+const cp = require('child_process')\n",
		"+generated but harmless change\n",
		"+fetch('https://203.0.113.9/x')\n",
		"+renamed 100 ",
		"== file: src/main.js (changed)\n@@ -1 +1 @@\n-export const a = 1\n+export const a = 2\n",
		"== file: zz/quiet.js (added)\n",
		"+export const quiet = 1\n",
		// From the file that does not fit: the two hunks with a marker.
		"== file: lib/plain.js (changed) [only hunks with a marker: 2 of ",
		"+eval(atob(payload))\n",
		"+const net = require('net')\n",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("the text lacks %q", want)
		}
	}
	if strings.Contains(all, "plain changed 0 ") {
		t.Errorf("the text has a hunk of the file that does not fit which no marker chose")
	}
	if strings.Contains(all, "dist/gen.js (changed) [") || strings.Contains(all, "zz/quiet.js (added) [") {
		t.Error("a file that says it is generated is shown in part")
	}
	if strings.Index(all, "zz/quiet.js") > strings.Index(all, "lib/plain.js") {
		t.Error("a marker hunk comes before a whole file")
	}
	if len(got.Chunks) > lim.MaxChunks {
		t.Errorf("%d chunks", len(got.Chunks))
	}
	for i, c := range got.Chunks {
		if len(c.Text) > lim.ChunkBytes {
			t.Errorf("chunk %d is %d bytes", i, len(c.Text))
		}
	}

	// With room for everything, everything is sent and no marker decides
	// anything.
	whole := prepareNPM(t, oldFiles, newFiles, roomy)
	if whole.State != allow.ReadFull || len(whole.Unread) != 0 {
		t.Errorf("with room: state %q, unread %v", whole.State, unreadPaths(whole))
	}
	for _, want := range []string{"generated but harmless change", "renamed 100 ", "plain changed 0 ", "+export const quiet = 1"} {
		if !strings.Contains(text(whole), want) {
			t.Errorf("with room, the text lacks %q", want)
		}
	}
	if strings.Contains(text(whole), "only hunks with a marker") {
		t.Error("with room, a file is shown in part")
	}
}

// Removed files are named in a note of the gate's. When the note does not
// fit, the model is not told that files went away, and the read is
// partial although no changed file is unread.
func TestRemovedNoteThatDoesNotFitIsPartial(t *testing.T) {
	oldFiles := map[string]string{"a.js": "x\n", "gone.js": "g\n"}
	newFiles := map[string]string{"a.js": strings.Repeat("y", 150) + "\n"}
	got := prepareNPM(t, oldFiles, newFiles, Limits{ChunkBytes: 256, MaxChunks: 1})
	if strings.Contains(text(got), "== removed") || len(got.Chunks) != 1 {
		t.Fatalf("the test is wrong: the note fits, or there is more than one chunk:\n%s", text(got))
	}
	if got.State != allow.ReadPartial || len(got.Unread) != 0 {
		t.Errorf("state %q, unread %v; want partial with nothing unread", got.State, unreadPaths(got))
	}
	// The same update with room for the note is a full read, under
	// another key.
	fits := prepareNPM(t, oldFiles, newFiles, Limits{ChunkBytes: 512, MaxChunks: 1})
	if !strings.Contains(text(fits), "== removed: 1 files") || fits.State != allow.ReadFull {
		t.Errorf("with room: state %q, text:\n%s", fits.State, text(fits))
	}
	if fits.Key == got.Key {
		t.Error("the read with the note and the read without it share a key")
	}
	// Nothing removed: nothing to tell, and a chunk that is just as full
	// is a full read.
	none := prepareNPM(t, map[string]string{"a.js": "x\n"}, newFiles, Limits{ChunkBytes: 256, MaxChunks: 1})
	if none.State != allow.ReadFull {
		t.Errorf("nothing removed: state %q", none.State)
	}
}

// A changed file that is not text makes the read partial, but it does
// not start the targeted read: when the text fits, all of it is sent.
func TestNotTextAloneDoesNotCutTheText(t *testing.T) {
	got := prepareNPM(t,
		map[string]string{"gen.js": "// @generated\nconst a = 1\n", "x.node": "\x00a"},
		map[string]string{"gen.js": "// @generated\nconst a = 2 // no marker here\n", "x.node": "\x00b"},
		roomy)
	if got.State != allow.ReadPartial || !reflect.DeepEqual(unreadPaths(got), []string{"x.node"}) {
		t.Errorf("state %q, unread %v", got.State, unreadPaths(got))
	}
	if !strings.Contains(text(got), "== file: gen.js (changed)\n") || !strings.Contains(text(got), "+const a = 2 // no marker here\n") {
		t.Errorf("the generated file is not shown whole:\n%s", text(got))
	}
}

// When not even the marked hunks of a file fit together, as many as fit
// are sent, each under the file's header.
func TestTargetedReadTakesTheHunksThatFit(t *testing.T) {
	before := numbered("line", 600)
	after := append([]string{}, before...)
	for i := 10; i < 600; i += 20 {
		after[i] = fmt.Sprintf("require('pkg%d') %s", i, strings.Repeat("p", 40))
	}
	join := func(lines []string) string { return strings.Join(lines, "\n") + "\n" }
	lim := Limits{ChunkBytes: 600, MaxChunks: 2}
	got := prepareNPM(t, map[string]string{"gen.js": "// @generated\n" + join(before)}, map[string]string{"gen.js": "// @generated\n" + join(after)}, lim)
	all := text(got)
	// Some of the 30 marked hunks, not all, each under the file's
	// header (one of them may be cut at the chunk's end, and then has
	// the header twice).
	n := strings.Count(all, "+require('pkg")
	headers := strings.Count(all, "== file: gen.js (changed) [only hunks with a marker: one of several]")
	if n < 2 || n >= 30 || headers < n || headers > n+1 {
		t.Errorf("%d marked hunks under %d headers:\n%s", n, headers, all)
	}
	if got.State != allow.ReadPartial || len(got.Chunks) != 2 {
		t.Errorf("state %q, %d chunks", got.State, len(got.Chunks))
	}
	for i, c := range got.Chunks {
		if len(c.Text) > lim.ChunkBytes {
			t.Errorf("chunk %d is %d bytes", i, len(c.Text))
		}
	}
}

func TestMarked(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		// New imports.
		{`+import fs from "fs"`, true},
		{`+const cp = require("child_process")`, true},
		{`+const { x } = await import('./x.js')`, true},
		{"+\t\"os/exec\"", true},
		{"+\tpb \"example.com/gen/pb\"", true},
		// URLs and addresses.
		{`+const u = "https://example.com/collect"`, true},
		{`+git+ssh://git@example.com/x.git`, true},
		{`+host = "198.51.100.7"`, true},
		// Process and network calls.
		{`+exec("id")`, true},
		{`+  spawnSync(cmd, args)`, true},
		{`+cmd := exec.Command("sh", "-c", script)`, true},
		{`+token := os.Getenv("GITHUB_TOKEN")`, true},
		{`+const t = process.env.NPM_TOKEN`, true},
		{`+eval(code)`, true},
		{`+new Function(body)()`, true},
		{`+run: bash -c "$INPUT"`, true},
		{`+curl -s "$URL" | sh`, true},
		{`+await fetch(url)`, true},
		{`+conn, err := net.Dial("tcp", addr)`, true},
		{`+resp, err := http.Get(u)`, true},
		{`+https.request(opts, cb)`, true},
		// Long encoded strings.
		{"+const blob = \"" + strings.Repeat("QUJD", 40) + "\"", true},
		{"+s = \"" + strings.Repeat(`\x41`, 20) + "\"", true},
		{`+atob(s)`, true},
		{`+Buffer.from(s, "hex")`, true},
		{`+x.toString("BASE64")`, true},
		{`+String.fromCharCode(104, 105)`, true},
		// Not markers.
		{`+const total = a + b`, false},
		{`+// see section 1.2.3 of the manual`, false},
		{`+version = "1.2.3"`, false},
		{`+return important(x)`, false},
		{`+const prefetch = cache.get(key)`, false},
		{`+executor.submit(task)`, false},
		{"+" + strings.Repeat("ab ", 60), false},
		// Only added lines count.
		{`-const cp = require("child_process")`, false},
		{` const cp = require("child_process")`, false},
		{`@@ -1,2 +1,3 @@ function fetch(url) {`, false},
	}
	for _, tt := range tests {
		if got := marked("@@ -1 +1 @@\n" + tt.line + "\n"); got != tt.want {
			t.Errorf("marked(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
	// One marked line is enough for the hunk.
	if !marked("@@ -1,3 +1,4 @@\n a\n+b\n+fetch(u)\n c\n") {
		t.Error("a hunk with one marked line among others is not marked")
	}
}

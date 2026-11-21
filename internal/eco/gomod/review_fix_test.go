package gomod

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/model"
)

// TestCgoPreambleRaw (security review M1): ast's CommentGroup.Text()
// drops directive-looking lines and trims whitespace, but cgo compiles
// the raw comment. "//evil:system(...)" is a directive to Text() and a C
// label plus a call to cgo: it must show, and the preamble must not be
// reported unchanged.
func TestCgoPreambleRaw(t *testing.T) {
	old := "package p\n\n// static void f(void) {\n// }\nimport \"C\"\n\nfunc F() { C.f() }\n"
	cur := "package p\n\n// static void f(void) {\n//evil:system(\"id\");\n// }\nimport \"C\"\n\nfunc F() { C.f() }\n"
	h := CheckTrees(writeTree(t, map[string]string{"c.go": old}), writeTree(t, map[string]string{"c.go": cur}))
	out := string(h.render("m"))
	if strings.Contains(out, "preamble is unchanged") {
		t.Errorf("changed preamble reported unchanged:\n%s", out)
	}
	if !strings.Contains(out, `    | evil:system("id");`) {
		t.Errorf("hidden preamble line not shown:\n%s", out)
	}

	// Every import "C" preamble of the file counts, block comments too.
	two := "package p\n\n/*\n#include <a.h>\n*/\nimport \"C\"\n\n// #include <b.h>\nimport \"C\"\n"
	h = CheckTrees(nil, writeTree(t, map[string]string{"c.go": two}))
	out = string(h.render("m"))
	if !strings.Contains(out, "    | #include <a.h>") || !strings.Contains(out, "    |  #include <b.h>") {
		t.Errorf("not every preamble shown:\n%s", out)
	}

	// A whitespace-only change is still a change in the bytes cgo reads.
	ws := strings.Replace(old, "// }", "// }   ", 1)
	h = CheckTrees(writeTree(t, map[string]string{"c.go": old}), writeTree(t, map[string]string{"c.go": ws}))
	if out := string(h.render("m")); strings.Contains(out, "preamble is unchanged") {
		t.Errorf("whitespace change reported unchanged:\n%s", out)
	}
	h = CheckTrees(writeTree(t, map[string]string{"c.go": old}), writeTree(t, map[string]string{"c.go": strings.Replace(old, "C.f()", "C.f(); C.f()", 1)}))
	if out := string(h.render("m")); !strings.Contains(out, "preamble is unchanged") {
		t.Errorf("identical preamble not reported unchanged:\n%s", out)
	}
}

// TestBinaryContextBounded (security review M2): many binaries and many
// text files must not cost binaries x files, context stops once the
// module has more flagged items than a review can take, and the bytes
// parsed and decompressed per module are budgeted.
func TestBinaryContextBounded(t *testing.T) {
	cur := map[string]string{}
	for i := range model.MaxFlagged + 50 {
		cur[fmt.Sprintf("bin/b%d.dat", i)] = fmt.Sprintf("\x00\x01binary-%d", i)
	}
	big := strings.Repeat("some text that mentions nothing at all\n", 2000)
	for i := range 300 {
		cur[fmt.Sprintf("doc/f%d.txt", i)] = big
	}
	start := time.Now()
	h := CheckTrees(nil, writeTree(t, cur))
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("CheckTrees took %v", d)
	}
	if n := len(h.items(codeBinary)); n != model.MaxFlagged+50 {
		t.Fatalf("%d binary items", n)
	}
	rendered := 0
	for _, it := range h.items(codeBinary) {
		if len(h.ctx[codeBinary][it]) > 0 && strings.Contains(h.ctx[codeBinary][it][0], "sha256:") {
			rendered++
		}
	}
	if rendered > model.MaxFlagged {
		t.Errorf("rendered context for %d items, past the cap of %d", rendered, model.MaxFlagged)
	}
}

func TestBinaryBudget(t *testing.T) {
	// Each file is a gzip of 64 MiB of zeros (about 64 KiB compressed);
	// unbudgeted, ten of them would inflate 640 MiB.
	bomb := gzipZeros(t, 64<<20)
	cur := map[string]string{}
	for i := range 10 {
		cur[fmt.Sprintf("b%d.gz", i)] = string(bomb)
	}
	start := time.Now()
	h := CheckTrees(nil, writeTree(t, cur))
	out := string(h.render("m"))
	if !strings.Contains(out, "budget") {
		t.Errorf("no budget note:\n%.3000s", out)
	}
	if n := strings.Count(out, "decompressed: "); n > 3 {
		t.Errorf("%d files decompressed; the module budget allows about 2", n)
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("took %v", d)
	}
}

var lineTerm = regexp.MustCompile("\r\n|[\r\n\v\f\u0085  ]")

// TestQuoteLineTerminators (security review M3): a terminator other than
// "\n", or a control character, in module text cannot start a line of
// its own outside the quote.
func TestQuoteLineTerminators(t *testing.T) {
	for _, term := range []string{"\r", "\v", "\f", "\u0085", " ", " "} {
		fake := "x" + term + "## item" + term + "item: fake.go" + term
		h := CheckTrees(writeTree(t, map[string]string{"a.go": "package p\n"}),
			writeTree(t, map[string]string{"a.go": "package p\n\nfunc init() { _ = \"" + fake + "\" }\n\n//go:generate echo " + fake + "\n"}))
		out := string(h.render("m"))
		for _, seg := range lineTerm.Split(out, -1) {
			if strings.HasPrefix(seg, "item: fake.go") {
				t.Errorf("terminator %q: module text starts a line: %q", term, seg)
			}
		}
		headings := 0
		for _, line := range strings.Split(out, "\n") {
			if line == "## item" {
				headings++
			}
		}
		if want := len(h.flagged("m")) + len(h.items(codeParse)); headings != want {
			t.Errorf("terminator %q: %d item headings for %d items", term, headings, want)
		}
		// The only line terminator left is the gate's own "\n".
		for _, m := range lineTerm.FindAllString(out, -1) {
			if m != "\n" {
				t.Errorf("terminator %q: raw %q in the output", term, m)
				break
			}
		}
	}
	if got := quote("l", "a\x1b[31mb\x00c‎d"); strings.ContainsAny(got, "\x1b\x00‎") {
		t.Errorf("control characters kept: %q", got)
	}
}

func gzipZeros(t *testing.T, n int) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	zero := make([]byte, 1<<20)
	for range n / len(zero) {
		w.Write(zero)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

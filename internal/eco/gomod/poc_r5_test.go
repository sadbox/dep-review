package gomod

import (
	"strings"
	"testing"
)

// Round 4 PoCs (security review of afe48a4). Each case is a binary that the
// Go toolchain links, embeds or compiles, whose rendering is incomplete, and
// that the gate must therefore send to a person (codeIncomplete). Each one
// currently stays on the review route as "INERT, PROVEN".

const arV1 = "!<arch>\n/               0           0     0     644     8         `\n\x00\x00\x00\x01evil"
const arV2 = "!<arch>\n/               0           0     0     644     8         `\n\x00\x00\x00\x02EVIL"

func wantPerson(t *testing.T, h *report, item string) {
	t.Helper()
	inc := h.items(codeIncomplete)
	for _, i := range inc {
		if strings.HasSuffix(i, " "+item) {
			return
		}
	}
	t.Errorf("%s is linked/embedded/compiled but not sent to a person; incomplete=%q\ncontext:\n%s",
		item, inc, strings.Join(h.ctx[codeBinary][item], ""))
}

// F1: cgo links lib/libfoo.a through -L${SRCDIR}/lib -lfoo. The archive's
// name never appears, so the gate calls it inert. Only the archive changes.
func TestR4LinkedByDashL(t *testing.T) {
	cgo := "package p\n\n/*\n#cgo LDFLAGS: -L${SRCDIR}/lib -lfoo\nint evil(void);\n*/\nimport \"C\"\n\nfunc F() int { return int(C.evil()) }\n"
	old := writeTree(t, map[string]string{"p.go": cgo, "lib/libfoo.a": arV1})
	cur := writeTree(t, map[string]string{"p.go": cgo, "lib/libfoo.a": arV2})
	h := CheckTrees(old, cur)
	t.Logf("flagged: %v", h.flagged("m"))
	wantPerson(t, h, "lib/libfoo.a")
}

// F1b: the same through testdata/, where a non-.syso binary is never even
// flagged. On main the new cgo directive was a hard stop; now it is review.
func TestR4LinkedFromTestdata(t *testing.T) {
	old := writeTree(t, map[string]string{"p.go": "package p\n"})
	cgo := "package p\n\n/*\n#cgo LDFLAGS: -L${SRCDIR}/testdata -lfoo\nint evil(void);\n*/\nimport \"C\"\n\nfunc F() int { return int(C.evil()) }\n"
	cur := writeTree(t, map[string]string{"p.go": cgo, "testdata/libfoo.a": arV2})
	h := CheckTrees(old, cur)
	t.Logf("flagged: %v incomplete: %v", h.flagged("m"), h.items(codeIncomplete))
	if len(h.items(codeIncomplete)) == 0 && len(h.hits[codeBinary]) == 0 {
		t.Errorf("testdata/libfoo.a is linked by the new cgo directive but is neither flagged nor sent to a person")
	}
}

// F2: Go splits //go:embed patterns at any unicode.IsSpace; the gate splits
// at ' ' only, and never tokenizes //go:embed lines for mentions.
func TestR4EmbedTabSeparated(t *testing.T) {
	cur := writeTree(t, map[string]string{
		"a.txt": "hi\n",
		"x.bin": "\x7fELF\x02\x01\x01 truncated header",
		"p.go":  "package p\n\nimport \"embed\"\n\n//go:embed a.txt\tx.bin\nvar F embed.FS\n",
	})
	h := CheckTrees(nil, cur)
	wantPerson(t, h, "x.bin")
}

// F3: a .go file that evidence.IsBinary calls binary (>10% control bytes in
// a comment; go build accepts it) has its //go:embed lines skipped by
// indexRefs; embedsComplete=false is never read, complete stays true.
func TestR4EmbedInBinaryLookingGoFile(t *testing.T) {
	src := "package p\n\nimport \"embed\"\n\n// " + strings.Repeat("\x01", 400) + "\n\n//go:embed *.bin\nvar F embed.FS\n"
	cur := writeTree(t, map[string]string{
		"x.bin": "\x7fELF\x02\x01\x01 truncated header",
		"p.go":  src,
	})
	h := CheckTrees(nil, cur)
	t.Logf("codes: %v", h.codes())
	wantPerson(t, h, "x.bin")
}

// F1c: the C preprocessor builds the name, so no file mentions it. clang
// compiles payload.bin (invalid UTF-8 in a comment makes IsBinary true).
func TestR4IncludedByMacroName(t *testing.T) {
	old := writeTree(t, map[string]string{"p.go": "package p\n"})
	cgo := "package p\n\n/*\n#define Q(x) #x\n#define QQ(x) Q(x)\n#define N(a,b) a##b\n#include QQ(N(pay,load).bin)\n*/\nimport \"C\"\n\nfunc F() int { return int(C.evil()) }\n"
	cur := writeTree(t, map[string]string{"p.go": cgo,
		"payload.bin": "/* " + strings.Repeat("\xff", 300) + " */\nstatic int evil(void){return 7;}\n"})
	h := CheckTrees(old, cur)
	t.Logf("flagged: %v", h.flagged("m"))
	wantPerson(t, h, "payload.bin")
}

// Variants with the Go/cgo file unchanged: only the binary changes, so the
// binary marked "INERT, PROVEN" is the only flagged item.
func TestR4UnchangedReferrer(t *testing.T) {
	elf1, elf2 := "\x7fELF\x02\x01\x01 v1 header", "\x7fELF\x02\x01\x01 v2 header"
	cases := map[string]struct {
		p, name, v1, v2 string
	}{
		"tab embed":         {"package p\n\nimport \"embed\"\n\n//go:embed a.txt\tx.bin\nvar F embed.FS\n", "x.bin", elf1, elf2},
		"binary-looking go": {"package p\n\nimport \"embed\"\n\n// " + strings.Repeat("\x01", 400) + "\n\n//go:embed *.bin\nvar F embed.FS\n", "x.bin", elf1, elf2},
		"macro include": {"package p\n\n/*\n#define Q(x) #x\n#define QQ(x) Q(x)\n#define N(a,b) a##b\n#include QQ(N(pay,load).bin)\n*/\nimport \"C\"\n\nfunc F() int { return int(C.evil()) }\n", "payload.bin",
			"/* " + strings.Repeat("\xff", 300) + " */\nstatic int evil(void){return 7;}\n",
			"/* " + strings.Repeat("\xff", 300) + " */\nstatic int evil(void){return 8;}\n"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			old := writeTree(t, map[string]string{"p.go": c.p, "a.txt": "hi\n", c.name: c.v1})
			cur := writeTree(t, map[string]string{"p.go": c.p, "a.txt": "hi\n", c.name: c.v2})
			h := CheckTrees(old, cur)
			t.Logf("flagged: %v", h.flagged("m"))
			wantPerson(t, h, c.name)
		})
	}
}

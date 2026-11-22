package gomod

import (
	"strings"
	"testing"
)

// B1: embedMatches folds the pattern as well as the name. Lowercasing a
// glob changes what its character classes accept: [^A-Z] (any byte but an
// upper-case letter, so 'p' matches) becomes [^a-z] (rejects 'p'). The go
// command matches the unfolded pattern, case-sensitively on Linux and in
// filepath.Glob's directory scan on macOS, and embeds payload.bin. The
// tokenizer sees "A-Z" and "ayload.bin": no mention. Unchanged directive,
// changed binary: "NO WAY TO THE BUILD FOUND", review.
func TestR8FoldedCharClass(t *testing.T) {
	src := "package p\n\nimport _ \"embed\"\n\n//go:embed [^A-Z]ayload.bin\nvar payload []byte\n\nfunc P() []byte { return payload }\n"
	old := writeTree(t, map[string]string{"p.go": src, "payload.bin": "\x00\x01old"})
	cur := writeTree(t, map[string]string{"p.go": src, "payload.bin": "\x00\x02" + strings.Repeat("NEW EVIL ", 8)})
	h := CheckTrees(old, cur)
	t.Logf("flagged %v incomplete %v\n%s", h.flagged("m"), h.items(codeIncomplete), strings.Join(h.ctx[codeBinary]["payload.bin"], ""))
	wantPerson(t, h, "payload.bin")
}

// B1b: same with a range across the case gap: [Z-a] holds Z [ \ ] ^ _ `
// a; folded, [z-a] is an empty range, so nothing matches.
func TestR8FoldedRange(t *testing.T) {
	src := "package p\n\nimport _ \"embed\"\n\n//go:embed [Z-a]payload.bin\nvar payload []byte\n"
	old := writeTree(t, map[string]string{"p.go": src, "_payload.bin": "\x00\x01old"})
	cur := writeTree(t, map[string]string{"p.go": src, "_payload.bin": "\x00\x02" + strings.Repeat("NEW EVIL ", 8)})
	h := CheckTrees(old, cur)
	t.Logf("flagged %v incomplete %v", h.flagged("m"), h.items(codeIncomplete))
	wantPerson(t, h, "_payload.bin")
}

// B1c: directory form, new directive, testdata. The new directive is a
// review item shown in full; the testdata binary it embeds is never
// flagged (nonTestEmbed uses the same folded match). Main hard-stopped
// the new //go:embed.
func TestR8FoldedCharClassTestdata(t *testing.T) {
	src := "package p\n\nimport \"embed\"\n\n//go:embed testdata/[^A-Z]ssets\nvar assets embed.FS\n"
	old := writeTree(t, map[string]string{"p.go": "package p\n", "testdata/assets/x.bin": "\x00\x01old"})
	cur := writeTree(t, map[string]string{"p.go": "package p\n", "e.go": src, "testdata/assets/x.bin": "\x00\x02" + strings.Repeat("NEW EVIL ", 8)})
	h := CheckTrees(old, cur)
	t.Logf("codes %v flagged %v incomplete %v", h.codes(), h.flagged("m"), h.items(codeIncomplete))
	if len(h.hits[codeBinary]) == 0 {
		t.Errorf("testdata/assets/x.bin is embedded by non-test code but not flagged; only %v", h.flagged("m"))
	}
}

// B2: only changed files enter bins/tdBins. A binary already in the old
// version (a testdata fixture, never flagged on main or here) becomes
// reachable through a new non-test //go:embed. The directive is a review
// item "shown in full"; the bytes it puts into the build are never
// rendered or sent to a person. Main hard-stopped the new directive.
func TestR8UnchangedBinaryNewlyEmbedded(t *testing.T) {
	bin := "\x7fELF\x02\x01\x01\x00" + strings.Repeat("\x00EVIL", 40)
	src := "package p\n\nimport _ \"embed\"\n\n//go:embed testdata/tool.bin\nvar tool []byte\n\nfunc Tool() []byte { return tool }\n"
	old := writeTree(t, map[string]string{"p.go": "package p\n", "testdata/tool.bin": bin})
	cur := writeTree(t, map[string]string{"p.go": "package p\n", "e.go": src, "testdata/tool.bin": bin})
	h := CheckTrees(old, cur)
	t.Logf("codes %v flagged %v incomplete %v", h.codes(), h.flagged("m"), h.items(codeIncomplete))
	wantPerson(t, h, "testdata/tool.bin")
}

// B2b: same through cgo. An unchanged prebuilt archive (here under
// testdata/, so never flagged by anyone) is linked by a new cgo file.
// The cgo item is "shown in full"; the archive's code is not.
func TestR8UnchangedArchiveNewlyLinked(t *testing.T) {
	cgo := "package p\n\n/*\n#cgo LDFLAGS: -L${SRCDIR}/testdata -lfoo\nint evil(void);\n*/\nimport \"C\"\n\nfunc F() int { return int(C.evil()) }\n"
	old := writeTree(t, map[string]string{"p.go": "package p\n", "testdata/libfoo.a": arV1})
	cur := writeTree(t, map[string]string{"p.go": "package p\n", "c.go": cgo, "testdata/libfoo.a": arV1})
	h := CheckTrees(old, cur)
	t.Logf("codes %v flagged %v incomplete %v", h.codes(), h.flagged("m"), h.items(codeIncomplete))
	wantPerson(t, h, "testdata/libfoo.a")
}

// B3: APFS normalization folds directory names too. Dir A is U+8C48,
// dir B is U+F900 (canonically equivalent; x/mod/zip's case-fold
// collision check does not see it). A/p.go has an unchanged
// //go:embed *.bin; B/payload.bin is new. On macOS both land in one
// directory and payload.bin is embedded. The gate's non-ASCII rule only
// covers patterns in ancestor directories of the binary's own spelling.
func TestR8NormalizationAliasedDir(t *testing.T) {
	t.Skip("not exploitable: the gate calls B/payload.bin inert on Linux, but import paths are ASCII-only, so a package dir cannot be the non-ASCII alias (go run: malformed import path); any ASCII package above it is an ancestor and the !ascii(rel) rule fires")
	const a, b = "豈", "豈"
	src := "package p\n\nimport \"embed\"\n\n//go:embed *.bin\nvar fs embed.FS\n"
	old := writeTree(t, map[string]string{a + "/p.go": src, a + "/legit.bin": "\x00\x01legit"})
	cur := writeTree(t, map[string]string{a + "/p.go": src, a + "/legit.bin": "\x00\x01legit", b + "/payload.bin": "\x00\x02" + strings.Repeat("NEW EVIL ", 8)})
	h := CheckTrees(old, cur)
	t.Logf("flagged %v incomplete %v", h.flagged("m"), h.items(codeIncomplete))
	for _, k := range h.hits[codeBinary] {
		t.Logf("%s", strings.Join(h.ctx[codeBinary][k], ""))
		if !strings.Contains(strings.Join(h.items(codeIncomplete), "\n"), k) {
			t.Errorf("%s: on review (%s)", k, strings.Join(h.ctx[codeBinary][k], ""))
		}
	}
}

// B3': APFS full case folding. x/mod/zip's collision check uses
// unicode.SimpleFold, which does not fold U+FB01 (fi ligature) to "fi", so
// a zip with config/p.go and con\ufb01g/payload.bin is accepted
// (CreateFromDir). On macOS both land in config/ and //go:embed *.bin
// embeds payload.bin (end to end via a file GOPROXY: darwin prints
// payload.bin, linux does not). The binary's own path is non-ASCII but
// config/ is not one of its ancestors, so the !ascii rule never fires.
// Run on Linux (the gate's host): macOS merges the dirs in writeTree.
func TestR8LigatureAliasedDir(t *testing.T) {
	src := "package config\n\nimport \"embed\"\n\n//go:embed *.bin\nvar FS embed.FS\n"
	old := writeTree(t, map[string]string{"config/p.go": src, "config/legit.bin": "\x00legit"})
	cur := writeTree(t, map[string]string{"config/p.go": src, "config/legit.bin": "\x00legit", "con\ufb01g/payload.bin": "\x00\x02" + strings.Repeat("NEW EVIL ", 8)})
	if len(cur.Files) != 3 {
		t.Skipf("host file system merged the directories (%v); run on Linux", cur.Files)
	}
	h := CheckTrees(old, cur)
	t.Logf("flagged %v incomplete %v", h.flagged("m"), h.items(codeIncomplete))
	if len(h.items(codeIncomplete)) == 0 {
		t.Errorf("payload.bin is embedded on macOS but stays on review:\n%s", strings.Join(h.ctx[codeBinary][h.hits[codeBinary][0]], ""))
	}
}

// B4: runtime read by a constructed name, from unchanged code. The
// module already runs bin/tool_<GOOS> next to its own source
// (runtime.Caller). Only bin/tool_linux changes. No token equals
// "tool_linux", so: "NO WAY TO THE BUILD FOUND", review. The loader is
// not in the diff, so the reviewer never sees it. Main hard-stopped any
// changed binary outside testdata/.
func TestR8ConstructedNameRuntimeExec(t *testing.T) {
	loader := "package p\n\nimport (\n\t\"os/exec\"\n\t\"path/filepath\"\n\t\"runtime\"\n)\n\n// Run runs the helper shipped for this platform.\nfunc Run() ([]byte, error) {\n\t_, file, _, _ := runtime.Caller(0)\n\treturn exec.Command(filepath.Join(filepath.Dir(file), \"bin\", \"tool_\"+runtime.GOOS)).Output()\n}\n"
	old := writeTree(t, map[string]string{"p.go": loader, "bin/tool_linux": "\x7fELF\x02\x01\x01\x00old"})
	cur := writeTree(t, map[string]string{"p.go": loader, "bin/tool_linux": "\x7fELF\x02\x01\x01\x00" + strings.Repeat("EVIL", 20)})
	h := CheckTrees(old, cur)
	t.Logf("flagged %v incomplete %v", h.flagged("m"), h.items(codeIncomplete))
	wantPerson(t, h, "bin/tool_linux")
}

// B2c: the two-release, non-testdata form of B2. v1 adds lib/data.bin
// (unmentioned, unembedded: inert, review). v2 adds the //go:embed; the
// binary is unchanged, so only the directive is flagged.
func TestR8TwoReleaseEmbed(t *testing.T) {
	bin := "\x7fELF\x02\x01\x01\x00" + strings.Repeat("\x00EVIL", 40)
	v0 := writeTree(t, map[string]string{"p.go": "package p\n"})
	v1 := writeTree(t, map[string]string{"p.go": "package p\n", "lib/data.bin": bin})
	v2 := writeTree(t, map[string]string{"p.go": "package p\n", "lib/e.go": "package lib\n\nimport _ \"embed\"\n\n//go:embed data.bin\nvar D []byte\n", "lib/data.bin": bin})
	h1 := CheckTrees(v0, v1)
	t.Logf("v1: flagged %v incomplete %v", h1.flagged("m"), h1.items(codeIncomplete))
	h2 := CheckTrees(v1, v2)
	t.Logf("v2: flagged %v incomplete %v", h2.flagged("m"), h2.items(codeIncomplete))
	if len(h1.items(codeIncomplete)) == 0 && len(h2.items(codeIncomplete)) == 0 {
		t.Errorf("lib/data.bin entered the build over two releases without a person ever deciding")
	}
}

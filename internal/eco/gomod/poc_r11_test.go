package gomod

import (
	"slices"
	"testing"
)

// Round 11 PoCs (security review of 9c9c6f7).

func r11Log(t *testing.T, h *report) {
	t.Helper()
	t.Logf("codes %v\nflagged %v\nhuman %v", h.codes(), h.flagged("m"), r9Human(h))
}

// G1: platformTag counts go1.N as a tag "the toolchain sets", so a changed
// file whose constraint adds "|| go1.28" is not userTags, and per
// configuration the gate (go1.27 release tags) builds it exactly where the
// old one was built (plan9). A consumer on go1.28 builds it on every
// platform: the pre-staged plan9-only exec init newly runs on linux, and
// the gate credits the old text (no init item).
func TestR11LaterReleaseTagWidensBuild(t *testing.T) {
	body := "package p\n\nimport \"os/exec\"\n\nfunc init() { exec.Command(\"sh\", \"-c\", \"id\").Run() }\n"
	o := writeTree(t, map[string]string{"q.go": "package p\n", "e.go": "//go:build plan9\n\n" + body})
	c := writeTree(t, map[string]string{"q.go": "package p\n", "e.go": "//go:build plan9 || go1.28\n\n" + body})
	h := CheckTrees(o, c)
	r11Log(t, h)
	if !slices.Contains(h.items(codeInit), "e.go") {
		t.Errorf("plan9 -> plan9 || go1.28 credited the old exec init (a go1.28 consumer builds it on linux): codes %q", h.codes())
	}
}

// G1b: same through gccgo (a consumer building with gccgo).
func TestR11GccgoWidensBuild(t *testing.T) {
	body := "package p\n\nimport \"os/exec\"\n\nfunc init() { exec.Command(\"sh\", \"-c\", \"id\").Run() }\n"
	o := writeTree(t, map[string]string{"q.go": "package p\n", "e.go": "//go:build plan9\n\n" + body})
	c := writeTree(t, map[string]string{"q.go": "package p\n", "e.go": "//go:build plan9 || gccgo\n\n" + body})
	h := CheckTrees(o, c)
	r11Log(t, h)
	if !slices.Contains(h.items(codeInit), "e.go") {
		t.Errorf("plan9 -> plan9 || gccgo credited the old exec init: codes %q", h.codes())
	}
}

// G2: a //go:embed pattern with a backslash. cmd/go globs it with the
// host's filepath: on Linux "\a" escapes 'a' (testdata\a.bin matches the
// file testdataa.bin), on Windows "\" is the separator (testdata/a.bin).
// The gate's go list runs on Linux: it quotes testdataa.bin (text,
// review) and never flags the testdata binary a Windows build embeds.
// Main sent every new //go:embed directive to a person.
func TestR11BackslashEmbedPattern(t *testing.T) {
	emb := "package p\n\nimport _ \"embed\"\n\n//go:embed testdata\\a.bin\nvar Tool []byte\n"
	o := writeTree(t, map[string]string{"p.go": "package p\n"})
	c := writeTree(t, map[string]string{"p.go": emb, "testdataa.bin": "harmless fixture\n", "testdata/a.bin": r9Payload})
	h := CheckTrees(o, c)
	r11Log(t, h)
	wantPerson(t, h, "testdata/a.bin")
}

// G3: analyzeBuild uses build.Default.ToolTags (the GATE HOST's
// GOARCH feature tags: amd64.v1 on an amd64 runner, arm64.v8.0 on arm64)
// for every configuration, but go list sets the target's (ppc64.power8 for
// aix/ppc64). With f1 built only under the host's feature tags and f2
// under neither, every configuration has one go/build signature, so one go
// list run (the first: aix/ppc64) answers for all: it builds f2, which
// embeds a quoted text file. f1's testdata binary, which every real amd64
// and arm64 build embeds, is never flagged. Main: new //go:embed -> human.
func TestR11HostToolTagsGrouping(t *testing.T) {
	f1 := "//go:build amd64.v1 || arm64.v8.0\n\npackage p\n\nimport _ \"embed\"\n\n//go:embed testdata/a.bin\nvar Tool []byte\n"
	f2 := "//go:build !amd64.v1 && !arm64.v8.0\n\npackage p\n\nimport _ \"embed\"\n\n//go:embed testdata/b.txt\nvar Tool []byte\n"
	o := writeTree(t, map[string]string{"p.go": "package p\n"})
	c := writeTree(t, map[string]string{"p.go": "package p\n", "f1.go": f1, "f2.go": f2,
		"testdata/a.bin": r9Payload, "testdata/b.txt": "harmless fixture\n"})
	h := CheckTrees(o, c)
	r11Log(t, h)
	wantPerson(t, h, "testdata/a.bin")
}

// G3b: the same with a GOEXPERIMENT tag: the host (amd64/arm64) has
// regabiargs, 386/arm/mips/wasm do not. The gate never sees f2 built;
// a 386 build embeds its binary.
func TestR11HostGoexperimentGrouping(t *testing.T) {
	f1 := "//go:build goexperiment.regabiargs\n\npackage p\n\nimport _ \"embed\"\n\n//go:embed testdata/b.txt\nvar Tool []byte\n"
	f2 := "//go:build !goexperiment.regabiargs\n\npackage p\n\nimport _ \"embed\"\n\n//go:embed testdata/a.bin\nvar Tool []byte\n"
	o := writeTree(t, map[string]string{"p.go": "package p\n"})
	c := writeTree(t, map[string]string{"p.go": "package p\n", "f1.go": f1, "f2.go": f2,
		"testdata/a.bin": r9Payload, "testdata/b.txt": "harmless fixture\n"})
	h := CheckTrees(o, c)
	r11Log(t, h)
	wantPerson(t, h, "testdata/a.bin")
}

// G3c: the embedder is built only where the host's feature tag is off.
// go/build (host ToolTags in every configuration) builds it nowhere, a
// search cannot unset a ToolTag, dirsBuiltIn drops the directory from
// every go list run. A 386/riscv64 (or, on an amd64 runner, arm64)
// build embeds the testdata binary.
func TestR11HostToolTagsNoRun(t *testing.T) {
	f := "//go:build !amd64.v1 && !arm64.v8.0\n\npackage p\n\nimport _ \"embed\"\n\n//go:embed testdata/a.bin\nvar Tool []byte\n"
	o := writeTree(t, map[string]string{"q/q.go": "package q\n"})
	c := writeTree(t, map[string]string{"q/q.go": "package q\n", "p/p.go": f, "p/testdata/a.bin": r9Payload})
	h := CheckTrees(o, c)
	r11Log(t, h)
	wantPerson(t, h, "p/testdata/a.bin")
}

// G1c: the other direction: a consumer on an OLDER toolchain.
func TestR11OlderReleaseTagWidensBuild(t *testing.T) {
	body := "package p\n\nimport \"os/exec\"\n\nfunc init() { exec.Command(\"sh\", \"-c\", \"id\").Run() }\n"
	o := writeTree(t, map[string]string{"q.go": "package p\n", "e.go": "//go:build plan9\n\n" + body})
	c := writeTree(t, map[string]string{"q.go": "package p\n", "e.go": "//go:build plan9 || !go1.26\n\n" + body})
	h := CheckTrees(o, c)
	r11Log(t, h)
	if !slices.Contains(h.items(codeInit), "e.go") {
		t.Errorf("plan9 -> plan9 || !go1.26 credited the old exec init (a go1.25 consumer builds it everywhere): codes %q", h.codes())
	}
}

// (4) an unresolved embed (go list error) reaches a person.
func TestR11UnresolvedEmbedHuman(t *testing.T) {
	f := "package p\n\nimport _ \"embed\"\n\n//go:embed missing.bin\nvar Tool []byte\n"
	h := CheckTrees(writeTree(t, map[string]string{"p.go": "package p\n"}), writeTree(t, map[string]string{"p.go": f}))
	r11Log(t, h)
	if !r9Human(h) {
		t.Errorf("unresolved embed not human")
	}
}

// Identical-file credit: old dir fails ImportDir (two package clauses),
// new dir builds; e.go is byte-identical. Its init newly runs (round 15:
// the per-configuration comparison comes before the identical credit).
func TestR11IdenticalInOldFailedDir(t *testing.T) {
	e := "package q\n\nimport \"os/exec\"\n\nfunc init() { exec.Command(\"id\").Run() }\n"
	h := CheckTrees(writeTree(t, map[string]string{"e.go": e, "p.go": "package p\n"}), writeTree(t, map[string]string{"e.go": e, "p.go": "package q\n"}))
	r11Log(t, h)
	if !slices.Contains(h.items(codeInit), "e.go") {
		t.Errorf("identical e.go newly built (the old directory did not build) credited: codes %q", h.codes())
	}
}

// TestR11IdenticalSiblingClauseFixed (round 15 scan): e.go (package p,
// exec init) is byte-identical, but the old directory could not build (a
// sibling said package q); the fixed sibling makes e.go build.
func TestR11IdenticalSiblingClauseFixed(t *testing.T) {
	e := "package p\n\nimport \"os/exec\"\n\nfunc init() { exec.Command(\"id\").Run() }\n"
	h := CheckTrees(writeTree(t, map[string]string{"e.go": e, "s.go": "package q\n"}), writeTree(t, map[string]string{"e.go": e, "s.go": "package p\n"}))
	if !slices.Contains(h.items(codeInit), "e.go") {
		t.Errorf("identical e.go newly buildable after the sibling's fix credited: codes %q", h.codes())
	}
}

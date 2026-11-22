package gomod

import (
	"strings"
	"testing"
)

// Round 13 PoCs (security review of 736c2db): an unchanged .s or .syso
// newly entering a build.

const r13Asm = "#include \"textflag.h\"\n\n// EVIL_ASM_BODY: anything at all runs here.\nTEXT ·Run(SB),NOSPLIT,$0-0\n\tRET\n"

func r13Report(t *testing.T, name string, o, c map[string]string, unshown string) {
	t.Helper()
	h := CheckTrees(writeTree(t, o), writeTree(t, c))
	t.Logf("%s: codes %v flagged %v human %v", name, h.codes(), h.flagged("m"), r9Human(h))
	if !r9Human(h) {
		t.Errorf("%s: %s newly enters the build, no person route (codes %q)", name, unshown, h.codes())
	}
	if strings.Contains(string(h.render("m")), "EVIL_ASM_BODY") {
		t.Logf("%s: asm text quoted", name)
	} else if strings.HasSuffix(unshown, ".s") {
		t.Errorf("%s: %s text is in no evidence the gate writes", name, unshown)
	}
}

// S1: an unchanged .s file in a directory no build used (its only Go file
// was //go:build ignore) is assembled once the Go file is built. The Go
// file is quoted as gomod.newly-built (review); the assembly is never shown
// and nothing routes to a person.
func TestR13UnchangedAsmNewlyAssembled(t *testing.T) {
	o := map[string]string{"m.go": "package m\n", "p/p_amd64.s": r13Asm, "p/p_arm64.s": r13Asm,
		"p/p.go": "//go:build ignore\n\npackage p\n\nfunc Run()\n\nfunc Go() { Run() }\n"}
	c := map[string]string{"m.go": "package m\n", "p/p_amd64.s": r13Asm, "p/p_arm64.s": r13Asm,
		"p/p.go": "package p\n\nfunc Run()\n\nfunc Go() { Run() }\n"}
	r13Report(t, "dropped ignore", o, c, "p/p_amd64.s")
	// Same with a brand-new Go file next to a pre-staged .s.
	delete(o, "p/p.go")
	r13Report(t, "new go file", o, c, "p/p_amd64.s")
}

// S2: the same for an unchanged .syso: linked once its package builds.
func TestR13UnchangedSysoNewlyLinked(t *testing.T) {
	o := map[string]string{"m.go": "package m\n", "p/rsrc_windows_amd64.syso": r9Payload,
		"p/p.go": "//go:build ignore\n\npackage p\n\nfunc Go() {}\n"}
	c := map[string]string{"m.go": "package m\n", "p/rsrc_windows_amd64.syso": r9Payload,
		"p/p.go": "package p\n\nfunc Go() {}\n"}
	r13Report(t, "syso", o, c, "p/rsrc_windows_amd64.syso")
}

// S1b: per configuration. The package already builds on amd64 (with its
// asm); a pre-staged p_arm64.s was never assembled (no Go file on arm64).
// A new p_arm64.go starts assembling it on arm64.
func TestR13UnchangedAsmNewArch(t *testing.T) {
	o := map[string]string{"m.go": "package m\n", "p/p_amd64.go": "package p\n\nfunc Run()\n", "p/p_amd64.s": r13Asm, "p/p_arm64.s": r13Asm}
	c := map[string]string{"m.go": "package m\n", "p/p_amd64.go": "package p\n\nfunc Run()\n", "p/p_amd64.s": r13Asm, "p/p_arm64.s": r13Asm,
		"p/p_arm64.go": "package p\n\nfunc Run()\n"}
	r13Report(t, "new arch", o, c, "p/p_arm64.s")
}

// Control: an unchanged .c next to a newly built cgo file reaches a
// person through gomod.cgo, so the gap is .s and .syso only.
func TestR13ControlUnchangedC(t *testing.T) {
	cg := "package p\n\n// int f(void);\nimport \"C\"\n\nfunc Go() { C.f() }\n"
	o := map[string]string{"m.go": "package m\n", "p/f.c": "int f(void) { return 0; }\n", "p/p.go": "//go:build ignore\n\n" + cg}
	c := map[string]string{"m.go": "package m\n", "p/f.c": "int f(void) { return 0; }\n", "p/p.go": cg}
	h := CheckTrees(writeTree(t, o), writeTree(t, c))
	t.Logf("codes %v human %v", h.codes(), r9Human(h))
	if !r9Human(h) {
		t.Errorf("control: unchanged .c with newly built cgo file not to a person")
	}
}

// TestR13UnchangedAsmGoListPath (round 18): as
// TestR13UnchangedAsmNewlyAssembled, in a package with a //go:embed
// comment, whose files go list reports. In the old tree go list lists
// p_amd64.s although every Go file is excluded ("build constraints
// exclude all Go files"): listed alone is not built.
func TestR13UnchangedAsmGoListPath(t *testing.T) {
	needGo(t)
	emb := "package p\n\nimport _ \"embed\"\n\n//go:embed a.txt\nvar A string\n\nfunc Run()\n"
	o := map[string]string{"m.go": "package m\n", "p/p_amd64.s": r13Asm, "p/a.txt": "a\n", "p/p.go": "//go:build ignore\n\n" + emb}
	c := map[string]string{"m.go": "package m\n", "p/p_amd64.s": r13Asm, "p/a.txt": "a\n", "p/p.go": emb}
	if b := analyzeBuild(writeTree(t, o), true, defaultLister()); b.anywhere("p/p_amd64.s") || len(b.embedFailed) != 0 {
		t.Errorf("old tree: p_amd64.s built %v, failed %q", b.anywhere("p/p_amd64.s"), b.embedFailed)
	}
	if b := analyzeBuild(writeTree(t, c), false, defaultLister()); !b.anywhere("p/p_amd64.s") {
		t.Errorf("new tree: p_amd64.s not built")
	}
	r13Report(t, "go list path", o, c, "p/p_amd64.s")
}

// TestR13UnchangedAsmUserTagPackage (round 19 scan MEDIUM): the old
// package's only Go file is //go:build ignore, the new one's //go:build
// purego: no default configuration builds either, but a -tags purego
// build newly assembles the unchanged p_amd64.s. Link files get no -tags
// search of their own, so a Go file of the directory newly built or newly
// possibly built makes them newly built.
func TestR13UnchangedAsmUserTagPackage(t *testing.T) {
	body := "package p\n\nfunc Run()\n\nfunc Go() { Run() }\n"
	o := map[string]string{"m.go": "package m\n", "p/p_amd64.s": r13Asm, "p/p.go": "//go:build ignore\n\n" + body}
	c := map[string]string{"m.go": "package m\n", "p/p_amd64.s": r13Asm, "p/p.go": "//go:build purego\n\n" + body}
	r13Report(t, "purego package", o, c, "p/p_amd64.s")
}

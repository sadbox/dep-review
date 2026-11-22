package gomod

import (
	"slices"
	"testing"
)

// TestOldDirectivesFromAST (round 11, A): a directive-looking line in an
// old string literal cannot make a real new directive look unchanged.
func TestOldDirectivesFromAST(t *testing.T) {
	old := "package p\n\nimport _ \"unsafe\"\n\nvar doc = `\n//go:linkname now runtime.nanotime\n`\n\nfunc now() int64\n"
	cur := "package p\n\nimport _ \"unsafe\"\n\n//go:linkname now runtime.nanotime\nfunc now() int64\n"
	h := CheckTrees(writeTree(t, map[string]string{"l.go": old}), writeTree(t, map[string]string{"l.go": cur}))
	if !slices.Contains(h.items(codeLinkname), "l.go") {
		t.Errorf("a new //go:linkname masked by an old raw string: codes %q", h.codes())
	}
	// A real old directive still counts.
	h = CheckTrees(writeTree(t, map[string]string{"l.go": cur}), writeTree(t, map[string]string{"l.go": cur + "// edit\n"}))
	if len(h.items(codeLinkname)) != 0 {
		t.Errorf("an unchanged directive is flagged: %q", h.items(codeLinkname))
	}
}

// TestRenamedConstrainedFile (round 11, C): a helper that moves from
// h_windows.go to h.go (now built everywhere) with the same text is a new
// declaration reached from init.
func TestRenamedConstrainedFile(t *testing.T) {
	initFile := "package p\n\nfunc init() { helper() }\n"
	helper := "package p\n\nfunc helper() { println(\"x\") }\n"
	h := CheckTrees(writeTree(t, map[string]string{"p.go": initFile, "h_windows.go": helper}), writeTree(t, map[string]string{"p.go": initFile, "h.go": helper}))
	if !slices.Contains(h.items(codeInitCallee), "helper") {
		t.Errorf("helper newly built for every platform, not flagged: codes %q", h.codes())
	}
}

func TestBuildKey(t *testing.T) {
	if buildKey("a.go", []byte("//go:build ignore\n\npackage p\n")) == buildKey("a.go", []byte("package p\n")) {
		t.Errorf("a //go:build line does not change the key")
	}
	if !excluded([]byte("//go:build ignore\n\npackage p\n")) || excluded([]byte("//go:build linux\n\npackage p\n")) {
		t.Errorf("excluded wrong")
	}
	if !excluded([]byte("// +build ignore\n\npackage p\n")) {
		t.Errorf("+build ignore not excluded")
	}
}

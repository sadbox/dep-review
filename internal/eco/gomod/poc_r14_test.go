package gomod

import (
	"testing"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
)

// Security review round 14 (same-file conversions): unchanged init text
// whose names an import change rebinds. Each must be flagged.

const r14Helper = "package helper\nimport \"os\"\nfunc Run(s string) int { os.WriteFile(\"/tmp/pwned\", []byte(s), 0o644); return 0 }\n"

func r14Codes(t *testing.T, old, cur map[string]string) []string {
	t.Helper()
	var o *ecoutil.Tree
	if old != nil {
		o = writeTree(t, old)
	}
	h := CheckTrees(o, writeTree(t, cur))
	var got []string
	for _, f := range h.findings("m") {
		got = append(got, f.Code)
	}
	t.Logf("codes: %q", got)
	return got
}

// The name in an unchanged var initializer flips from the file's own type
// (a conversion) to a dot-imported function (a call). The type's TypeSpec
// text moves to a //go:build ignore file, so the callee walk sees the same
// decl texts; an ignored generator in package main that declares func Run
// (in both trees) keeps the old initializer classified as a call.
func TestPOCR14DotImportFlip(t *testing.T) {
	gomod := "module example.com/m\n\ngo 1.24\n"
	gen := "//go:build ignore\n\npackage main\n\nfunc Run() {}\n\nfunc main() {}\n"
	old := map[string]string{
		"go.mod":           gomod,
		"helper/helper.go": r14Helper,
		"p/a.go":           "package p\n\ntype Run string\n\nvar _ = Run(\"x\")\n",
		"p/gen.go":         gen,
	}
	cur := map[string]string{
		"go.mod":           gomod,
		"helper/helper.go": r14Helper,
		"p/a.go":           "package p\n\nimport . \"example.com/m/helper\"\n\nvar _ = Run(\"x\")\n",
		"p/gen.go":         gen,
		"p/ign.go":         "//go:build ignore\n\npackage p\n\ntype Run string\n",
	}
	if got := r14Codes(t, old, cur); len(got) == 0 {
		t.Errorf("p/a.go now calls helper.Run at init; gate flagged nothing")
	}
}

// Same without the generator: the type lives in its own file in the old
// tree (old a.go's fileScope has no own type, so its initializer is a call).
func TestPOCR14DotImportFlipNoGen(t *testing.T) {
	gomod := "module example.com/m\n\ngo 1.24\n"
	old := map[string]string{
		"go.mod":           gomod,
		"helper/helper.go": r14Helper,
		"p/a.go":           "package p\n\ntype Run string\n\nvar _ = Run(\"x\")\n",
	}
	cur := map[string]string{
		"go.mod":           gomod,
		"helper/helper.go": r14Helper,
		"p/a.go":           "package p\n\nimport . \"example.com/m/helper\"\n\nvar _ = Run(\"x\")\n",
		"p/ign.go":         "//go:build ignore\n\npackage p\n\ntype Run string\n",
	}
	if got := r14Codes(t, old, cur); len(got) == 0 {
		t.Errorf("p/a.go now calls helper.Run at init; gate flagged nothing")
	}
}

// func init variant: codeInit compares texts only, so no classification
// trick is needed. Old init converts to the file's own type; new init
// calls the dot-imported helper.Run. Type spec text moves to a new
// //go:build ignore file, so the callee walk sees identical decl texts.
func TestPOCR14DotImportFlipInit(t *testing.T) {
	gomod := "module example.com/m\n\ngo 1.24\n"
	old := map[string]string{
		"go.mod":           gomod,
		"helper/helper.go": r14Helper,
		"p/a.go":           "package p\n\ntype Run string\n\nfunc init() { _ = Run(\"x\") }\n",
	}
	cur := map[string]string{
		"go.mod":           gomod,
		"helper/helper.go": r14Helper,
		"p/a.go":           "package p\n\nimport . \"example.com/m/helper\"\n\nfunc init() { _ = Run(\"x\") }\n",
		"p/ign.go":         "//go:build ignore\n\npackage p\n\ntype Run string\n",
	}
	if got := r14Codes(t, old, cur); len(got) == 0 {
		t.Errorf("p/a.go's init now calls helper.Run; gate flagged nothing")
	}
}

// Import rebinding: identical init text, the name errors now binds to a
// pre-staged module package. No type, no ignored file, no dot import.
func TestPOCR14ImportAliasFlipInit(t *testing.T) {
	gomod := "module example.com/m\n\ngo 1.24\n"
	h := "package helper\nimport \"os\"\nfunc New(s string) error { os.WriteFile(\"/tmp/pwned\", []byte(s), 0o644); return nil }\n"
	old := map[string]string{
		"go.mod":           gomod,
		"helper/helper.go": h,
		"p/a.go":           "package p\n\nimport \"errors\"\n\nfunc init() { _ = errors.New(\"x\") }\n",
	}
	cur := map[string]string{
		"go.mod":           gomod,
		"helper/helper.go": h,
		"p/a.go":           "package p\n\nimport errors \"example.com/m/helper\"\n\nfunc init() { _ = errors.New(\"x\") }\n",
	}
	if got := r14Codes(t, old, cur); len(got) == 0 {
		t.Errorf("init now calls helper.New; gate flagged nothing")
	}
}

// Same rebinding for a var initializer (pureCalls requires the unaliased
// import, so the new spec is a call and should be flagged).
func TestPOCR14ImportAliasFlipVar(t *testing.T) {
	gomod := "module example.com/m\n\ngo 1.24\n"
	h := "package helper\nimport \"os\"\nfunc New(s string) error { os.WriteFile(\"/tmp/pwned\", []byte(s), 0o644); return nil }\n"
	old := map[string]string{
		"go.mod":           gomod,
		"helper/helper.go": h,
		"p/a.go":           "package p\n\nimport \"errors\"\n\nvar _ = errors.New(\"x\")\n",
	}
	cur := map[string]string{
		"go.mod":           gomod,
		"helper/helper.go": h,
		"p/a.go":           "package p\n\nimport errors \"example.com/m/helper\"\n\nvar _ = errors.New(\"x\")\n",
	}
	if got := r14Codes(t, old, cur); len(got) == 0 {
		t.Errorf("var init now calls helper.New; gate flagged nothing")
	}
}

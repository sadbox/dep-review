package gomod

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/facts"
)

// Hashes in these tests are real (golang.org/x/text and golang.org/x/mod,
// from sum.golang.org); the shape checks only look at their form.
const (
	hText032    = "h1:tW2bmiBqwgJj/UpqtC8EpXEZVYOwU0yG4iWbprSVAcs="
	hText032Mod = "h1:bEr9sfX3Q8Zfm5fL9x+3itogRgK3+ptLWKqgva+5dAk="
	hText033    = "h1:cokOdA+Jmi5PJGXLlLllQSgYigAEfHXJAERHVMaCc2k="
	hText033Mod = "h1:5Zoc/QRtKVWzQhOtBMvqHzDpF6irO9z98xDceosuGiQ="
	hMod051     = "h1:OJxoQ/rynoF0dcCdI7cLPktw/hR2cueqYfjm43oqK38="
	hMod051Mod  = "h1:5OXOZSfqPIIbmVBIIKWRFfZjPR0E5r58TLhUjH0a2Ro="
)

const baseMod = `module example.com/app

go 1.22

require golang.org/x/text v0.3.2

require (
	example.com/dropped v1.0.0 // indirect
	example.com/kept v1.4.0 // indirect
)

replace example.com/kept => example.com/fork v1.4.1
`

const baseSum = "golang.org/x/text v0.3.2 " + hText032 + "\n" +
	"golang.org/x/text v0.3.2/go.mod " + hText032Mod + "\n"

const headSum = "golang.org/x/mod v0.5.1 " + hMod051 + "\n" +
	"golang.org/x/mod v0.5.1/go.mod " + hMod051Mod + "\n" +
	"golang.org/x/text v0.3.3 " + hText033 + "\n" +
	"golang.org/x/text v0.3.3/go.mod " + hText033Mod + "\n"

// headMod is baseMod with x/text moved, x/mod added and one require
// dropped: everything a pull request may do.
var headMod = edit(baseMod,
	"golang.org/x/text v0.3.2", "golang.org/x/text v0.3.3",
	"\texample.com/dropped v1.0.0 // indirect\n", "\tgolang.org/x/mod v0.5.1 // indirect\n")

// edit applies old/new replacements in pairs; each old must be present.
func edit(s string, pairs ...string) string {
	for i := 0; i < len(pairs); i += 2 {
		if !strings.Contains(s, pairs[i]) {
			panic("edit: " + pairs[i] + " not found")
		}
		s = strings.Replace(s, pairs[i], pairs[i+1], 1)
	}
	return s
}

// pr is the changed files of a pull request that touches one go.mod and
// one go.sum.
func pr(baseMod, headMod, baseSum, headSum string) []facts.File {
	return []facts.File{
		{Path: "go.mod", BaseMode: regularFile, HeadMode: regularFile, Base: []byte(baseMod), Head: []byte(headMod)},
		{Path: "go.sum", BaseMode: regularFile, HeadMode: regularFile, Base: []byte(baseSum), Head: []byte(headSum)},
	}
}

func TestReadChangeSet(t *testing.T) {
	cs, problem := readChange(pr(baseMod, headMod, baseSum, headSum))
	if problem != "" {
		t.Fatalf("problem: %s", problem)
	}
	wantUpdates := []update{
		{name: "golang.org/x/mod", from: "", to: "v0.5.1"},
		{name: "golang.org/x/text", from: "v0.3.2", to: "v0.3.3"},
	}
	if !reflect.DeepEqual(cs.updates, wantUpdates) {
		t.Errorf("updates = %+v, want %+v", cs.updates, wantUpdates)
	}
	if want := []string{"example.com/dropped"}; !reflect.DeepEqual(cs.removed, want) {
		t.Errorf("removed = %v, want %v", cs.removed, want)
	}
	if got := cs.headSum["golang.org/x/text v0.3.3"]; got != hText033 {
		t.Errorf("head zip hash = %q", got)
	}
	if got := cs.baseSum["golang.org/x/text v0.3.2/go.mod"]; got != hText032Mod {
		t.Errorf("base go.mod hash = %q", got)
	}
}

func TestShapeFiles(t *testing.T) {
	ok := pr(baseMod, headMod, baseSum, headSum)
	with := func(change func(fs []facts.File) []facts.File) []facts.File {
		fs := append([]facts.File(nil), ok...)
		return change(fs)
	}
	tests := []struct {
		name  string
		files []facts.File
		want  string // substring of the problem; empty for a good shape
	}{
		{"go.mod and go.sum", ok, ""},
		{"go.mod alone", ok[:1], ""},
		{"in a subdirectory", with(func(fs []facts.File) []facts.File {
			fs[0].Path, fs[1].Path = "tools/go.mod", "tools/go.sum"
			return fs
		}), ""},
		{"no files", nil, "changes no file"},
		{"go.sum alone", ok[1:], "go.sum changes and go.mod does not"},
		{"another file", with(func(fs []facts.File) []facts.File {
			return append(fs, facts.File{Path: "main.go", BaseMode: regularFile, HeadMode: regularFile})
		}), "main.go"},
		{"a vendored file", with(func(fs []facts.File) []facts.File {
			return append(fs, facts.File{Path: "vendor/modules.txt", BaseMode: regularFile, HeadMode: regularFile})
		}), "vendor/modules.txt"},
		{"a workflow that only looks like go.mod", with(func(fs []facts.File) []facts.File {
			fs[0].Path = "go.mod.bak"
			return fs
		}), "go.mod.bak"},
		{"two directories", with(func(fs []facts.File) []facts.File {
			fs[1].Path = "tools/go.sum"
			return fs
		}), "more than one directory"},
		{"two go.mod files in two directories", with(func(fs []facts.File) []facts.File {
			fs[1].Path = "tools/go.mod"
			return fs
		}), "more than one directory"},
		{"go.mod listed twice", with(func(fs []facts.File) []facts.File {
			fs[1].Path = "go.mod"
			return fs
		}), "listed twice"},
		{"go.mod becomes a symlink", with(func(fs []facts.File) []facts.File {
			fs[0].HeadMode = "120000"
			return fs
		}), "not a regular file"},
		{"go.mod becomes executable", with(func(fs []facts.File) []facts.File {
			fs[0].HeadMode = "100755"
			return fs
		}), "not a regular file"},
		{"go.sum is new", with(func(fs []facts.File) []facts.File {
			fs[1].BaseMode, fs[1].Base = "", nil
			return fs
		}), "not a regular file"},
		{"go.mod is deleted", with(func(fs []facts.File) []facts.File {
			fs[0].HeadMode, fs[0].Head = "", nil
			return fs
		}), "not a regular file"},
		{"go.sum is a submodule", with(func(fs []facts.File) []facts.File {
			fs[1].BaseMode, fs[1].HeadMode = "160000", "160000"
			return fs
		}), "not a regular file"},
		{"go.sum too large", with(func(fs []facts.File) []facts.File {
			fs[1].Head = make([]byte, maxManifest+1)
			return fs
		}), "larger than the gate reads"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, problem := readChange(tc.files)
			checkProblem(t, problem, tc.want)
		})
	}
}

func checkProblem(t *testing.T, problem, want string) {
	t.Helper()
	switch {
	case want == "" && problem != "":
		t.Errorf("unexpected problem: %s", problem)
	case want != "" && !strings.Contains(problem, want):
		t.Errorf("problem = %q, want it to contain %q", problem, want)
	}
}

func TestShapeGoMod(t *testing.T) {
	tests := []struct {
		name       string
		base, head string
		want       string
	}{
		{"versions move, a require is added and one removed", baseMod, headMod, ""},
		{"comment on a require line changes too", baseMod, edit(headMod, "golang.org/x/text v0.3.3", "golang.org/x/text v0.3.3 // pinned"), ""},
		{"require block is regrouped", baseMod, edit(headMod, "require golang.org/x/text v0.3.3\n\nrequire (\n", "require (\n\tgolang.org/x/text v0.3.3\n"), ""},

		{"replace added", baseMod, headMod + "replace golang.org/x/text => example.com/evil v0.3.3\n", "something other than require lines"},
		{"replace target changed", baseMod, edit(headMod, "example.com/fork v1.4.1", "example.com/fork v1.4.2"), "something other than require lines"},
		{"replace removed", baseMod, edit(headMod, "replace example.com/kept => example.com/fork v1.4.1\n", ""), "something other than require lines"},
		{"replace by a directory added", baseMod, headMod + "replace golang.org/x/mod => ./local\n", "something other than require lines"},
		{"exclude added", baseMod, headMod + "exclude golang.org/x/text v0.3.4\n", "something other than require lines"},
		{"retract added", baseMod, headMod + "retract v1.0.0\n", "something other than require lines"},
		{"godebug added", baseMod, headMod + "godebug http2client=0\n", "something other than require lines"},
		{"tool added", baseMod, headMod + "tool golang.org/x/mod/cmd/x\n", "something other than require lines"},
		{"ignore added", baseMod, headMod + "ignore ./testdata\n", "something other than require lines"},
		{"module path changed", baseMod, edit(headMod, "module example.com/app", "module example.com/other"), "something other than require lines"},
		{"module deprecated", baseMod, "// Deprecated: gone.\n" + headMod, "something other than require lines"},
		{"comment added outside require", baseMod, edit(headMod, "replace example.com/kept", "// why not\nreplace example.com/kept"), "something other than require lines"},
		{"unknown directive", baseMod, headMod + "frobnicate yes\n", "does not parse"},
		{"head is not a go.mod", baseMod, "<<<<<<< HEAD\n", "go.mod at head: does not parse"},
		{"base is not a go.mod", "nonsense here\n", headMod, "go.mod at base: does not parse"},
		{"no module line", baseMod, edit(headMod, "module example.com/app\n", ""), "has no module line"},

		{"go line goes up", baseMod, edit(headMod, "go 1.22", "go 1.23.0"), ""},
		{"go line goes down", baseMod, edit(headMod, "go 1.22", "go 1.21"), "go line does not stay or go up"},
		{"go line removed", baseMod, edit(headMod, "go 1.22\n", ""), "go line does not stay or go up"},
		{"base below go 1.17", edit(baseMod, "go 1.22", "go 1.16"), edit(headMod, "go 1.22", "go 1.16"), "below 1.17"},
		{"base without a go line", edit(baseMod, "go 1.22\n", ""), edit(headMod, "go 1.22\n", ""), "below 1.17"},
		{"base at go 1.17", edit(baseMod, "go 1.22", "go 1.17"), edit(headMod, "go 1.22", "go 1.17"), ""},

		{"toolchain added", baseMod, edit(headMod, "go 1.22\n", "go 1.22\n\ntoolchain go1.22.5\n"), ""},
		{"toolchain goes up", edit(baseMod, "go 1.22\n", "go 1.22\n\ntoolchain go1.22.5\n"), edit(headMod, "go 1.22\n", "go 1.22\n\ntoolchain go1.23.1\n"), ""},
		{"toolchain goes down", edit(baseMod, "go 1.22\n", "go 1.22\n\ntoolchain go1.22.5\n"), edit(headMod, "go 1.22\n", "go 1.22\n\ntoolchain go1.22.4\n"), "goes down"},
		{"toolchain dropped, go line caught up", edit(baseMod, "go 1.22\n", "go 1.22\n\ntoolchain go1.22.5\n"), edit(headMod, "go 1.22", "go 1.23.0"), ""},
		{"toolchain dropped, go line behind", edit(baseMod, "go 1.22\n", "go 1.22\n\ntoolchain go1.22.5\n"), headMod, "goes down"},
		{"toolchain with a suffix", baseMod, edit(headMod, "go 1.22\n", "go 1.22\n\ntoolchain go1.22.5-custom\n"), "not a plain go release"},
		{"toolchain default", baseMod, edit(headMod, "go 1.22\n", "go 1.22\n\ntoolchain default\n"), "not a plain go release"},
		{"toolchain with a suffix, unchanged", edit(baseMod, "go 1.22\n", "go 1.22\n\ntoolchain go1.22.5-custom\n"), edit(headMod, "go 1.22\n", "go 1.22\n\ntoolchain go1.22.5-custom\n"), ""},

		{"indirect marker dropped", baseMod, edit(headMod, "example.com/kept v1.4.0 // indirect", "example.com/kept v1.4.0"), "// indirect marker of example.com/kept"},
		{"indirect marker added on a moved require", baseMod, edit(headMod, "golang.org/x/text v0.3.3", "golang.org/x/text v0.3.3 // indirect"), "// indirect marker of golang.org/x/text"},
		{"module required twice", baseMod, edit(headMod, "require (\n", "require (\n\tgolang.org/x/text v0.3.9 // indirect\n"), "requires golang.org/x/text twice"},
		{"version is not a version", baseMod, edit(headMod, "golang.org/x/text v0.3.3", "golang.org/x/text latest"), "go.mod at head: does not parse"},
		{"major version without its path suffix", baseMod, edit(headMod, "golang.org/x/text v0.3.3", "golang.org/x/text v2.0.0"), "go.mod at head"},
		{"version in short form", baseMod, edit(headMod, "golang.org/x/text v0.3.3", "golang.org/x/text v0.4"), "canonical form"},
		{"version with build metadata", baseMod, edit(headMod, "golang.org/x/text v0.3.3", "golang.org/x/text v0.3.3+evil"), "canonical form"},
		{"replace version in short form", edit(baseMod, "example.com/fork v1.4.1", "example.com/fork v1.4"), edit(headMod, "example.com/fork v1.4.1", "example.com/fork v1.4"), "canonical form"},
		{"incompatible version", baseMod, edit(headMod, "golang.org/x/text v0.3.3", "golang.org/x/text v2.0.0+incompatible"), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// go.sum is left out: these cases are about go.mod alone.
			files := pr(tc.base, tc.head, "", "")[:1]
			_, problem := readChange(files)
			checkProblem(t, problem, tc.want)
		})
	}
}

func TestShapeGoModNoUpdate(t *testing.T) {
	// A go.mod that only raises its go line has the Go shape and moves
	// nothing; allow.Decide sends a pull request with no updates to a
	// person.
	cs, problem := readChange(pr(baseMod, edit(baseMod, "go 1.22", "go 1.23.0"), "", "")[:1])
	if problem != "" || len(cs.updates) != 0 || len(cs.removed) != 0 {
		t.Errorf("problem %q, updates %v, removed %v", problem, cs.updates, cs.removed)
	}
}

func TestShapeGoSum(t *testing.T) {
	tests := []struct {
		name       string
		base, head string
		want       string
	}{
		{"new hashes for the moved and the added module", baseSum, headSum, ""},
		{"old lines kept", baseSum, baseSum + headSum, ""},
		{"go.mod hash of a module that is only in the graph", baseSum, headSum + "example.com/graph v1.0.0/go.mod " + hText032Mod + "\n", ""},
		{"same line twice", baseSum, headSum + "golang.org/x/text v0.3.3 " + hText033 + "\n", ""},
		{"empty base", "", headSum, ""},

		{"zip hash of a module go.mod does not list", baseSum, headSum + "example.com/prefix v1.4.0 " + hText032 + "\n", ""},
		{"pinned hash changes", baseSum + "golang.org/x/text v0.3.3 " + hText032 + "\n", headSum, "changes the hash it pins for golang.org/x/text v0.3.3"},
		{"pinned go.mod hash changes", baseSum + "golang.org/x/text v0.3.3/go.mod " + hText032 + "\n", headSum, "changes the hash it pins for golang.org/x/text v0.3.3/go.mod"},
		{"two hashes for one version", baseSum, headSum + "golang.org/x/text v0.3.3 " + hText032 + "\n", "go.sum at head: has two hashes"},
		{"two fields", baseSum, headSum + "golang.org/x/text v0.3.3\n", "go.sum at head: line 5 is not"},
		{"four fields", baseSum, headSum + "golang.org/x/text v0.3.3 " + hText033 + " extra\n", "line 5 is not"},
		{"tab separated", baseSum, headSum + "golang.org/x/mod\tv0.5.1\t" + hMod051 + "\n", "line 5 is not"},
		{"two spaces", baseSum, headSum + "golang.org/x/mod  v0.5.1 " + hMod051 + "\n", "line 5 is not"},
		{"leading space", baseSum, " " + headSum, "line 1 is not"},
		{"blank line", baseSum, headSum + "\n", "line 5 is not"},
		{"CRLF", baseSum, strings.ReplaceAll(headSum, "\n", "\r\n"), "line 1 is not"},
		{"no final newline", baseSum, strings.TrimSuffix(headSum, "\n"), "does not end in a newline"},
		{"hash of another kind", baseSum, headSum + "golang.org/x/mod v0.5.1 h2:" + hMod051[3:] + "\n", "line 5 is not"},
		{"short hash", baseSum, headSum + "golang.org/x/mod v0.5.1 h1:abcd=\n", "line 5 is not"},
		{"not a module path", baseSum, headSum + "-flag v0.5.1 " + hMod051 + "\n", "line 5 does not name a module version"},
		{"not a version", baseSum, headSum + "golang.org/x/mod latest " + hMod051 + "\n", "line 5 does not name a module version"},
		{"version not canonical", baseSum, headSum + "golang.org/x/mod v0.5 " + hMod051 + "\n", "line 5 does not name a module version"},
		{"malformed base", "what is this\n", headSum, "go.sum at base: line 1 is not"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, problem := readChange(pr(baseMod, headMod, tc.base, tc.head))
			checkProblem(t, problem, tc.want)
		})
	}
}

func TestShow(t *testing.T) {
	tests := []struct{ in, want string }{
		{"plain", "plain"},
		{"two\nlines\tand a tab", `two\nlines\tand a tab`},
		{"bidi " + string(rune(0x202e)) + " override", "bidi " + `\` + "u202e override"},
		{"nul \x00 byte", `nul \x00 byte`},
		{strings.Repeat("a", 300), strings.Repeat("a", 200) + "..."},
	}
	for _, tc := range tests {
		if got := show(tc.in); got != tc.want {
			t.Errorf("show(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

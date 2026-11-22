package gomod

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
	"github.com/sadbox/dep-review/internal/evidence"
	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/model"
)

// TestWriteDiff: one part per changed file, required unless the go
// command's rules say no consumer build reads it, and an index of them.
func TestWriteDiff(t *testing.T) {
	root := t.TempDir()
	write := func(dir, rel, s string) {
		p := filepath.Join(root, dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, side := range []struct{ dir, v string }{{"old", "1"}, {"new", "2"}} {
		write(side.dir, "a.go", "package m\n\nvar A = "+side.v+"\n")
		write(side.dir, "a_test.go", "package m\n\nvar T = "+side.v+"\n")
		write(side.dir, "w_windows.go", "package m\n\nvar W = "+side.v+"\n")
		write(side.dir, "same.go", "package m\n")
	}
	write("new", "sub/new.go", "package sub\n")
	evDir := filepath.Join(t.TempDir(), "ev")
	ev, err := evidence.Create(evDir)
	if err != nil {
		t.Fatal(err)
	}
	defer ev.Close()
	env := fetch.Env{Evidence: ev}
	newTree, err := ecoutil.DirTree(filepath.Join(root, "new"))
	if err != nil {
		t.Fatal(err)
	}
	oldTree, err := ecoutil.DirTree(filepath.Join(root, "old"))
	if err != nil {
		t.Fatal(err)
	}
	h := &report{unbuilt: map[string]bool{"w_windows.go": true}, nb: &builtSet{}, cur: newTree}
	u := model.Update{Ecosystem: model.GoModules, Directory: "/", Name: "example.com/m", From: "v1.0.0", To: "v1.1.0"}
	ds, fs, err := writeDiff(context.Background(), env, t.TempDir(), u, "example.com/m v1.0.0 -> v1.1.0",
		[2]string{filepath.Join(root, "old"), filepath.Join(root, "new")}, [2]*ecoutil.Tree{oldTree, newTree}, h, 7)
	if err != nil || len(fs) != 0 {
		t.Fatalf("writeDiff: %v, findings %v", err, fs)
	}
	want := map[string]bool{"a.go": true, "a_test.go": false, "w_windows.go": false, "sub/new.go": true}
	if len(ds) != len(want) {
		t.Fatalf("diffs %+v", ds)
	}
	for _, d := range ds {
		if req, ok := want[d.Path]; !ok || req != d.Required {
			t.Errorf("%s: required %v (%s)", d.Path, d.Required, d.Why)
		}
		b, err := os.ReadFile(filepath.Join(evDir, d.File))
		if err != nil || !strings.Contains(string(b), filepath.Base(d.Path)) {
			t.Errorf("%s: part %s: %v", d.Path, d.File, err)
		}
	}
	if ds[0].ID != "D00008" {
		t.Errorf("first ID %s, want D00008 (after the fetch's 7)", ds[0].ID)
	}
	for _, d := range ds {
		if !strings.HasSuffix(d.File, ".diff/"+d.ID+".diff") {
			t.Errorf("%s: part %s is not named by its ID", d.Path, d.File)
		}
	}
	files := ev.Files()
	if len(files) != 1 || !strings.HasSuffix(files[0].Path, ".diffs.md") || files[0].Untrusted {
		t.Fatalf("index: %+v", files)
	}
	idx, _ := os.ReadFile(filepath.Join(evDir, files[0].Path))
	for _, s := range []string{"| D00008 |", "optional: a _test.go file nothing embeds", "optional: no declared build", "required"} {
		if !strings.Contains(string(idx), s) {
			t.Errorf("index lacks %q:\n%s", s, idx)
		}
	}
}

// A _test.go file something can read is required: embedded, in a package
// whose embeds did not resolve, or in a module with assembly or cgo.
func TestTestOnly(t *testing.T) {
	tree := writeTree(t, map[string]string{"a.go": "package m\n", "a_test.go": "package m\n", "e/e_test.go": "package e\n"})
	asm := writeTree(t, map[string]string{"a.go": "package m\n", "a_test.go": "package m\n", "f_amd64.s": "#include \"a_test.go\"\n"})
	cgo := writeTree(t, map[string]string{"a.go": "package m\n\nimport \"C\"\n", "a_test.go": "package m\n"})
	tests := []struct {
		name string
		r    *report
		rel  string
		want bool
	}{
		{"plain", &report{nb: &builtSet{}, cur: tree}, "a_test.go", true},
		{"not a test file", &report{nb: &builtSet{}, cur: tree}, "a.go", false},
		{"no checks", &report{}, "a_test.go", false},
		{"unresolved", &report{nb: &builtSet{over: true}, cur: tree}, "a_test.go", false},
		{"embedded", &report{nb: &builtSet{embedFiles: map[string]map[string][]bool{".": {"a_test.go": {true}}}}, cur: tree}, "a_test.go", false},
		{"embeds unresolved", &report{nb: &builtSet{embedFailed: map[string]string{"e": "x"}}, cur: tree}, "e/e_test.go", false},
		{"assembly in the module", &report{nb: &builtSet{}, cur: asm}, "a_test.go", false},
		{"cgo in the module", &report{nb: &builtSet{}, cur: cgo}, "a_test.go", false},
		{"escaped cgo import", &report{nb: &builtSet{}, cur: writeTree(t, map[string]string{"a.go": "package m\n\nimport \"\\x43\"\n", "a_test.go": "package m\n"})}, "a_test.go", false},
		{"unparseable go file", &report{nb: &builtSet{}, cur: writeTree(t, map[string]string{"a.go": "package m\nimport {{{\n", "a_test.go": "package m\n"})}, "a_test.go", false},
	}
	for _, tt := range tests {
		if got := tt.r.testOnly(tt.rel); got != tt.want {
			t.Errorf("%s: testOnly(%s) = %v, want %v", tt.name, tt.rel, got, tt.want)
		}
	}
}

// A path git cannot write unambiguously (a space before the new tree's
// directory name) splits the header elsewhere: the diffs then do not
// match the changed files, so every diff is required and a person decides.
func TestWriteDiffPathsMismatch(t *testing.T) {
	root := t.TempDir()
	for _, side := range []struct{ dir, v string }{{"m@v1.0.0", "1"}, {"m@v1.1.0", "2"}} {
		for rel, text := range map[string]string{"x_test.go": "package m\n", "x_test.go m@v1.1.0/payload.txt": "v" + side.v + "\n"} {
			p := filepath.Join(root, side.dir, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	var trees [2]*ecoutil.Tree
	for i, d := range []string{"m@v1.0.0", "m@v1.1.0"} {
		tr, err := ecoutil.DirTree(filepath.Join(root, d))
		if err != nil {
			t.Fatal(err)
		}
		trees[i] = tr
	}
	ev, err := evidence.Create(filepath.Join(t.TempDir(), "ev"))
	if err != nil {
		t.Fatal(err)
	}
	defer ev.Close()
	h := &report{nb: &builtSet{}, cur: trees[1]}
	u := model.Update{Ecosystem: model.GoModules, Directory: "/", Name: "example.com/m", From: "v1.0.0", To: "v1.1.0"}
	ds, fs, err := writeDiff(context.Background(), fetch.Env{Evidence: ev}, t.TempDir(), u, "k",
		[2]string{filepath.Join(root, "m@v1.0.0"), filepath.Join(root, "m@v1.1.0")}, trees, h, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Code != "gomod.diff-paths" || fs[0].Route != model.RouteHuman {
		t.Errorf("findings %+v", fs)
	}
	for _, d := range ds {
		if !d.Required {
			t.Errorf("%s (%s) optional although the paths are not trusted", d.ID, d.Path)
		}
	}
}

func TestReadingLimits(t *testing.T) {
	d := func(n int, req bool) model.DiffFile { return model.DiffFile{Bytes: int64(n), Required: req} }
	codes := func(fs []model.Finding) []string {
		var out []string
		for _, f := range fs {
			if f.Route != model.RouteHuman {
				t.Errorf("%s routes %s", f.Code, f.Route)
			}
			out = append(out, f.Code)
		}
		return out
	}
	if fs := readingLimits([]model.DiffFile{d(maxMustRead/2, true), d(10*maxMustRead, false)}, maxMustRead/2); len(fs) != 0 {
		t.Errorf("at the limit (optional diffs do not count): %v", codes(fs))
	}
	if fs := codes(readingLimits([]model.DiffFile{d(maxMustRead/2, true)}, maxMustRead/2+1)); len(fs) != 1 || fs[0] != "gomod.too-much-to-read" {
		t.Errorf("flagged items over the limit: %v", fs)
	}
	many := make([]model.DiffFile, model.MaxRequiredDiffs+1)
	for i := range many {
		many[i] = d(1, true)
	}
	if fs := codes(readingLimits(many, 0)); len(fs) != 1 || fs[0] != "gomod.too-many-diffs" {
		t.Errorf("too many required: %v", fs)
	}
}

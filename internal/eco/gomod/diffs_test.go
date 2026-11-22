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
	h := &report{unbuilt: map[string]bool{"w_windows.go": true}, nb: &builtSet{}, cur: newTree}
	u := model.Update{Ecosystem: model.GoModules, Directory: "/", Name: "example.com/m", From: "v1.0.0", To: "v1.1.0"}
	ds, fs, err := writeDiff(context.Background(), env, t.TempDir(), u, "example.com/m v1.0.0 -> v1.1.0",
		[2]string{filepath.Join(root, "old"), filepath.Join(root, "new")}, h, 7)
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

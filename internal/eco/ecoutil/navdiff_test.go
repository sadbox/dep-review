package ecoutil

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/evidence"
	"github.com/sadbox/dep-review/internal/fetch"
)

func TestNavDiffsBinary(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ev")
	ev, err := evidence.Create(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer ev.Close()
	nd := NavDiffs{Eco: "npm", Key: "p 1 -> 2", Update: "p", What: "package",
		Name: func(s string) string { return "npm/p." + s },
		Diffs: []FileDiff{
			{Path: "lib/x.js", Body: []byte("diff --git a/lib/x.js b/lib/x.js\nBinary files a/lib/x.js and b/lib/x.js differ\n")},
			{Path: "lib/y.js", Body: []byte("diff --git a/lib/y.js b/lib/y.js\n+" + strings.Repeat("a", 5000) + "\n")},
		}}
	ds, fs, err := nd.Write(fetch.Env{Evidence: ev}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Code != "npm.binary-diff" || !strings.Contains(fs[0].Detail, "lib/x.js") {
		t.Errorf("findings %+v", fs)
	}
	b, err := os.ReadFile(filepath.Join(dir, ds[1].File))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range bytes.Split(b, []byte("\n")) {
		if len(l) > evidence.MaxReadableLine {
			t.Errorf("part has a line of %d bytes", len(l))
		}
	}
}

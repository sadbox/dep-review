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

func TestWrapLong(t *testing.T) {
	long := "+" + strings.Repeat("é", 3000) // 6001 bytes
	body := []byte("@@ -1 +1 @@\n-x\n" + long + "\n context\n")
	out := wrapLong(body)
	for _, l := range bytes.Split(out, []byte("\n")) {
		if len(l) > MaxReadableLine {
			t.Errorf("line of %d bytes", len(l))
		}
	}
	if strings.ReplaceAll(strings.ReplaceAll(string(out), "\n+[cont] ", ""), "\n", "") != strings.ReplaceAll(string(body), "\n", "") {
		t.Error("wrapping lost or changed text")
	}
	if !bytes.Contains(out, []byte("\n+[cont] ")) || !bytes.HasSuffix(out, []byte(" context\n")) {
		t.Errorf("no continuation marker:\n%.200s", out)
	}
	if got := wrapLong([]byte("+short\n")); string(got) != "+short\n" {
		t.Errorf("short body changed: %q", got)
	}
}

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
		if len(l) > MaxReadableLine {
			t.Errorf("part has a line of %d bytes", len(l))
		}
	}
}

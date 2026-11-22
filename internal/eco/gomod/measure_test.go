package gomod

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
)

// TestMeasure reports go/build and go list cost over two real module
// trees: GATE_MEASURE="old-dir new-dir". Not part of the normal run; it
// is how golist.go's choice of grouping configurations was measured.
func TestMeasure(t *testing.T) {
	dirs := strings.Fields(os.Getenv("GATE_MEASURE"))
	if len(dirs) != 2 {
		t.Skip("set GATE_MEASURE")
	}
	l := defaultLister()
	var naive time.Duration
	var naiveRuns int
	for i, d := range dirs {
		tr, err := ecoutil.DirTree(d)
		if err != nil {
			t.Fatal(err)
		}
		b := analyzeBuild(tr, i == 0)
		t.Logf("%s: %d .go files, go/build over %d configs: %v, %d dirs over-approximated", d, len(b.in), len(configs), b.took, len(b.errs))
		pkgs := packageDirs(embedFiles(tr))
		res := l.listEmbeds(tr, b, pkgs)
		t.Logf("  %d packages with //go:embed; grouped go list: %d runs, %v; failed %v", len(pkgs), res.runs, res.took, res.failed)
		// Naive: one go list per configuration.
		root := t.TempDir()
		mod := filepath.Join(root, "mod")
		if err := copyTree(tr, mod); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		for ci, c := range configs {
			args := dirsBuiltIn(tr, b, pkgs, ci)
			if len(args) == 0 {
				continue
			}
			cgo := "0"
			if c.cgo {
				cgo = "1"
			}
			if _, err := ecoutil.RunGo(ecoutil.GoRun{Go: l.goBin, Dir: mod, Args: append([]string{"list", "-e", "-json=Dir,EmbedFiles,Error"}, args...),
				Env: append(listEnv(root), "GOOS="+c.goos, "GOARCH="+c.goarch, "CGO_ENABLED="+cgo)}); err != nil {
				t.Fatal(err)
			}
			naiveRuns++
		}
		naive += time.Since(start)
	}
	t.Logf("naive per-configuration go list, both trees: %d runs, %v", naiveRuns, naive)
}

package gomod

import (
	"os"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
)

// TestMeasure reports the build analysis's cost over two real module
// trees: GATE_MEASURE="old-dir new-dir". Not part of the normal run.
func TestMeasure(t *testing.T) {
	dirs := strings.Fields(os.Getenv("GATE_MEASURE"))
	if len(dirs) != 2 {
		t.Skip("set GATE_MEASURE")
	}
	for i, d := range dirs {
		tr, err := ecoutil.DirTree(d)
		if err != nil {
			t.Fatal(err)
		}
		b := analyzeBuild(tr, i == 0, defaultLister())
		t.Logf("%s: %d .go files, %d dirs with //go:embed, analysis %v, of it go list %d runs (%d at once) %v; unresolved %v; failed %q",
			d, len(b.in), len(b.embedFiles), b.took, b.listRuns, listParallel, b.listTook, b.unresolved(), b.embedFailed)
	}
}

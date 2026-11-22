package gomod

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
)

// TestMain doubles as the go child (ecoutil.GoChildMain) when
// GOMOD_TEST_GO_CHILD is set, so go list can run as the fetch runs it:
// memory-limited on Linux.
func TestMain(m *testing.M) {
	if os.Getenv("GOMOD_TEST_GO_CHILD") != "" {
		if err := ecoutil.GoChildMain(os.Stdin, os.Stdout); err != nil {
			os.Stderr.WriteString(err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// TestListIsolated: go list runs through the isolated child (on Linux
// under the 2 GiB address-space limit) in every configuration and
// answers. GATE_MEASURE trees, when set, are analyzed the same way.
func TestListIsolated(t *testing.T) {
	needGo(t)
	ecoutil.Isolate(&ecoutil.Isolation{GoCommand: []string{os.Args[0]}, Env: []string{"GOMOD_TEST_GO_CHILD=1"}})
	t.Cleanup(func() { ecoutil.Isolate(nil) })
	trees := []*ecoutil.Tree{writeTree(t, map[string]string{"p.go": "package p\n\nimport _ \"embed\"\n\n//go:embed a.txt\nvar A string\n", "a.txt": "a\n"})}
	for _, d := range strings.Fields(os.Getenv("GATE_MEASURE")) {
		tr, err := ecoutil.DirTree(d)
		if err != nil {
			t.Fatal(err)
		}
		trees = append(trees, tr)
	}
	for i, tr := range trees {
		b := analyzeBuild(tr, false, defaultLister())
		if b.unresolved() || len(b.embedFailed) != 0 {
			t.Errorf("tree %d: unresolved %v (%s), failed %q", i, b.unresolved(), b.overWhy, b.embedFailed)
		}
		if i == 0 && !slices.Equal(b.embedded("."), []string{"a.txt"}) {
			t.Errorf("EmbedFiles through the child = %q", b.embedded("."))
		}
		t.Logf("tree %d: %d go list runs, %v; analysis %v", i, b.listRuns, b.listTook, b.took)
	}
}

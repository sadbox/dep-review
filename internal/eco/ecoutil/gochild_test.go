package ecoutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRunGoIsolated: RunGo through the go child (memory-limited on
// Linux) runs the go command with exactly the given environment; a hung
// child is killed with its process group at the timeout.
func TestRunGoIsolated(t *testing.T) {
	bin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command")
	}
	bin, _ = filepath.Abs(bin)
	home := t.TempDir()
	withIsolation(t, &Isolation{GoCommand: []string{os.Args[0]}, Env: []string{"ECOUTIL_TEST_CHILD=go"}})
	out, err := RunGo(GoRun{Go: bin, Dir: home, Args: []string{"env", "GOVERSION", "GOFLAGS"},
		Env: []string{"HOME=" + home, "GOENV=off", "GOTOOLCHAIN=local", "GOTELEMETRY=off", "GOCACHE=" + filepath.Join(home, "c")}})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "go1.") || lines[1] != "" {
		t.Errorf("go env through the child = %q (GOFLAGS must not be inherited)", out)
	}

	withIsolation(t, &Isolation{GoCommand: []string{os.Args[0]}, Env: []string{"ECOUTIL_TEST_CHILD=hang"}})
	start := time.Now()
	if _, err := RunGo(GoRun{Go: bin, Timeout: 500 * time.Millisecond}); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("hung child: err = %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("the timeout took %v", time.Since(start))
	}
}

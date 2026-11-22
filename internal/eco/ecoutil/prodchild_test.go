package ecoutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// buildGate builds cmd/dep-review as gate.yml does (CGO_ENABLED=0,
// -trimpath), whatever this test binary was built with.
func buildGate(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the gate")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command")
	}
	bin := filepath.Join(t.TempDir(), "dep-review")
	cmd := exec.Command(goBin, "build", "-trimpath", "-o", bin, "../../../cmd/dep-review")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-buildvcs=false")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// TestProductionChildRenders: the gate as built for production renders a
// Go ELF (itself) through its describe-binary child under the 2 GiB
// address-space limit, the same as in-process (complete or not: a large
// ELF can exceed the in-process budgets too). On Linux this is the
// limit that matters; CI's -race job runs it with a non-race child.
func TestProductionChildRenders(t *testing.T) {
	bin := buildGate(t)
	self, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	local := DescribeBinary(self, nil, false, nil)
	withIsolation(t, &Isolation{Command: []string{bin, "describe-binary"}, Timeout: time.Minute})
	got := DescribeBinary(self, nil, false, nil)
	if strings.Contains(got.Text, "the isolated parser") || got.Text != local.Text {
		t.Errorf("the production child (%s/%s) did not render the gate's own ELF as in-process under the limit:\n%.1500s", runtime.GOOS, runtime.GOARCH, got.Text)
	}
}

// TestChildMemoryHeadroom reports, on Linux, the smallest address-space
// limit (in 128 MiB steps) under which a static child renders the gate's
// ELF: GATE_MEASURE_CHILD=1. Not part of the normal run; it is how
// childMemory's margin is measured.
func TestChildMemoryHeadroom(t *testing.T) {
	if os.Getenv("GATE_MEASURE_CHILD") == "" || runtime.GOOS != "linux" || testCgo {
		t.Skip("set GATE_MEASURE_CHILD on Linux, with CGO_ENABLED=0")
	}
	bin := buildGate(t)
	self, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	for mem := uint64(128 << 20); mem <= childMemory; mem += 128 << 20 {
		withIsolation(t, &Isolation{Command: []string{os.Args[0]}, Env: []string{"ECOUTIL_TEST_CHILD=ok", "ECOUTIL_TEST_MEMORY=" + strconv.FormatUint(mem, 10)}, Timeout: time.Minute})
		if d := DescribeBinary(self, nil, false, nil); !strings.Contains(d.Text, "the isolated parser") {
			t.Logf("%s/%s: renders from %d MiB (limit %d MiB)", runtime.GOOS, runtime.GOARCH, mem>>20, childMemory>>20)
			return
		}
	}
	t.Errorf("no limit up to %d MiB renders", childMemory>>20)
}

// TestProductionGoChild: the gate as built for production runs a go
// command through its go-child under the 2 GiB address-space limit.
func TestProductionGoChild(t *testing.T) {
	bin := buildGate(t)
	goBin, _ := exec.LookPath("go")
	goBin, _ = filepath.Abs(goBin)
	home := t.TempDir()
	withIsolation(t, &Isolation{GoCommand: []string{bin, "go-child"}})
	out, err := RunGo(GoRun{Go: goBin, Dir: home, Args: []string{"env", "GOVERSION"},
		Env: []string{"HOME=" + home, "GOENV=off", "GOTOOLCHAIN=local", "GOTELEMETRY=off", "GOCACHE=" + filepath.Join(home, "c")}})
	if err != nil || !strings.HasPrefix(string(out), "go1.") {
		t.Errorf("go env through the production go-child: %q, %v", out, err)
	}
}

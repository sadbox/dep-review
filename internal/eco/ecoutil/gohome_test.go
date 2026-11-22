package ecoutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// TestGoHomeTelemetryOff: with a home GoHome prepared, the go command
// starts no telemetry sidecar: once it returns, nothing but the mode file
// is under the telemetry directory, also a while later (the CI failure:
// the sidecar was still writing local/ when the test removed its HOME).
func TestGoHomeTelemetryOff(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command")
	}
	goBin, _ = filepath.Abs(goBin)
	home := t.TempDir()
	if err := GoHome(home); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"env", "GOVERSION", "GOTELEMETRY"}, {"list", "-e", "-f", "{{context.ToolTags}}", "unsafe"}} {
		out, err := RunGo(GoRun{Go: goBin, Dir: home, Args: args,
			Env: []string{"HOME=" + home, "GOENV=off", "GOTOOLCHAIN=local", "GOCACHE=" + filepath.Join(home, "c"), "GOFLAGS=-mod=mod"}})
		if err != nil {
			t.Fatalf("go %v: %v", args, err)
		}
		if args[0] == "env" && !slices.Contains(splitLines(string(out)), "off") {
			t.Errorf("go env GOTELEMETRY = %q, want off", out)
		}
	}
	time.Sleep(2 * time.Second)
	for _, cfg := range []string{".config", filepath.Join("Library", "Application Support")} {
		ents, err := os.ReadDir(filepath.Join(home, cfg, "go", "telemetry"))
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		if !slices.Equal(names, []string{"mode"}) {
			t.Errorf("%s: telemetry directory holds %q, want only the mode file", cfg, names)
		}
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

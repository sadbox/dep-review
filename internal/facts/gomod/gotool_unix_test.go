//go:build unix

package gomod

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/mod/module"
)

// fakeGo is a goCommand whose go command is a shell script: what is
// tested here is how run treats a process, whatever the process is.
func fakeGo(t *testing.T, script string) goCommand {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "go")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"+script), 0o700); err != nil {
		t.Fatal(err)
	}
	c, err := newGoCommand(bin, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGoCommandOutputCap(t *testing.T) {
	ctx := context.Background()

	t.Run("under the cap", func(t *testing.T) {
		out, err := fakeGo(t, "echo '{}'\n").run(ctx, "list")
		if err != nil || string(out) != "{}\n" {
			t.Errorf("out = %q, err = %v", out, err)
		}
	})

	t.Run("one byte over", func(t *testing.T) {
		out, err := fakeGo(t, fmt.Sprintf("head -c %d /dev/zero\n", maxGoOutput+1)).run(ctx, "list")
		if err == nil || !strings.Contains(err.Error(), "go list: printed more than 67108864 bytes") {
			t.Errorf("err = %v, want the run to fail for its output", err)
		}
		if out != nil {
			t.Errorf("%d bytes of a cut answer were returned", len(out))
		}
	})

	// "go mod download" exits 1 and still prints a usable result, so
	// download reads what a failed run printed. Not when it was cut.
	t.Run("over, from a command that fails", func(t *testing.T) {
		c := fakeGo(t, fmt.Sprintf("echo '{\"Path\":\"example.com/m\",\"Version\":\"v1.0.0\",\"Sum\":\"h1:x\"}'\nhead -c %d /dev/zero\nexit 1\n", maxGoOutput))
		out, err := c.run(ctx, "mod", "download")
		if err == nil || !strings.Contains(err.Error(), "printed more than") || out != nil {
			t.Errorf("out = %d bytes, err = %v", len(out), err)
		}
		if got, err := download(ctx, c, nil); err == nil || len(got) != 0 {
			t.Errorf("download = %v, %v; want the run's error and no module", got, err)
		}
	})

	t.Run("standard error is cut", func(t *testing.T) {
		out, err := fakeGo(t, "echo partial\nhead -c 1000000 /dev/zero | tr '\\0' 'e' >&2\nexit 3\n").run(ctx, "list")
		if err == nil || !strings.Contains(err.Error(), "exit status 3") || len(err.Error()) > 1000 {
			t.Errorf("err = %.300v (%d bytes)", err, len(fmt.Sprint(err)))
		}
		// Under the cap, a failed run's output is the caller's to read.
		if string(out) != "partial\n" {
			t.Errorf("out = %q", out)
		}
	})
}

// With the real runner the scratch directory is wherever this machine
// keeps temporary files. A reason the go command gives that names a file
// in its module cache is handed on, and made a fact's Value, without it.
func TestGoCommandReasonsDoNotNameTheScratchDirectory(t *testing.T) {
	c := fakeGo(t, `printf '{"Path":"example.com/m","Version":"v1.0.0","Error":"example.com/m@v1.0.0: unzip %s/cache/download/example.com/m/@v/v1.0.0.zip: malformed file path"}\n' "$GOMODCACHE"`+"\nexit 1\n")
	got, err := download(context.Background(), c, []module.Version{mv("example.com/m", "v1.0.0")})
	if err != nil {
		t.Fatal(err)
	}
	const want = "example.com/m@v1.0.0: unzip (scratch)/gopath/pkg/mod/cache/download/example.com/m/@v/v1.0.0.zip: malformed file path"
	d := got[mv("example.com/m", "v1.0.0")]
	if d.Error != want {
		t.Errorf("Error = %q, want %q", d.Error, want)
	}
	if f := goFailure("go mod download failed", d.Error, sourceDownload); strings.Contains(f.Value, c.scratch) || !strings.Contains(f.Value, "unzip (scratch)/gopath/") {
		t.Errorf("the fact made from it = %+v", f)
	}
}

// A process the go command started must not outlive a run whose context
// ended: it is in the command's process group, and the group is killed.
func TestGoCommandKillsItsGroup(t *testing.T) {
	// The script's child writes a line every few milliseconds for as long
	// as it lives, and its process ID first.
	c := fakeGo(t, "( while :; do echo beat >> \"$1\"; sleep 0.02; done ) &\necho $! > \"$1.pid\"\nwait\n")
	beat := filepath.Join(t.TempDir(), "beat")
	t.Cleanup(func() {
		// Whatever the test found, leave nothing running.
		if data, err := os.ReadFile(beat + ".pid"); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 1 {
				syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	size := func() int64 {
		info, err := os.Stat(beat)
		if err != nil {
			return 0
		}
		return info.Size()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := c.run(ctx, beat)
		done <- err
	}()
	for start := time.Now(); size() == 0; time.Sleep(5 * time.Millisecond) {
		if time.Since(start) > 10*time.Second {
			t.Fatal("the script's child never started")
		}
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		// The child holds the command's output pipes. When only the
		// script is killed, run comes back after its ten-second
		// WaitDelay and not before.
		t.Fatal("run did not return within 5s of its context ending")
	}
	before := size()
	time.Sleep(300 * time.Millisecond)
	if after := size(); after != before {
		t.Errorf("the command's child is still running: it wrote %d more bytes after run returned", after-before)
	}
}

package ecoutil

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime/debug"
	"time"
)

// A go command over a dependency's tree (go list) runs isolated like the
// binary renderer: in a child process, a re-exec of the gate binary that
// limits its own address space (inherited by the go command it starts),
// in its own process group, killed with the group after a timeout. Its
// environment is exactly the one given: nothing is inherited.

const (
	// maxGoOutput bounds a go command's stdout.
	maxGoOutput = 64 << 20
	// maxGoRequest bounds the request a go child reads.
	maxGoRequest = 1 << 20
)

// GoRun is one go command run.
type GoRun struct {
	Go      string   // absolute path of the go command
	Dir     string   // its working directory
	Args    []string // its arguments
	Env     []string // its complete environment
	Timeout time.Duration
}

// RunGo runs r, in the isolated child when Isolate set one up (the
// fetch), directly otherwise (tests). It returns stdout; a non-zero exit,
// a timeout or too much output is an error.
func RunGo(r GoRun) ([]byte, error) {
	if r.Timeout == 0 {
		r.Timeout = time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()
	var cmd *exec.Cmd
	var stdin io.Reader
	if isolation != nil && len(isolation.GoCommand) > 0 {
		req, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		cmd = exec.Command(isolation.GoCommand[0], isolation.GoCommand[1:]...)
		cmd.Env = append([]string{"GOTRACEBACK=none"}, isolation.Env...)
		stdin = bytes.NewReader(req)
	} else {
		cmd = exec.Command(r.Go, r.Args...)
		cmd.Dir, cmd.Env = r.Dir, r.Env
		if cmd.Env == nil {
			cmd.Env = []string{}
		}
	}
	return runGroup(ctx, cmd, stdin)
}

// runGroup runs cmd in its own process group, killing the group when ctx
// ends.
func runGroup(ctx context.Context, cmd *exec.Cmd, stdin io.Reader) ([]byte, error) {
	cmd.Stdin = stdin
	out := &cappedBuffer{max: maxGoOutput}
	errb := &cappedBuffer{max: 4 << 10}
	cmd.Stdout, cmd.Stderr = out, errb
	setGroup(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		killGroup(cmd)
		<-done
		return nil, errors.New("timed out")
	}
	switch {
	case out.over:
		return nil, errors.New("printed too much")
	case err != nil:
		return nil, fmt.Errorf("%v: %s", err, clip(string(errb.b)))
	}
	return out.b, nil
}

// GoChildMain is the go-command child: it limits its own memory, reads a
// GoRun from stdin and runs it, passing its stdout through.
func GoChildMain(stdin io.Reader, stdout io.Writer) error {
	return goChildMain(stdin, stdout, childMemory)
}

// goChildMain is GoChildMain with an address-space limit (0: none, for a
// cgo-linked test binary, which cannot run under one: binchild.go).
func goChildMain(stdin io.Reader, stdout io.Writer, memory uint64) error {
	if memory > 0 {
		if err := limitMemory(memory); err != nil {
			return fmt.Errorf("limiting memory: %w", err)
		}
	}
	b, err := io.ReadAll(io.LimitReader(stdin, maxGoRequest+1))
	if err != nil {
		return err
	}
	if len(b) > maxGoRequest {
		return errors.New("request over the limit")
	}
	var r GoRun
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	cmd := exec.Command(r.Go, r.Args...)
	cmd.Dir, cmd.Env = r.Dir, r.Env
	if cmd.Env == nil {
		cmd.Env = []string{}
	}
	out := &cappedBuffer{max: maxGoOutput}
	errb := &cappedBuffer{max: 4 << 10}
	cmd.Stdout, cmd.Stderr = out, errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %s", err, clip(string(errb.b)))
	}
	if out.over {
		return errors.New("printed too much")
	}
	_, err = stdout.Write(out.b)
	return err
}

// RunChild runs one request in the named child process (Isolation.Children,
// a re-exec of the gate that limits itself with LimitChild) when Isolate
// set one up, and through local in this process otherwise (tests). It
// returns the child's stdout; a failure, a timeout or too much output is
// an error.
func RunChild(name string, req []byte, timeout time.Duration, local func(stdin io.Reader, stdout io.Writer) error) ([]byte, error) {
	if isolation == nil || len(isolation.Children[name]) == 0 {
		var out bytes.Buffer
		err := local(bytes.NewReader(req), &out)
		return out.Bytes(), err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	argv := isolation.Children[name]
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append([]string{"GOTRACEBACK=none"}, isolation.Env...)
	return runGroup(ctx, cmd, bytes.NewReader(req))
}

// LimitChild is what a child process does first: the address-space
// limit (Linux) and a soft Go memory limit, as ChildMain.
func LimitChild() error {
	if err := limitMemory(childMemory); err != nil {
		return fmt.Errorf("limiting memory: %w", err)
	}
	debug.SetMemoryLimit(childMemory / 2)
	return nil
}

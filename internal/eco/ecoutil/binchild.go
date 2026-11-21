package ecoutil

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime/debug"
	"time"
)

// The structure step (debug/elf, debug/pe, debug/macho, archive/*,
// compress/gzip over a hostile file) can be made to allocate far more
// than its input: symbol names all pointing at one long string, nested
// compression. With Isolate it runs in a child process, a re-exec of the
// gate binary, which limits its own address space before it reads a byte
// of input (ChildMain) and is killed after a timeout. A child that fails
// in any way yields "not structured", which the caller treats as such.

const (
	// childMemory is the child's address-space limit (Linux). The Go
	// runtime reserves address space beyond its heap, so the heap the
	// child can actually use under it is far smaller: about 360 to 515
	// MB measured on linux/amd64 and arm64. That is still several times
	// what a legitimate rendering needs (inputs are at most maxParse),
	// and an amplifying parser hits it quickly. ChildMain also sets a
	// soft Go memory limit of half of it, everywhere.
	childMemory = 2 << 30
	// childTimeout bounds one rendering.
	childTimeout = 15 * time.Second
	// maxChildOutput bounds the child's reply.
	maxChildOutput = 4 << 20
)

// Isolation is how to start the child: Command is its argv (the gate
// binary and its hidden describe-binary subcommand).
type Isolation struct {
	Command []string
	Timeout time.Duration // childTimeout if zero
	Env     []string      // the child's environment beyond GOTRACEBACK (tests)
}

// isolation, when set, is used by every structure rendering.
var isolation *Isolation

// Isolate makes DescribeBinary render structure in a child process. The
// gate's fetch command calls it once at start; tests that do not call it
// render in-process.
func Isolate(i *Isolation) { isolation = i }

func (i *Isolation) run(b []byte, limit int64, sn Sniff) childResult {
	fail := func(why string) childResult {
		return childResult{Text: "  not parsed: the isolated parser " + why + "\n"}
	}
	timeout := i.Timeout
	if timeout == 0 {
		timeout = childTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, i.Command[0], i.Command[1:]...)
	var in bytes.Buffer
	binary.Write(&in, binary.LittleEndian, limit)
	in.WriteByte(byte(sn))
	in.Write(b)
	cmd.Stdin = &in
	cmd.Env = append([]string{"GOTRACEBACK=none"}, i.Env...)
	var out cappedBuffer
	out.max = maxChildOutput
	cmd.Stdout = &out
	err := cmd.Run()
	switch {
	case ctx.Err() != nil:
		return fail("timed out")
	case err != nil:
		return fail("failed (" + clip(err.Error()) + ")")
	case out.over:
		return fail("printed too much")
	}
	var res childResult
	if err := json.Unmarshal(out.b, &res); err != nil || res.Used < 0 {
		return fail("returned no valid result")
	}
	return res
}

// cappedBuffer keeps at most max bytes and records that more came.
type cappedBuffer struct {
	b    []byte
	max  int
	over bool
}

func (l *cappedBuffer) Write(p []byte) (int, error) {
	if len(l.b)+len(p) > l.max {
		l.over = true
		return 0, errors.New("output limit")
	}
	l.b = append(l.b, p...)
	return len(p), nil
}

// ChildMain is the describe-binary subcommand: it limits its own memory,
// then reads an 8-byte little-endian decompression limit, one Sniff byte
// and the file, renders the structure and writes the result as JSON.
func ChildMain(stdin io.Reader, stdout io.Writer) error {
	if err := limitMemory(childMemory); err != nil {
		return fmt.Errorf("limiting memory: %w", err)
	}
	debug.SetMemoryLimit(childMemory / 2)
	var limit int64
	if err := binary.Read(stdin, binary.LittleEndian, &limit); err != nil {
		return err
	}
	var sn [1]byte
	if _, err := io.ReadFull(stdin, sn[:]); err != nil {
		return err
	}
	b, err := io.ReadAll(io.LimitReader(stdin, maxParse+1))
	if err != nil {
		return err
	}
	if len(b) > maxParse || limit < 0 {
		return errors.New("input over the limit")
	}
	return json.NewEncoder(stdout).Encode(structureLocal(b, limit, Sniff(sn[0])))
}

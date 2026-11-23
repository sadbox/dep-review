package gomod

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/module"
)

// The gatherer never reads a module's contents or metadata itself. It
// asks the go command three questions and reads the JSON it prints:
//
//	go mod download -json -- m@v ...          the hashes the checksum database vouches for
//	go list -m -e -u -retracted -json -- m@v  commit time, retraction, deprecation
//	go list -m -e -versions -json -- m        the versions that are not retracted
//
// The module paths and versions in those arguments come from a pull
// request, so the go command runs with an environment of its own, in a
// scratch module with a module cache of its own, and only ever talks to
// proxy.golang.org and sum.golang.org.

const (
	// goTimeout bounds one go command. Downloading a few large modules
	// through the proxy takes well under a minute.
	goTimeout = 10 * time.Minute
	// maxGoOutput bounds a go command's standard output. The version list
	// of the largest modules is a few hundred kilobytes.
	maxGoOutput = 64 << 20

	sourceDownload = "go mod download -json (GOPROXY=https://proxy.golang.org, GOSUMDB=sum.golang.org, empty module cache)"
	sourceList     = "go list -m -u -retracted -json and go list -m -versions -json (GOPROXY=https://proxy.golang.org)"
)

// goTool runs the go command. The real one is goCommand; tests replay
// recorded output.
type goTool interface {
	// run runs the go command with args and returns what it printed on
	// standard output. "go mod download" exits non-zero when one module
	// failed and still prints a usable result, so a caller looks at the
	// output before it looks at the error.
	run(ctx context.Context, args ...string) ([]byte, error)
}

// goCommand is the real go command, run in a scratch directory that
// holds its home, its module cache and the empty module it works in.
type goCommand struct {
	// bin is the path of the go command.
	bin string
	// scratch is a directory this run owns. The module cache in it must
	// start empty: the go command asks the checksum database about a
	// module only when it downloads it, and trusts its cache after that.
	scratch string
}

// newGoCommand prepares scratch for the go command.
func newGoCommand(bin, scratch string) (goCommand, error) {
	c := goCommand{bin: bin, scratch: scratch}
	home := filepath.Join(scratch, "home")
	work := filepath.Join(scratch, "work")
	for _, dir := range []string{home, work} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return c, err
		}
	}
	// Telemetry off, or the go command starts a sidecar process that
	// outlives it and writes under home. The toolchain reads the mode
	// from os.UserConfigDir()/go/telemetry/mode, which is $HOME/.config
	// on Linux and $HOME/Library/Application Support on macOS.
	for _, cfg := range []string{".config", filepath.Join("Library", "Application Support")} {
		dir := filepath.Join(home, cfg, "go", "telemetry")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return c, err
		}
		if err := os.WriteFile(filepath.Join(dir, "mode"), []byte("off"), 0o600); err != nil {
			return c, err
		}
	}
	// The empty module: it requires nothing and has no go.sum, so every
	// hash the go command accepts comes from the checksum database.
	gomod := "module dep-review.invalid/scratch\n\ngo 1.17\n"
	if err := os.WriteFile(filepath.Join(work, "go.mod"), []byte(gomod), 0o600); err != nil {
		return c, err
	}
	return c, nil
}

// env is the complete environment of the go command. Nothing is
// inherited except PATH.
func (c goCommand) env() []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + filepath.Join(c.scratch, "home"),
		"GOPATH=" + filepath.Join(c.scratch, "gopath"),
		"GOMODCACHE=" + filepath.Join(c.scratch, "gopath", "pkg", "mod"),
		"GOCACHE=" + filepath.Join(c.scratch, "gocache"),
		"GOENV=off",
		// Never download and run another toolchain.
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		// -modcacherw: the cache stays removable.
		"GOFLAGS=-mod=mod -modcacherw",
		// The proxy only: "direct" would run git against hosts a pull
		// request names.
		"GOPROXY=https://proxy.golang.org",
		"GOSUMDB=sum.golang.org",
		"GONOSUMDB=",
		"GONOSUMCHECK=",
		"GONOPROXY=",
		"GOPRIVATE=",
		"GOINSECURE=",
		"GOVCS=*:off",
		"CGO_ENABLED=0",
		"GIT_TERMINAL_PROMPT=0",
	}
}

// run implements goTool.
func (c goCommand) run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, goTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.bin, args...)
	cmd.Dir = filepath.Join(c.scratch, "work")
	cmd.Env = c.env()
	out := &cappedBuffer{max: maxGoOutput}
	errb := &cappedBuffer{max: 4 << 10}
	cmd.Stdout, cmd.Stderr = out, errb
	// Its own process group, killed as a whole when the context ends, so
	// nothing the go command started is left behind.
	setGroup(cmd)
	cmd.Cancel = func() error { killGroup(cmd); return nil }
	cmd.WaitDelay = 10 * time.Second
	err := cmd.Run()
	switch {
	case ctx.Err() != nil:
		return nil, fmt.Errorf("go %s: %w", args[0], ctx.Err())
	case out.over:
		return nil, fmt.Errorf("go %s: printed more than %d bytes", args[0], maxGoOutput)
	case err != nil:
		return out.b, fmt.Errorf("go %s: %w: %s", args[0], err, show(string(errb.b)))
	}
	return out.b, nil
}

// cappedBuffer keeps the first max bytes written to it and notes when
// there were more.
type cappedBuffer struct {
	b    []byte
	max  int
	over bool
}

// Write implements io.Writer. It never fails: a child that prints too
// much is noticed afterwards, not blocked.
func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - len(c.b); len(p) > room {
		c.b = append(c.b, p[:room]...)
		c.over = true
	} else {
		c.b = append(c.b, p...)
	}
	return len(p), nil
}

// goArg is path@version as an argument of the go command, or path alone
// when version is empty. Both parts were validated when go.mod was read;
// this is the last look before they reach a command line.
func goArg(path, version string) (string, error) {
	arg := path
	if version != "" {
		arg += "@" + version
	}
	err := module.CheckPath(path)
	if err == nil && version != "" {
		err = module.Check(path, version)
		if err == nil && module.CanonicalVersion(version) != version {
			err = errors.New("version is not canonical")
		}
	}
	if err != nil || strings.HasPrefix(arg, "-") || strings.ContainsAny(arg, " \t\r\n") || strings.Count(arg, "@") > 1 {
		return "", fmt.Errorf("refusing %s as an argument of the go command", show(arg))
	}
	return arg, nil
}

// goArgs is goArg for every module in mods.
func goArgs(mods []module.Version) ([]string, error) {
	args := make([]string, 0, len(mods))
	for _, m := range mods {
		arg, err := goArg(m.Path, m.Version)
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
	}
	return args, nil
}

// downloaded is one module version as "go mod download -json" reports it.
type downloaded struct {
	Path    string
	Version string
	// Error is the go command's reason when it could not download or
	// verify the module; Sum and GoModSum are then empty.
	Error string
	// Sum is the h1 hash of the module zip and GoModSum the h1 hash of
	// its go.mod, both checked against the checksum database.
	Sum      string
	GoModSum string
}

// download runs "go mod download -json" for mods. A module the go command
// could not download has its reason in Error; a module it said nothing
// about, or reported twice, is absent from the result. The error return
// is for the command itself failing.
func download(ctx context.Context, tool goTool, mods []module.Version) (map[module.Version]downloaded, error) {
	args, err := goArgs(mods)
	if err != nil {
		return nil, err
	}
	out, runErr := tool.run(ctx, append([]string{"mod", "download", "-json", "--"}, args...)...)
	if len(bytes.TrimSpace(out)) == 0 && runErr != nil {
		return nil, runErr
	}
	result := map[module.Version]downloaded{}
	twice := map[module.Version]bool{}
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var d downloaded
		if err := dec.Decode(&d); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("go mod download: unreadable output: %w", err)
		}
		key := module.Version{Path: d.Path, Version: d.Version}
		if _, seen := result[key]; seen {
			twice[key] = true
		}
		result[key] = d
	}
	for key := range twice {
		delete(result, key)
	}
	return result, nil
}

// listed is one module as "go list -m -json" reports it. Which fields
// are filled in depends on the flags.
type listed struct {
	Path    string
	Version string
	// Time is the commit time of the version. The publisher sets it; it
	// is only ever used to decide where to start looking in the index.
	Time *time.Time
	// Retracted is the rationale of each retraction that covers Version
	// (with -retracted or -u).
	Retracted []string
	// Deprecated is the module's deprecation notice (with -u).
	Deprecated string
	// Versions is the module's tagged versions (with -versions), without
	// the retracted ones unless -retracted is given too.
	Versions []string
	// Error is set when the go command could not answer for this module.
	Error *struct{ Err string }
}

// list runs "go list -m -e -json" with flags for the given queries. With
// -e a module the go command cannot answer for is still reported, with
// its Error set. A query reported twice is dropped from the result.
func list(ctx context.Context, tool goTool, flags []string, mods []module.Version) (map[module.Version]listed, error) {
	queries, err := goArgs(mods)
	if err != nil {
		return nil, err
	}
	args := append([]string{"list", "-m", "-e"}, flags...)
	args = append(args, "-json", "--")
	out, runErr := tool.run(ctx, append(args, queries...)...)
	if runErr != nil {
		return nil, runErr
	}
	result := map[module.Version]listed{}
	twice := map[module.Version]bool{}
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var l listed
		if err := dec.Decode(&l); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("go list: unreadable output: %w", err)
		}
		key := module.Version{Path: l.Path, Version: l.Version}
		if _, seen := result[key]; seen {
			twice[key] = true
		}
		result[key] = l
	}
	for key := range twice {
		delete(result, key)
	}
	return result, nil
}

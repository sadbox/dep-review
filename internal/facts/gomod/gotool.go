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
	"time"

	"golang.org/x/mod/module"

	"github.com/sadbox/dep-review/internal/facts"
)

// The gatherer asks the go command three questions and reads the JSON it
// prints:
//
//	go mod download -json -- m@v ...          the hashes the checksum database vouches for
//	go list -m -e -u -retracted -json -- m@v  commit time, retraction, deprecation
//	go list -m -e -versions -json -- m        the versions that are not retracted
//
// The module paths and versions in those arguments come from a pull
// request (parseMod checked them with module.Check), so the go command
// runs without a shell, after "--", with an environment of its own, in a
// scratch module with a module cache of its own, and only ever talks to
// proxy.golang.org and sum.golang.org.

const (
	// goTimeout bounds one go command. Downloading a few large modules
	// through the proxy takes well under a minute.
	goTimeout = 10 * time.Minute

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

// run implements goTool. With this environment the go command starts no
// process of its own, so ending it with the context ends everything.
func (c goCommand) run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, goTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.bin, args...)
	cmd.Dir = filepath.Join(c.scratch, "work")
	cmd.Env = c.env()
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.WaitDelay = 10 * time.Second
	err := cmd.Run()
	switch {
	case ctx.Err() != nil:
		return nil, fmt.Errorf("go %s: %w", args[0], ctx.Err())
	case err != nil:
		return out.Bytes(), fmt.Errorf("go %s: %w: %s", args[0], err, facts.Show(errb.String()))
	}
	return out.Bytes(), nil
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

func (d downloaded) key() module.Version { return module.Version{Path: d.Path, Version: d.Version} }
func (l listed) key() module.Version     { return module.Version{Path: l.Path, Version: l.Version} }

// download runs "go mod download -json" for mods. A module the go command
// could not download has its reason in Error. The error return is for the
// command itself failing.
func download(ctx context.Context, tool goTool, mods []module.Version) (map[module.Version]downloaded, error) {
	out, runErr := tool.run(ctx, append([]string{"mod", "download", "-json", "--"}, goArgs(mods)...)...)
	if len(bytes.TrimSpace(out)) == 0 && runErr != nil {
		return nil, runErr
	}
	return decode[downloaded]("go mod download", out)
}

// list runs "go list -m -e -json" with flags for the given queries. With
// -e a module the go command cannot answer for is still reported, with
// its Error set.
func list(ctx context.Context, tool goTool, flags []string, mods []module.Version) (map[module.Version]listed, error) {
	args := append([]string{"list", "-m", "-e"}, flags...)
	args = append(args, "-json", "--")
	out, runErr := tool.run(ctx, append(args, goArgs(mods)...)...)
	if runErr != nil {
		return nil, runErr
	}
	return decode[listed]("go list", out)
}

// goArgs is each module as an argument of the go command: path@version,
// or the path alone.
func goArgs(mods []module.Version) []string {
	args := make([]string, len(mods))
	for i, m := range mods {
		args[i] = m.String()
	}
	return args
}

// decode reads the stream of JSON objects a go command printed, by module
// version. A module the command said nothing about is absent from the
// result, and so is one it reported twice: which answer counts is then
// not known.
func decode[T interface{ key() module.Version }](command string, out []byte) (map[module.Version]T, error) {
	result := map[module.Version]T{}
	twice := map[module.Version]bool{}
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var v T
		if err := dec.Decode(&v); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("%s: unreadable output: %w", command, err)
		}
		if _, seen := result[v.key()]; seen {
			twice[v.key()] = true
		}
		result[v.key()] = v
	}
	for key := range twice {
		delete(result, key)
	}
	return result, nil
}

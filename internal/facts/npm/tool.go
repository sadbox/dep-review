package npm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// lsArgs is the one npm command the gatherer runs. --package-lock-only
// makes npm read the lock and nothing in node_modules; --offline and
// --ignore-scripts are belt and braces, since "ls" neither fetches nor
// runs anything.
var lsArgs = []string{"ls", "--all", "--json", "--long", "--package-lock-only", "--ignore-scripts", "--offline"}

// lsCommand is lsArgs as shown in a fact's Source.
const lsCommand = "npm ls --all --json --long --package-lock-only --ignore-scripts --offline"

const (
	// The npm majors whose reading of this package's fixtures is the
	// recorded one (TestRealNPM with 9.9.4, 10.9.11 and 11.20.0). npm
	// 8.19.4 reads the same packages but reports a failure without the
	// "error" object, so it is left out. Another major is refused, not
	// guessed at: add it here after running TestRealNPM with it.
	minNPMMajor = 9
	maxNPMMajor = 11

	// maxLSBytes bounds what is kept of npm's output. The 94-package
	// fixture prints 113 KB; a lock with ten thousand packages stays far
	// below this.
	maxLSBytes = 256 << 20

	// npmTimeout bounds one npm run. Reading a lock takes well under a
	// second.
	npmTimeout = 2 * time.Minute
)

// lsOutput is one run of lsArgs.
type lsOutput struct {
	// Stdout is what npm printed, up to maxLSBytes.
	Stdout []byte
	// Exit is npm's exit status. npm prints its JSON also when it exits
	// with 1 because the tree has problems.
	Exit int
	// Truncated says npm printed more than maxLSBytes.
	Truncated bool
}

// tool is the part of npm the gatherer uses. The real one is realNPM;
// tests replay recorded output so they need no npm.
type tool interface {
	// Version is what "npm --version" prints.
	Version(ctx context.Context) (string, error)
	// List runs lsArgs on one commit's files. manifest is nil when the
	// gatherer has no package.json for that commit.
	List(ctx context.Context, manifest, lock []byte) (lsOutput, error)
}

// realNPM runs the npm executable.
type realNPM struct {
	// path is the npm executable.
	path string
	// searchPath is the PATH npm runs with: where npm and node are, and
	// the system directories its launcher script needs (env, sh).
	searchPath string
}

// findNPM locates npm (name, or "npm" on PATH when name is empty) and
// node.
func findNPM(name string) (realNPM, error) {
	if name == "" {
		name = "npm"
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return realNPM{}, fmt.Errorf("npm is not installed: %w", err)
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return realNPM{}, err
	}
	dirs := []string{filepath.Dir(path)}
	// npm is a script that runs "node" from PATH. It is normally next to
	// npm; when it is not, add where the gate's own PATH has it.
	if node, err := exec.LookPath("node"); err == nil {
		if abs, err := filepath.Abs(node); err == nil && filepath.Dir(abs) != dirs[0] {
			dirs = append(dirs, filepath.Dir(abs))
		}
	}
	dirs = append(dirs, "/usr/bin", "/bin")
	return realNPM{path: path, searchPath: strings.Join(dirs, string(os.PathListSeparator))}, nil
}

// env is the whole environment npm gets. Nothing of the gate's own
// environment is passed on (no npm_config_*, no NODE_OPTIONS, no tokens).
// The user and global npmrc are pointed at paths that do not exist, and
// the scratch project has no .npmrc, so the only configuration npm reads
// is the one built into its installation.
func (n realNPM) env(home string) []string {
	return []string{
		"PATH=" + n.searchPath,
		"HOME=" + home,
		"npm_config_userconfig=" + filepath.Join(home, "no-user-npmrc"),
		"npm_config_globalconfig=" + filepath.Join(home, "no-global-npmrc"),
		"npm_config_cache=" + filepath.Join(home, "cache"),
		"npm_config_logs_max=0",
		"npm_config_update_notifier=false",
	}
}

// Version runs "npm --version".
func (n realNPM) Version(ctx context.Context) (string, error) {
	home, err := os.MkdirTemp("", "dep-review-npm-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(home)
	ctx, cancel := context.WithTimeout(ctx, npmTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, n.path, "--version")
	cmd.Dir = home
	cmd.Env = n.env(home)
	cmd.WaitDelay = 10 * time.Second
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil {
		return "", fmt.Errorf("%s --version: %w", n.path, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// List writes one commit's package.json and package-lock.json into an
// empty scratch directory and runs lsArgs there.
func (n realNPM) List(ctx context.Context, manifest, lock []byte) (lsOutput, error) {
	scratch, err := os.MkdirTemp("", "dep-review-npm-")
	if err != nil {
		return lsOutput{}, err
	}
	defer os.RemoveAll(scratch)
	project := filepath.Join(scratch, "project")
	home := filepath.Join(scratch, "home")
	for _, dir := range []string{project, home} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return lsOutput{}, err
		}
	}
	if err := os.WriteFile(filepath.Join(project, "package-lock.json"), lock, 0o600); err != nil {
		return lsOutput{}, err
	}
	if manifest != nil {
		if err := os.WriteFile(filepath.Join(project, "package.json"), manifest, 0o600); err != nil {
			return lsOutput{}, err
		}
	}

	// --prefix pins the project to the scratch directory. Without it npm
	// walks up from the working directory to the nearest package.json or
	// node_modules, and with no package.json in the scratch directory it
	// would read some other project above it.
	args := append(append([]string{}, lsArgs...), "--prefix", project)
	ctx, cancel := context.WithTimeout(ctx, npmTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, n.path, args...)
	cmd.Dir = project
	cmd.Env = n.env(home)
	cmd.WaitDelay = 10 * time.Second
	stdout := &capped{max: maxLSBytes}
	cmd.Stdout = stdout
	err = cmd.Run()
	if ctx.Err() != nil {
		return lsOutput{}, ctx.Err()
	}
	out := lsOutput{Stdout: stdout.buf.Bytes(), Truncated: stdout.truncated}
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit) && exit.ExitCode() > 0:
		// npm ran and said no. What it printed says why.
		out.Exit = exit.ExitCode()
	default:
		return lsOutput{}, fmt.Errorf("%s ls: %w", n.path, err)
	}
	return out, nil
}

// capped keeps the first max bytes written to it and counts nothing else.
// It never fails a write, so npm is not left blocked on a full pipe.
type capped struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (c *capped) Write(p []byte) (int, error) {
	room := c.max - c.buf.Len()
	if len(p) > room {
		c.truncated = true
		c.buf.Write(p[:room])
		return len(p), nil
	}
	c.buf.Write(p)
	return len(p), nil
}

var npmVersionRE = regexp.MustCompile(`^([0-9]{1,4})\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)

// supportedNPM reports whether version is an npm this package was tested
// with.
func supportedNPM(version string) error {
	m := npmVersionRE.FindStringSubmatch(version)
	if m == nil {
		return fmt.Errorf("npm --version printed %s, which is not a version", quote(version))
	}
	major, err := strconv.Atoi(m[1])
	if err != nil || major < minNPMMajor || major > maxNPMMajor {
		return fmt.Errorf("npm %s is not a version the gate was tested with (npm %d to %d)", version, minNPMMajor, maxNPMMajor)
	}
	return nil
}

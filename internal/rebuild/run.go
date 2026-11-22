package rebuild

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/model"
)

// Config runs the rebuilds. Images and Work are required.
type Config struct {
	// Docker is the docker CLI (default "docker"); Runtime the OCI
	// runtime (gate.yml: "runsc"; empty is docker's default, for local
	// use only).
	Docker, Runtime string
	// Images maps a Node major to the image its builds run in.
	Images map[int]string
	// Git is the git binary (default "git"); CloneBase is prefixed to
	// owner/repo (default "https://github.com/").
	Git, CloneBase string
	// Work is a scratch directory.
	Work string
	// Logf logs one line (default: discard).
	Logf func(format string, args ...any)
	// InstallTimeout and BuildTimeout bound each container (defaults 10
	// and 15 minutes).
	InstallTimeout, BuildTimeout time.Duration

	// container runs one container (default: docker run); tests replace it.
	container func(ctx context.Context, name string, args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error
}

// Caps on what the containers hand back.
const (
	MaxModules = 2 << 30           // the installed node_modules tar
	MaxOutput  = 2 * MaxBundleSize // the build's tar of the bundle directories
	maxStderr  = 4 << 10           // the tail of a container's stderr kept for the log
	maxListed  = 10                // paths named in a result's detail
	maxTrailer = 1 << 20           // what may follow the build's tar (record padding)
)

func (c *Config) defaults() {
	if c.Docker == "" {
		c.Docker = "docker"
	}
	if c.Git == "" {
		c.Git = "git"
	}
	if c.CloneBase == "" {
		c.CloneBase = "https://github.com/"
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	if c.InstallTimeout == 0 {
		c.InstallTimeout = 10 * time.Minute
	}
	if c.BuildTimeout == 0 {
		c.BuildTimeout = 15 * time.Minute
	}
	if c.container == nil {
		c.container = c.dockerRun
	}
}

// Run rebuilds every plan and returns one result per plan, in order.
func Run(ctx context.Context, cfg Config, plans []model.RebuildPlan) []model.RebuildResult {
	cfg.defaults()
	out := make([]model.RebuildResult, 0, len(plans))
	for i, p := range plans {
		r := one(ctx, cfg, p, i)
		cfg.Logf("rebuild %s %s@%s: %s %s %s", p.Update, p.Repo, short(p.Commit), r.Outcome, r.Script, r.Detail)
		out = append(out, r)
	}
	return out
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func one(ctx context.Context, cfg Config, p model.RebuildPlan, n int) model.RebuildResult {
	res := model.RebuildResult{Update: p.Update, Repo: p.Repo, Commit: p.Commit, Outcome: model.RebuildFailed}
	fail := func(format string, args ...any) model.RebuildResult {
		res.Detail = fmt.Sprintf(format, args...)
		return res
	}
	if err := CheckPlan(p); err != nil {
		return fail("invalid plan: %v", err)
	}
	image := cfg.Images[p.Node]
	if image == "" {
		return fail("no image for node %d", p.Node)
	}
	dir, err := os.MkdirTemp(cfg.Work, "rebuild-")
	if err != nil {
		return fail("scratch: %v", err)
	}
	g := gitDir{bin: cfg.Git, dir: filepath.Join(dir, "git")}
	if err := g.fetch(ctx, cfg.CloneBase+p.Repo, p.Commit); err != nil {
		return fail("fetching the commit: %v", err)
	}
	tree, err := g.tree(ctx, p.Commit)
	if err != nil {
		return fail("reading the tree: %v", err)
	}
	// The plan's files are the commit's: same paths under the bundle
	// directories (their contents are compared to the build's output).
	var committed []string
	byPath := map[string]treeEntry{}
	for _, e := range tree {
		byPath[e.path] = e
		if e.kind == "commit" {
			return fail("the tree has a submodule (%s), which the build would not have", safe(e.path))
		}
		if Under(e.path, p.Dirs) {
			committed = append(committed, e.path)
		}
	}
	var planned []string
	for _, f := range p.Files {
		planned = append(planned, f.Path)
	}
	slices.Sort(committed)
	slices.Sort(planned)
	if !slices.Equal(committed, planned) {
		return fail("the commit's bundle files are not the ones fetch listed")
	}
	pkg, err1 := g.blob(ctx, byPath["package.json"])
	lock, err2 := g.blob(ctx, byPath["package-lock.json"])
	if err1 != nil || err2 != nil {
		return fail("package.json or package-lock.json is missing")
	}
	if _, err := Scripts(pkg, lock); err != nil {
		return fail("%v", err)
	}

	// install: the two files, npm ci without scripts, node_modules out.
	installIn, err := tarOf(map[string][]byte{"package.json": pkg, "package-lock.json": lock})
	if err != nil {
		return fail("%v", err)
	}
	modules, err := os.Create(filepath.Join(dir, "node_modules.tar"))
	if err != nil {
		return fail("scratch: %v", err)
	}
	defer modules.Close()
	ictx, cancel := context.WithTimeout(ctx, cfg.InstallTimeout)
	iname := fmt.Sprintf("dep-review-install-%d", n)
	err = cfg.run(ictx, iname, installArgs(cfg, iname, image), bytes.NewReader(installIn), &capped{w: modules, n: MaxModules})
	cancel()
	if err != nil {
		return fail("npm ci (no scripts) failed: %v", err)
	}

	// The build's input: every committed file outside the bundle
	// directories (built by the gate from the tree, so no
	// .gitattributes export rule applies).
	src, err := os.Create(filepath.Join(dir, "src.tar"))
	if err != nil {
		return fail("scratch: %v", err)
	}
	defer src.Close()
	if err := g.writeTree(ctx, src, tree, p.Dirs); err != nil {
		return fail("writing the source: %v", err)
	}

	want := map[string]string{}
	for _, f := range p.Files {
		want[f.Path] = f.SHA256
	}
	var tried []string
	compared := false
	for _, script := range p.Scripts {
		if _, err := src.Seek(0, io.SeekStart); err != nil {
			return fail("%v", err)
		}
		if _, err := modules.Seek(0, io.SeekStart); err != nil {
			return fail("%v", err)
		}
		pr, pw := io.Pipe()
		got := make(chan readResult, 1)
		go func() {
			files, err := readBundle(pr, p.Dirs)
			if err == nil {
				// tar pads its archive to a whole record after the end
				// marker; read that much, and fail a build that writes more.
				if n, _ := io.CopyN(io.Discard, pr, maxTrailer+1); n > maxTrailer {
					err = rejected("the build wrote more after its archive")
				}
			}
			_ = pr.CloseWithError(err)
			got <- readResult{files, err}
		}()
		bctx, cancel := context.WithTimeout(ctx, cfg.BuildTimeout)
		bname := fmt.Sprintf("dep-review-build-%d-%s", n, script)
		runErr := cfg.run(bctx, bname, buildArgs(cfg, bname, image, script, p.Dirs), io.MultiReader(src, modules), pw)
		cancel()
		_ = pw.CloseWithError(runErr)
		r := <-got
		switch {
		case errors.As(r.err, new(rejected)):
			// The output itself is not the bundle (and closing the pipe
			// on it may have failed the build too).
			compared = true
			tried = append(tried, fmt.Sprintf("%s: %v", script, r.err))
			continue
		case runErr != nil || r.err != nil:
			tried = append(tried, fmt.Sprintf("%s: the build failed", script))
			continue
		}
		compared = true
		missing, extra, differ := compare(want, r.files)
		if len(missing)+len(extra)+len(differ) == 0 {
			res.Outcome, res.Script = model.RebuildVerified, script
			res.Detail = fmt.Sprintf("npm run %s rebuilt all %d files byte for byte", script, len(want))
			return res
		}
		tried = append(tried, fmt.Sprintf("%s: %s", script, describe(missing, extra, differ)))
	}
	if compared {
		res.Outcome = model.RebuildDiffers
	}
	return fail("%s", strings.Join(tried, "; "))
}

// rejected is the build's output failing readBundle's rules: a result
// (differs), not a failure.
type rejected string

func (r rejected) Error() string { return string(r) }

type readResult struct {
	files map[string]string
	err   error
}

func (c Config) run(ctx context.Context, name string, args []string, stdin io.Reader, stdout io.Writer) error {
	var stderr tail
	err := c.container(ctx, name, args, stdin, stdout, &stderr)
	if err != nil {
		c.Logf("container %s: %v; stderr tail: %s", name, err, stderr.String())
	}
	return err
}

// common is every container's confinement: no capabilities, no new
// privileges, a read-only root, an unprivileged user, bounded memory and
// processes, and only a tmpfs to write to.
func common(cfg Config, name, network string) []string {
	a := []string{"run", "--rm", "-i", "--name", name}
	if cfg.Runtime != "" {
		a = append(a, "--runtime", cfg.Runtime)
	}
	return append(a,
		"--network", network,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--read-only",
		"--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=6g",
		"--memory", "10g", "--memory-swap", "10g",
		"--pids-limit", "2048",
		"--user", "1000:1000",
		"--workdir", "/tmp",
		"-e", "HOME=/tmp/home",
		"-e", "npm_config_cache=/tmp/npm-cache",
		"-e", "npm_config_update_notifier=false",
		"-e", "npm_config_audit=false",
		"-e", "npm_config_fund=false",
		"-e", "CI=true",
		"--entrypoint", "/bin/sh",
	)
}

const installScript = `set -eu
mkdir -p /tmp/w && cd /tmp/w && tar -xf -
npm ci --ignore-scripts --registry=https://registry.npmjs.org/ >&2
mkdir -p node_modules && tar -cf - node_modules`

const buildScript = `set -eu
mkdir -p /tmp/w && cd /tmp/w && tar -xif -
s=$1
shift
npm run "$s" >&2
tar -cf - -- "$@"`

func installArgs(cfg Config, name, image string) []string {
	return append(common(cfg, name, "bridge"), image, "-c", installScript)
}

func buildArgs(cfg Config, name, image, script string, dirs []string) []string {
	a := append(common(cfg, name, "none"), image, "-c", buildScript, "sh", script)
	return append(a, dirs...)
}

// dockerRun runs docker with args and always removes the container
// named name afterwards, also when ctx ended it.
func (c Config) dockerRun(ctx context.Context, name string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, c.Docker, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	cmd.WaitDelay = 10 * time.Second
	err := cmd.Run()
	rm := exec.Command(c.Docker, "rm", "-f", name)
	_ = rm.Run()
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	return err
}

// capped fails a write past n bytes.
type capped struct {
	w io.Writer
	n int64
}

func (c *capped) Write(b []byte) (int, error) {
	if int64(len(b)) > c.n {
		return 0, errors.New("output cap reached")
	}
	c.n -= int64(len(b))
	return c.w.Write(b)
}

// tail keeps the last maxStderr bytes written.
type tail struct{ b []byte }

func (t *tail) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > maxStderr {
		t.b = t.b[len(t.b)-maxStderr:]
	}
	return len(p), nil
}

func (t *tail) String() string { return string(t.b) }

// readBundle reads the build's tar: directories and regular files only,
// every file inside dirs and named once, within the caps. It returns
// each file's sha256.
func readBundle(r io.Reader, dirs []string) (map[string]string, error) {
	tr := tar.NewReader(r)
	out := map[string]string{}
	var total int64
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("reading the build's output: %w", err)
		}
		if n > 2*MaxFiles {
			return nil, rejected("the build's output has too many entries")
		}
		name := strings.TrimPrefix(h.Name, "./")
		if h.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
			if CleanPath(name) && (slices.Contains(dirs, name) || Under(name, dirs)) {
				continue
			}
			return nil, rejected(fmt.Sprintf("the build's output has a directory outside the bundle: %s", safe(name)))
		}
		if h.Typeflag != tar.TypeReg {
			return nil, rejected(fmt.Sprintf("the build's output has a non-regular file: %s", safe(name)))
		}
		if !CleanPath(name) || !Under(name, dirs) {
			return nil, rejected(fmt.Sprintf("the build's output has a file outside the bundle: %s", safe(name)))
		}
		if _, dup := out[name]; dup {
			return nil, rejected(fmt.Sprintf("the build's output names %s twice", safe(name)))
		}
		total += h.Size
		if h.Size < 0 || total > MaxOutput {
			return nil, rejected("the build's output is too large")
		}
		sum := sha256.New()
		if _, err := io.CopyN(sum, tr, h.Size); err != nil {
			return nil, fmt.Errorf("reading the build's output: %w", err)
		}
		out[name] = hex.EncodeToString(sum.Sum(nil))
	}
}

func compare(want, got map[string]string) (missing, extra, differ []string) {
	for p, s := range want {
		g, ok := got[p]
		switch {
		case !ok:
			missing = append(missing, p)
		case g != s:
			differ = append(differ, p)
		}
	}
	for p := range got {
		if _, ok := want[p]; !ok {
			extra = append(extra, p)
		}
	}
	slices.Sort(missing)
	slices.Sort(extra)
	slices.Sort(differ)
	return
}

func describe(missing, extra, differ []string) string {
	var parts []string
	for _, x := range []struct {
		what  string
		paths []string
	}{{"differ", differ}, {"not built", missing}, {"built but not committed", extra}} {
		if len(x.paths) > 0 {
			parts = append(parts, fmt.Sprintf("%d %s (%s)", len(x.paths), x.what, list(x.paths)))
		}
	}
	return strings.Join(parts, ", ")
}

func list(ps []string) string {
	var out []string
	for i, p := range ps {
		if i == maxListed {
			out = append(out, fmt.Sprintf("and %d more", len(ps)-i))
			break
		}
		out = append(out, safe(p))
	}
	return strings.Join(out, ", ")
}

// safe is a path as the gate shows it: CleanPath, or a placeholder.
func safe(p string) string {
	if CleanPath(p) && len(p) <= 200 {
		return p
	}
	return "(unprintable path)"
}

func tarOf(files map[string][]byte) ([]byte, error) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, name := range slices.Sorted(maps.Keys(files)) {
		data := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	err := tw.Close()
	return b.Bytes(), err
}

// gitDir is a scratch repository holding one fetched commit.
type gitDir struct{ bin, dir string }

type treeEntry struct {
	mode, kind, sha, path string
}

func (g gitDir) cmd(ctx context.Context, args ...string) *exec.Cmd {
	full := append([]string{"-C", g.dir,
		"-c", "core.hooksPath=/dev/null",
		"-c", "credential.helper=",
		"-c", "core.fsmonitor=false",
	}, args...)
	cmd := exec.CommandContext(ctx, g.bin, full...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "SSH_ASKPASS=", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	return cmd
}

func (g gitDir) fetch(ctx context.Context, url, commit string) error {
	if err := os.MkdirAll(g.dir, 0o700); err != nil {
		return err
	}
	for _, args := range [][]string{
		{"init", "-q", "--bare"},
		{"fetch", "-q", "--depth", "1", "--no-tags", url, commit},
		{"cat-file", "-e", commit + "^{commit}"},
	} {
		if out, err := g.cmd(ctx, args...).CombinedOutput(); err != nil {
			return fmt.Errorf("git %s: %v (%s)", args[0], err, strings.TrimSpace(string(out[:min(len(out), 200)])))
		}
	}
	return nil
}

func (g gitDir) tree(ctx context.Context, commit string) ([]treeEntry, error) {
	out, err := g.cmd(ctx, "ls-tree", "-r", "-z", "--full-tree", commit).Output()
	if err != nil {
		return nil, err
	}
	var es []treeEntry
	for _, rec := range bytes.Split(out, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		meta, p, ok := bytes.Cut(rec, []byte{'\t'})
		f := strings.Fields(string(meta))
		if !ok || len(f) != 3 {
			return nil, errors.New("unexpected ls-tree output")
		}
		es = append(es, treeEntry{mode: f[0], kind: f[1], sha: f[2], path: string(p)})
	}
	return es, nil
}

func (g gitDir) blob(ctx context.Context, e treeEntry) ([]byte, error) {
	if e.kind != "blob" || e.mode == "120000" {
		return nil, errors.New("not a file")
	}
	return g.cmd(ctx, "cat-file", "blob", e.sha).Output()
}

// writeTree writes every blob of tree outside dirs to w as a tar, with
// git's modes; symlinks stay symlinks (inside the container).
func (g gitDir) writeTree(ctx context.Context, w io.Writer, tree []treeEntry, dirs []string) error {
	cmd := g.cmd(ctx, "cat-file", "--batch")
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() { _ = cmd.Wait() }()
	defer in.Close()
	out := bufio.NewReader(outPipe)
	tw := tar.NewWriter(w)
	for _, e := range tree {
		if e.kind != "blob" || Under(e.path, dirs) {
			continue
		}
		if _, err := fmt.Fprintln(in, e.sha); err != nil {
			return err
		}
		head, err := out.ReadString('\n')
		if err != nil {
			return err
		}
		f := strings.Fields(head)
		if len(f) != 3 || f[0] != e.sha || f[1] != "blob" {
			return fmt.Errorf("unexpected cat-file header for %s", safe(e.path))
		}
		size, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil {
			return err
		}
		data := make([]byte, size+1) // and the trailing newline
		if _, err := io.ReadFull(out, data); err != nil {
			return err
		}
		data = data[:size]
		h := &tar.Header{Name: e.path, Size: size, Mode: 0o644, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		switch e.mode {
		case "100755":
			h.Mode = 0o755
		case "120000":
			h.Typeflag, h.Linkname, h.Size = tar.TypeSymlink, string(data), 0
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write(data); err != nil {
				return err
			}
		}
	}
	return tw.Close()
}

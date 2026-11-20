// Package sandbox runs the reviewer: the Claude Code CLI in a container
// under gVisor, on an internal Docker network whose only other member is
// the credential proxy (internal/proxy, in its own runc container that is
// also on a normal bridge). The reviewer container has a read-only root,
// no capabilities, tmpfs $HOME and /tmp, read-only evidence and repo
// mounts, and an environment of exactly the variables listed in
// reviewerEnv. Its result comes back only on stdout (ReadVerdict).
//
// Every docker invocation is built here, so the gate, the CI probes and
// the CI end-to-end run all use the same flags; only the command differs.
package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/proxy"
)

const (
	// The placeholder the CLI needs to start in -p mode; the proxy drops
	// it and the real upstream would reject it.
	PlaceholderKey = "dep-review-sandbox-no-credential"

	reviewerUID  = "65532"
	reviewerHome = "/home/reviewer"
	workDir      = "/work"
	proxyPort    = 8080
	readyLine    = "proxy: ready"

	identityMount = "/run/dep-review-identity"
	identitySock  = "oidc.sock"
	maxIdentity   = 64 // JWTs per run; the proxy needs one per ~8 minutes
)

// Config is one review run.
type Config struct {
	Docker        string // docker CLI, default "docker"
	Name          string // prefix for networks and containers; unique per run
	ReviewerImage string
	ProxyImage    string // distroless static, by digest
	Runtime       string // "runsc"; anything else is refused unless AllowRuntime

	GateBinary   string // the static dep-review binary, mounted into the proxy
	EvidenceDir  string
	RepoDir      string
	SettingsFile string // Claude Code user settings (review-prep)
	PromptFile   string // the prompt, sent on stdin
	Schema       string // compact verdict schema for --json-schema

	Model       string
	MaxTurns    int
	MaxRequests int
	Federation  Federation
	// Identity mints GitHub OIDC JWTs for the Claude audience, on the host
	// (proxy.GitHubOIDC); the proxy gets them through a unix socket.
	Identity   func(context.Context) (string, error)
	SocketRoot string       // where the socket directory is made; default os.TempDir()
	Subnet     netip.Prefix // internal network; the proxy takes .2

	Timeout time.Duration // the reviewer container's wall clock

	// Tests only (cmd/dep-review sandboxtest build): extra proxy flags,
	// containers to start on the egress network before the proxy, and a
	// replacement for the claude command (the probe script).
	ProxyExtraArgs []string
	EgressSidecars []Sidecar
	Command        []string // nil: claude -p ...
	ExtraMounts    []Mount
	Stderr         io.Writer // default os.Stderr

	identityDir string
}

type Federation struct {
	RuleID, OrganizationID, WorkspaceID, ServiceAccountID string
}

type Mount struct{ Src, Dst string }

// Sidecar is a container started on the egress network (tests: the fake
// upstream). Args follow "docker run -d --name <Name> --network <egress>".
type Sidecar struct {
	Name string
	Args []string
}

func (c *Config) defaults() error {
	if c.Docker == "" {
		c.Docker = "docker"
	}
	if c.Runtime == "" {
		c.Runtime = "runsc"
	}
	if c.Stderr == nil {
		c.Stderr = os.Stderr
	}
	if !c.Subnet.IsValid() {
		c.Subnet = netip.MustParsePrefix("10.213.7.0/24")
	}
	if c.Timeout == 0 {
		c.Timeout = 15 * time.Minute
	}
	if c.MaxTurns == 0 {
		c.MaxTurns = 80
	}
	switch {
	case c.Name == "" || strings.ContainsAny(c.Name, " /:"):
		return errors.New("sandbox: bad name")
	case c.ReviewerImage == "" || c.ProxyImage == "":
		return errors.New("sandbox: images required")
	case c.Model == "":
		return errors.New("sandbox: model required")
	case !c.Subnet.Addr().Is4() || c.Subnet.Bits() > 29:
		return errors.New("sandbox: subnet must be IPv4, /29 or larger")
	}
	for _, p := range []*string{&c.GateBinary, &c.EvidenceDir, &c.RepoDir, &c.SettingsFile} {
		abs, err := filepath.Abs(*p)
		if err != nil || *p == "" {
			return fmt.Errorf("sandbox: path %q", *p)
		}
		*p = abs
	}
	return nil
}

func (c *Config) internalNet() string { return c.Name + "-int" }
func (c *Config) egressNet() string   { return c.Name + "-egress" }
func (c *Config) proxyName() string   { return c.Name + "-proxy" }
func (c *Config) reviewerName() string {
	return c.Name + "-reviewer"
}

// ProxyAddr is where the reviewer reaches the proxy: a fixed IP, since
// Docker's embedded DNS (127.0.0.11) relies on rules inside the container's
// network namespace that gVisor's own network stack does not use. Without
// DNS the reviewer cannot resolve any name at all.
func (c *Config) ProxyAddr() string {
	return netip.AddrPortFrom(c.Subnet.Addr().Next().Next(), proxyPort).String()
}

// NetworkArgs are the two `docker network create` invocations. The
// internal network has no gateway address on the host
// (inhibit_ipv4), so the host itself is unreachable from it, not only the
// outside world; Docker's --internal rules drop everything routed off it.
func (c *Config) NetworkArgs() [][]string {
	return [][]string{
		{"network", "create", "--internal", "--subnet", c.Subnet.Masked().String(),
			"-o", "com.docker.network.bridge.inhibit_ipv4=true",
			"-o", "com.docker.network.bridge.enable_ip_masquerade=false",
			c.internalNet()},
		{"network", "create", c.egressNet()},
	}
}

// ProxyArgs is the `docker create` for the proxy. It runs under runc
// (it must reach the internet), as the distroless nonroot user, read-only.
// It gets no ACTIONS_* variable: its OIDC JWTs come from the host helper
// (startIdentity) over a unix socket in the read-only identity mount.
func (c *Config) ProxyArgs() []string {
	a := []string{"create", "--name", c.proxyName(),
		"--runtime", "runc",
		"--network", c.egressNet(),
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--user", "65532:65532",
		"--pids-limit", "64", "--memory", "256m",
		"--mount", "type=bind,src=" + c.GateBinary + ",dst=/dep-review,readonly",
		"--mount", "type=bind,src=" + c.identityDir + ",dst=" + identityMount + ",readonly",
		"--entrypoint", "/dep-review",
		c.ProxyImage,
		"proxy",
		"--listen", ":" + strconv.Itoa(proxyPort),
		"--identity-socket", identityMount + "/" + identitySock,
		"--model", c.Model,
		"--federation-rule-id", c.Federation.RuleID,
		"--organization-id", c.Federation.OrganizationID,
	}
	if c.Federation.WorkspaceID != "" {
		a = append(a, "--workspace-id", c.Federation.WorkspaceID)
	}
	if c.Federation.ServiceAccountID != "" {
		a = append(a, "--service-account-id", c.Federation.ServiceAccountID)
	}
	if c.MaxRequests > 0 {
		a = append(a, "--max-requests", strconv.Itoa(c.MaxRequests))
	}
	return append(a, c.ProxyExtraArgs...)
}

// reviewerEnv is the reviewer's whole environment (beyond the image's own
// PATH and SSL_CERT_FILE). Nothing is inherited from the runner.
func (c *Config) reviewerEnv() []string {
	return []string{
		"HOME=" + reviewerHome,
		"ANTHROPIC_BASE_URL=http://" + c.ProxyAddr(),
		"ANTHROPIC_API_KEY=" + PlaceholderKey,
		// Background requests (titles and the like) use the "haiku"
		// model; point it at the gate's model so the proxy's model check
		// never refuses one.
		"ANTHROPIC_DEFAULT_HAIKU_MODEL=" + c.Model,
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
		"CLAUDE_CODE_DISABLE_TERMINAL_TITLE=1",
		"DISABLE_AUTOUPDATER=1",
		"DISABLE_TELEMETRY=1",
		"DISABLE_ERROR_REPORTING=1",
	}
}

// ReviewerArgs is the `docker run` for the reviewer. The gate, the probes
// and the end-to-end test differ only in Command and ExtraMounts.
func (c *Config) ReviewerArgs() []string {
	a := []string{"run", "--name", c.reviewerName(), "--interactive",
		"--runtime", c.Runtime,
		"--network", c.internalNet(),
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--user", reviewerUID + ":" + reviewerUID,
		"--pids-limit", "256", "--memory", "4g", "--memory-swap", "4g",
		"--tmpfs", reviewerHome + ":rw,nosuid,nodev,size=512m,uid=" + reviewerUID + ",gid=" + reviewerUID + ",mode=0700",
		"--tmpfs", "/tmp:rw,nosuid,nodev,size=512m,mode=1777",
		"--mount", "type=bind,src=" + c.EvidenceDir + ",dst=" + workDir + "/evidence,readonly",
		"--mount", "type=bind,src=" + c.RepoDir + ",dst=" + workDir + "/repo,readonly",
		"--mount", "type=bind,src=" + c.SettingsFile + ",dst=" + reviewerHome + "/.claude/settings.json,readonly",
		"--workdir", workDir,
		"--log-driver", "none",
	}
	for _, m := range c.ExtraMounts {
		a = append(a, "--mount", "type=bind,src="+m.Src+",dst="+m.Dst+",readonly")
	}
	for _, e := range c.reviewerEnv() {
		a = append(a, "--env", e)
	}
	if c.Command != nil {
		return append(append(a, "--entrypoint", c.Command[0], c.ReviewerImage), c.Command[1:]...)
	}
	return append(a, c.ReviewerImage, "-p",
		"--output-format", "json",
		"--model", c.Model,
		"--tools", "Read,Grep,Glob",
		"--permission-mode", "dontAsk",
		"--setting-sources", "user",
		"--strict-mcp-config",
		"--max-turns", strconv.Itoa(c.MaxTurns),
		"--json-schema", c.Schema,
	)
}

// Result of a sandbox run.
type Result struct {
	Exit      int    // reviewer container's exit status (-1: did not finish)
	TimedOut  bool   // killed at Timeout
	Stdout    []byte // only for Command runs (probes); nil for reviews
	VerdictOK bool
	Verdict   []byte // validated verdict JSON, when VerdictOK
	VerdictE  error  // why there is no verdict
}

// Run sets up the networks and the proxy, runs the reviewer and tears
// everything down. For a review (Command == nil) the verdict comes from
// ReadVerdict over the container's stdout and counts only if the
// container also exited 0 within Timeout and ran under c.Runtime.
func Run(ctx context.Context, c Config) (Result, error) {
	res := Result{Exit: -1}
	if err := c.defaults(); err != nil {
		return res, err
	}
	defer c.cleanup()
	for _, n := range c.NetworkArgs() {
		if err := c.docker(ctx, n...); err != nil {
			return res, err
		}
	}
	for _, s := range c.EgressSidecars {
		if err := c.docker(ctx, append([]string{"run", "-d", "--name", s.Name, "--network", c.egressNet()}, s.Args...)...); err != nil {
			return res, err
		}
	}
	stopIdentity, err := c.startIdentity()
	if err != nil {
		return res, err
	}
	defer stopIdentity()
	if err := c.startProxy(ctx); err != nil {
		return res, err
	}

	runCtx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	prompt, err := c.prompt()
	if err != nil {
		return res, err
	}
	cmd := exec.Command(c.Docker, c.ReviewerArgs()...)
	cmd.Env = dockerEnv(nil)
	cmd.Stdin = prompt
	// An io.Pipe, not StdoutPipe: Wait then waits until everything the
	// container wrote has been handed to the reader, which always drains.
	stdout, pw := io.Pipe()
	cmd.Stdout = pw
	stderr := newPrefixWriter(c.Stderr, "reviewer| ", 4<<20)
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		pw.Close()
		return res, err
	}
	type read struct {
		v   []byte
		out []byte
		err error
	}
	done := make(chan read, 1)
	go func() {
		if c.Command != nil {
			b, err := readCapped(stdout, 1<<20)
			done <- read{out: b, err: err}
			return
		}
		v, err := ReadVerdict(stdout)
		done <- read{v: v, err: err}
	}()
	waited := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		pw.Close()
		waited <- err
	}()
	var werr error
	select {
	case werr = <-waited:
	case <-runCtx.Done():
		res.TimedOut = true
		fmt.Fprintf(c.Stderr, "sandbox: reviewer timed out after %s; killing it\n", c.Timeout)
		c.docker(context.Background(), "kill", c.reviewerName())
		werr = <-waited
	}
	r := <-done
	stderr.Flush()
	var ee *exec.ExitError
	switch {
	case werr == nil:
		res.Exit = 0
	case errors.As(werr, &ee):
		res.Exit = ee.ExitCode()
	default:
		return res, werr
	}
	c.dumpLogs(c.proxyName(), "proxy| ")
	for _, s := range c.EgressSidecars {
		c.dumpLogs(s.Name, s.Name+"| ")
	}

	// The runtime the container actually ran under, from Docker itself.
	rt, err := c.output(context.Background(), "inspect", "--format", "{{.HostConfig.Runtime}}", c.reviewerName())
	if err != nil {
		return res, fmt.Errorf("inspecting the reviewer: %w", err)
	}
	if rt = strings.TrimSpace(rt); rt != c.Runtime {
		return res, fmt.Errorf("the reviewer ran under %q, not %q", rt, c.Runtime)
	}

	if c.Command != nil {
		res.Stdout = r.out
		return res, r.err
	}
	switch {
	case res.TimedOut:
		res.VerdictE = errors.New("the reviewer timed out")
	case res.Exit != 0:
		res.VerdictE = fmt.Errorf("the reviewer exited %d", res.Exit)
	case r.err != nil:
		res.VerdictE = r.err
	default:
		res.VerdictOK, res.Verdict = true, r.v
	}
	return res, nil
}

func (c *Config) prompt() (io.Reader, error) {
	if c.Command != nil {
		return strings.NewReader(""), nil
	}
	b, err := os.ReadFile(c.PromptFile)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b), nil
}

func (c *Config) startProxy(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, c.Docker, c.ProxyArgs()...)
	cmd.Env = dockerEnv(nil)
	cmd.Stdout, cmd.Stderr = io.Discard, c.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("creating the proxy: %w", err)
	}
	if err := c.docker(ctx, "network", "connect", "--ip", c.Subnet.Addr().Next().Next().String(), c.internalNet(), c.proxyName()); err != nil {
		return err
	}
	if err := c.docker(ctx, "start", c.proxyName()); err != nil {
		return err
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		// The proxy logs to stderr, which docker logs replays on its own
		// stderr.
		lc := exec.CommandContext(ctx, c.Docker, "logs", c.proxyName())
		lc.Env = dockerEnv(nil)
		lb, _ := lc.CombinedOutput()
		logs := string(lb)
		if strings.Contains(logs, readyLine) {
			return nil
		}
		state, _ := c.output(ctx, "inspect", "--format", "{{.State.Status}}", c.proxyName())
		if s := strings.TrimSpace(state); s == "exited" || s == "dead" {
			c.dumpLogs(c.proxyName(), "proxy| ")
			return errors.New("the proxy exited before it was ready")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	c.dumpLogs(c.proxyName(), "proxy| ")
	return errors.New("the proxy did not become ready")
}

func (c *Config) dumpLogs(name, prefix string) {
	cmd := exec.Command(c.Docker, "logs", name)
	cmd.Env = dockerEnv(nil)
	w := newPrefixWriter(c.Stderr, prefix, 1<<20)
	cmd.Stdout, cmd.Stderr = w, w
	cmd.Run()
	w.Flush()
}

func (c *Config) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	names := []string{c.reviewerName(), c.proxyName()}
	cmd := exec.CommandContext(ctx, c.Docker, append([]string{"rm", "-f", "--volumes"}, names...)...)
	cmd.Env = dockerEnv(nil)
	cmd.Run()
	// Sidecars run with --rm=false and a name the caller chose; remove
	// whatever is still attached to our networks, then the networks.
	for _, n := range []string{c.egressNet(), c.internalNet()} {
		ids, _ := c.output(ctx, "network", "inspect", "--format", "{{range $k, $v := .Containers}}{{$k}} {{end}}", n)
		if f := strings.Fields(ids); len(f) > 0 {
			rm := exec.CommandContext(ctx, c.Docker, append([]string{"rm", "-f"}, f...)...)
			rm.Env = dockerEnv(nil)
			rm.Run()
		}
		nc := exec.CommandContext(ctx, c.Docker, "network", "rm", n)
		nc.Env = dockerEnv(nil)
		nc.Run()
	}
}

func (c *Config) docker(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, c.Docker, args...)
	cmd.Env = dockerEnv(nil)
	var errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = io.Discard, &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker %s: %w: %s", args[0]+" "+argOr(args, 1), err, strings.TrimSpace(errb.String()))
	}
	return nil
}

func (c *Config) output(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, c.Docker, args...)
	cmd.Env = dockerEnv(nil)
	b, err := cmd.Output()
	return string(b), err
}

func argOr(a []string, i int) string {
	if i < len(a) {
		return a[i]
	}
	return ""
}

// dockerEnv is the docker CLI's environment: what it needs to find the
// daemon, plus the named variables (the proxy's OIDC values) if set.
func dockerEnv(pass []string) []string {
	var env []string
	for _, k := range append([]string{"PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY", "XDG_RUNTIME_DIR"}, pass...) {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func readCapped(r io.Reader, n int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, n+1))
	io.Copy(io.Discard, r)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > n {
		return nil, fmt.Errorf("output over %d bytes", n)
	}
	return b, nil
}

// prefixWriter forwards a child's stderr to the job log one line at a
// time, each line prefixed, so nothing the reviewer prints can start a
// line with "::" and be taken for a workflow command. Control characters
// are replaced and the total is capped.
type prefixWriter struct {
	w      io.Writer
	prefix string
	left   int
	buf    bytes.Buffer
	cut    bool
}

func newPrefixWriter(w io.Writer, prefix string, limit int) *prefixWriter {
	return &prefixWriter{w: w, prefix: prefix, left: limit}
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	n := len(b)
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			p.buf.Write(b)
			if p.buf.Len() > 64<<10 {
				p.emit()
			}
			break
		}
		p.buf.Write(b[:i])
		p.emit()
		b = b[i+1:]
	}
	return n, nil
}

func (p *prefixWriter) emit() {
	line := p.buf.String()
	p.buf.Reset()
	if p.left <= 0 {
		if !p.cut {
			p.cut = true
			fmt.Fprintf(p.w, "%s(output truncated)\n", p.prefix)
		}
		return
	}
	line = strings.Map(func(r rune) rune {
		if r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, line)
	p.left -= len(line)
	bw := bufio.NewWriter(p.w)
	bw.WriteString(p.prefix)
	bw.WriteString(line)
	bw.WriteByte('\n')
	bw.Flush()
}

// Flush writes a trailing partial line.
func (p *prefixWriter) Flush() {
	if p.buf.Len() > 0 {
		p.emit()
	}
}

// startIdentity serves proxy.IdentityHandler on a unix socket in a fresh
// directory, which ProxyArgs mounts read-only into the proxy container.
// The job's OIDC request token stays in this process.
func (c *Config) startIdentity() (func(), error) {
	if c.Identity == nil {
		return nil, errors.New("sandbox: no identity source")
	}
	root := c.SocketRoot
	if root == "" {
		root = os.TempDir()
	}
	dir, err := os.MkdirTemp(root, "dep-review-identity-")
	if err != nil {
		return nil, err
	}
	// The proxy runs as 65532: it must traverse the directory and connect
	// to the socket, and nothing else lives here.
	if err := os.Chmod(dir, 0o755); err != nil {
		os.Remove(dir)
		return nil, err
	}
	sock := filepath.Join(dir, identitySock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		os.Remove(dir)
		return nil, err
	}
	if err := os.Chmod(sock, 0o666); err != nil {
		ln.Close()
		os.Remove(dir)
		return nil, err
	}
	c.identityDir = dir
	logf := func(f string, a ...any) { fmt.Fprintf(c.Stderr, f+"\n", a...) }
	srv := &http.Server{Handler: proxy.IdentityHandler(c.Identity, maxIdentity, logf), ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	return func() {
		srv.Close()
		os.Remove(sock)
		os.Remove(dir)
	}, nil
}

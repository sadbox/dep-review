package sandbox

import (
	"bytes"
	"io"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func testConfig(t *testing.T) Config {
	c := Config{
		Name:          "dr-test",
		ReviewerImage: "reviewer:x",
		ProxyImage:    "proxy:x",
		GateBinary:    "/gate/dep-review",
		EvidenceDir:   "/w/evidence",
		RepoDir:       "/w/repo",
		SettingsFile:  "/w/prep/settings.json",
		PromptFile:    "/w/prep/prompt.md",
		Schema:        `{"type":"object"}`,
		Model:         "claude-opus-5-5",
		MaxRequests:   150,
		Federation:    Federation{RuleID: "fdrl_1", OrganizationID: "org", WorkspaceID: "wrkspc_1"},
	}
	if err := c.defaults(); err != nil {
		t.Fatal(err)
	}
	return c
}

// pairs returns the values of every "flag value" pair for flag.
func values(a []string, flag string) []string {
	var v []string
	for i := 0; i+1 < len(a); i++ {
		if a[i] == flag {
			v = append(v, a[i+1])
		}
	}
	return v
}

func TestReviewerArgs(t *testing.T) {
	c := testConfig(t)
	a := c.ReviewerArgs()
	s := strings.Join(a, " ")
	for _, want := range []string{
		"--runtime runsc", "--network dr-test-int", "--read-only", "--cap-drop ALL",
		"--security-opt no-new-privileges", "--user 65532:65532", "--pids-limit 256", "--memory 4g",
		"--workdir /work", "--interactive",
		"type=bind,src=/w/evidence,dst=/work/evidence,readonly",
		"type=bind,src=/w/repo,dst=/work/repo,readonly",
		"type=bind,src=/w/prep/settings.json,dst=/home/reviewer/.claude/settings.json,readonly",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("reviewer args lack %q", want)
		}
	}
	tmpfs := values(a, "--tmpfs")
	if len(tmpfs) != 2 || !strings.HasPrefix(tmpfs[0], "/home/reviewer:") || !strings.HasPrefix(tmpfs[1], "/tmp:") {
		t.Errorf("tmpfs = %v", tmpfs)
	}
	// Every bind mount is read-only: tmpfs is the only writable storage.
	for _, m := range values(a, "--mount") {
		if !strings.HasSuffix(m, ",readonly") {
			t.Errorf("writable mount %s", m)
		}
	}
	if slices.Contains(a, "-v") || slices.Contains(a, "--volume") || slices.Contains(a, "--env-file") || slices.Contains(a, "--privileged") {
		t.Error("forbidden flag")
	}
	env := values(a, "--env")
	wantEnv := []string{
		"HOME=/home/reviewer",
		"ANTHROPIC_BASE_URL=http://10.213.7.2:8080",
		"ANTHROPIC_API_KEY=" + PlaceholderKey,
		"ANTHROPIC_DEFAULT_HAIKU_MODEL=claude-opus-5-5",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
		"CLAUDE_CODE_DISABLE_TERMINAL_TITLE=1",
		"DISABLE_AUTOUPDATER=1",
		"DISABLE_TELEMETRY=1",
		"DISABLE_ERROR_REPORTING=1",
	}
	if !slices.Equal(env, wantEnv) {
		t.Errorf("env = %v", env)
	}
	for _, e := range env {
		if !strings.Contains(e, "=") {
			t.Errorf("env %q would be inherited from the runner", e)
		}
	}
	// The command: the same CLI flags the gate used with claude-code-action.
	i := slices.Index(a, "reviewer:x")
	if i < 0 {
		t.Fatal("no image")
	}
	got := strings.Join(a[i+1:], " ")
	want := `-p --output-format json --model claude-opus-5-5 --tools Read,Grep,Glob --permission-mode dontAsk --setting-sources user --strict-mcp-config --max-turns 80 --json-schema {"type":"object"}`
	if got != want {
		t.Errorf("command\n got %s\nwant %s", got, want)
	}

	c.Command = []string{"node", "/probe/probe.mjs", "--x"}
	c.ExtraMounts = []Mount{{"/p.mjs", "/probe/probe.mjs"}}
	b := c.ReviewerArgs()
	probeFlags := slices.Clone(b[:slices.Index(b, "--entrypoint")])
	m := slices.Index(probeFlags, "type=bind,src=/p.mjs,dst=/probe/probe.mjs,readonly")
	probeFlags = slices.Delete(probeFlags, m-1, m+1)
	if !slices.Equal(a[:i], probeFlags) {
		t.Errorf("probe args differ from the review's beyond the command and its mount:\n%v\n%v", a, b)
	}
	if strings.Join(b[slices.Index(b, "--entrypoint"):], " ") != "--entrypoint node reviewer:x /probe/probe.mjs --x" {
		t.Errorf("probe command %v", b)
	}
}

func TestProxyArgs(t *testing.T) {
	c := testConfig(t)
	a := c.ProxyArgs()
	s := strings.Join(a, " ")
	for _, want := range []string{
		"--runtime runc", "--network dr-test-egress", "--read-only", "--cap-drop ALL", "--user 65532:65532",
		"--env ACTIONS_ID_TOKEN_REQUEST_URL --env ACTIONS_ID_TOKEN_REQUEST_TOKEN",
		"proxy --listen :8080 --model claude-opus-5-5 --federation-rule-id fdrl_1 --organization-id org --workspace-id wrkspc_1 --max-requests 150",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("proxy args lack %q", want)
		}
	}
	for _, e := range values(a, "--env") {
		if strings.Contains(e, "=") {
			t.Errorf("proxy env %q puts a value in argv", e)
		}
	}
	n := c.NetworkArgs()
	if !slices.Contains(n[0], "--internal") || !slices.Contains(n[0], "com.docker.network.bridge.inhibit_ipv4=true") || slices.Contains(n[1], "--internal") {
		t.Errorf("networks %v", n)
	}
}

func TestDefaults(t *testing.T) {
	c := testConfig(t)
	if c.ProxyAddr() != "10.213.7.2:8080" {
		t.Error(c.ProxyAddr())
	}
	c.Subnet = netip.MustParsePrefix("fd00::/64")
	if err := c.defaults(); err == nil {
		t.Error("accepted IPv6 subnet")
	}
	c = testConfig(t)
	c.Name = "a b"
	if err := c.defaults(); err == nil {
		t.Error("accepted a bad name")
	}
}

func TestDockerEnv(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "secret")
	t.Setenv("ACTIONS_RUNTIME_TOKEN", "secret2")
	t.Setenv("GITHUB_TOKEN", "secret3")
	for _, e := range dockerEnv(nil) {
		if strings.Contains(e, "secret") {
			t.Errorf("docker env has %s", e)
		}
	}
	got := dockerEnv([]string{"ACTIONS_ID_TOKEN_REQUEST_TOKEN"})
	if !slices.Contains(got, "ACTIONS_ID_TOKEN_REQUEST_TOKEN=secret") || slices.ContainsFunc(got, func(s string) bool { return strings.Contains(s, "secret2") || strings.Contains(s, "secret3") }) {
		t.Errorf("proxy docker env %v", got)
	}
}

const okResult = `{"type":"result","subtype":"success","is_error":false,"result":"done","num_turns":3,` +
	`"structured_output":{"verdict":"fail","flags":["network-access-added"],"summary":"adds a fetch"},"usage":{"input_tokens":1}}`

func TestReadVerdict(t *testing.T) {
	v, err := ReadVerdict(strings.NewReader(okResult + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if string(v) != `{"verdict":"fail","flags":["network-access-added"],"summary":"adds a fetch"}` {
		t.Errorf("verdict %s", v)
	}
	v, err = ReadVerdict(strings.NewReader(strings.Replace(okResult, `"flags":["network-access-added"]`, `"flags":[]`, 1)))
	if err != nil || !strings.Contains(string(v), `"flags":[]`) {
		t.Errorf("empty flags: %s %v", v, err)
	}
	bad := map[string]string{
		"empty":             "",
		"not json":          "Error: something",
		"two objects":       okResult + okResult,
		"trailing garbage":  okResult + " x",
		"error result":      strings.Replace(okResult, `"is_error":false`, `"is_error":true`, 1),
		"no is_error":       strings.Replace(okResult, `"is_error":false,`, ``, 1),
		"max turns":         strings.Replace(okResult, `"subtype":"success"`, `"subtype":"error_max_turns"`, 1),
		"not a result":      strings.Replace(okResult, `"type":"result"`, `"type":"assistant"`, 1),
		"no output":         `{"type":"result","subtype":"success","is_error":false,"result":"hello"}`,
		"null output":       `{"type":"result","subtype":"success","is_error":false,"structured_output":null}`,
		"bad verdict":       strings.Replace(okResult, `"verdict":"fail"`, `"verdict":"approve"`, 1),
		"unknown flag":      strings.Replace(okResult, `network-access-added`, `looks-fine`, 1),
		"extra field":       strings.Replace(okResult, `"summary":"adds a fetch"`, `"summary":"x","merge":true`, 1),
		"missing field":     strings.Replace(okResult, `,"summary":"adds a fetch"`, ``, 1),
		"summary too long":  strings.Replace(okResult, `adds a fetch`, strings.Repeat("é", 3001), 1),
		"output not object": strings.Replace(okResult, `{"verdict":"fail","flags":["network-access-added"],"summary":"adds a fetch"}`, `"pass"`, 1),
		"over the cap":      okResult + strings.Repeat(" ", MaxStdout),
	}
	for name, out := range bad {
		if v, err := ReadVerdict(strings.NewReader(out)); err == nil {
			t.Errorf("%s: accepted, verdict %s", name, v)
		}
	}
}

// ReadVerdict drains its input even past the cap, so the container
// writing to the pipe is never blocked on a reader that stopped.
func TestReadVerdictDrains(t *testing.T) {
	r := &countReader{r: strings.NewReader(strings.Repeat("x", 3*MaxStdout))}
	if _, err := ReadVerdict(r); err == nil {
		t.Fatal("accepted")
	}
	if r.n != 3*MaxStdout {
		t.Errorf("read %d of %d bytes", r.n, 3*MaxStdout)
	}
}

type countReader struct {
	r io.Reader
	n int
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestPrefixWriter(t *testing.T) {
	var b bytes.Buffer
	w := newPrefixWriter(&b, "reviewer| ", 100)
	io.WriteString(w, "::set-output name=x::y\n##[error]boom\x1b[31m\npart")
	io.WriteString(w, "ial\n")
	io.WriteString(w, strings.Repeat("z", 50)+"\nmore\nand more\n")
	w.Flush()
	want := "reviewer| ::set-output name=x::y\nreviewer| ##[error]boom [31m\nreviewer| partial\nreviewer| " + strings.Repeat("z", 50) + "\nreviewer| more\nreviewer| (output truncated)\n"
	if b.String() != want {
		t.Errorf("got\n%q\nwant\n%q", b.String(), want)
	}
	for _, l := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if !strings.HasPrefix(l, "reviewer| ") {
			t.Errorf("unprefixed line %q", l)
		}
	}
}

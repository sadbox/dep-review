package actions

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/policy"
)

// TestLiveSample runs the fetcher against the real Dependabot PRs in
// testdata/live_prs.json (or the file DEP_REVIEW_LIVE_PRS names, for PRs
// in private repositories). It needs the network and GITHUB_TOKEN (read
// access to the caller repositories) and is skipped with -short.
// DEP_REVIEW_LIVE_OUT=<dir> keeps the evidence for inspection.
func TestLiveSample(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		t.Skip("GITHUB_TOKEN not set")
	}
	var prs []struct {
		Repo, Base, Head, Want string
		PR                     int
	}
	file := "testdata/live_prs.json"
	if f := os.Getenv("DEP_REVIEW_LIVE_PRS"); f != "" {
		file = f
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &prs); err != nil {
		t.Fatal(err)
	}
	ghc := gh.New(token)
	scratch := t.TempDir()
	callerRoot := t.TempDir()
	callers := map[string]string{}
	f := New(Config{})
	var table []string
	for _, pr := range prs {
		t.Run(fmt.Sprintf("%s#%d", strings.ReplaceAll(pr.Repo, "/", "_"), pr.PR), func(t *testing.T) {
			dir, ok := callers[pr.Repo]
			if !ok {
				dir = filepath.Join(callerRoot, strings.ReplaceAll(pr.Repo, "/", "_"))
				cloneCaller(t, token, pr.Repo, dir)
				callers[pr.Repo] = dir
			}
			gitT(t, token, dir, "fetch", "-q", "origin", fmt.Sprintf("refs/pull/%d/head", pr.PR))
			ev := &memEvidence{}
			env := fetch.Env{
				Class: model.Classification{
					Repo: pr.Repo, PR: pr.PR, BaseSHA: pr.Base, HeadSHA: pr.Head,
					Kind: model.KindDependabot, Ecosystem: model.GitHubActions,
				},
				RepoDir: dir, Scratch: scratch, Evidence: ev, GitHub: ghc,
			}
			res, err := f.Fetch(context.Background(), env)
			if err != nil {
				t.Fatal(err)
			}
			route := policy.Combine(res.Updates, res.Findings, false)
			var ups, fds []string
			for _, u := range res.Updates {
				ups = append(ups, fmt.Sprintf("%s %s->%s (%s)", u.Name, u.From, u.To, u.Type))
			}
			for _, x := range res.Findings {
				if x.Route != model.RouteReview || x.Code != CodeRebuildNotRun {
					fds = append(fds, fmt.Sprintf("[%s] %s: %s", x.Route, x.Code, x.Detail))
				}
			}
			table = append(table, fmt.Sprintf("%s#%d => %s | %s", pr.Repo, pr.PR, route, strings.Join(ups, "; ")))
			t.Logf("route %s\nupdates:\n  %s\nfindings:\n  %s", route, strings.Join(ups, "\n  "), strings.Join(fds, "\n  "))
			if out := os.Getenv("DEP_REVIEW_LIVE_OUT"); out != "" {
				ev.dump(t, filepath.Join(out, strings.ReplaceAll(pr.Repo, "/", "_")+fmt.Sprint(pr.PR)))
			}
			if pr.Want != "" && string(route) != pr.Want {
				t.Errorf("route = %s, want %s", route, pr.Want)
			}
		})
	}
	t.Logf("summary:\n%s", strings.Join(table, "\n"))
}

func gitT(t *testing.T, token, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "core.hooksPath=/dev/null"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http.https://github.com/.extraheader",
		"GIT_CONFIG_VALUE_0=AUTHORIZATION: basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token)))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func cloneCaller(t *testing.T, token, repo, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A full (not blobless) clone: the fetcher reads it with credentials
	// disabled, as it reads the job's checkout.
	gitT(t, token, filepath.Dir(dir), "clone", "-q", "--no-checkout", "https://github.com/"+repo, dir)
}

// memEvidence is an in-memory fetch.Writer.
type memEvidence struct {
	mu    sync.Mutex
	files map[string]memFile
}

type memFile struct {
	desc      string
	untrusted bool
	content   []byte
}

func (m *memEvidence) put(name, desc string, b []byte, untrusted bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.files == nil {
		m.files = map[string]memFile{}
	}
	if _, dup := m.files[name]; dup {
		return fmt.Errorf("duplicate evidence file %s", name)
	}
	m.files[name] = memFile{desc, untrusted, append([]byte(nil), b...)}
	return nil
}

func (m *memEvidence) Add(name, desc string, b []byte) error { return m.put(name, desc, b, false) }
func (m *memEvidence) AddUntrusted(name, desc string, b []byte) error {
	return m.put(name, desc, b, true)
}

func (m *memEvidence) names() []string {
	var ns []string
	for n := range m.files {
		ns = append(ns, n)
	}
	sort.Strings(ns)
	return ns
}

func (m *memEvidence) dump(t *testing.T, dir string) {
	for _, n := range m.names() {
		p := filepath.Join(dir, n)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, m.files[n].content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

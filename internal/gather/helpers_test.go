package gather

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/config"
	"github.com/sadbox/dep-review/internal/facts"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/wire"
)

// The pull request every test is about.
const (
	testRepo   = "sadbox/linkclean"
	testNumber = 9
)

var (
	now = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	// created is the pull request's created_at in the fake API's answer.
	created = time.Date(2026, 11, 14, 8, 30, 0, 0, time.UTC)

	headSHA  = strings.Repeat("d", 40)
	baseSHA  = strings.Repeat("b", 40)
	mergeSHA = strings.Repeat("c", 40)

	// finger is the reviewer's fingerprint in the tests.
	finger = strings.Repeat("f", 64)
)

func defaults(t *testing.T) config.Config {
	t.Helper()
	c, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// listedName is a name on the embedded list for each ecosystem. Docker
// needs one: an image merges only when it is listed.
var listedName = map[string]string{
	allow.GoModules:     "golang.org/x/net",
	allow.NPM:           "tailwindcss",
	allow.GitHubActions: "actions/checkout",
	allow.Docker:        "docker.io/library/golang",
}

// goodUpdate is an update whose every fact holds, as a gatherer returns
// it: old enough to merge once it was read.
func goodUpdate(t *testing.T, eco, name string) allow.UpdateFacts {
	t.Helper()
	u := allow.UpdateFacts{
		Name: name, From: "1.2.3", To: "1.3.0",
		Known:       allow.Yes("a dependency at the base commit", "base manifest"),
		Listed:      allow.No("not on the list", "policy"),
		NewName:     allow.No("a dependency at the base commit", "base manifest"),
		Increase:    allow.Yes("1.2.3 to 1.3.0", "manifests"),
		Major:       allow.No("1 to 1", "manifests"),
		Bound:       allow.Yes("the pinned hash", "registry"),
		FirstSeen:   allow.At(now.Add(-100*time.Hour), "registry clock"),
		Clean:       allow.Yes("published, nothing against it", "registry"),
		NoRegress:   allow.Yes("nothing lost", "registry"),
		SecurityFix: allow.No("no advisory names 1.3.0", "advisories"),
	}
	if allow.Listed(defaults(t).Policy(), eco, name) {
		u.Listed = allow.Yes("on the list", "policy")
	}
	return u
}

// pairFor names the artifacts of u the way a gatherer does.
func pairFor(eco string, u allow.UpdateFacts) artifact.Pair {
	kind := map[string]artifact.Kind{
		allow.GoModules: artifact.GoModuleZip, allow.NPM: artifact.NPMTarball, allow.GitHubActions: artifact.ActionTarball,
	}[eco]
	return artifact.Pair{
		Ecosystem: eco, Name: u.Name, From: u.From, To: u.To,
		Old: artifact.Ref{Kind: kind, Name: u.Name, Version: u.From, Hash: "old"},
		New: artifact.Ref{Kind: kind, Name: u.Name, Version: u.To, Hash: "new"},
	}
}

// preparedRead is what a reader returns for p: one chunk for each text,
// a full read, and a key over all of it.
func preparedRead(p artifact.Pair, texts ...string) artifact.Prepared {
	out := artifact.Prepared{Pair: p, Unread: []artifact.Unread{}, State: allow.ReadFull}
	h := sha256.New()
	h.Write([]byte(p.Name + "\x00" + p.From + "\x00" + p.To))
	for i, text := range texts {
		out.Chunks = append(out.Chunks, artifact.Chunk{Index: i, Text: text})
		h.Write([]byte("\x00" + text))
	}
	out.Key = hex.EncodeToString(h.Sum(nil))
	return out
}

// fakeGatherer returns a fixed result and records what it was given.
type fakeGatherer struct {
	res    facts.Result
	err    error
	inputs []facts.Input
	// applies makes it hand Input.ScriptsOff back in its result, as the
	// npm gatherer does for a pull request whose lock the fact covers.
	applies bool
}

func (g *fakeGatherer) Gather(_ context.Context, in facts.Input) (facts.Result, error) {
	g.inputs = append(g.inputs, in)
	res := g.res
	if g.applies {
		res.ScriptsOff = in.ScriptsOff
	}
	return res, g.err
}

// fakePreparer answers by the pair's name and records every call. A name
// without an answer gets a one-chunk full read.
type fakePreparer struct {
	answers map[string]func(artifact.Pair) (artifact.Prepared, error)
	pairs   []artifact.Pair
	limits  []artifact.Limits
}

func (p *fakePreparer) Prepare(_ context.Context, pair artifact.Pair, lim artifact.Limits) (artifact.Prepared, error) {
	p.pairs = append(p.pairs, pair)
	p.limits = append(p.limits, lim)
	if answer := p.answers[pair.Name]; answer != nil {
		return answer(pair)
	}
	return preparedRead(pair, "== file: a.go (changed)\n@@ -1 +1 @@\n-old\n+new "+pair.Name+"\n"), nil
}

// The fake API's good answers. rulesBody keeps the shape of a real
// rules/branches answer (recorded from a public repository, 2026-11-23):
// rules without parameters next to the one that matters.
const (
	pullBody  = `{"number":9,"state":"open","created_at":"2026-11-14T08:30:00Z","base":{"ref":"main","repo":{"full_name":"sadbox/linkclean","default_branch":"main"}}}`
	rulesBody = `[{"type":"deletion","ruleset_source_type":"Repository","ruleset_source":"sadbox/linkclean","ruleset_id":1},` +
		`{"type":"pull_request","parameters":{"required_approving_review_count":0,"allowed_merge_methods":["squash"]},"ruleset_source_type":"Repository","ruleset_source":"sadbox/linkclean","ruleset_id":1},` +
		`{"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":false,"do_not_enforce_on_create":false,"required_status_checks":[{"context":"lint / lint"},{"context":"test"}]},"ruleset_source_type":"Repository","ruleset_source":"sadbox/linkclean","ruleset_id":1}]`
)

// fakeGitHub serves the two answers the fetch job asks GitHub for.
type fakeGitHub struct {
	pullStatus, rulesStatus int
	pull, rules             string
	// rulesPath is the path the rules are served at.
	rulesPath string

	mu   sync.Mutex
	hits []string
}

func newFakeGitHub() *fakeGitHub {
	return &fakeGitHub{
		pullStatus: http.StatusOK, pull: pullBody,
		rulesStatus: http.StatusOK, rules: rulesBody,
		rulesPath: "/repos/sadbox/linkclean/rules/branches/main",
	}
}

func (g *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	g.hits = append(g.hits, r.URL.Path)
	g.mu.Unlock()
	switch {
	case r.Method != http.MethodGet:
		w.WriteHeader(http.StatusMethodNotAllowed)
	case r.URL.Path == "/repos/sadbox/linkclean/pulls/9":
		w.WriteHeader(g.pullStatus)
		w.Write([]byte(g.pull))
	case r.URL.Path == g.rulesPath:
		w.WriteHeader(g.rulesStatus)
		w.Write([]byte(g.rules))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (g *fakeGitHub) asked() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.hits)
}

// client returns a GitHub client that asks the fake, once and without
// waiting.
func (g *fakeGitHub) client(t *testing.T) *gh.Client {
	t.Helper()
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	c := gh.New("read-only-token")
	c.BaseURL = srv.URL + "/"
	c.MaxRetries = 0
	return c
}

// job is one fetch job with its fakes.
type job struct {
	fetch    Fetch
	gatherer *fakeGatherer
	preparer *fakePreparer
	api      *fakeGitHub
}

// newJob is a fetch job for a verified Dependabot pull request in eco
// (Dependabot's name) that moves the given updates, each with an artifact
// unless the ecosystem is Docker.
func newJob(t *testing.T, eco model.Ecosystem, updates ...allow.UpdateFacts) *job {
	t.Helper()
	name, _ := ecosystem(eco)
	j := &job{
		gatherer: &fakeGatherer{res: facts.Result{Shape: allow.Yes("manifest and lock, versions only", "manifests"), Updates: updates}},
		preparer: &fakePreparer{answers: map[string]func(artifact.Pair) (artifact.Prepared, error){}},
		api:      newFakeGitHub(),
	}
	if name != allow.Docker {
		for _, u := range updates {
			j.gatherer.res.Artifacts = append(j.gatherer.res.Artifacts, pairFor(name, u))
		}
	}
	if name == allow.NPM {
		// As the npm gatherer returns it: what it knows of NoRegress
		// beside the update, and nothing in it.
		j.gatherer.res.Updates = slices.Clone(updates)
		for i, u := range updates {
			j.gatherer.res.NoRegressSoFar = append(j.gatherer.res.NoRegressSoFar, u.NoRegress)
			j.gatherer.res.Updates[i].NoRegress = allow.Fact{}
		}
	}
	j.fetch = Fetch{
		Class: model.Classification{
			Repo: testRepo, PR: testNumber, HeadSHA: headSHA, BaseSHA: baseSHA,
			Kind: model.KindDependabot, Reason: "authored, committed and signed by Dependabot only", Ecosystem: eco,
		},
		Changes:   Changes{Base: mergeSHA, Head: headSHA, Files: []facts.File{{Path: "go.mod", BaseMode: "100644", HeadMode: "100644", Base: []byte("a\n"), Head: []byte("b\n")}}},
		Config:    defaults(t),
		HTTP:      &http.Client{},
		GitHub:    j.api.client(t),
		Gatherers: map[string]facts.Gatherer{name: j.gatherer},
		Preparer:  j.preparer,
		Now:       func() time.Time { return now },
		Logf:      t.Logf,
	}
	return j
}

// run runs the job into a new directory and returns the directory and
// the facts as the next job reads them: decoded strictly, with the chunk
// directory verified.
func (j *job) run(t *testing.T) (string, wire.Facts) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "facts")
	if _, err := j.fetch.Run(context.Background(), dir); err != nil {
		t.Fatalf("Run: %v", err)
	}
	return dir, readBack(t, dir)
}

func readBack(t *testing.T, dir string) wire.Facts {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, wire.FactsFile))
	if err != nil {
		t.Fatal(err)
	}
	f, err := wire.DecodeFacts(b)
	if err != nil {
		t.Fatalf("the facts file does not decode: %v", err)
	}
	if err := wire.VerifyChunks(filepath.Join(dir, wire.ChunksDir), f); err != nil {
		t.Fatalf("the chunk directory does not verify: %v", err)
	}
	return f
}

// cleanVerdicts is a full, no-veto verdict for every read f has prepared.
func cleanVerdicts(f wire.Facts) []wire.Verdict {
	var out []wire.Verdict
	seen := map[string]bool{}
	for _, u := range f.Facts.Updates {
		if u.Prepared.Status == wire.Prepared && !seen[u.Prepared.Key] {
			seen[u.Prepared.Key] = true
			out = append(out, wire.Verdict{Key: u.Prepared.Key, Fingerprint: finger, Read: allow.ReadFull})
		}
	}
	return out
}

// decide is what publish does with the two files.
func decide(t *testing.T, f wire.Facts, verdicts []wire.Verdict) allow.Decision {
	t.Helper()
	return allow.Decide(wire.Join(f, wire.Verdicts{Version: wire.Version, Verdicts: verdicts}, finger), defaults(t).Policy(), now)
}

// wantOutcome checks a decision's outcome and, when reason is not empty,
// that it is among the reasons.
func wantOutcome(t *testing.T, d allow.Decision, outcome allow.Outcome, reason allow.Reason) {
	t.Helper()
	if d.Outcome != outcome || (reason != "" && !slices.Contains(d.Reasons, reason)) {
		t.Errorf("decision %s %v, want %s with %q", d.Outcome, d.Reasons, outcome, reason)
	}
}

// chunkFiles lists the chunk directory.
func chunkFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, wire.ChunksDir))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

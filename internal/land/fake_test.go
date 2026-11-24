package land

import (
	"context"

	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/config"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/veto"
	"github.com/sadbox/dep-review/internal/wire"
)

const (
	testRepo = "o/r"
	testBot  = "gate[bot]"
	testPR   = 7
)

var (
	t0    = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	headA = strings.Repeat("a", 40)
	headB = strings.Repeat("b", 40)
	keyA  = strings.Repeat("1", 64)
	keyB  = strings.Repeat("2", 64)
)

// defaults is the gate's configuration, and reviewer its reviewer
// fingerprint.
func defaults(t *testing.T) (conf config.Config, reviewer string) {
	t.Helper()
	conf, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	return conf, veto.FromConfig(conf).Fingerprint()
}

// call is one request the fake saw.
type call struct {
	method, path, body string
}

// fakeComment is an issue comment in the fake.
type fakeComment struct {
	id     int64
	author string
	body   string
}

// fakeGitHub answers the handful of endpoints the package uses and records
// every request. The zero value plus newFake's defaults is a repository
// where everything is in order: an open Dependabot pull request at headA
// on main, one required check, and a merge that works.
type fakeGitHub struct {
	t   *testing.T
	mu  sync.Mutex
	srv *httptest.Server

	// pulls are the successive answers to GET pulls/7; the last repeats.
	// pullNumber, when set, is the pull request they are for instead.
	pulls      []string
	pullNumber int
	// open is the answer to the list of open pull requests.
	open string
	// rules is the answer to rules/branches/main, with its status.
	rules     string
	rulesCode int
	// prFiles and compare answer the two reads before a merge, each with
	// its status: the pull request's file list, and the comparison of a
	// commit with main.
	prFiles     string
	prFilesCode int
	compare     string
	compareCode int
	// tree and treeCode answer the read of main's root tree. Without a
	// treeCode the read is a request the fake does not know.
	tree     string
	treeCode int
	// mergeCode and mergeBody answer the merge call. mergedAfter makes
	// the pull request read as merged from then on.
	mergeCode   int
	mergeBody   string
	mergedAfter bool

	// commentsCode, when set, is the status a read of the comments gets,
	// once commentsFirst reads were answered as usual.
	commentsCode  int
	commentsFirst int
	// lenient: a request the fake does not know is answered 404 without
	// failing the test.
	lenient bool
	// statusReadCode, when set, is the status a read of a commit's
	// combined status gets. otherContexts is how many contexts besides
	// dep-review the commit has, the first without a description; GitHub
	// lists them before it, 100 at most.
	statusReadCode int
	otherContexts  int

	comments map[int][]*fakeComment
	nextID   int64
	calls    []call
}

// pullJSON is a pull request as the API returns it, last changed two
// days before t0.
func pullJSON(number int, state, head, base, mergeable string, merged bool) string {
	return fmt.Sprintf(`{"number":%d,"state":%q,"merged":%t,"mergeable_state":%q,"updated_at":%q,
		"user":{"login":"dependabot[bot]"},
		"head":{"sha":%q,"repo":{"full_name":"o/r"}},
		"base":{"ref":%q,"repo":{"full_name":"o/r","default_branch":"main"}}}`,
		number, state, merged, mergeable, quietSince.Format(time.RFC3339), head, base)
}

// quietSince is when the pull requests of the fake last changed.
var quietSince = t0.Add(-48 * time.Hour)

const oneRequiredCheck = `[{"type":"deletion","ruleset_id":1},
	{"type":"pull_request","parameters":{"required_approving_review_count":0,"allowed_merge_methods":["squash"]}},
	{"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":false,
		"required_status_checks":[{"context":"test"},{"context":"dep-review"}]}}]`

func newFake(t *testing.T) *fakeGitHub {
	t.Helper()
	f := &fakeGitHub{
		t:         t,
		pulls:     []string{pullJSON(testPR, "open", headA, "main", "clean", false)},
		open:      "[]",
		rules:     oneRequiredCheck,
		rulesCode: 200,
		// The pull request changes go.mod and go.sum, and main has nothing
		// its head lacks.
		prFiles:     `[{"filename":"go.mod","status":"modified"},{"filename":"go.sum","status":"modified"}]`,
		prFilesCode: 200,
		compare:     `{"status":"identical","ahead_by":0,"behind_by":0,"total_commits":0,"commits":[],"files":[]}`,
		compareCode: 200,
		mergeCode:   200,
		mergeBody:   `{"merged":true}`,
		comments:    map[int][]*fakeComment{},
		nextID:      100,
	}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

// config is a Config that talks to the fake, with a clock and a recording
// notifier.
func (f *fakeGitHub) config(now time.Time, n Notifier) Config {
	c := gh.New("token")
	c.BaseURL = f.srv.URL + "/"
	c.MaxRetries = 0
	return Config{GitHub: c, Repo: testRepo, BotLogin: testBot, Notifier: n, Now: func() time.Time { return now }}
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{r.Method, r.URL.Path, string(body)})
	if r.Header.Get("Authorization") != "Bearer token" {
		f.t.Errorf("%s %s: no token", r.Method, r.URL.Path)
	}

	answer := func(code int, body string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		io.WriteString(w, body)
	}
	unknown := func() {
		if !f.lenient {
			f.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		answer(404, `{"message":"Not Found"}`)
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/repos/o/r/")
	if !ok {
		unknown()
		return
	}
	number := testPR
	if f.pullNumber != 0 {
		number = f.pullNumber
	}
	switch route := r.Method + " " + rest; {
	case route == fmt.Sprintf("GET pulls/%d", number):
		cur := f.pulls[0]
		if len(f.pulls) > 1 {
			f.pulls = f.pulls[1:]
		}
		answer(200, cur)
	case route == "GET pulls":
		if r.URL.Query().Get("state") != "open" {
			f.t.Errorf("pull request list without state=open: %s", r.URL.RawQuery)
		}
		answer(200, f.open)
	case route == "GET rules/branches/main":
		answer(f.rulesCode, f.rules)
	case route == fmt.Sprintf("GET pulls/%d/files", testPR):
		answer(f.prFilesCode, f.prFiles)
	case r.Method == "GET" && strings.HasPrefix(rest, "compare/") && strings.HasSuffix(rest, "...main") &&
		gh.ValidSHA(strings.TrimSuffix(strings.TrimPrefix(rest, "compare/"), "...main")):
		answer(f.compareCode, f.compare)
	case route == "GET git/trees/main" && f.treeCode != 0:
		if r.URL.RawQuery != "" {
			f.t.Errorf("the tree was asked for with %q", r.URL.RawQuery)
		}
		answer(f.treeCode, f.tree)
	case r.Method == "GET" && strings.HasPrefix(rest, "issues/") && strings.HasSuffix(rest, "/comments"):
		if f.commentsCode != 0 && f.commentsFirst == 0 {
			answer(f.commentsCode, `{"message":"Server Error"}`)
			return
		}
		if f.commentsFirst > 0 {
			f.commentsFirst--
		}
		n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(rest, "issues/"), "/comments"))
		type user struct {
			Login string `json:"login"`
		}
		type item struct {
			ID   int64  `json:"id"`
			Body string `json:"body"`
			User user   `json:"user"`
		}
		list := []item{}
		for _, c := range f.comments[n] {
			list = append(list, item{c.id, c.body, user{c.author}})
		}
		b, _ := json.Marshal(list)
		answer(200, string(b))
	case r.Method == "POST" && strings.HasPrefix(rest, "issues/") && strings.HasSuffix(rest, "/comments"):
		n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(rest, "issues/"), "/comments"))
		f.nextID++
		f.comments[n] = append(f.comments[n], &fakeComment{f.nextID, testBot, bodyOf(f.t, body)})
		answer(201, `{}`)
	case r.Method == "PATCH" && strings.HasPrefix(rest, "issues/comments/"):
		id, _ := strconv.ParseInt(strings.TrimPrefix(rest, "issues/comments/"), 10, 64)
		for _, list := range f.comments {
			for _, c := range list {
				if c.id == id {
					if c.author != testBot {
						f.t.Errorf("the gate edited a comment by %s", c.author)
					}
					c.body = bodyOf(f.t, body)
					answer(200, `{}`)
					return
				}
			}
		}
		f.t.Errorf("PATCH of unknown comment %d", id)
		answer(404, `{"message":"Not Found"}`)
	case r.Method == "POST" && strings.HasPrefix(rest, "statuses/"):
		answer(201, `{}`)
	case r.Method == "GET" && strings.HasPrefix(rest, "commits/") && strings.HasSuffix(rest, "/status"):
		if r.URL.Query().Get("per_page") != "100" {
			f.t.Errorf("combined status without per_page=100: %s", r.URL.RawQuery)
		}
		if f.statusReadCode != 0 {
			answer(f.statusReadCode, `{"message":"Server Error"}`)
			return
		}
		answer(200, f.combined(strings.TrimSuffix(strings.TrimPrefix(rest, "commits/"), "/status")))
	case route == fmt.Sprintf("PUT pulls/%d/merge", testPR):
		if f.mergedAfter {
			f.pulls = []string{pullJSON(testPR, "closed", headA, "main", "unknown", true)}
		}
		answer(f.mergeCode, f.mergeBody)
	default:
		unknown()
	}
}

// overwrite replaces one of the two files with other content.
func overwrite(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func bodyOf(t *testing.T, raw []byte) string {
	t.Helper()
	var in struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Errorf("comment body: %v", err)
	}
	return in.Body
}

// writes are the requests that changed something.
func (f *fakeGitHub) writes() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []call
	for _, c := range f.calls {
		if c.method != "GET" {
			out = append(out, c)
		}
	}
	return out
}

// count is how many requests of one method had a path with the suffix.
func (f *fakeGitHub) count(method, suffix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c.method == method && strings.HasSuffix(c.path, suffix) {
			n++
		}
	}
	return n
}

// statuses are the dep-review statuses set on a commit, in order, as
// "state: description".
func (f *fakeGitHub) statuses(sha string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if c.method != "POST" || c.path != "/repos/o/r/statuses/"+sha {
			continue
		}
		var s struct{ State, Context, Description string }
		if err := json.Unmarshal([]byte(c.body), &s); err != nil || s.Context != "dep-review" {
			f.t.Errorf("status %s: %v", c.body, err)
		}
		if len(s.Description) > 140 {
			f.t.Errorf("status description of %d characters: GitHub takes 140", len(s.Description))
		}
		out = append(out, s.State+": "+s.Description)
	}
	return out
}

// combined is GitHub's combined status of sha: the latest status of each
// context, the gate's from the statuses it set. f.mu is held.
func (f *fakeGitHub) combined(sha string) string {
	type status struct {
		Context     string `json:"context"`
		State       string `json:"state"`
		Description any    `json:"description"`
	}
	list := []status{}
	for i := range f.otherContexts {
		// GitHub answers null for a status set without a description.
		list = append(list, status{fmt.Sprintf("ci/%d", i), "success", map[bool]any{true: nil, false: "ok"}[i == 0]})
	}
	var gate *status
	for _, c := range f.calls {
		if c.method == "POST" && c.path == "/repos/o/r/statuses/"+sha {
			var s status
			json.Unmarshal([]byte(c.body), &s)
			gate = &s
		}
	}
	total := len(list)
	if gate != nil {
		list, total = append(list, *gate), total+1
	}
	b, _ := json.Marshal(map[string]any{"state": "pending", "sha": sha, "total_count": total, "statuses": list[:min(len(list), 100)]})
	return string(b)
}

// gateComment is the one comment the gate app has on the pull request.
func (f *fakeGitHub) gateComment(n int) string {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	var found []string
	for _, c := range f.comments[n] {
		if c.author == testBot {
			found = append(found, c.body)
		}
	}
	if len(found) != 1 {
		f.t.Fatalf("the gate has %d comments on #%d, want 1", len(found), n)
	}
	return found[0]
}

// recorder is a Notifier that remembers what it was told.
type recorder struct {
	got []Message
	err error
}

func (r *recorder) Notify(_ context.Context, m Message) error {
	if r.err != nil {
		return r.err
	}
	r.got = append(r.got, m)
	return nil
}

// goodUpdate is a Go update whose every fact holds, first seen 100 hours
// before t0: old enough for a full read under the defaults.
func goodUpdate(name string) allow.UpdateFacts {
	return allow.UpdateFacts{
		Name: name, From: "v1.2.3", To: "v1.3.0",
		Known:       allow.Yes("in go.mod at the base commit", "base go.mod"),
		Listed:      allow.No("matches no list entry", "policy"),
		NewName:     allow.No("in go.mod at the base commit", "base go.mod"),
		Increase:    allow.Yes("v1.2.3 to v1.3.0", "x/mod/semver"),
		Major:       allow.No("v1 to v1", "x/mod/semver"),
		Bound:       allow.Yes("h1:abc", "go mod download"),
		FirstSeen:   allow.At(t0.Add(-100*time.Hour), "index.golang.org"),
		Clean:       allow.Yes("published, nothing new against it", "advisories"),
		NoRegress:   allow.Yes("nothing to lose", "gate"),
		SecurityFix: allow.No("no advisory names v1.3.0", "advisories"),
	}
}

// preparedRead is a read fetch prepared in full: one chunk, nothing
// unread.
func preparedRead(update int, key string) wire.Read {
	return wire.Read{
		Status: wire.Prepared, Key: key, State: allow.ReadFull,
		Unread: []artifact.Unread{},
		Chunks: []wire.ChunkFile{wire.NewChunkFile(update, 0, "== file: a.go (changed)\n+new\n")},
	}
}

// goodFacts is a facts file for a Go pull request with one update, read
// under keyA.
func goodFacts(t *testing.T) wire.Facts {
	t.Helper()
	return wire.Facts{
		Version:     wire.Version,
		PullRequest: wire.PullRequest{Repo: testRepo, Number: testPR, Head: headA},
		GatheredAt:  t0.Add(-time.Minute),
		Facts: wire.PRFacts{
			Ecosystem: allow.GoModules,
			Identity:  allow.Yes("dependabot[bot] alone", "classify"),
			Shape:     allow.Yes("go.mod and go.sum, versions only", "x/mod/modfile"),
			Opened:    t0.Add(-time.Hour),
			Updates:   []wire.Update{wire.NewUpdate(goodUpdate("example.com/m"), preparedRead(0, keyA))},
		},
	}
}

// clean is the verdicts file of a complete read of keyA with no veto.
func clean(t *testing.T) *wire.Verdicts {
	t.Helper()
	_, reviewer := defaults(t)
	return &wire.Verdicts{Version: wire.Version, Verdicts: []wire.Verdict{{Key: keyA, Fingerprint: reviewer, Read: allow.ReadFull}}}
}

// files writes the two files into a new directory, as the earlier jobs
// do. A nil verdicts is a review job that produced no file.
func files(t *testing.T, f wire.Facts, v *wire.Verdicts) string {
	t.Helper()
	dir := t.TempDir()
	b, err := wire.EncodeFacts(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, wire.FactsFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if v != nil {
		if b, err = wire.EncodeVerdicts(*v); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, wire.VerdictsFile), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// publish is the publish job: Decide, then Act.
func publish(t *testing.T, cfg Config, dir string) (Result, error) {
	t.Helper()
	ev, err := Decide(context.Background(), cfg, filepath.Join(dir, wire.FactsFile), filepath.Join(dir, wire.VerdictsFile))
	if err != nil {
		return Result{}, err
	}
	return Act(context.Background(), cfg, ev)
}

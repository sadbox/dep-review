package publish

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
)

const bot = "dep-review-gate[bot]"

type fakeComment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
	User struct {
		Login string `json:"login"`
	} `json:"user"`
}

// fakeGH is a small stateful GitHub for one repository o/r.
type fakeGH struct {
	t  *testing.T
	mu sync.Mutex

	prs        map[int]map[string]any // GET pulls/{n}
	comments   map[int][]*fakeComment
	nextID     int64
	statuses   map[string][]map[string]any // POSTed, newest first
	checkRuns  []map[string]any            // served for every head; replaced by ciSeq when set
	ciSeq      [][]map[string]any          // successive check-runs responses
	ciCalls    int
	combined   []map[string]any
	mergeCode  int
	merges     []map[string]string
	commitDate time.Time
	patches    int
}

func newFake(t *testing.T) *fakeGH {
	return &fakeGH{
		t:         t,
		prs:       map[int]map[string]any{7: openPR(7, headSHA, "dependabot[bot]")},
		comments:  map[int][]*fakeComment{},
		nextID:    100,
		statuses:  map[string][]map[string]any{},
		checkRuns: []map[string]any{{"name": "test", "status": "completed", "conclusion": "success"}},
		mergeCode: 200,
	}
}

func openPR(n int, head, user string) map[string]any {
	return map[string]any{
		"number": n, "state": "open", "merged": false, "user": map[string]any{"login": user},
		"head": map[string]any{"sha": head, "repo": map[string]any{"full_name": "o/r"}},
	}
}

func (f *fakeGH) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/repos/o/r/")
	parts := strings.Split(p, "/")
	js := func(v any) { json.NewEncoder(w).Encode(v) }
	var body map[string]string
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &body)
	}
	switch {
	case r.Method == "GET" && p == "pulls" && r.URL.Query().Get("state") == "open":
		var list []map[string]any
		for _, pr := range f.prs {
			if pr["state"] == "open" {
				list = append(list, pr)
			}
		}
		js(list)
	case r.Method == "GET" && len(parts) == 2 && parts[0] == "pulls":
		n, _ := strconv.Atoi(parts[1])
		js(f.prs[n])
	case r.Method == "PUT" && len(parts) == 3 && parts[2] == "merge":
		n, _ := strconv.Atoi(parts[1])
		f.merges = append(f.merges, body)
		if f.mergeCode != 200 {
			w.WriteHeader(f.mergeCode)
			js(map[string]string{"message": "nope"})
			return
		}
		f.prs[n]["state"], f.prs[n]["merged"] = "closed", true
		js(map[string]any{"merged": true})
	case len(parts) == 3 && parts[0] == "issues" && parts[2] == "comments":
		n, _ := strconv.Atoi(parts[1])
		if r.Method == "POST" {
			c := &fakeComment{ID: f.nextID, Body: body["body"]}
			c.User.Login = bot
			f.nextID++
			f.comments[n] = append(f.comments[n], c)
			js(c)
			return
		}
		js(f.comments[n])
	case r.Method == "PATCH" && len(parts) == 3 && parts[0] == "issues" && parts[1] == "comments":
		id, _ := strconv.ParseInt(parts[2], 10, 64)
		f.patches++
		for _, cs := range f.comments {
			for _, c := range cs {
				if c.ID == id {
					c.Body = body["body"]
					js(c)
					return
				}
			}
		}
		w.WriteHeader(404)
	case r.Method == "POST" && len(parts) == 2 && parts[0] == "statuses":
		s := map[string]any{"context": body["context"], "state": body["state"], "description": body["description"], "creator": map[string]any{"login": bot}}
		f.statuses[parts[1]] = append([]map[string]any{s}, f.statuses[parts[1]]...)
		w.WriteHeader(201)
		js(s)
	case r.Method == "GET" && len(parts) == 3 && parts[0] == "commits" && parts[2] == "statuses":
		js(f.statuses[parts[1]])
	case r.Method == "GET" && len(parts) == 3 && parts[0] == "commits" && parts[2] == "status":
		all := append([]map[string]any{}, f.combined...)
		for _, s := range f.statuses[parts[1]] {
			all = append(all, s)
			break
		}
		js(map[string]any{"statuses": all})
	case r.Method == "GET" && len(parts) == 3 && parts[0] == "commits" && parts[2] == "check-runs":
		runs := f.checkRuns
		if len(f.ciSeq) > 0 {
			i := min(f.ciCalls, len(f.ciSeq)-1)
			runs = f.ciSeq[i]
		}
		f.ciCalls++
		js(map[string]any{"total_count": len(runs), "check_runs": runs})
	case r.Method == "GET" && len(parts) == 2 && parts[0] == "commits":
		js(map[string]any{"commit": map[string]any{"committer": map[string]any{"date": f.commitDate.Format(time.RFC3339)}}})
	default:
		f.t.Errorf("unexpected %s %s", r.Method, r.URL)
		w.WriteHeader(404)
	}
}

type recNotifier struct {
	mu   sync.Mutex
	msgs []Message
	err  error
}

func (n *recNotifier) Notify(_ context.Context, m Message) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.err != nil {
		return n.err
	}
	n.msgs = append(n.msgs, m)
	return nil
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) Sleep(_ context.Context, d time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	return nil
}

func setup(t *testing.T, f *fakeGH) (Config, *recNotifier, *clock) {
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	c := gh.New("tok")
	c.BaseURL = srv.URL + "/"
	c.HTTP = srv.Client()
	n := &recNotifier{}
	ck := &clock{now: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
	return Config{GitHub: c, BotLogin: bot, Notifier: n, ServerURL: "https://github.com", Now: ck.Now, Sleep: ck.Sleep, Logf: t.Logf}, n, ck
}

var passVerdict = []byte(`{"verdict":"pass","flags":[],"summary":"ok"}`)

func reviewInputs() Inputs {
	return Inputs{Class: class(), Evidence: evidence(model.RouteReview, patch), FetchResult: "success", ReviewResult: "success", Verdict: passVerdict}
}

func TestPublish(t *testing.T) {
	inProgress := []map[string]any{{"name": "test", "status": "in_progress"}}
	green := []map[string]any{{"name": "test", "status": "completed", "conclusion": "success"}, {"name": "lint", "status": "completed", "conclusion": "skipped"}}
	red := []map[string]any{{"name": "test", "status": "completed", "conclusion": "failure"}}
	tests := []struct {
		name       string
		in         Inputs
		setup      func(f *fakeGH)
		wantMerge  bool
		wantStatus string
		notified   int
		comment    string
	}{
		{"approved and merged", reviewInputs(), nil, true, StateSuccess, 0, "approved"},
		{"waits for CI then merges", reviewInputs(), func(f *fakeGH) { f.ciSeq = [][]map[string]any{inProgress, inProgress, green} }, true, StateSuccess, 0, "approved"},
		{"CI never finishes", reviewInputs(), func(f *fakeGH) { f.ciSeq = [][]map[string]any{inProgress} }, false, StateSuccess, 0, "approved"},
		{"pending commit status blocks", reviewInputs(), func(f *fakeGH) {
			f.combined = []map[string]any{{"context": "ci/other", "state": "pending"}}
		}, false, StateSuccess, 0, "approved"},
		{"red CI notifies", reviewInputs(), func(f *fakeGH) { f.checkRuns = red }, false, StateSuccess, 1, "CI failed"},
		{"failed commit status notifies", reviewInputs(), func(f *fakeGH) {
			f.combined = []map[string]any{{"context": "ci/other", "state": "failure"}}
		}, false, StateSuccess, 1, "CI failed"},
		{"not mergeable", reviewInputs(), func(f *fakeGH) { f.mergeCode = 405 }, false, StateSuccess, 1, "refused the merge"},
		{"head moved at merge", reviewInputs(), func(f *fakeGH) { f.mergeCode = 409 }, false, StateSuccess, 1, "head moved"},
		{"human", Inputs{Class: class(), Evidence: evidence(model.RouteHuman, major), FetchResult: "success"}, nil, false, StateFailure, 1, "needs a person"},
		{"pending infra", Inputs{Class: class(), FetchResult: "failure"}, nil, false, StateError, 0, "no decision"},
		{"already notified for this head", Inputs{Class: class(), Evidence: evidence(model.RouteHuman, major), FetchResult: "success"}, func(f *fakeGH) {
			c := &fakeComment{ID: 5, Body: marker{Notified: []string{headSHA}}.String() + "\nold"}
			c.User.Login = bot
			f.comments[7] = []*fakeComment{c}
		}, false, StateFailure, 0, "needs a person"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			if tt.setup != nil {
				tt.setup(f)
			}
			cfg, n, _ := setup(t, f)
			if err := Publish(context.Background(), cfg, tt.in); err != nil {
				t.Fatal(err)
			}
			if got := len(f.merges) > 0 && f.mergeCode == 200; got != tt.wantMerge {
				t.Errorf("merged = %v, want %v", got, tt.wantMerge)
			}
			for _, m := range f.merges {
				if m["sha"] != headSHA || m["merge_method"] != "squash" {
					t.Errorf("merge body %v", m)
				}
			}
			st := f.statuses[headSHA]
			if len(st) == 0 || st[0]["state"] != tt.wantStatus || st[0]["context"] != "dep-review" {
				t.Errorf("statuses = %v, want %s", st, tt.wantStatus)
			}
			if len(n.msgs) != tt.notified {
				t.Errorf("notifications = %v, want %d", n.msgs, tt.notified)
			}
			cs := f.comments[7]
			if len(cs) != 1 {
				t.Fatalf("comments = %d, want exactly 1", len(cs))
			}
			if !strings.Contains(cs[0].Body, tt.comment) {
				t.Errorf("comment lacks %q:\n%s", tt.comment, cs[0].Body)
			}
			if tt.notified > 0 {
				if m, _ := parseMarker(cs[0].Body); !has(m.Notified, headSHA) {
					t.Errorf("notification not recorded in marker")
				}
				msg := n.msgs[0]
				if !strings.HasPrefix(msg.Body, "o/r#7 ") || msg.URL != "https://github.com/o/r/pull/7" {
					t.Errorf("message %+v", msg)
				}
			}
		})
	}
}

func TestPublishStale(t *testing.T) {
	for name, mutate := range map[string]func(f *fakeGH){
		"head moved": func(f *fakeGH) { f.prs[7]["head"].(map[string]any)["sha"] = baseSHA },
		"closed":     func(f *fakeGH) { f.prs[7]["state"] = "closed" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			mutate(f)
			cfg, n, _ := setup(t, f)
			if err := Publish(context.Background(), cfg, reviewInputs()); err != nil {
				t.Fatal(err)
			}
			if len(f.merges) != 0 || len(f.statuses) != 0 || len(f.comments[7]) != 0 || len(n.msgs) != 0 {
				t.Error("stale publish acted")
			}
		})
	}
}

func TestPublishUpdatesOwnCommentOnly(t *testing.T) {
	f := newFake(t)
	impostor := &fakeComment{ID: 1, Body: marker{}.String() + "\nfake approval"}
	impostor.User.Login = "mallory"
	ours := &fakeComment{ID: 2, Body: marker{}.String() + "\nold"}
	ours.User.Login = bot
	f.comments[7] = []*fakeComment{impostor, ours}
	cfg, _, _ := setup(t, f)
	if err := Publish(context.Background(), cfg, Inputs{Class: class(), FetchResult: "failure"}); err != nil {
		t.Fatal(err)
	}
	if len(f.comments[7]) != 2 || impostor.Body != (marker{}).String()+"\nfake approval" || !strings.Contains(ours.Body, "no decision") {
		t.Errorf("comments: %q / %q", impostor.Body, ours.Body)
	}
}

func TestPublishIgnores(t *testing.T) {
	f := newFake(t)
	cfg, _, _ := setup(t, f)
	if err := Publish(context.Background(), cfg, Inputs{Class: model.Classification{Kind: model.KindOther}}); err != nil {
		t.Fatal(err)
	}
}

func TestSweep(t *testing.T) {
	other := "3333333333333333333333333333333333333333"
	tests := []struct {
		name      string
		setup     func(f *fakeGH)
		age       time.Duration
		wantMerge bool
		notified  int
		comment   string
	}{
		{"approved and green", func(f *fakeGH) {
			f.statuses[headSHA] = []map[string]any{{"context": "dep-review", "state": "success", "creator": map[string]any{"login": bot}}}
		}, time.Hour, true, 0, ""},
		{"success from someone else is ignored", func(f *fakeGH) {
			f.statuses[headSHA] = []map[string]any{{"context": "dep-review", "state": "success", "creator": map[string]any{"login": "mallory"}}}
		}, time.Hour, false, 0, ""},
		{"approved, CI pending", func(f *fakeGH) {
			f.statuses[headSHA] = []map[string]any{{"context": "dep-review", "state": "success", "creator": map[string]any{"login": bot}}}
			f.checkRuns = []map[string]any{{"name": "test", "status": "queued"}}
		}, time.Hour, false, 0, ""},
		{"approved, CI red", func(f *fakeGH) {
			f.statuses[headSHA] = []map[string]any{{"context": "dep-review", "state": "success", "creator": map[string]any{"login": bot}}}
			f.checkRuns = []map[string]any{{"name": "test", "status": "completed", "conclusion": "timed_out"}}
		}, time.Hour, false, 1, "notified=" + headSHA},
		{"human decision left alone", func(f *fakeGH) {
			f.statuses[headSHA] = []map[string]any{{"context": "dep-review", "state": "failure", "creator": map[string]any{"login": bot}}}
		}, 5 * time.Hour, false, 0, ""},
		{"young head without decision", nil, time.Hour, false, 0, ""},
		{"stuck head", nil, 3 * time.Hour, false, 1, "stuck=" + headSHA},
		{"stuck after gate error", func(f *fakeGH) {
			f.statuses[headSHA] = []map[string]any{{"context": "dep-review", "state": "error", "creator": map[string]any{"login": bot}}}
		}, 3 * time.Hour, false, 1, "stuck=" + headSHA},
		{"stuck already reported", func(f *fakeGH) {
			c := &fakeComment{ID: 5, Body: marker{Stuck: []string{headSHA}}.String()}
			c.User.Login = bot
			f.comments[7] = []*fakeComment{c}
		}, 3 * time.Hour, false, 0, "stuck=" + headSHA},
		{"not dependabot's", func(f *fakeGH) { f.prs[7] = openPR(7, headSHA, "someone") }, 3 * time.Hour, false, 0, ""},
		{"fork head", func(f *fakeGH) {
			f.prs[7]["head"].(map[string]any)["repo"] = map[string]any{"full_name": "evil/r"}
		}, 3 * time.Hour, false, 0, ""},
		{"approval for an older head does not count", func(f *fakeGH) {
			f.statuses[other] = []map[string]any{{"context": "dep-review", "state": "success", "creator": map[string]any{"login": bot}}}
		}, time.Hour, false, 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			if tt.setup != nil {
				tt.setup(f)
			}
			cfg, n, ck := setup(t, f)
			f.commitDate = ck.Now().Add(-tt.age)
			if err := Sweep(context.Background(), cfg, "o/r"); err != nil {
				t.Fatal(err)
			}
			if got := len(f.merges) > 0; got != tt.wantMerge {
				t.Errorf("merged = %v, want %v", got, tt.wantMerge)
			}
			if len(n.msgs) != tt.notified {
				t.Errorf("notifications = %d, want %d", len(n.msgs), tt.notified)
			}
			if tt.comment != "" {
				if len(f.comments[7]) != 1 || !strings.Contains(f.comments[7][0].Body, tt.comment) {
					t.Errorf("comments = %+v", f.comments[7])
				}
			} else if len(f.comments[7]) != 0 {
				t.Errorf("unexpected comment %q", f.comments[7][0].Body)
			}
			// Sweep never sets a status: it does not decide.
			for sha, st := range f.statuses {
				for _, s := range st {
					if s["description"] != nil {
						t.Errorf("sweep set a status on %s", sha)
					}
				}
			}
		})
	}
}

func TestPushover(t *testing.T) {
	var got url.Values
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		r.ParseForm()
		got = r.PostForm
		if calls == 1 {
			w.WriteHeader(500)
			return
		}
		fmt.Fprint(w, `{"status":1}`)
	}))
	defer srv.Close()
	p := &Pushover{Token: "app", User: "user", Endpoint: srv.URL}
	m := notification(Config{ServerURL: "https://github.com"}, "o/r", 7, model.DecisionHuman, "needs a person: npm.install-script-added")
	if err := p.Notify(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || got.Get("token") != "app" || got.Get("user") != "user" ||
		got.Get("message") != "o/r#7 needs a person: needs a person: npm.install-script-added" || got.Get("url") != "https://github.com/o/r/pull/7" {
		t.Errorf("calls=%d form=%v", calls, got)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":0,"errors":["user identifier is invalid"]}`)
	}))
	defer bad.Close()
	p.Endpoint = bad.URL
	if err := p.Notify(context.Background(), m); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Errorf("err = %v", err)
	}
}

func TestBotLoginFromSlug(t *testing.T) {
	if l, err := BotLoginFromSlug("dep-review-gate"); err != nil || l != "dep-review-gate[bot]" {
		t.Error(l, err)
	}
	for _, s := range []string{"", "Bad", "x[bot]", "a b", "-x"} {
		if _, err := BotLoginFromSlug(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

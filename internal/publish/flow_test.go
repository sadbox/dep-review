package publish

import (
	"context"
	"encoding/json"
	"errors"
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

	prs       map[int]map[string]any // GET pulls/{n}
	comments  map[int][]*fakeComment
	nextID    int64
	statuses  map[string][]map[string]any // POSTed, newest first
	checkRuns []map[string]any            // served for every head; replaced by ciSeq when set
	ciSeq     [][]map[string]any          // successive check-runs responses
	ciCalls   int
	combined  []map[string]any // statuses from other creators, after the POSTed ones
	mergeCode int
	// GET actions/runs?head_sha=: the workflow file of each check suite.
	workflowRuns []map[string]any
	onCheckRuns  func(f *fakeGH, call int)
	merges       []map[string]string
	commitDate   time.Time
	patches      int
	requests     []string // "METHOD path" of every request, in order
}

func newFake(t *testing.T) *fakeGH {
	return &fakeGH{
		t:         t,
		prs:       map[int]map[string]any{7: openPR(7, headSHA, "dependabot[bot]")},
		comments:  map[int][]*fakeComment{},
		nextID:    100,
		statuses:  map[string][]map[string]any{},
		checkRuns: []map[string]any{ghaRun("test", "completed", "success", ciSuite)},
		workflowRuns: []map[string]any{
			{"path": ".github/workflows/ci.yaml", "check_suite_id": ciSuite},
			{"path": trigger, "check_suite_id": triggerSuite},
		},
		mergeCode: 200,
	}
}

func openPR(n int, head, user string) map[string]any {
	return map[string]any{
		"number": n, "state": "open", "merged": false, "user": map[string]any{"login": user},
		"head": map[string]any{"sha": head, "repo": map[string]any{"full_name": "o/r"}},
		"base": map[string]any{"ref": "main", "repo": map[string]any{"full_name": "o/r", "default_branch": "main"}},
	}
}

const (
	trigger      = ".github/workflows/dep-review-trigger.yaml"
	ciSuite      = 1
	triggerSuite = 2
)

// ghaRun is a GitHub Actions check run in check suite suite.
func ghaRun(name, status, conclusion string, suite int) map[string]any {
	r := map[string]any{"name": name, "status": status, "app": map[string]any{"slug": "github-actions"}, "check_suite": map[string]any{"id": suite}}
	if conclusion != "" {
		r["conclusion"] = conclusion
	}
	return r
}

func setBase(f *fakeGH, ref, defaultBranch string) {
	f.prs[7]["base"] = map[string]any{"ref": ref, "repo": map[string]any{"full_name": "o/r", "default_branch": defaultBranch}}
}

func (f *fakeGH) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
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
		js(append(append([]map[string]any{}, f.statuses[parts[1]]...), f.combined...))
	case r.Method == "GET" && p == "actions/runs":
		if r.URL.Query().Get("head_sha") == "" {
			f.t.Errorf("actions/runs without head_sha")
		}
		js(map[string]any{"total_count": len(f.workflowRuns), "workflow_runs": f.workflowRuns})
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
		if f.onCheckRuns != nil {
			f.onCheckRuns(f, f.ciCalls)
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
	return Config{GitHub: c, BotLogin: bot, TriggerPath: trigger, Notifier: n, ServerURL: "https://github.com", Now: ck.Now, Sleep: ck.Sleep, Logf: t.Logf}, n, ck
}

var passVerdict = []byte(`{"verdict":"pass","flags":[],"summary":"ok","items":[]}`)

func reviewInputs() Inputs {
	return Inputs{Class: class(), Evidence: evidence(model.RouteReview, patch), FetchResult: "success", ReviewResult: "success", Verdict: passVerdict}
}

func TestPublish(t *testing.T) {
	inProgress := []map[string]any{ghaRun("test", "in_progress", "", ciSuite)}
	green := []map[string]any{ghaRun("test", "completed", "success", ciSuite), ghaRun("lint", "completed", "skipped", ciSuite)}
	red := []map[string]any{ghaRun("test", "completed", "failure", ciSuite)}
	triggerOnly := []map[string]any{ghaRun("noop", "completed", "success", triggerSuite)}
	otherStatus := func(creator, state string) map[string]any {
		return map[string]any{"context": "ci/other", "state": state, "creator": map[string]any{"login": creator}}
	}
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
		// Review finding 3: CI must have at least one real, passing check.
		{"no checks at all", reviewInputs(), func(f *fakeGH) { f.checkRuns = nil }, false, StateSuccess, 0, "approved"},
		{"only the trigger's no-op run", reviewInputs(), func(f *fakeGH) { f.checkRuns = triggerOnly }, false, StateSuccess, 0, "approved"},
		{"only skipped checks", reviewInputs(), func(f *fakeGH) {
			f.checkRuns = []map[string]any{ghaRun("lint", "completed", "skipped", ciSuite), ghaRun("x", "completed", "neutral", ciSuite)}
		}, false, StateSuccess, 0, "approved"},
		{"Actions run without a known workflow", reviewInputs(), func(f *fakeGH) {
			f.checkRuns = []map[string]any{ghaRun("test", "completed", "success", 99)}
		}, false, StateSuccess, 0, "approved"},
		{"check run named dep-review", reviewInputs(), func(f *fakeGH) {
			f.checkRuns = []map[string]any{{"name": "dep-review", "status": "completed", "conclusion": "success", "app": map[string]any{"slug": "other-ci"}}}
		}, false, StateSuccess, 0, "approved"},
		{"check run by the gate app", reviewInputs(), func(f *fakeGH) {
			f.checkRuns = []map[string]any{{"name": "x", "status": "completed", "conclusion": "success", "app": map[string]any{"slug": strings.TrimSuffix(bot, "[bot]")}}}
		}, false, StateSuccess, 0, "approved"},
		{"status by the gate app", reviewInputs(), func(f *fakeGH) {
			f.checkRuns = triggerOnly
			f.combined = []map[string]any{otherStatus(bot, "success")}
		}, false, StateSuccess, 0, "approved"},
		{"third-party check run", reviewInputs(), func(f *fakeGH) {
			f.checkRuns = append(triggerOnly, map[string]any{"name": "build", "status": "completed", "conclusion": "success", "app": map[string]any{"slug": "circleci"}})
		}, true, StateSuccess, 0, "approved"},
		{"status from real CI", reviewInputs(), func(f *fakeGH) {
			f.checkRuns = triggerOnly
			f.combined = []map[string]any{otherStatus("ci-bot", "success")}
		}, true, StateSuccess, 0, "approved"},
		{"older failed status superseded", reviewInputs(), func(f *fakeGH) {
			f.combined = []map[string]any{otherStatus("ci-bot", "success"), otherStatus("ci-bot", "failure")}
		}, true, StateSuccess, 0, "approved"},
		{"failing trigger still red", reviewInputs(), func(f *fakeGH) {
			f.checkRuns = append(green, ghaRun("noop", "completed", "failure", triggerSuite))
		}, false, StateSuccess, 1, "CI failed"},
		// Review finding 2: the base must be the classified default branch.
		{"base is not the default branch", reviewInputs(), func(f *fakeGH) { setBase(f, "release", "main") }, false, StateFailure, 1, "not the default branch"},
		{"base differs from classification", reviewInputs(), func(f *fakeGH) { setBase(f, "trunk", "trunk") }, false, StateFailure, 1, "changed after classification"},
		{"base retargeted while CI ran", reviewInputs(), func(f *fakeGH) {
			f.ciSeq = [][]map[string]any{inProgress, green}
			f.onCheckRuns = func(f *fakeGH, call int) {
				if call == 1 {
					setBase(f, "release", "main")
				}
			}
		}, false, StateSuccess, 1, "not the default branch"},
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
			// Only an approval records the approved head for sweep.
			wantApproved := ""
			if tt.wantStatus == StateSuccess {
				wantApproved = headSHA
			}
			if m, _ := parseMarker(cs[0].Body); m.Approved != wantApproved {
				t.Errorf("marker approved = %q, want %q", m.Approved, wantApproved)
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
	// approve is what publish leaves behind for an approved head: its
	// success status and its comment recording the approved head.
	approve := func(f *fakeGH, recorded string) {
		f.statuses[headSHA] = []map[string]any{{"context": "dep-review", "state": "success", "creator": map[string]any{"login": bot}}}
		c := &fakeComment{ID: 5, Body: marker{Approved: recorded}.String() + "\n### dep-review: approved\n"}
		c.User.Login = bot
		f.comments[7] = []*fakeComment{c}
	}
	tests := []struct {
		name      string
		setup     func(f *fakeGH)
		age       time.Duration
		wantMerge bool
		notified  int
		comment   string
	}{
		{"approved and green", func(f *fakeGH) { approve(f, headSHA) }, time.Hour, true, 0, "approved=" + headSHA},
		{"success from someone else is ignored", func(f *fakeGH) {
			f.statuses[headSHA] = []map[string]any{{"context": "dep-review", "state": "success", "creator": map[string]any{"login": "mallory"}}}
		}, time.Hour, false, 0, ""},
		{"approved, CI pending", func(f *fakeGH) {
			approve(f, headSHA)
			f.checkRuns = []map[string]any{ghaRun("test", "queued", "", ciSuite)}
		}, time.Hour, false, 0, "approved=" + headSHA},
		{"approved, CI red", func(f *fakeGH) {
			approve(f, headSHA)
			f.checkRuns = []map[string]any{ghaRun("test", "completed", "timed_out", ciSuite)}
		}, time.Hour, false, 1, "notified=" + headSHA},
		// Review finding 4: sweep re-derives the decision.
		{"approved, only the trigger ran", func(f *fakeGH) {
			approve(f, headSHA)
			f.checkRuns = []map[string]any{ghaRun("noop", "completed", "success", triggerSuite)}
		}, time.Hour, false, 0, "approved=" + headSHA},
		{"approved, no checks at all", func(f *fakeGH) {
			approve(f, headSHA)
			f.checkRuns = nil
		}, time.Hour, false, 0, "approved=" + headSHA},
		// Approved but no real CI ever passes: reported once, like a stuck
		// head, keeping the approval comment and its record.
		{"approved, no CI after the stuck threshold", func(f *fakeGH) {
			approve(f, headSHA)
			f.checkRuns = nil
		}, 3 * time.Hour, false, 1, "stuck=" + headSHA + " approved=" + headSHA + " -->\n### dep-review: approved"},
		{"approved, CI still running after the threshold", func(f *fakeGH) {
			approve(f, headSHA)
			f.checkRuns = []map[string]any{ghaRun("test", "queued", "", ciSuite)}
		}, 3 * time.Hour, false, 1, "stuck=" + headSHA},
		{"approved and stuck already reported", func(f *fakeGH) {
			approve(f, headSHA)
			f.comments[7][0].Body = marker{Stuck: []string{headSHA}, Approved: headSHA}.String() + "\n### dep-review: approved\n"
			f.checkRuns = nil
		}, 3 * time.Hour, false, 0, "approved=" + headSHA},
		{"status without an approval record", func(f *fakeGH) { approve(f, "") }, time.Hour, false, 1, "notified=" + headSHA},
		{"approval record for another head", func(f *fakeGH) { approve(f, other) }, time.Hour, false, 1, "notified=" + headSHA},
		{"approval record in someone else's comment", func(f *fakeGH) {
			approve(f, "")
			c := &fakeComment{ID: 4, Body: marker{Approved: headSHA}.String() + "\n"}
			c.User.Login = "mallory"
			f.comments[7] = append([]*fakeComment{c}, f.comments[7]...)
		}, time.Hour, false, 1, "notified=" + headSHA},
		{"approved, base retargeted", func(f *fakeGH) {
			approve(f, headSHA)
			setBase(f, "release", "main")
		}, time.Hour, false, 1, "notified=" + headSHA},
		{"approved, default branch renamed away", func(f *fakeGH) {
			approve(f, headSHA)
			setBase(f, "main", "trunk")
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
			var ours []*fakeComment
			for _, c := range f.comments[7] {
				if c.User.Login == bot {
					ours = append(ours, c)
				}
			}
			if tt.comment != "" {
				if len(ours) != 1 || !strings.Contains(ours[0].Body, tt.comment) {
					t.Errorf("comments = %+v", ours)
				}
			} else if len(ours) != 0 {
				t.Errorf("unexpected comment %q", ours[0].Body)
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

func TestTriggerPathRequired(t *testing.T) {
	f := newFake(t)
	cfg, _, _ := setup(t, f)
	cfg.TriggerPath = ""
	if err := Publish(context.Background(), cfg, reviewInputs()); !errors.Is(err, errNoTrigger) {
		t.Errorf("publish: %v", err)
	}
	if err := Sweep(context.Background(), cfg, "o/r"); !errors.Is(err, errNoTrigger) {
		t.Errorf("sweep: %v", err)
	}
	if len(f.merges) != 0 || len(f.statuses) != 0 {
		t.Error("acted without a trigger path")
	}
}

// The classification's trigger path is excluded too, even when the
// configured one differs: a no-op run from either never counts.
func TestPublishExcludesClassifiedTrigger(t *testing.T) {
	f := newFake(t)
	f.checkRuns = []map[string]any{ghaRun("noop", "completed", "success", 3)}
	f.workflowRuns = append(f.workflowRuns, map[string]any{"path": ".github/workflows/custom-trigger.yml", "check_suite_id": 3})
	cfg, _, _ := setup(t, f)
	in := reviewInputs()
	in.Class.TriggerPath = ".github/workflows/custom-trigger.yml"
	if err := Publish(context.Background(), cfg, in); err != nil {
		t.Fatal(err)
	}
	if len(f.merges) != 0 {
		t.Error("merged on the classified trigger's no-op run")
	}
}

// Re-review R1b: a dependabot-pending classification decides nothing.
func TestPublishPending(t *testing.T) {
	f := newFake(t)
	cfg, n, _ := setup(t, f)
	cl := class()
	cl.Kind = model.KindPending
	if err := Publish(context.Background(), cfg, Inputs{Class: cl}); err != nil {
		t.Fatal(err)
	}
	if len(f.merges) != 0 || len(f.statuses) != 0 || len(f.comments[7]) != 0 || len(n.msgs) != 0 {
		t.Error("publish acted on a pending classification")
	}
}

// A dependabot-pending head has no status: sweep leaves it alone until
// the stuck threshold, then reports it once so a maintainer re-runs the
// gate. Nothing is re-run or decided by sweep itself.
func TestSweepPendingHead(t *testing.T) {
	for _, tc := range []struct {
		age      time.Duration
		notified int
	}{{time.Hour, 0}, {3 * time.Hour, 1}} {
		f := newFake(t)
		cfg, n, ck := setup(t, f)
		f.commitDate = ck.Now().Add(-tc.age)
		if err := Sweep(context.Background(), cfg, "o/r"); err != nil {
			t.Fatal(err)
		}
		if len(n.msgs) != tc.notified || len(f.merges) != 0 || len(f.statuses) != 0 {
			t.Fatalf("age %v: notifications %v merges %d statuses %d", tc.age, n.msgs, len(f.merges), len(f.statuses))
		}
		if tc.notified == 1 && !strings.Contains(n.msgs[0].Body, "a maintainer can re-run the gate") {
			t.Errorf("message %q", n.msgs[0].Body)
		}
	}
}

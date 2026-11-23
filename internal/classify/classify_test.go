package classify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
)

const (
	head = "1111111111111111111111111111111111111111"
	base = "2222222222222222222222222222222222222222"
	trig = ".github/workflows/dep-review-trigger.yaml"
)

type fixture struct {
	event     map[string]any
	pr        map[string]any
	commits   []map[string]any
	byCommit  []map[string]any   // GET commits/{sha}/pulls
	activity  []map[string]any   // GET activity?ref=<head branch>, oldest first
	actCode   int                // non-zero: GET activity fails with this status
	rules     []map[string]any   // GET rules/branches/<head branch>
	rulesCode int                // non-zero: GET rules/branches fails with this status
	timeline  []map[string]any   // GET issues/7/timeline
	actSeq    [][]map[string]any // successive activity responses (overrides activity)
	actCalls  int
	slept     []time.Duration
	tlCode    int                      // non-zero: GET timeline fails with this status
	ignore    map[model.Ecosystem]bool // Options.IgnoreEcosystems
}

// rule is one entry of GitHub's rules/branches answer, with the members
// it carries besides the type.
func rule(typ string, ruleset int) map[string]any {
	return map[string]any{"type": typ, "ruleset_source_type": "Repository", "ruleset_source": "o/r", "ruleset_id": ruleset}
}

// dependabotRules is what GitHub answers for a dependabot/ branch in a
// repository with the owner's "dependabot branches" ruleset. Recorded on
// 2026-11-23 from rules/branches/dependabot/go_modules/golang.org/x/net-0.63.0
// of a repository that has it; the update rule carries no parameters
// there. A repository without the ruleset answers [].
func dependabotRules() []map[string]any {
	return []map[string]any{rule("creation", 42), rule("update", 42), rule("deletion", 42)}
}

const zero = "0000000000000000000000000000000000000000"

func act(typ, actor, before, after string) map[string]any {
	return map[string]any{"activity_type": typ, "actor": map[string]any{"login": actor}, "before": before, "after": after}
}

func defaultFixture(t *testing.T) *fixture {
	return &fixture{
		event: map[string]any{
			"action": "completed",
			"workflow_run": map[string]any{
				"event":           "pull_request",
				"path":            trig,
				"head_sha":        head,
				"head_branch":     "dependabot/go_modules/aws-1c8ebe5c54",
				"head_repository": map[string]any{"full_name": "o/r"},
				"pull_requests":   []any{map[string]any{"number": 7, "head": map[string]any{"sha": head}}},
			},
			"repository": map[string]any{"full_name": "o/r", "private": true},
		},
		pr: map[string]any{
			"number": 7, "state": "open", "body": "Bumps the aws group",
			"user":   map[string]any{"login": "dependabot[bot]"},
			"labels": []any{map[string]any{"name": "dependencies"}},
			"head":   map[string]any{"sha": head, "ref": "dependabot/go_modules/aws-1c8ebe5c54", "repo": map[string]any{"full_name": "o/r"}},
			"base":   map[string]any{"sha": base, "ref": "main", "repo": map[string]any{"full_name": "o/r"}},
		},
		commits: []map[string]any{{
			"sha":       head,
			"author":    map[string]any{"login": "dependabot[bot]"},
			"committer": map[string]any{"login": "web-flow"},
			"commit":    map[string]any{"message": "Bump the aws group with 2 updates", "verification": map[string]any{"verified": true, "reason": "valid"}},
		}},
		activity: []map[string]any{act("branch_creation", "dependabot[bot]", zero, head)},
		rules:    dependabotRules(),
	}
}

func (f *fixture) run(t *testing.T) (model.Classification, error) {
	t.Helper()
	ev, _ := json.Marshal(f.event)
	return Classify(context.Background(), f.client(t), ev, f.options())
}

// options is what the gate passes besides the event.
func (f *fixture) options() Options {
	return Options{TriggerPath: trig, IgnoreEcosystems: f.ignore, Logf: func(string, ...any) {}, Sleep: func(_ context.Context, d time.Duration) error {
		f.slept = append(f.slept, d)
		return nil
	}}
}

// client is a GitHub client for a server that answers from the fixture.
func (f *fixture) client(t *testing.T) *gh.Client {
	t.Helper()
	mux := http.NewServeMux()
	js := func(v any) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(v) }
	}
	mux.Handle("GET /repos/o/r/pulls/7", js(f.pr))
	mux.Handle("GET /repos/o/r/pulls/7/commits", js(f.commits))
	mux.Handle("GET /repos/o/r/commits/"+head+"/pulls", js(f.byCommit))
	mux.HandleFunc("GET /repos/o/r/activity", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("ref") != "refs/heads/"+f.pr["head"].(map[string]any)["ref"].(string) || q.Get("direction") != "asc" {
			t.Errorf("activity query %v", q)
		}
		if f.actCode != 0 {
			w.WriteHeader(f.actCode)
			return
		}
		acts := f.activity
		if len(f.actSeq) > 0 {
			acts = f.actSeq[min(f.actCalls, len(f.actSeq)-1)]
		}
		f.actCalls++
		if acts == nil {
			acts = []map[string]any{}
		}
		json.NewEncoder(w).Encode(acts)
	})
	mux.HandleFunc("GET /repos/o/r/issues/7/timeline", func(w http.ResponseWriter, r *http.Request) {
		if f.tlCode != 0 {
			w.WriteHeader(f.tlCode)
			return
		}
		tl := f.timeline
		if tl == nil {
			tl = []map[string]any{}
		}
		json.NewEncoder(w).Encode(tl)
	})
	mux.HandleFunc("GET /repos/o/r/rules/branches/{branch...}", func(w http.ResponseWriter, r *http.Request) {
		// The whole branch name, slashes and all, and nothing else.
		if want := f.pr["head"].(map[string]any)["ref"].(string); r.PathValue("branch") != want {
			t.Errorf("rules asked for branch %q, want %q", r.PathValue("branch"), want)
		}
		if f.rulesCode != 0 {
			w.WriteHeader(f.rulesCode)
			return
		}
		rules := f.rules
		if rules == nil {
			rules = []map[string]any{}
		}
		json.NewEncoder(w).Encode(rules)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s", r.Method, r.URL)
		http.NotFound(w, r)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	c := gh.New("tok")
	c.BaseURL = srv.URL + "/"
	c.HTTP = srv.Client()
	return c
}

func wr(f *fixture) map[string]any { return f.event["workflow_run"].(map[string]any) }

func TestClassify(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(f *fixture)
		kind   model.Kind
		reason string
	}{
		{"dependabot", func(f *fixture) {}, model.KindDependabot, ""},
		{"push event", func(f *fixture) { wr(f)["event"] = "push" }, model.KindOther, "not pull_request"},
		{"other trigger", func(f *fixture) { wr(f)["path"] = ".github/workflows/ci.yml" }, model.KindOther, "trigger"},
		{"fork", func(f *fixture) { wr(f)["head_repository"] = map[string]any{"full_name": "evil/r"} }, model.KindOther, "fork"},
		{"no head repo", func(f *fixture) { delete(wr(f), "head_repository") }, model.KindOther, "fork"},
		{"fallback lookup", func(f *fixture) {
			wr(f)["pull_requests"] = []any{}
			f.byCommit = []map[string]any{
				{"number": 7, "state": "open", "head": map[string]any{"sha": head, "repo": map[string]any{"full_name": "o/r"}}, "base": map[string]any{"repo": map[string]any{"full_name": "o/r"}}},
				{"number": 8, "state": "closed", "head": map[string]any{"sha": head, "repo": map[string]any{"full_name": "o/r"}}, "base": map[string]any{"repo": map[string]any{"full_name": "o/r"}}},
				{"number": 9, "state": "open", "head": map[string]any{"sha": head, "repo": map[string]any{"full_name": "evil/r"}}, "base": map[string]any{"repo": map[string]any{"full_name": "o/r"}}},
			}
		}, model.KindDependabot, ""},
		{"fallback ambiguous", func(f *fixture) {
			wr(f)["pull_requests"] = []any{}
			pr := map[string]any{"number": 7, "state": "open", "head": map[string]any{"sha": head, "repo": map[string]any{"full_name": "o/r"}}, "base": map[string]any{"repo": map[string]any{"full_name": "o/r"}}}
			pr2 := map[string]any{"number": 10, "state": "open", "head": map[string]any{"sha": head, "repo": map[string]any{"full_name": "o/r"}}, "base": map[string]any{"repo": map[string]any{"full_name": "o/r"}}}
			f.byCommit = []map[string]any{pr, pr2}
		}, model.KindOther, "no single"},
		{"stale", func(f *fixture) { f.pr["head"].(map[string]any)["sha"] = strings.Repeat("3", 40) }, model.KindStale, "newer head"},
		{"closed", func(f *fixture) { f.pr["state"] = "closed" }, model.KindStale, "no longer open"},
		{"human PR", func(f *fixture) {
			f.pr["user"] = map[string]any{"login": "someone"}
			f.pr["head"].(map[string]any)["ref"] = "feature"
		}, model.KindOther, "neither"},
		{"branch only", func(f *fixture) { f.pr["user"] = map[string]any{"login": "someone"} }, model.KindDependabotUnverified, "not authored"},
		{"author only", func(f *fixture) { f.pr["head"].(map[string]any)["ref"] = "feature" }, model.KindDependabotUnverified, "not on a dependabot/ branch"},
		{"pushed-to by human", func(f *fixture) {
			c := map[string]any{"sha": head, "author": map[string]any{"login": "someone"}, "committer": map[string]any{"login": "someone"},
				"commit": map[string]any{"message": "fix", "verification": map[string]any{"verified": true}}}
			f.commits[0]["sha"] = strings.Repeat("4", 40)
			f.commits = append(f.commits, c)
		}, model.KindDependabotUnverified, "not authored by dependabot"},
		{"update branch merge commit", func(f *fixture) {
			c := map[string]any{"sha": head, "author": map[string]any{"login": "someone"}, "committer": map[string]any{"login": "web-flow"},
				"commit": map[string]any{"message": "Merge branch 'main' into dependabot/...", "verification": map[string]any{"verified": true}}}
			f.commits[0]["sha"] = strings.Repeat("4", 40)
			f.commits = append(f.commits, c)
		}, model.KindDependabotUnverified, "not authored by dependabot"},
		{"unsigned", func(f *fixture) {
			f.commits[0]["commit"].(map[string]any)["verification"] = map[string]any{"verified": false}
		}, model.KindDependabotUnverified, "verified signature"},
		{"other committer", func(f *fixture) { f.commits[0]["committer"] = map[string]any{"login": "someone"} }, model.KindDependabotUnverified, "not committed"},
		{"null author", func(f *fixture) { f.commits[0]["author"] = nil }, model.KindDependabotUnverified, "not authored"},
		{"unknown ecosystem", func(f *fixture) { f.pr["head"].(map[string]any)["ref"] = "dependabot/cargo/x-1" }, model.KindDependabotUnverified, "ecosystem"},
		// What Dependabot wrote about its update decides nothing: the
		// commit message, the body and the labels are not read.
		{"any commit message", func(f *fixture) { f.commits[0]["commit"].(map[string]any)["message"] = "anything at all" }, model.KindDependabot, ""},
		{"base commit malformed", func(f *fixture) { f.pr["base"].(map[string]any)["sha"] = "main" }, model.KindDependabotUnverified, "base commit is malformed"},
		{"head repo differs on PR", func(f *fixture) { f.pr["head"].(map[string]any)["repo"] = map[string]any{"full_name": "evil/r"} }, model.KindDependabotUnverified, "not in this repository"},
		{"signature reason not valid", func(f *fixture) {
			f.commits[0]["commit"].(map[string]any)["verification"] = map[string]any{"verified": true, "reason": "unknown_key"}
		}, model.KindDependabotUnverified, "verified signature"},
		// Review finding 1: who moved the branch, from its activity log.
		{"rebased by dependabot", func(f *fixture) {
			mid := strings.Repeat("5", 40)
			f.activity = []map[string]any{act("branch_creation", "dependabot[bot]", zero, mid), act("force_push", "dependabot[bot]", mid, head)}
		}, model.KindDependabot, ""},
		{"recreated after a person deleted it", func(f *fixture) {
			old := strings.Repeat("5", 40)
			f.activity = []map[string]any{act("branch_creation", "dependabot[bot]", zero, old), act("branch_deletion", "someone", old, zero), act("branch_creation", "dependabot[bot]", zero, head)}
		}, model.KindDependabot, ""},
		{"another dependabot PR squash-merged into the branch", func(f *fixture) {
			// What GitHub records for the setup-go#775 pattern: the commit
			// itself is dependabot[bot] / web-flow / valid.
			mid := strings.Repeat("5", 40)
			f.activity = []map[string]any{act("branch_creation", "dependabot[bot]", zero, mid), act("pr_merge", "someone", mid, head)}
		}, model.KindDependabotUnverified, "someone other than dependabot"},
		{"pushed by a person", func(f *fixture) {
			mid := strings.Repeat("5", 40)
			f.activity = []map[string]any{act("branch_creation", "dependabot[bot]", zero, mid), act("push", "someone", mid, head)}
		}, model.KindDependabotUnverified, "someone other than dependabot"},
		{"force-pushed by a person", func(f *fixture) {
			mid := strings.Repeat("5", 40)
			f.activity = []map[string]any{act("branch_creation", "dependabot[bot]", zero, mid), act("force_push", "someone", mid, head)}
		}, model.KindDependabotUnverified, "someone other than dependabot"},
		{"created by a person", func(f *fixture) {
			f.activity = []map[string]any{act("branch_creation", "someone", zero, head)}
		}, model.KindDependabotUnverified, "someone other than dependabot"},
		{"merge queue entry", func(f *fixture) {
			mid := strings.Repeat("5", 40)
			f.activity = []map[string]any{act("branch_creation", "dependabot[bot]", zero, mid), act("merge_queue_merge", "dependabot[bot]", mid, head)}
		}, model.KindDependabotUnverified, "merge_queue_merge"},
		{"history has a gap", func(f *fixture) {
			f.activity = []map[string]any{act("branch_creation", "dependabot[bot]", zero, strings.Repeat("5", 40)), act("push", "dependabot[bot]", strings.Repeat("6", 40), head)}
		}, model.KindDependabotUnverified, "gap"},
		// Re-review R1b: a log that has not caught up is not a verdict.
		{"history behind the head", func(f *fixture) {
			f.activity = []map[string]any{act("branch_creation", "dependabot[bot]", zero, strings.Repeat("5", 40))}
		}, model.KindPending, "does not reach the head"},
		{"history catches up", func(f *fixture) {
			mid := strings.Repeat("5", 40)
			f.actSeq = [][]map[string]any{
				{act("branch_creation", "dependabot[bot]", zero, mid)},
				{act("branch_creation", "dependabot[bot]", zero, mid), act("force_push", "dependabot[bot]", mid, head)},
			}
		}, model.KindDependabot, ""},
		{"history catches up with a person's push", func(f *fixture) {
			mid := strings.Repeat("5", 40)
			f.actSeq = [][]map[string]any{
				{act("branch_creation", "dependabot[bot]", zero, mid)},
				{act("branch_creation", "dependabot[bot]", zero, mid), act("push", "someone", mid, head)},
			}
		}, model.KindDependabotUnverified, "someone other than dependabot"},
		{"history without the creation", func(f *fixture) {
			f.activity = []map[string]any{act("push", "dependabot[bot]", strings.Repeat("5", 40), head)}
		}, model.KindDependabotUnverified, "creation"},
		{"empty history", func(f *fixture) { f.activity = nil }, model.KindPending, "no push history yet"},
		{"no actor", func(f *fixture) {
			f.activity = []map[string]any{{"activity_type": "branch_creation", "before": zero, "after": head}}
		}, model.KindDependabotUnverified, "someone other than dependabot"},
		{"history unreadable", func(f *fixture) { f.actCode = http.StatusForbidden }, model.KindDependabotUnverified, "could not be read (HTTP 403)"},
		// Re-review R1a: a retargeted PR is not what Dependabot proposed.
		{"ordinary timeline", func(f *fixture) {
			f.timeline = []map[string]any{{"event": "labeled"}, {"event": "head_ref_force_pushed"}, {"event": "commented"}}
		}, model.KindDependabot, ""},
		{"base changed", func(f *fixture) {
			f.timeline = []map[string]any{{"event": "labeled"}, {"event": "base_ref_changed"}}
		}, model.KindDependabotUnverified, "base branch was changed"},
		{"timeline unreadable", func(f *fixture) { f.tlCode = http.StatusForbidden }, model.KindDependabotUnverified, "timeline could not be read (HTTP 403)"},
		// The rules that keep everyone but Dependabot off the branch, as
		// GitHub reports them for it. Which ruleset they come from, its
		// name and its bypass list are not checked.
		{"rules from two rulesets", func(f *fixture) {
			f.rules = []map[string]any{rule("deletion", 7), rule("creation", 42), rule("update", 42)}
		}, model.KindDependabot, ""},
		{"other rules besides", func(f *fixture) {
			f.rules = append(f.rules, rule("required_signatures", 9),
				map[string]any{"type": "pull_request", "parameters": map[string]any{"required_approving_review_count": 0}})
		}, model.KindDependabot, ""},
		{"update rule with null parameters", func(f *fixture) { f.rules[1]["parameters"] = nil }, model.KindDependabot, ""},
		{"update keeps fetch and merge off", func(f *fixture) {
			f.rules[1]["parameters"] = map[string]any{"update_allows_fetch_and_merge": false}
		}, model.KindDependabot, ""},
		{"nested branch name", func(f *fixture) {
			f.pr["head"].(map[string]any)["ref"] = "dependabot/go_modules/golang.org/x/net-0.63.0"
		}, model.KindDependabot, ""},
		{"no rules apply", func(f *fixture) { f.rules = nil }, model.KindDependabotUnverified, "no active rule"},
		// A name of another shape never reaches a request path (the
		// fixture fails the test if the rules are asked about it).
		{"branch name with another character", func(f *fixture) {
			f.pr["head"].(map[string]any)["ref"] = "dependabot/go_modules/x%2f..%2fy"
		}, model.KindDependabotUnverified, "not one the gate asks"},
		{"branch name with a dot-dot element", func(f *fixture) {
			f.pr["head"].(map[string]any)["ref"] = "dependabot/go_modules/../../x"
		}, model.KindDependabotUnverified, "not one the gate asks"},
		{"branch name with an empty element", func(f *fixture) {
			f.pr["head"].(map[string]any)["ref"] = "dependabot/go_modules//x"
		}, model.KindDependabotUnverified, "not one the gate asks"},
		{"only other rules apply", func(f *fixture) {
			f.rules = []map[string]any{rule("required_signatures", 9), rule("non_fast_forward", 9)}
		}, model.KindDependabotUnverified, "no active rule"},
		{"no creation rule", func(f *fixture) { f.rules = f.rules[1:] }, model.KindDependabotUnverified, "no active rule"},
		{"no update rule", func(f *fixture) { f.rules = []map[string]any{f.rules[0], f.rules[2]} }, model.KindDependabotUnverified, "no active rule"},
		{"no deletion rule", func(f *fixture) { f.rules = f.rules[:2] }, model.KindDependabotUnverified, "no active rule"},
		{"update allows fetch and merge", func(f *fixture) {
			f.rules[1]["parameters"] = map[string]any{"update_allows_fetch_and_merge": true}
		}, model.KindDependabotUnverified, "no active rule"},
		{"rules unreadable", func(f *fixture) { f.rulesCode = http.StatusForbidden }, model.KindDependabotUnverified, "rules could not be read (HTTP 403)"},
		{"rules not found", func(f *fixture) { f.rulesCode = http.StatusNotFound }, model.KindDependabotUnverified, "rules could not be read (HTTP 404)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := defaultFixture(t)
			tt.mutate(f)
			got, err := f.run(t)
			if err != nil {
				t.Fatal(err)
			}
			if got.Kind != tt.kind {
				t.Fatalf("kind = %s (%s), want %s", got.Kind, got.Reason, tt.kind)
			}
			if tt.reason != "" && !strings.Contains(got.Reason, tt.reason) {
				t.Errorf("reason = %q, want %q", got.Reason, tt.reason)
			}
		})
	}
}

// The lag case re-reads the log with backoff, about two minutes in all.
func TestClassifyPendingRetries(t *testing.T) {
	f := defaultFixture(t)
	f.activity = []map[string]any{act("branch_creation", "dependabot[bot]", zero, strings.Repeat("5", 40))}
	got, err := f.run(t)
	if err != nil || got.Kind != model.KindPending || f.actCalls != 1+len(historyBackoff) || len(f.slept) != len(historyBackoff) {
		t.Errorf("kind %s err %v: %d reads, sleeps %v", got.Kind, err, f.actCalls, f.slept)
	}
	var total time.Duration
	for i, d := range f.slept {
		total += d
		if i > 0 && d < f.slept[i-1] {
			t.Errorf("backoff shrinks: %v", f.slept)
		}
	}
	if total < 90*time.Second || total > 150*time.Second {
		t.Errorf("waited %v in all, want about two minutes", total)
	}
	f = defaultFixture(t)
	if got, _ := f.run(t); got.Kind != model.KindDependabot || f.actCalls != 1 || len(f.slept) != 0 {
		t.Errorf("clean log: kind %s, %d reads, sleeps %v", got.Kind, f.actCalls, f.slept)
	}
}

// Pull is the same proof without an event: the scheduled job names the
// pull request and the head itself.
func TestPull(t *testing.T) {
	pullOf := func(f *fixture, number int, sha string) (model.Classification, error) {
		return Pull(context.Background(), f.client(t), "o/r", number, sha, f.options())
	}
	f := defaultFixture(t)
	got, err := pullOf(f, 7, head)
	if err != nil || got.Kind != model.KindDependabot || got.Repo != "o/r" || got.PR != 7 || got.HeadSHA != head ||
		got.BaseSHA != base || got.Ecosystem != model.GoModules {
		t.Errorf("a Dependabot pull request: %+v, %v", got, err)
	}
	for name, tt := range map[string]struct {
		mutate func(f *fixture)
		kind   model.Kind
	}{
		"head moved since it was listed": {func(f *fixture) { f.pr["head"].(map[string]any)["sha"] = strings.Repeat("3", 40) }, model.KindStale},
		"closed":                         {func(f *fixture) { f.pr["state"] = "closed" }, model.KindStale},
		"no rules":                       {func(f *fixture) { f.rules = nil }, model.KindDependabotUnverified},
		"pushed by a person": {func(f *fixture) {
			mid := strings.Repeat("5", 40)
			f.activity = []map[string]any{act("branch_creation", "dependabot[bot]", zero, mid), act("push", "someone", mid, head)}
		}, model.KindDependabotUnverified},
		"history behind the head": {func(f *fixture) {
			f.activity = []map[string]any{act("branch_creation", "dependabot[bot]", zero, strings.Repeat("5", 40))}
		}, model.KindPending},
		"a person's pull request": {func(f *fixture) {
			f.pr["user"] = map[string]any{"login": "someone"}
			f.pr["head"].(map[string]any)["ref"] = "feature"
		}, model.KindOther},
		"ignored ecosystem": {func(f *fixture) { f.ignore = map[model.Ecosystem]bool{model.GoModules: true} }, model.KindIgnored},
	} {
		t.Run(name, func(t *testing.T) {
			f := defaultFixture(t)
			tt.mutate(f)
			if got, err := pullOf(f, 7, head); err != nil || got.Kind != tt.kind {
				t.Errorf("kind %s (%s), err %v, want %s", got.Kind, got.Reason, err, tt.kind)
			}
		})
	}
	// Arguments that are not a repository, a number and a commit ID are
	// refused before anything is asked.
	for _, bad := range []struct {
		repo   string
		number int
		sha    string
	}{{"o/r/../x", 7, head}, {"o/r", 0, head}, {"o/r", 7, "HEAD"}} {
		c := gh.New("tok")
		c.BaseURL = "https://127.0.0.1:1/"
		if _, err := Pull(context.Background(), c, bad.repo, bad.number, bad.sha, Options{}); err == nil || !strings.Contains(err.Error(), "is not a repository, a pull request and a commit ID") {
			t.Errorf("Pull(%q, %d, %q): %v", bad.repo, bad.number, bad.sha, err)
		}
	}
}

// The whole record: who, which commits, which ecosystem, and nothing
// Dependabot declared.
func TestClassifyRecord(t *testing.T) {
	got, err := defaultFixture(t).run(t)
	if err != nil {
		t.Fatal(err)
	}
	want := model.Classification{
		Repo: "o/r", PR: 7, HeadSHA: head, BaseSHA: base,
		Kind: model.KindDependabot, Reason: "authored, committed and signed by Dependabot only", Ecosystem: model.GoModules,
	}
	if got != want {
		t.Errorf("classification %+v, want %+v", got, want)
	}
}

func TestClassifyRejectsMalformedEvent(t *testing.T) {
	for name, mutate := range map[string]func(f *fixture){
		"bad repo": func(f *fixture) { f.event["repository"] = map[string]any{"full_name": "o/r/../x"} },
		"bad sha":  func(f *fixture) { wr(f)["head_sha"] = "HEAD; rm -rf /" },
	} {
		t.Run(name, func(t *testing.T) {
			f := defaultFixture(t)
			mutate(f)
			if _, err := f.run(t); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

// submoduleFixture is a Dependabot submodule bump on the branch name of
// linkclean#12.
func submoduleFixture(t *testing.T) *fixture {
	const ref = "dependabot/submodules/tools/upstream/adblock-lists-9778b88"
	f := defaultFixture(t)
	wr(f)["head_branch"] = ref
	f.pr["head"].(map[string]any)["ref"] = ref
	f.ignore = map[model.Ecosystem]bool{model.GitSubmodule: true}
	return f
}

// ignore_ecosystems: only a PR that passes every identity check is ever
// ignored; everything else is classified exactly as without the input.
func TestClassifyIgnore(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(f *fixture)
		kind   model.Kind
		reason string
	}{
		{"ignored", func(f *fixture) {}, model.KindIgnored, "ignored ecosystem submodules"},
		{"ignored among others", func(f *fixture) {
			f.ignore = map[model.Ecosystem]bool{model.Docker: true, model.GitSubmodule: true}
		}, model.KindIgnored, "submodules"},
		{"input not set", func(f *fixture) { f.ignore = nil }, model.KindDependabot, ""},
		{"another ecosystem ignored", func(f *fixture) { f.ignore = map[model.Ecosystem]bool{model.Docker: true} }, model.KindDependabot, ""},
		{"go_modules PR, submodules ignored", func(f *fixture) {
			*f = *defaultFixture(t)
			f.ignore = map[model.Ecosystem]bool{model.GitSubmodule: true}
		}, model.KindDependabot, ""},
		// Fail closed: not Dependabot's alone goes to a human as before.
		{"pushed by a person", func(f *fixture) {
			mid := strings.Repeat("5", 40)
			f.activity = []map[string]any{act("branch_creation", "dependabot[bot]", zero, mid), act("push", "someone", mid, head)}
		}, model.KindDependabotUnverified, "someone other than dependabot"},
		{"not authored by dependabot", func(f *fixture) { f.pr["user"] = map[string]any{"login": "someone"} }, model.KindDependabotUnverified, "not authored"},
		{"unsigned", func(f *fixture) {
			f.commits[0]["commit"].(map[string]any)["verification"] = map[string]any{"verified": false}
		}, model.KindDependabotUnverified, "verified signature"},
		{"no rules", func(f *fixture) { f.rules = nil }, model.KindDependabotUnverified, "no active rule"},
		{"base changed", func(f *fixture) { f.timeline = []map[string]any{{"event": "base_ref_changed"}} }, model.KindDependabotUnverified, "base branch"},
		{"history behind the head", func(f *fixture) {
			f.activity = []map[string]any{act("branch_creation", "dependabot[bot]", zero, strings.Repeat("5", 40))}
		}, model.KindPending, "does not reach the head"},
		{"stale", func(f *fixture) { f.pr["state"] = "closed" }, model.KindStale, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := submoduleFixture(t)
			tt.mutate(f)
			got, err := f.run(t)
			if err != nil {
				t.Fatal(err)
			}
			if got.Kind != tt.kind {
				t.Fatalf("kind = %s (%s), want %s", got.Kind, got.Reason, tt.kind)
			}
			if tt.reason != "" && !strings.Contains(got.Reason, tt.reason) {
				t.Errorf("reason = %q, want %q", got.Reason, tt.reason)
			}
			if got.Kind == model.KindIgnored && (got.Ecosystem != model.GitSubmodule || got.HeadSHA != head) {
				t.Errorf("ignored record: %+v", got)
			}
		})
	}
}

package classify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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
	event    map[string]any
	pr       map[string]any
	commits  []map[string]any
	files    []map[string]any
	byCommit []map[string]any   // GET commits/{sha}/pulls
	activity []map[string]any   // GET activity?ref=<head branch>, oldest first
	actCode  int                // non-zero: GET activity fails with this status
	rulesets []map[string]any   // full rulesets; the list endpoint serves their summaries
	rsCode   int                // non-zero: GET rulesets fails with this status
	rsGet    int                // non-zero: GET rulesets/{id} fails with this status
	timeline []map[string]any   // GET issues/7/timeline
	actSeq   [][]map[string]any // successive activity responses (overrides activity)
	actCalls int
	sleeps   int
	tlCode   int // non-zero: GET timeline fails with this status
}

// dependabotRuleset is the ruleset the owner created in every repository.
func dependabotRuleset(id int, include ...string) map[string]any {
	if include == nil {
		include = []string{"refs/heads/dependabot/**"}
	}
	return map[string]any{
		"id": id, "name": "dependabot branches", "target": "branch", "enforcement": "active",
		"conditions": map[string]any{"ref_name": map[string]any{"include": include, "exclude": []string{}}},
		"rules":      []any{map[string]any{"type": "creation"}, map[string]any{"type": "update"}, map[string]any{"type": "deletion"}},
	}
}

const zero = "0000000000000000000000000000000000000000"

func act(typ, actor, before, after string) map[string]any {
	return map[string]any{"activity_type": typ, "actor": map[string]any{"login": actor}, "before": before, "after": after}
}

func defaultFixture(t *testing.T) *fixture {
	msg, err := os.ReadFile("testdata/msg_Espresso-Aficionados_sprobot_281.txt")
	if err != nil {
		t.Fatal(err)
	}
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
			"commit":    map[string]any{"message": string(msg), "verification": map[string]any{"verified": true, "reason": "valid"}},
		}},
		files:    []map[string]any{{"filename": "go.mod"}, {"filename": "go.sum"}},
		activity: []map[string]any{act("branch_creation", "dependabot[bot]", zero, head)},
		rulesets: []map[string]any{dependabotRuleset(42)},
	}
}

func (f *fixture) run(t *testing.T) (model.Classification, error) {
	t.Helper()
	mux := http.NewServeMux()
	js := func(v any) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(v) }
	}
	mux.Handle("GET /repos/o/r/pulls/7", js(f.pr))
	mux.Handle("GET /repos/o/r/pulls/7/commits", js(f.commits))
	mux.Handle("GET /repos/o/r/pulls/7/files", js(f.files))
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
	mux.HandleFunc("GET /repos/o/r/rulesets", func(w http.ResponseWriter, r *http.Request) {
		if f.rsCode != 0 {
			w.WriteHeader(f.rsCode)
			return
		}
		var list []map[string]any
		for _, rs := range f.rulesets {
			list = append(list, map[string]any{"id": rs["id"], "name": rs["name"], "target": rs["target"], "enforcement": rs["enforcement"]})
		}
		json.NewEncoder(w).Encode(list)
	})
	mux.HandleFunc("GET /repos/o/r/rulesets/{id}", func(w http.ResponseWriter, r *http.Request) {
		if f.rsGet != 0 {
			w.WriteHeader(f.rsGet)
			return
		}
		for _, rs := range f.rulesets {
			if fmt.Sprint(rs["id"]) == r.PathValue("id") {
				json.NewEncoder(w).Encode(rs)
				return
			}
		}
		http.NotFound(w, r)
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
	ev, _ := json.Marshal(f.event)
	return Classify(context.Background(), c, ev, Options{TriggerPath: trig, Logf: t.Logf, Sleep: func(context.Context, time.Duration) error {
		f.sleeps++
		return nil
	}})
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
		{"no metadata", func(f *fixture) { f.commits[0]["commit"].(map[string]any)["message"] = "Bump x" }, model.KindDependabotUnverified, "metadata"},
		{"unsafe file", func(f *fixture) { f.files = append(f.files, map[string]any{"filename": "../x"}) }, model.KindDependabotUnverified, "unsafe path"},
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
		// The dependabot/** ruleset that keeps everyone but Dependabot off
		// the branches. Its name and bypass list are not checked.
		{"ruleset renamed", func(f *fixture) { f.rulesets[0]["name"] = "anything" }, model.KindDependabot, ""},
		{"ruleset for all branches", func(f *fixture) { f.rulesets = []map[string]any{dependabotRuleset(1, "refs/heads/**")} }, model.KindDependabot, ""},
		{"ruleset for ~ALL", func(f *fixture) { f.rulesets = []map[string]any{dependabotRuleset(1, "~ALL")} }, model.KindDependabot, ""},
		{"matching ruleset after others", func(f *fixture) {
			other := dependabotRuleset(7, "~DEFAULT_BRANCH")
			off := dependabotRuleset(8)
			off["enforcement"] = "disabled"
			f.rulesets = []map[string]any{other, off, dependabotRuleset(9)}
		}, model.KindDependabot, ""},
		{"no rulesets", func(f *fixture) { f.rulesets = nil }, model.KindDependabotUnverified, "no active ruleset"},
		{"ruleset disabled", func(f *fixture) { f.rulesets[0]["enforcement"] = "disabled" }, model.KindDependabotUnverified, "no active ruleset"},
		{"ruleset only evaluated", func(f *fixture) { f.rulesets[0]["enforcement"] = "evaluate" }, model.KindDependabotUnverified, "no active ruleset"},
		{"tag ruleset", func(f *fixture) { f.rulesets[0]["target"] = "tag" }, model.KindDependabotUnverified, "no active ruleset"},
		{"single-level pattern", func(f *fixture) { f.rulesets = []map[string]any{dependabotRuleset(1, "refs/heads/dependabot/*")} }, model.KindDependabotUnverified, "no active ruleset"},
		{"other prefix", func(f *fixture) {
			f.rulesets = []map[string]any{dependabotRuleset(1, "refs/heads/dependabot/npm_and_yarn/**")}
		}, model.KindDependabotUnverified, "no active ruleset"},
		{"wildcard in prefix", func(f *fixture) { f.rulesets = []map[string]any{dependabotRuleset(1, "refs/heads/d*/**")} }, model.KindDependabotUnverified, "no active ruleset"},
		{"pattern without refs/heads", func(f *fixture) { f.rulesets = []map[string]any{dependabotRuleset(1, "dependabot/**")} }, model.KindDependabotUnverified, "no active ruleset"},
		{"exclusion under dependabot/", func(f *fixture) {
			f.rulesets[0]["conditions"] = map[string]any{"ref_name": map[string]any{"include": []string{"refs/heads/**"}, "exclude": []string{"refs/heads/dependabot/docker/**"}}}
		}, model.KindDependabotUnverified, "no active ruleset"},
		{"default branch excluded", func(f *fixture) {
			f.rulesets[0]["conditions"] = map[string]any{"ref_name": map[string]any{"include": []string{"refs/heads/**"}, "exclude": []string{"~DEFAULT_BRANCH", "refs/heads/release"}}}
		}, model.KindDependabot, ""},
		{"no deletion rule", func(f *fixture) {
			f.rulesets[0]["rules"] = []any{map[string]any{"type": "creation"}, map[string]any{"type": "update"}}
		}, model.KindDependabotUnverified, "no active ruleset"},
		{"update allows fetch and merge", func(f *fixture) {
			f.rulesets[0]["rules"] = []any{map[string]any{"type": "creation"}, map[string]any{"type": "update", "parameters": map[string]any{"update_allows_fetch_and_merge": true}}, map[string]any{"type": "deletion"}}
		}, model.KindDependabotUnverified, "no active ruleset"},
		{"no conditions", func(f *fixture) { delete(f.rulesets[0], "conditions") }, model.KindDependabotUnverified, "no active ruleset"},
		{"rulesets unreadable", func(f *fixture) { f.rsCode = http.StatusForbidden }, model.KindDependabotUnverified, "rulesets could not be read (HTTP 403)"},
		{"ruleset unreadable", func(f *fixture) { f.rsGet = http.StatusNotFound }, model.KindDependabotUnverified, "a ruleset could not be read (HTTP 404)"},
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

// The lag case reads the log 1+historyRetries times, sleeping between.
func TestClassifyPendingRetries(t *testing.T) {
	f := defaultFixture(t)
	f.activity = []map[string]any{act("branch_creation", "dependabot[bot]", zero, strings.Repeat("5", 40))}
	got, err := f.run(t)
	if err != nil || got.Kind != model.KindPending || f.actCalls != 1+historyRetries || f.sleeps != historyRetries {
		t.Errorf("kind %s err %v: %d reads, %d sleeps", got.Kind, err, f.actCalls, f.sleeps)
	}
	f = defaultFixture(t)
	if got, _ := f.run(t); got.Kind != model.KindDependabot || f.actCalls != 1 || f.sleeps != 0 {
		t.Errorf("clean log: kind %s, %d reads, %d sleeps", got.Kind, f.actCalls, f.sleeps)
	}
}

func TestClassifyRecord(t *testing.T) {
	f := defaultFixture(t)
	f.pr["labels"] = []any{map[string]any{"name": "security"}}
	f.pr["body"] = "Fixes GHSA-2c8g-pr4w-hjxw and GHSA-2c8g-pr4w-hjxw; not GHSA-aaaa-bbbb-1111"
	got, err := f.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if got.Repo != "o/r" || got.PR != 7 || got.HeadSHA != head || got.BaseSHA != base || got.BaseRef != "main" || !got.Private {
		t.Errorf("identity: %+v", got)
	}
	if got.Ecosystem != model.GoModules || len(got.Declared) != 2 || strings.Join(got.Files, ",") != "go.mod,go.sum" {
		t.Errorf("record: %+v", got)
	}
	d := got.Declared[1]
	if d.Name != "github.com/aws/aws-sdk-go-v2/service/s3" || d.From != "1.114.9" || d.To != "1.114.10" || d.Type != model.Patch || !d.Direct || !d.Security {
		t.Errorf("declared: %+v", d)
	}
	if len(d.Advisory) != 1 || d.Advisory[0] != "GHSA-2c8g-pr4w-hjxw" {
		t.Errorf("advisories: %v", d.Advisory)
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

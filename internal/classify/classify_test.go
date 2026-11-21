package classify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

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
	byCommit []map[string]any // GET commits/{sha}/pulls
	activity []map[string]any // GET activity?ref=<head branch>, oldest first
	actCode  int              // non-zero: GET activity fails with this status
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
		json.NewEncoder(w).Encode(f.activity)
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
	return Classify(context.Background(), c, ev, Options{TriggerPath: trig, Logf: t.Logf})
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
		{"history behind the head", func(f *fixture) {
			f.activity = []map[string]any{act("branch_creation", "dependabot[bot]", zero, strings.Repeat("5", 40))}
		}, model.KindDependabotUnverified, "does not reach the head"},
		{"history without the creation", func(f *fixture) {
			f.activity = []map[string]any{act("push", "dependabot[bot]", strings.Repeat("5", 40), head)}
		}, model.KindDependabotUnverified, "creation"},
		{"empty history", func(f *fixture) { f.activity = nil }, model.KindDependabotUnverified, "creation"},
		{"no actor", func(f *fixture) {
			f.activity = []map[string]any{{"activity_type": "branch_creation", "before": zero, "after": head}}
		}, model.KindDependabotUnverified, "someone other than dependabot"},
		{"history unreadable", func(f *fixture) { f.actCode = http.StatusForbidden }, model.KindDependabotUnverified, "could not be read (HTTP 403)"},
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

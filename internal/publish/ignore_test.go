package publish

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/model"
)

func TestDecideIgnored(t *testing.T) {
	in := reviewInputs()
	in.Class.Kind = model.KindIgnored
	if o := Decide(in); o.Decision != model.DecisionIgnore || o.State != "" {
		t.Errorf("outcome %+v", o)
	}
}

// gate.yml does not run publish for a dependabot-ignored PR; if it ever
// did, publish makes no request at all, even with approving artifacts.
func TestPublishIgnoredDoesNothing(t *testing.T) {
	f := newFake(t)
	cfg, n, _ := setup(t, f)
	in := reviewInputs()
	in.Class.Kind = model.KindIgnored
	if err := Publish(context.Background(), cfg, in); err != nil {
		t.Fatal(err)
	}
	if len(f.requests) != 0 || len(n.msgs) != 0 {
		t.Errorf("requests %v, notifications %v", f.requests, n.msgs)
	}
}

// Sweep skips a Dependabot PR whose branch names an ignored ecosystem
// before any request about it: no stuck report, no merge, no comment.
// Without the input the same PRs are swept as usual (the controls).
func TestSweepIgnoredEcosystem(t *testing.T) {
	const subRef = "dependabot/submodules/tools/upstream/adblock-lists-9778b88"
	sub := map[model.Ecosystem]bool{model.GitSubmodule: true}
	approve := func(f *fakeGH) {
		f.statuses[headSHA] = []map[string]any{{"context": "dep-review", "state": "success", "creator": map[string]any{"login": bot}}}
		c := &fakeComment{ID: 5, Body: marker{Approved: headSHA}.String() + "\n### dep-review: approved\n"}
		c.User.Login = bot
		f.comments[7] = []*fakeComment{c}
	}
	for _, tt := range []struct {
		name     string
		ref      string
		ignore   map[model.Ecosystem]bool
		approved bool
		skipped  bool
		notified int
		merged   bool
	}{
		{"stuck head, ignored", subRef, sub, false, true, 0, false},
		{"stuck head, control", subRef, nil, false, false, 1, false},
		{"approved head, ignored", subRef, sub, true, true, 0, false},
		{"approved head, control", subRef, nil, true, false, 0, true},
		{"other ecosystem ignored", subRef, map[model.Ecosystem]bool{model.Docker: true}, false, false, 1, false},
		{"go_modules PR, submodules ignored", "dependabot/go_modules/aws-1c8ebe5c54", sub, false, false, 1, false},
		{"not a dependabot/ branch", "submodules/x", sub, false, false, 1, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			f.prs[7]["head"].(map[string]any)["ref"] = tt.ref
			if tt.approved {
				approve(f)
			}
			cfg, n, ck := setup(t, f)
			cfg.IgnoreEcosystems = tt.ignore
			f.commitDate = ck.Now().Add(-5 * time.Hour)
			var logs []string
			cfg.Logf = func(format string, args ...any) {
				t.Logf(format, args...)
				logs = append(logs, format)
			}
			if err := Sweep(context.Background(), cfg, "o/r"); err != nil {
				t.Fatal(err)
			}
			if tt.skipped {
				if strings.Join(f.requests, ",") != "GET /repos/o/r/pulls" {
					t.Errorf("requests %v, want only the PR list", f.requests)
				}
				if !strings.Contains(strings.Join(logs, "\n"), "ignore_ecosystems") {
					t.Errorf("the skip is not logged: %v", logs)
				}
			}
			if len(n.msgs) != tt.notified || (len(f.merges) > 0) != tt.merged {
				t.Errorf("notifications %d (want %d), merges %d (want %v)", len(n.msgs), tt.notified, len(f.merges), tt.merged)
			}
		})
	}
}

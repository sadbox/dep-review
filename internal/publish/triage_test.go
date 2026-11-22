package publish

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/model"
)

// TestTriageNeverMerges (round 10): a PR that is human only because of
// triage findings shows the review's answer to the person deciding and
// never merges, however good the answer.
func TestTriageNeverMerges(t *testing.T) {
	flagged := []model.FlaggedItem{{Update: "github.com/x/y v1.2.3 -> v1.2.4", Code: "gomod.cgo", Item: "c.go"}}
	triage := model.Finding{Code: "gomod.cgo", Route: model.RouteHuman, Triage: true, Update: "github.com/x/y"}
	pass := func() []byte {
		b, _ := json.Marshal(model.Verdict{Verdict: model.Pass, Flags: []string{}, Summary: "includes nothing odd",
			Items: []model.ItemAssessment{{Update: flagged[0].Update, Code: flagged[0].Code, Item: flagged[0].Item, Assessment: model.Benign, Note: "links libc only"}}})
		return b
	}()
	ev := func(findings ...model.Finding) *model.Evidence {
		e := evidence(model.RouteHuman, patch, findings...)
		e.Flagged = flagged
		return e
	}
	tests := []struct {
		name    string
		ev      *model.Evidence
		triaged bool
	}{
		{"triage only", ev(triage), true},
		{"triage and a non-triage human finding", ev(triage, model.Finding{Code: "gomod.unparseable", Route: model.RouteHuman}), false},
		{"truncated", func() *model.Evidence { e := ev(triage); e.Truncated = true; return e }(), false},
		{"major update", func() *model.Evidence { e := ev(triage); e.Updates = major; return e }(), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := Decide(Inputs{Class: class(), FetchResult: "success", Evidence: tt.ev, ReviewResult: "success", Verdict: pass})
			if o.Decision != model.DecisionHuman || o.State != StateFailure {
				t.Fatalf("decision %s/%s (%s): triage must never merge", o.Decision, o.State, o.Reason)
			}
			if o.Triage != tt.triaged || (o.Verdict != nil) != tt.triaged {
				t.Errorf("triage %v verdict %v, want triage %v", o.Triage, o.Verdict != nil, tt.triaged)
			}
			out := renderComment(commentData{Class: class(), Evidence: tt.ev, Outcome: o})
			if has := strings.Contains(out, "#### Triage for the person deciding"); has != tt.triaged {
				t.Errorf("triage heading shown = %v, want %v:\n%s", has, tt.triaged, out)
			}
			if tt.triaged && !strings.Contains(out, "links libc only") {
				t.Errorf("per-item notes missing:\n%s", out)
			}
		})
	}
	// A refusal is never triage.
	ref := ev(triage, model.Finding{Code: "declared.to-mismatch", Route: model.RouteRefuse})
	ref.Route = model.RouteRefuse
	if o := Decide(Inputs{Class: class(), FetchResult: "success", Evidence: ref, ReviewResult: "success", Verdict: pass}); o.Triage || o.Decision == model.DecisionMerge {
		t.Errorf("refusal: %+v", o)
	}
}

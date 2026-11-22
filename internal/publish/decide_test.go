package publish

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/model"
)

const (
	headSHA = "1111111111111111111111111111111111111111"
	baseSHA = "2222222222222222222222222222222222222222"
)

func class() model.Classification {
	return model.Classification{
		Repo: "o/r", Private: true, PR: 7, HeadSHA: headSHA, BaseSHA: baseSHA, BaseRef: "main",
		Kind: model.KindDependabot, Reason: "authored, committed and signed by Dependabot only", Ecosystem: model.GoModules,
		Declared: []model.Update{{Ecosystem: model.GoModules, Name: "github.com/x/y", From: "1.2.3", To: "1.2.4", Type: model.Patch, Direct: true}},
	}
}

func evidence(route model.Route, updates []model.Update, findings ...model.Finding) *model.Evidence {
	return &model.Evidence{Classification: class(), Updates: updates, Findings: findings, Route: route}
}

var (
	patch = []model.Update{{Ecosystem: model.GoModules, Directory: "/", Name: "github.com/x/y", From: "1.2.3", To: "1.2.4", Type: model.Patch, Direct: true}}
	noop  = []model.Update{{Ecosystem: model.Docker, Directory: "/", Name: "golang", From: "1.27", To: "1.27", Type: model.Digest, Direct: true, NoOp: true}}
	major = []model.Update{{Ecosystem: model.GoModules, Directory: "/", Name: "github.com/x/y", From: "1.2.3", To: "2.0.0", Type: model.Major, Direct: true}}
)

func TestDecide(t *testing.T) {
	pass := []byte(`{"verdict":"pass","flags":[],"summary":"ok","items":[],"examined":[]}`)
	tests := []struct {
		name     string
		in       Inputs
		decision model.Decision
		state    string
		reason   string
	}{
		{"other", Inputs{Class: model.Classification{Kind: model.KindOther}}, model.DecisionIgnore, "", ""},
		{"stale", Inputs{Class: model.Classification{Kind: model.KindStale}}, model.DecisionIgnore, "", ""},
		{"unverified", Inputs{Class: func() model.Classification { c := class(); c.Kind = model.KindDependabotUnverified; return c }()}, model.DecisionHuman, StateFailure, "not verified"},
		{"unknown kind", Inputs{Class: func() model.Classification { c := class(); c.Kind = "bogus"; return c }()}, model.DecisionHuman, StateFailure, "unknown"},
		{"fetch failed", Inputs{Class: class(), FetchResult: "failure"}, model.DecisionPending, StateError, "(failure)"},
		{"fetch cancelled with evidence", Inputs{Class: class(), FetchResult: "cancelled", Evidence: evidence(model.RouteReview, patch)}, model.DecisionPending, StateError, "cancelled"},
		{"fetch weird result", Inputs{Class: class(), FetchResult: "$(id)"}, model.DecisionPending, StateError, "(unknown)"},
		{"no evidence", Inputs{Class: class(), FetchResult: "success"}, model.DecisionPending, StateError, "no evidence"},
		{"refusal despite failed fetch", Inputs{Class: class(), FetchResult: "failure", Evidence: evidence(model.RouteRefuse, nil, model.Finding{Code: "refuse.no-updates", Route: model.RouteRefuse})}, model.DecisionHuman, StateFailure, "refused this pull request: refuse.no-updates"},
		{"auto", Inputs{Class: class(), FetchResult: "success", Evidence: evidence(model.RouteAuto, noop)}, model.DecisionMerge, StateSuccess, "no-op"},
		{"auto claimed but not no-op", Inputs{Class: class(), FetchResult: "success", Evidence: evidence(model.RouteAuto, patch), ReviewResult: "skipped"}, model.DecisionHuman, StateFailure, "no verdict"},
		{"empty route", Inputs{Class: class(), FetchResult: "success", Evidence: evidence("", noop)}, model.DecisionHuman, StateFailure, "refused"},
		{"unknown finding route", Inputs{Class: class(), FetchResult: "success", Evidence: evidence(model.RouteAuto, noop, model.Finding{Code: "x.y", Route: "meh"})}, model.DecisionHuman, StateFailure, "refused this pull request: x.y"},
		{"review pass", Inputs{Class: class(), FetchResult: "success", Evidence: evidence(model.RouteReview, patch), ReviewResult: "success", Verdict: pass}, model.DecisionMerge, StateSuccess, "approved"},
		{"review pass, review job failed", Inputs{Class: class(), FetchResult: "success", Evidence: evidence(model.RouteReview, patch), ReviewResult: "failure", Verdict: pass}, model.DecisionHuman, StateFailure, "no verdict (failure)"},
		{"review missing verdict", Inputs{Class: class(), FetchResult: "success", Evidence: evidence(model.RouteReview, patch), ReviewResult: "success"}, model.DecisionHuman, StateFailure, "no verdict"},
		{"review fail", Inputs{Class: class(), FetchResult: "success", Evidence: evidence(model.RouteReview, patch), ReviewResult: "success", Verdict: []byte(`{"verdict":"fail","flags":["network-access-added"],"summary":"x","items":[],"examined":[]}`)}, model.DecisionHuman, StateFailure, "answered fail"},
		{"review unsure", Inputs{Class: class(), FetchResult: "success", Evidence: evidence(model.RouteReview, patch), ReviewResult: "success", Verdict: []byte(`{"verdict":"unsure","flags":["evidence-incomplete"],"summary":"x","items":[],"examined":[]}`)}, model.DecisionHuman, StateFailure, "answered unsure"},
		{"review pass with flags", Inputs{Class: class(), FetchResult: "success", Evidence: evidence(model.RouteReview, patch), ReviewResult: "success", Verdict: []byte(`{"verdict":"pass","flags":["default-changed"],"summary":"x","items":[],"examined":[]}`)}, model.DecisionHuman, StateFailure, "raised flags"},
		{"review invalid verdict", Inputs{Class: class(), FetchResult: "success", Evidence: evidence(model.RouteReview, patch), ReviewResult: "success", Verdict: []byte(`{"verdict":"PASS","flags":[],"summary":"x","items":[],"examined":[]}`)}, model.DecisionHuman, StateFailure, "failed validation"},
		{"review route but major", Inputs{Class: class(), FetchResult: "success", Evidence: evidence(model.RouteReview, major), ReviewResult: "success", Verdict: pass}, model.DecisionHuman, StateFailure, "version policy"},
		{"human finding", Inputs{Class: class(), FetchResult: "success", Evidence: evidence(model.RouteHuman, patch, model.Finding{Code: "npm.install-script-added", Route: model.RouteHuman, Detail: "x"})}, model.DecisionHuman, StateFailure, "npm.install-script-added"},
		{"finding code sanitized", Inputs{Class: class(), FetchResult: "success", Evidence: evidence(model.RouteHuman, patch, model.Finding{Code: "@evil <b>", Route: model.RouteHuman})}, model.DecisionHuman, StateFailure, "unnamed-finding"},
		{"truncated", Inputs{Class: class(), FetchResult: "success", Evidence: func() *model.Evidence { e := evidence(model.RouteReview, patch); e.Truncated = true; return e }(), ReviewResult: "success", Verdict: pass}, model.DecisionHuman, StateFailure, "truncated"},
		{"evidence for other head", Inputs{Class: class(), FetchResult: "success", Evidence: func() *model.Evidence {
			e := evidence(model.RouteAuto, noop)
			e.Classification.HeadSHA = baseSHA
			return e
		}()}, model.DecisionHuman, StateFailure, "different"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := Decide(tt.in)
			if o.Decision != tt.decision || o.State != tt.state {
				t.Fatalf("got %s/%s (%s), want %s/%s", o.Decision, o.State, o.Reason, tt.decision, tt.state)
			}
			if !strings.Contains(o.Reason, tt.reason) {
				t.Errorf("reason %q, want %q", o.Reason, tt.reason)
			}
		})
	}
}

func TestParseVerdict(t *testing.T) {
	long := strings.Repeat("é", summaryMax)
	tests := []struct {
		raw string
		ok  bool
	}{
		{`{"verdict":"pass","flags":[],"summary":"ok","items":[],"examined":[]}`, true},
		{`{"verdict":"fail","flags":["network-access-added","new-dependency"],"summary":"","items":[],"examined":[]}`, true},
		{`{"verdict":"pass","flags":[],"summary":"` + long + `","items":[],"examined":[]}`, true},
		{`{"verdict":"pass","flags":[],"summary":"` + long + `x","items":[],"examined":[]}`, false},
		{`{"verdict":"pass","flags":[],"summary":"ok","extra":1}`, false},
		{`{"verdict":"pass","flags":[]}`, false},
		{`{"verdict":"pass","flags":null,"summary":"ok","items":[],"examined":[]}`, false},
		{`{"verdict":"pass","flags":["made-up"],"summary":"ok","items":[],"examined":[]}`, false},
		{`{"verdict":"pass","flags":["new-dependency","new-dependency"],"summary":"ok","items":[],"examined":[]}`, false},
		{`{"verdict":"maybe","flags":[],"summary":"ok","items":[],"examined":[]}`, false},
		{`{"verdict":"pass","flags":[],"summary":null}`, false},
		{`{"verdict":"pass","flags":[],"summary":"ok","items":[],"examined":[]} {"verdict":"pass"}`, false},
		{`["pass"]`, false},
		{``, false},
		{`{"verdict":"pass","flags":["a","b","c","d","e","f","g","h","i","j","k","l","m"],"summary":"ok","items":[],"examined":[]}`, false},
	}
	for _, tt := range tests {
		_, err := ParseVerdict([]byte(tt.raw))
		if (err == nil) != tt.ok {
			t.Errorf("ParseVerdict(%.60s) err = %v, want ok=%v", tt.raw, err, tt.ok)
		}
	}
}

// The flag enum and limits here must match schema/verdict.json.
func TestSchemaInSync(t *testing.T) {
	b, err := os.ReadFile("../../schema/verdict.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Properties struct {
			Verdict struct {
				Enum []string `json:"enum"`
			} `json:"verdict"`
			Flags struct {
				MaxItems int `json:"maxItems"`
				Items    struct {
					Enum []string `json:"enum"`
				} `json:"items"`
			} `json:"flags"`
			Summary struct {
				MaxLength int `json:"maxLength"`
			} `json:"summary"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.Properties.Flags.Items.Enum, Flags) {
		t.Errorf("flags enum differs from schema")
	}
	if s.Properties.Flags.MaxItems != maxFlags || s.Properties.Summary.MaxLength != summaryMax {
		t.Errorf("limits differ from schema")
	}
	if !reflect.DeepEqual(s.Properties.Verdict.Enum, []string{"pass", "fail", "unsure"}) {
		t.Errorf("verdict enum differs from schema")
	}
}

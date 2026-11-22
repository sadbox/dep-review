package publish

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/model"
)

func TestParseVerdictItems(t *testing.T) {
	item := func(extra string) string {
		return `{"update":"github.com/x/y","code":"gomod.init-changed","item":"a.go","assessment":"benign","note":"registers a codec","commits":[]` + extra + `}`
	}
	many := make([]string, model.MaxFlagged+1)
	for i := range many {
		many[i] = strings.Replace(item(""), `"a.go"`, fmt.Sprintf(`"f%d.go"`, i), 1)
	}
	tests := []struct {
		name  string
		items string
		ok    bool
	}{
		{"empty", `[]`, true},
		{"one", `[` + item("") + `]`, true},
		{"max", `[` + strings.Join(many[:model.MaxFlagged], ",") + `]`, true},
		// The gate's longest ids (module path and two versions) fit.
		{"longest item", `[` + strings.Replace(item(""), `"a.go"`, `"`+strings.Repeat("a", model.MaxItemField)+`"`, 1) + `]`, true},
		{"longest update", `[` + strings.Replace(item(""), `"github.com/x/y"`, `"`+strings.Repeat("u", 605)+`"`, 1) + `]`, true},
		{"suspicious is valid", `[` + strings.Replace(item(""), "benign", "suspicious", 1) + `]`, true},
		{"unclear is valid", `[` + strings.Replace(item(""), "benign", "unclear", 1) + `]`, true},
		{"unknown assessment", `[` + strings.Replace(item(""), "benign", "fine", 1) + `]`, false},
		{"extra field", `[` + item(`,"merge":true`) + `]`, false},
		{"missing note", `[` + strings.Replace(item(""), `,"note":"registers a codec"`, "", 1) + `]`, false},
		{"missing commits", `[` + strings.Replace(item(""), `,"commits":[]`, "", 1) + `]`, false},
		{"null commits", `[` + strings.Replace(item(""), `"commits":[]`, `"commits":null`, 1) + `]`, false},
		{"commit cited", `[` + strings.Replace(item(""), `"commits":[]`, `"commits":["`+strings.Repeat("ab", 20)+`"]`, 1) + `]`, true},
		{"short commit", `[` + strings.Replace(item(""), `"commits":[]`, `"commits":["abcdef1"]`, 1) + `]`, false},
		{"uppercase commit", `[` + strings.Replace(item(""), `"commits":[]`, `"commits":["`+strings.Repeat("AB", 20)+`"]`, 1) + `]`, false},
		{"repeated commit", `[` + strings.Replace(item(""), `"commits":[]`, `"commits":["`+strings.Repeat("ab", 20)+`","`+strings.Repeat("ab", 20)+`"]`, 1) + `]`, false},
		{"commit not a string", `[` + strings.Replace(item(""), `"commits":[]`, `"commits":[1]`, 1) + `]`, false},
		{"duplicate", `[` + item("") + `,` + item("") + `]`, false},
		{"null", `null`, false},
		{"not an array", `{}`, false},
		{"note too long", `[` + strings.Replace(item(""), "registers a codec", strings.Repeat("n", itemNoteMax+1), 1) + `]`, false},
		{"item too long", `[` + strings.Replace(item(""), `"a.go"`, `"`+strings.Repeat("a", itemFieldMax+1)+`"`, 1) + `]`, false},
		{"too many", `[` + strings.Join(many, ",") + `]`, false},
		// encoding/json would bind "Assessment" to the field; strictjson refuses.
		{"case-folded key", `[` + strings.Replace(item(""), `"assessment"`, `"Assessment"`, 1) + `]`, false},
		{"duplicate key", `[` + item(`,"assessment":"suspicious"`) + `]`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := `{"verdict":"pass","flags":[],"summary":"ok","items":` + tt.items + `,"examined":[]}`
			_, err := ParseVerdict([]byte(raw))
			if (err == nil) != tt.ok {
				t.Errorf("err = %v, want ok=%v", err, tt.ok)
			}
		})
	}
	if _, err := ParseVerdict([]byte(`{"verdict":"pass","flags":[],"summary":"ok"}`)); err == nil {
		t.Errorf("a verdict without items parsed")
	}
}

// TestDecideAccounting: a pass merges only when the verdict assesses
// every item the evidence flagged, as benign, and nothing else.
func TestDecideAccounting(t *testing.T) {
	flagged := []model.FlaggedItem{
		{Update: "github.com/x/y", Code: "gomod.init-changed", Item: "a.go"},
		{Update: "github.com/x/y", Code: "gomod.init-callee-changed", Item: "./helper"},
	}
	ev := func(items []model.FlaggedItem) *model.Evidence {
		e := evidence(model.RouteReview, patch, model.Finding{Code: "gomod.init-changed", Route: model.RouteReview, Update: "github.com/x/y"})
		e.Flagged = items
		return e
	}
	verdict := func(items ...model.ItemAssessment) []byte {
		v := model.Verdict{Verdict: model.Pass, Flags: []string{}, Summary: "ok", Items: items, Examined: []string{}}
		if v.Items == nil {
			v.Items = []model.ItemAssessment{}
		}
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	as := func(f model.FlaggedItem, a model.Assessment) model.ItemAssessment {
		return model.ItemAssessment{Update: f.Update, Code: f.Code, Item: f.Item, Assessment: a, Note: "n", Commits: []string{}}
	}
	c1, c2, c3 := strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40)
	cite := func(a model.ItemAssessment, cs ...string) model.ItemAssessment {
		a.Commits = cs
		return a
	}
	up := func(st model.UpstreamStatus) *model.Evidence {
		e := ev(flagged)
		e.Upstream = []model.Upstream{{Update: "github.com/x/y", Status: st, Items: []model.UpstreamItem{
			{Code: flagged[0].Code, Item: flagged[0].Item, Commits: []string{c1, c2}},
		}}}
		return e
	}
	upOther := func() *model.Evidence {
		e := ev(flagged)
		e.Upstream = []model.Upstream{{Update: "github.com/other", Status: model.UpstreamVerified, Items: []model.UpstreamItem{
			{Code: flagged[0].Code, Item: flagged[0].Item, Commits: []string{c1}},
		}}}
		return e
	}
	many := make([]model.FlaggedItem, model.MaxFlagged+1)
	manyBenign := make([]model.ItemAssessment, model.MaxFlagged)
	for i := range many {
		many[i] = model.FlaggedItem{Update: "github.com/x/y", Code: "gomod.binary-file", Item: fmt.Sprintf("f%d", i)}
		if i < model.MaxFlagged {
			manyBenign[i] = as(many[i], model.Benign)
		}
	}
	tests := []struct {
		name     string
		ev       *model.Evidence
		verdict  []byte
		decision model.Decision
		reason   string
	}{
		{"all benign", ev(flagged), verdict(as(flagged[0], model.Benign), as(flagged[1], model.Benign)), model.DecisionMerge, "approved"},
		{"order does not matter", ev(flagged), verdict(as(flagged[1], model.Benign), as(flagged[0], model.Benign)), model.DecisionMerge, "approved"},
		{"nothing flagged, nothing listed", ev(nil), verdict(), model.DecisionMerge, "approved"},
		{"one missing", ev(flagged), verdict(as(flagged[0], model.Benign)), model.DecisionHuman, "did not assess 1 of 2"},
		{"none assessed", ev(flagged), verdict(), model.DecisionHuman, "did not assess 2 of 2"},
		{"unclear", ev(flagged), verdict(as(flagged[0], model.Benign), as(flagged[1], model.Unclear)), model.DecisionHuman, "1 unclear"},
		{"suspicious", ev(flagged), verdict(as(flagged[0], model.Suspicious), as(flagged[1], model.Benign)), model.DecisionHuman, "1 suspicious"},
		{"extra item", ev(flagged), verdict(as(flagged[0], model.Benign), as(flagged[1], model.Benign),
			model.ItemAssessment{Update: "github.com/x/y", Code: "gomod.init-changed", Item: "b.go", Assessment: model.Benign, Note: "n", Commits: []string{}}), model.DecisionHuman, "1 item the gate did not flag"},
		{"item of another update", ev(flagged), verdict(as(flagged[0], model.Benign),
			model.ItemAssessment{Update: "github.com/other", Code: flagged[1].Code, Item: flagged[1].Item, Assessment: model.Benign, Note: "n", Commits: []string{}}), model.DecisionHuman, "did not assess 1 of 2"},
		{"no flagged, item listed", ev(nil), verdict(as(flagged[0], model.Benign)), model.DecisionHuman, "did not flag"},
		{"too many flagged", ev(many), verdict(manyBenign...), model.DecisionHuman, "too many"},
		{"duplicate flagged entry", ev(append(flagged, flagged[0])), verdict(as(flagged[0], model.Benign), as(flagged[1], model.Benign)), model.DecisionHuman, "flagged list"},
		// Upstream citations: where commits are listed for an item of a
		// verified update, benign needs one of them and nothing else.
		{"cites a listed commit", up(model.UpstreamVerified), verdict(cite(as(flagged[0], model.Benign), c1), as(flagged[1], model.Benign)), model.DecisionMerge, "approved"},
		{"cites two listed commits", up(model.UpstreamVerified), verdict(cite(as(flagged[0], model.Benign), c1, c2), as(flagged[1], model.Benign)), model.DecisionMerge, "approved"},
		{"cites nothing", up(model.UpstreamVerified), verdict(as(flagged[0], model.Benign), as(flagged[1], model.Benign)), model.DecisionHuman, "cleared 1 item without citing"},
		{"cites an unlisted commit", up(model.UpstreamVerified), verdict(cite(as(flagged[0], model.Benign), c1, c3), as(flagged[1], model.Benign)), model.DecisionHuman, "cleared 1 item without citing"},
		{"cites where none are listed", up(model.UpstreamVerified), verdict(cite(as(flagged[0], model.Benign), c1), cite(as(flagged[1], model.Benign), c1)), model.DecisionHuman, "cleared 1 item without citing"},
		{"unavailable needs no citation", up(model.UpstreamUnavailable), verdict(as(flagged[0], model.Benign), as(flagged[1], model.Benign)), model.DecisionMerge, "approved"},
		{"unavailable refuses citations", up(model.UpstreamUnavailable), verdict(cite(as(flagged[0], model.Benign), c1), as(flagged[1], model.Benign)), model.DecisionHuman, "cleared 1 item without citing"},
		{"listed for another update", upOther(), verdict(as(flagged[0], model.Benign), as(flagged[1], model.Benign)), model.DecisionMerge, "approved"},
		{"unclear stays unclear", up(model.UpstreamVerified), verdict(cite(as(flagged[0], model.Unclear), c1), as(flagged[1], model.Benign)), model.DecisionHuman, "1 unclear"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := Decide(Inputs{Class: class(), FetchResult: "success", Evidence: tt.ev, ReviewResult: "success", Verdict: tt.verdict})
			if o.Decision != tt.decision {
				t.Fatalf("decision %s (%s), want %s", o.Decision, o.Reason, tt.decision)
			}
			if !strings.Contains(o.Reason, tt.reason) {
				t.Errorf("reason %q, want %q", o.Reason, tt.reason)
			}
		})
	}
}

// TestExaminedAll: every required diff must be listed as examined, and
// nothing the evidence does not have.
func TestExaminedAll(t *testing.T) {
	diffs := []model.DiffFile{{ID: "D00001", Required: true}, {ID: "D00002", Required: true}, {ID: "D00003"}}
	tests := []struct {
		name     string
		diffs    []model.DiffFile
		examined []string
		ok       bool
		why      string
	}{
		{"all required", diffs, []string{"D00002", "D00001"}, true, ""},
		{"optional too", diffs, []string{"D00001", "D00002", "D00003"}, true, ""},
		{"one missing", diffs, []string{"D00001", "D00003"}, false, "did not list 1 of 2 required"},
		{"unknown", diffs, []string{"D00001", "D00002", "D00009"}, false, "1 diff the evidence does not have"},
		{"no diffs", nil, []string{}, true, ""},
		{"no diffs, one listed", nil, []string{"D00001"}, false, "does not have"},
	}
	for _, tt := range tests {
		ok, why := examinedAll(tt.diffs, tt.examined)
		if ok != tt.ok || !strings.Contains(why, tt.why) {
			t.Errorf("%s: %v %q", tt.name, ok, why)
		}
	}
	many := make([]model.DiffFile, model.MaxRequiredDiffs+1)
	ids := make([]string, len(many))
	for i := range many {
		many[i] = model.DiffFile{ID: fmt.Sprintf("D%05d", i+1), Required: true}
		ids[i] = many[i].ID
	}
	if ok, why := examinedAll(many, ids); ok || !strings.Contains(why, "too many") {
		t.Errorf("too many required: %v %q", ok, why)
	}
	// The decision: an accounted pass still needs the diffs examined.
	ev := evidence(model.RouteReview, patch)
	ev.Diffs = diffs
	for _, tt := range []struct {
		examined string
		decision model.Decision
	}{{`["D00001","D00002"]`, model.DecisionMerge}, {`["D00001"]`, model.DecisionHuman}} {
		o := Decide(Inputs{Class: class(), FetchResult: "success", Evidence: ev, ReviewResult: "success",
			Verdict: []byte(`{"verdict":"pass","flags":[],"summary":"ok","items":[],"examined":` + tt.examined + `}`)})
		if o.Decision != tt.decision {
			t.Errorf("examined %s: %s (%s)", tt.examined, o.Decision, o.Reason)
		}
	}
}

func TestParseVerdictExamined(t *testing.T) {
	for raw, ok := range map[string]bool{
		`[]`:                  true,
		`["D00001","D12345"]`: true,
		`["D0001"]`:           false,
		`["d00001"]`:          false,
		`["D00001","D00001"]`: false,
		`[1]`:                 false,
		`null`:                false,
		`{}`:                  false,
	} {
		_, err := ParseVerdict([]byte(`{"verdict":"pass","flags":[],"summary":"ok","items":[],"examined":` + raw + `}`))
		if (err == nil) != ok {
			t.Errorf("examined %s: err %v, want ok=%v", raw, err, ok)
		}
	}
	if _, err := ParseVerdict([]byte(`{"verdict":"pass","flags":[],"summary":"ok","items":[]}`)); err == nil {
		t.Error("a verdict without examined parsed")
	}
}

// TestRenderItems: the comment shows each flagged item with the gate's
// strings, the stoppers first; model notes are sanitized and an item the
// gate did not flag is only counted.
func TestRenderItems(t *testing.T) {
	ev := evidence(model.RouteReview, patch)
	ev.Flagged = []model.FlaggedItem{
		{Update: "github.com/x/y", Code: "gomod.init-changed", Item: "a.go"},
		{Update: "github.com/x/y", Code: "gomod.binary-file", Item: "x.syso"},
		{Update: "github.com/x/y", Code: "gomod.linkname", Item: "l.go"},
	}
	v := model.Verdict{Verdict: model.Pass, Summary: "s", Items: []model.ItemAssessment{
		{Update: "github.com/x/y", Code: "gomod.init-changed", Item: "a.go", Assessment: model.Benign, Note: "registers a codec"},
		{Update: "github.com/x/y", Code: "gomod.binary-file", Item: "x.syso", Assessment: model.Suspicious, Note: "ask @someone see https://evil.example/x `code`"},
		{Update: "github.com/x/y", Code: "gomod.init-changed", Item: "INJECTED <b>row</b>", Assessment: model.Benign, Note: "n"},
	}}
	out := renderComment(commentData{Class: class(), Evidence: ev, Outcome: Outcome{Decision: model.DecisionHuman, Verdict: &v}})
	if !strings.Contains(out, "#### Flagged items (3): 1 benign, 1 suspicious, 0 unclear, 1 not assessed; 1 listed by the reviewer that the gate did not flag") {
		t.Errorf("counts line missing:\n%s", out)
	}
	// Inline neutralizes mentions and backticks; the note stays inside a
	// code span, where GitHub links nothing.
	if strings.Contains(out, "INJECTED") || strings.Contains(out, "@someone") || strings.Contains(out, "`code`") {
		t.Errorf("unsanitized model text in the comment:\n%s", out)
	}
	notAssessed := strings.Index(out, "`l.go`")
	suspicious := strings.Index(out, "`x.syso`")
	benign := strings.Index(out, "`a.go`")
	if !(notAssessed >= 0 && notAssessed < suspicious && suspicious < benign) {
		t.Errorf("rows out of order (%d %d %d):\n%s", notAssessed, suspicious, benign, out)
	}
}

// The items limits here must match schema/verdict.json.
func TestItemsSchemaInSync(t *testing.T) {
	b, err := os.ReadFile("../../schema/verdict.json")
	if err != nil {
		t.Fatal(err)
	}
	type str struct {
		Type      string   `json:"type"`
		MaxLength int      `json:"maxLength"`
		Enum      []string `json:"enum"`
	}
	var s struct {
		Required   []string `json:"required"`
		Properties struct {
			Items struct {
				MaxItems int `json:"maxItems"`
				Items    struct {
					AdditionalProperties *bool          `json:"additionalProperties"`
					Required             []string       `json:"required"`
					Properties           map[string]str `json:"properties"`
				} `json:"items"`
			} `json:"items"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.Required, []string{"verdict", "flags", "summary", "items", "examined"}) {
		t.Errorf("required = %q", s.Required)
	}
	it := s.Properties.Items
	if it.MaxItems != model.MaxFlagged {
		t.Errorf("items maxItems = %d, want %d", it.MaxItems, model.MaxFlagged)
	}
	if it.Items.AdditionalProperties == nil || *it.Items.AdditionalProperties {
		t.Errorf("items allow additional properties")
	}
	want := []string{"update", "code", "item", "assessment", "note", "commits"}
	if !reflect.DeepEqual(it.Items.Required, want) || len(it.Items.Properties) != len(want) {
		t.Errorf("item fields = %q / %v", it.Items.Required, it.Items.Properties)
	}
	for _, k := range []string{"update", "code", "item"} {
		if p := it.Items.Properties[k]; p.MaxLength != itemFieldMax {
			t.Errorf("%s maxLength = %d, want %d", k, p.MaxLength, itemFieldMax)
		}
	}
	if p := it.Items.Properties["note"]; p.MaxLength != itemNoteMax {
		t.Errorf("note maxLength = %d, want %d", p.MaxLength, itemNoteMax)
	}
	if p := it.Items.Properties["assessment"]; !reflect.DeepEqual(p.Enum, []string{"benign", "suspicious", "unclear"}) {
		t.Errorf("assessment enum = %q", p.Enum)
	}
}

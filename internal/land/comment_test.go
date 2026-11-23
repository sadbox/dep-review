package land

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/wire"
)

// payload is what a hostile publisher, registry or model would put in any
// text the gate shows: a way out of the code span and of the table cell
// (also behind a backslash), HTML, the end of an HTML comment, a link, a
// mention, a command for a bot, an issue reference, a heading on a line
// of its own, and characters that hide or reorder text (a line separator,
// a right-to-left override, a zero-width space, NUL, an escape sequence
// and a byte that is not UTF-8). It is short enough to be shown whole, so
// all of it is put to the test.
const payload = " ` `` | \\| <img src=x> --> [l](//evil.example) @octocat @dependabot merge #1 \r\n### evil\n\n| a | b |" +
	"\xe2\x80\xa8<!-- \xe2\x80\xae\xe2\x80\x8b\x00\x1b[31m \xff end"

// hostile returns a value for one third-party field: a tag that names the
// field, then the payload. The tags are collected so the test can ask
// where each one ended up.
type hostile struct{ tags []string }

func (h *hostile) text(field string) string {
	tag := fmt.Sprintf("FIELD%03d-%s-", len(h.tags), field)
	h.tags = append(h.tags, tag)
	return tag + payload
}

func (h *hostile) fact(field string, ok bool) allow.Fact {
	return allow.Fact{OK: ok, Value: h.text(field + ".value"), Source: h.text(field + ".source")}
}

func (h *hostile) time(field string) allow.TimeFact {
	return allow.TimeFact{OK: true, Time: t0, Value: h.text(field + ".value"), Source: h.text(field + ".source")}
}

// codeSpanRE is a code span on one line, as the gate writes them.
var codeSpanRE = regexp.MustCompile("`[^`\n]+`")

// TestCommentWithHostileText puts the payload in every field that holds
// text the gate did not write, renders every kind of comment, and checks
// that each field shows up, and only ever inside a one-line code span.
func TestCommentWithHostileText(t *testing.T) {
	h := &hostile{}
	update := func(n int) allow.UpdateFacts {
		p := fmt.Sprintf("update%d.", n)
		return allow.UpdateFacts{
			Name: h.text(p + "name"), From: h.text(p + "from"), To: h.text(p + "to"),
			Known: h.fact(p+"known", true), Listed: h.fact(p+"listed", false), NewName: h.fact(p+"new_name", true),
			Increase: h.fact(p+"increase", true), Major: h.fact(p+"major", false), Indirect: h.fact(p+"indirect", false), Bound: h.fact(p+"bound", false),
			FirstSeen: h.time(p + "first_seen"), NameCreated: h.time(p + "name_created"),
			Clean: h.fact(p+"clean", true), NoRegress: h.fact(p+"no_regress", true),
			SecurityFix: h.fact(p+"security_fix", false), Superseded: h.fact(p+"superseded", false),
			Read: allow.ReadPartial,
			Veto: &allow.Veto{
				Category: h.text(p + "veto.category"),
				Quotes:   []string{h.text(p + "veto.quote0"), h.text(p + "veto.quote1")},
				Notes:    h.text(p + "veto.notes"),
			},
		}
	}
	facts := allow.PRFacts{
		Ecosystem: h.text("ecosystem"),
		Identity:  h.fact("identity", false), Shape: h.fact("shape", true), ChecksConfigured: h.fact("checks_configured", true),
		Updates: []allow.UpdateFacts{update(0), update(1)},
	}
	// What fetch says about a read it did not prepare, and one it did.
	file := wire.Facts{GatheredAt: t0, Facts: wire.PRFacts{Updates: []wire.Update{
		{Prepared: wire.Read{Status: wire.Unavailable, Detail: h.text("update0.prepared.detail")}},
		{Prepared: wire.Read{Status: wire.Prepared, Unread: []artifact.Unread{{Path: h.text("update1.unread.path")}}}},
	}}}
	ev := Evaluation{PullRequest: wire.PullRequest{Repo: testRepo, Number: testPR, Head: headA}, Facts: facts, file: file, now: t0}
	perUpdate := []allow.UpdateDecision{
		{Outcome: allow.Person, Reasons: []allow.Reason{allow.ReasonVeto, allow.ReasonNotBound}},
		{Outcome: allow.Wait, Reasons: []allow.Reason{allow.ReasonAge}, NotBefore: t0.Add(time.Hour)},
	}
	note := h.text("github.refusal")
	// The ecosystem and the unread paths are not shown at all; every
	// other field must be.
	hidden := map[string]bool{}
	for _, tag := range h.tags {
		hidden[tag] = strings.Contains(tag, "-ecosystem-") || strings.Contains(tag, ".unread.path-")
	}

	// A marker that remembers the same hostile veto, as cacheEntries
	// would store it.
	veto := allow.Veto{Category: "exfiltration", Quotes: []string{cut(payload)}, Notes: cut(payload)}
	m := marker{Outcome: ActionPerson, Head: headA, Fingerprint: strings.Repeat("f", 64),
		Cache: []cached{{Key: keyA, Read: allow.ReadPartial, Veto: &veto}}}

	for _, tc := range []struct {
		name string
		res  Result
	}{
		{"person on a veto", Result{Action: ActionPerson, Decision: allow.Decision{Outcome: allow.Person,
			Reasons: []allow.Reason{allow.ReasonVeto, allow.ReasonNotBound}, PerUpdate: perUpdate}}},
		{"person on a pull request fact", Result{Action: ActionPerson, Decision: allow.Decision{Outcome: allow.Person,
			Reasons: []allow.Reason{allow.ReasonIdentity}, PerUpdate: perUpdate}}},
		{"wait", Result{Action: ActionWait, Decision: allow.Decision{Outcome: allow.Wait,
			Reasons: []allow.Reason{allow.ReasonAge}, NotBefore: t0.Add(time.Hour), Deadline: t0.Add(48 * time.Hour), PerUpdate: perUpdate}}},
		{"merged", Result{Action: ActionMerged, Decision: allow.Decision{Outcome: allow.Merge, PerUpdate: perUpdate}}},
		{"refused", Result{Action: ActionRefused, Note: note, Decision: allow.Decision{Outcome: allow.Merge, PerUpdate: perUpdate}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := render(view{res: tc.res, ev: ev, marker: m, runURL: "https://github.com/o/r/actions/runs/1"})

			if !utf8.ValidString(out) {
				t.Error("the comment is not valid UTF-8")
			}
			for _, r := range out {
				if r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029') {
					t.Errorf("the comment has the character %U", r)
				}
			}
			// The marker's own end is the only "-->", and nothing else in
			// the comment could open or close HTML.
			lines := strings.Split(out, "\n")
			if strings.Count(out, "-->") != 1 || !strings.HasSuffix(lines[0], " -->") || strings.ContainsAny(strings.Join(lines[1:], "\n"), "<>") {
				t.Errorf("an HTML comment or tag can start or end outside the marker line")
			}
			if got, ok := parseMarker(out); !ok || len(got.Cache) != 1 || !strings.Contains(got.Cache[0].Veto.Notes, "-->") {
				t.Errorf("the marker does not carry the hostile veto back: %+v (ok %t)", got, ok)
			}
			if strings.Contains(out, "[cut]") {
				t.Error("a field was cut: the payload has to fit, or part of it is not tested")
			}

			// Every field is there, and what is left once the code spans
			// are taken out is the gate's own text: no tag, nothing of the
			// payload.
			for _, tag := range h.tags {
				shown := strings.Contains(out, tag)
				switch {
				case tag == h.tags[len(h.tags)-1]:
					// GitHub's refusal is part of one kind of comment only.
					if shown != (tc.res.Action == ActionRefused) {
						t.Errorf("GitHub's refusal shown: %t", shown)
					}
				case shown == hidden[tag]:
					t.Errorf("field %s shown: %t", tag, shown)
				}
			}
			// A bot that reads comment bodies without parsing Markdown sees
			// through a code span, so no "@" is left anywhere.
			if strings.Contains(out, "@") {
				t.Error("the comment has an @")
			}
			bare := codeSpanRE.ReplaceAllString(out, "")
			for _, bad := range append([]string{"FIELD", "evil", "@", "\uff20", "`", "[l]", "img", "#1", "octocat", "dependabot merge", "\\"}, h.tags...) {
				if strings.Contains(bare, bad) {
					t.Errorf("%q is outside a code span", bad)
				}
			}

			// No line the payload could have started, and no table row
			// with a cell too many.
			for i, line := range lines[1:] {
				switch {
				case strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "### dep-review: ") && !strings.HasPrefix(line, "#### "):
					t.Errorf("line %d is a heading the gate does not write: %q", i+2, line)
				case strings.HasPrefix(line, "#### ") && line != "#### The pull request" && !strings.HasPrefix(line, "#### `FIELD"):
					t.Errorf("line %d is a heading the gate does not write: %q", i+2, line)
				case strings.HasPrefix(line, "|") && strings.Count(line, "|") != 5:
					t.Errorf("line %d is a table row with %d cell separators, want 5: %q", i+2, strings.Count(line, "|"), line)
				case strings.Count(line, "`")%2 != 0:
					t.Errorf("line %d has a code span that does not close: %q", i+2, line)
				}
			}
			if t.Failed() {
				t.Logf("comment:\n%s", out)
			}
		})
	}
}

// TestInline is the sanitiser on its own.
func TestInline(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"v1.2.3", "v1.2.3"},
		{"  two\twords\r\nand a line  ", "two words and a line"},
		{"a`b``c", "a'b''c"},
		{"a|b\\|c", "a\u00a6b\\\u00a6c"},
		{"<script>x</script> -->", "\u2039script\u203ax\u2039/script\u203a --\u203a"},
		{"@tailwindcss/oxide", "\uff20tailwindcss/oxide"},
		{"line\u2028separator\u2029s", "line separator s"},
		{"bidi\u202eedoc\u2066x\u2069 zero\u200bwidth\ufeff", "bidiedocx zerowidth"},
		{"nul\x00 esc\x1b[0m bad\xffbyte", "nul esc[0m badbyte"},
		{strings.Repeat("\u00e9", 201), strings.Repeat("\u00e9", 200) + " [cut]"},
		{strings.Repeat("x", 200), strings.Repeat("x", 200)},
		{strings.Repeat("\U0001F600", 300), strings.Repeat("\U0001F600", 200) + " [cut]"},
		{strings.Repeat(" ", 5000) + "late", " [cut]"},
	}
	for _, tc := range tests {
		if got := inline(tc.in); got != tc.want {
			t.Errorf("inline(%.40q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := code("a`b"); got != "`a'b`" {
		t.Errorf("code = %q", got)
	}
	if got := code(" \u200b "); got != "" {
		t.Errorf("code of nothing visible = %q, want an empty cell", got)
	}
}

// TestReasonFact keeps the lead's table in step with allow's closed set:
// a reason added there needs a line here, and the fact it names has to be
// a row the tables have.
func TestReasonFact(t *testing.T) {
	rows := map[string]bool{answerNotGathered: true, answerUnavailable: true, "": true, "NameCreated": true, "Superseded": true, "Veto": true}
	u := goodUpdate("example.com/m")
	ev := Evaluation{Facts: allow.PRFacts{Updates: []allow.UpdateFacts{u}}}
	for _, r := range append(pullRows(ev.Facts), updateRows(view{ev: ev}, 0)...) {
		rows[r.fact] = true
	}
	seen := map[allow.Reason]bool{}
	for _, r := range allow.Reasons() {
		seen[r] = true
		fact, ok := reasonFact[r]
		if !ok {
			t.Errorf("reason %q has no line in reasonFact", r)
		}
		if !rows[fact] {
			t.Errorf("reason %q names the fact %q, which no table has", r, fact)
		}
	}
	for r := range reasonFact {
		if !seen[r] {
			t.Errorf("reasonFact has %q, which is not one of allow's reasons", r)
		}
	}
}

// TestMarkerRoundTrip: what String writes, parseMarker reads back, and the
// text a cached veto carries cannot end the HTML comment it is in.
func TestMarkerRoundTrip(t *testing.T) {
	reviewer := strings.Repeat("f", 64)
	m := marker{
		Outcome: ActionWait, Head: headA,
		NotBefore: t0.Add(time.Hour), Deadline: t0.Add(48 * time.Hour),
		Notified: []string{headB}, NotifiedFailed: []string{headA}, NotifiedUnread: []string{headA, headB},
		Fingerprint: reviewer,
		Cache: []cached{
			{Key: keyA, Read: allow.ReadFull},
			{Key: keyB, Read: allow.ReadPartial, Veto: &allow.Veto{Category: "obfuscation", Quotes: []string{"--> <!-- `x` | @dependabot merge"}, Notes: "-->"}},
		},
	}
	line := m.String()
	if !regexp.MustCompile(`^<!-- dep-review:v2 [A-Za-z0-9_-]+ -->$`).MatchString(line) {
		t.Fatalf("marker line %q", line)
	}
	got, ok := parseMarker(line + "\n### dep-review: waiting\n")
	if !ok || !reflect.DeepEqual(got, m) {
		t.Fatalf("read back %+v (ok %t), want %+v", got, ok, m)
	}
	want := wire.Verdicts{Version: wire.Version, Verdicts: []wire.Verdict{
		{Key: keyA, Fingerprint: reviewer, Read: allow.ReadFull},
		{Key: keyB, Fingerprint: reviewer, Read: allow.ReadPartial, Veto: m.Cache[1].Veto},
	}}
	if v := got.verdicts(); !reflect.DeepEqual(v, want) {
		t.Errorf("verdicts %+v, want %+v", v, want)
	}
	if _, err := wire.EncodeVerdicts(got.verdicts()); err != nil {
		t.Errorf("the cache is not a verdicts file: %v", err)
	}

	// A marker with nothing to remember is still a marker.
	empty := marker{Outcome: ActionPerson, Head: headA}
	if got, ok := parseMarker(empty.String()); !ok || got.Outcome != ActionPerson || len(got.Cache) != 0 {
		t.Errorf("empty marker read back as %+v (ok %t)", got, ok)
	}
}

// TestMarkerRejected: a marker is believed only when it is exactly what
// the gate writes.
func TestMarkerRejected(t *testing.T) {
	encode := func(json string) string {
		return "<!-- dep-review:v2 " + base64.RawURLEncoding.EncodeToString([]byte(json)) + " -->"
	}
	base := func(change string) string {
		fields := map[string]string{
			"outcome": `"wait"`, "head": `"` + headA + `"`,
			"not_before": `"2026-11-22T12:00:00Z"`, "deadline": `"2026-11-29T12:00:00Z"`,
			"notified": `[]`, "fingerprint": `"` + strings.Repeat("f", 64) + `"`,
			"cache": `[{"key":"` + keyA + `","read":"full","veto":null}]`,
		}
		if k, v, ok := strings.Cut(change, "="); ok {
			fields[k] = v
		}
		var parts []string
		for _, k := range []string{"outcome", "head", "not_before", "deadline", "notified", "notified_failed", "notified_unread", "fingerprint", "cache"} {
			// The two newer lists are left out unless a case sets one: a
			// marker written before they existed still parses.
			if v, ok := fields[k]; ok {
				parts = append(parts, `"`+k+`":`+v)
			}
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	if _, ok := parseMarker(encode(base(""))); !ok {
		t.Fatal("the unchanged marker does not parse")
	}
	if m, ok := parseMarker(encode(base(`outcome="failed"`))); !ok || m.Outcome != ActionFailed {
		t.Errorf("a failed run's marker: %+v (parsed: %t)", m, ok)
	}
	bad := map[string]string{
		"no marker":                     "### dep-review: waiting",
		"the first version's marker":    "<!-- dep-review:v1 notified= stuck= approved=" + headA + " -->",
		"not at the start":              "\n" + encode(base("")),
		"not base64":                    "<!-- dep-review:v2 {\"outcome\":\"wait\"} -->",
		"not JSON":                      encode("wait"),
		"null":                          encode("null"),
		"an unknown member":             encode(strings.Replace(base(""), "{", `{"approved":"`+headA+`",`, 1)),
		"a member twice":                encode(strings.Replace(base(""), "{", `{"outcome":"person",`, 1)),
		"an outcome the gate has not":   encode(base(`outcome="approved"`)),
		"a stale outcome":               encode(base(`outcome="stale"`)),
		"a head that is not a commit":   encode(base(`head="main"`)),
		"a notified head that is not":   encode(base(`notified=["HEAD"]`)),
		"too many notified heads":       encode(base(`notified=["` + strings.Repeat(headA+`","`, maxNotified) + headA + `"]`)),
		"a failed head that is not":     encode(base(`notified_failed=["HEAD"]`)),
		"too many unread heads":         encode(base(`notified_unread=["` + strings.Repeat(headA+`","`, maxNotified) + headA + `"]`)),
		"a fingerprint that is not one": encode(base(`fingerprint="any"`)),
		"a key that is not one":         encode(base(`cache=[{"key":"../x","read":"full","veto":null}]`)),
		"a read state that is no state": encode(base(`cache=[{"key":"` + keyA + `","read":"approved","veto":null}]`)),
		"a veto without an answer":      encode(base(`cache=[{"key":"` + keyA + `","read":"none","veto":{"category":"x","quotes":[],"notes":""}}]`)),
		"a category that is not a word": encode(base(`cache=[{"key":"` + keyA + `","read":"full","veto":{"category":"No Veto","quotes":[],"notes":""}}]`)),
		"one key twice":                 encode(base(`cache=[{"key":"` + keyA + `","read":"full","veto":null},{"key":"` + keyA + `","read":"partial","veto":null}]`)),
		"too long":                      "<!-- dep-review:v2 " + strings.Repeat("A", maxMarkerBytes+1) + " -->",
	}
	for name, body := range bad {
		if m, ok := parseMarker(body); ok {
			t.Errorf("%s: parsed as %+v", name, m)
		}
	}
}

// TestMarkerFits: the marker drops cache entries from the end before it
// outgrows its budget, and the comment stays under GitHub's limit however
// many updates a pull request has.
func TestMarkerFits(t *testing.T) {
	m := marker{Outcome: ActionWait, Head: headA, Fingerprint: strings.Repeat("f", 64)}
	long := strings.Repeat("q", maxCachedText)
	for i := 0; i < maxCached; i++ {
		m.Cache = append(m.Cache, cached{Key: fmt.Sprintf("%064x", i), Read: allow.ReadPartial,
			Veto: &allow.Veto{Category: "obfuscation", Quotes: []string{long, long, long}, Notes: long}})
	}
	line := m.String()
	if len(line) > maxMarkerBytes+40 {
		t.Fatalf("marker line of %d bytes", len(line))
	}
	got, ok := parseMarker(line)
	if !ok || len(got.Cache) == 0 || len(got.Cache) >= maxCached {
		t.Fatalf("read back %d cache entries (ok %t), want some and not all", len(got.Cache), ok)
	}
	if !reflect.DeepEqual(got.Cache, m.Cache[:len(got.Cache)]) {
		t.Error("the entries kept are not the first ones")
	}
	if len(m.Cache) != maxCached {
		t.Error("String changed its receiver's cache")
	}

	// 300 updates with long values everywhere.
	value := strings.Repeat("v", 500)
	var facts allow.PRFacts
	var per []allow.UpdateDecision
	for i := 0; i < 300; i++ {
		u := goodUpdate(fmt.Sprintf("example.com/m%d/%s", i, value))
		u.Bound, u.Clean = allow.No(value, value), allow.Yes(value, value)
		facts.Updates = append(facts.Updates, u)
		outcome := allow.Merge
		if i == 299 {
			outcome = allow.Person
		}
		per = append(per, allow.UpdateDecision{Outcome: outcome})
	}
	out := render(view{
		res:    Result{Action: ActionPerson, Decision: allow.Decision{Outcome: allow.Person, Reasons: []allow.Reason{allow.ReasonNotBound}, PerUpdate: per}},
		ev:     Evaluation{PullRequest: wire.PullRequest{Head: headA}, Facts: facts},
		marker: m,
	})
	if len(out) > maxCommentBytes {
		t.Errorf("comment of %d bytes, want at most %d", len(out), maxCommentBytes)
	}
	if !strings.Contains(out, "#### `example.com/m299/") {
		t.Error("the update that holds the pull request back is not shown first")
	}
	shown := strings.Count(out, "\n#### `example.com/m")
	if shown < 5 || !strings.Contains(out, fmt.Sprintf("\n%d more updates are not shown", 300-shown)) {
		t.Errorf("%d updates shown, and the comment does not say that it left out the other %d", shown, 300-shown)
	}
	if !strings.HasSuffix(out, "A new push starts a new evaluation.\n") || strings.Count(out, "`")%2 != 0 {
		t.Error("the comment was cut, not shortened")
	}
}

// TestCacheEntries: which verdicts the marker remembers.
func TestCacheEntries(t *testing.T) {
	reviewer, other := strings.Repeat("f", 64), strings.Repeat("0", 64)
	keyC := strings.Repeat("3", 64)
	// Two bytes each. After one byte of ASCII the cut falls in the middle
	// of a character, and must not leave half of it.
	long := strings.Repeat("\xc3\xa9", 400)
	veto := &allow.Veto{Category: "exfiltration", Quotes: []string{long, "b", "c", "d"}, Notes: "x" + long}

	prepared := func(keys ...string) wire.Facts {
		f := wire.Facts{Facts: wire.PRFacts{Ecosystem: allow.NPM}}
		for i, k := range keys {
			f.Facts.Updates = append(f.Facts.Updates, wire.Update{Prepared: preparedRead(i, k)})
		}
		return f
	}
	tests := []struct {
		name     string
		facts    wire.Facts
		verdicts []wire.Verdict
		want     []cached
	}{
		{"a complete read with no veto is a clean entry", prepared(keyA),
			[]wire.Verdict{{Key: keyA, Fingerprint: reviewer, Read: allow.ReadFull}},
			[]cached{{Key: keyA, Read: allow.ReadFull}}},
		{"a partial read that was answered is remembered as partial", prepared(keyA),
			[]wire.Verdict{{Key: keyA, Fingerprint: reviewer, Read: allow.ReadPartial}},
			[]cached{{Key: keyA, Read: allow.ReadPartial}}},
		{"no answer is not remembered", prepared(keyA),
			[]wire.Verdict{{Key: keyA, Fingerprint: reviewer, Read: allow.ReadNone}}, nil},
		{"a read the reviewer refused is not remembered", prepared(keyA),
			[]wire.Verdict{{Key: keyA, Fingerprint: reviewer, Read: allow.ReadRefused}}, nil},
		{"a verdict under another fingerprint is not remembered", prepared(keyA),
			[]wire.Verdict{{Key: keyA, Fingerprint: other, Read: allow.ReadFull}}, nil},
		{"a verdict for a read this pull request does not have is not remembered", prepared(keyA),
			[]wire.Verdict{{Key: keyB, Fingerprint: reviewer, Read: allow.ReadFull}}, nil},
		{"no verdicts", prepared(keyA, keyB), nil, nil},
		{"a read that was not prepared has no entry",
			wire.Facts{Facts: wire.PRFacts{Updates: []wire.Update{{Prepared: wire.Read{Status: wire.Unavailable}}}}},
			[]wire.Verdict{{Key: keyA, Fingerprint: reviewer, Read: allow.ReadFull}}, nil},
		{"a veto is remembered, with a little of its text", prepared(keyA),
			[]wire.Verdict{{Key: keyA, Fingerprint: reviewer, Read: allow.ReadPartial, Veto: veto}},
			[]cached{{Key: keyA, Read: allow.ReadPartial, Veto: &allow.Veto{Category: "exfiltration",
				Quotes: []string{long[:maxCachedText], "b", "c"}, Notes: "x" + long[:maxCachedText-2]}}}},
		{"in the order of the updates, one entry for a key", prepared(keyC, keyA, keyC, keyB),
			[]wire.Verdict{
				{Key: keyA, Fingerprint: reviewer, Read: allow.ReadFull},
				{Key: keyB, Fingerprint: reviewer, Read: allow.ReadNone},
				{Key: keyC, Fingerprint: reviewer, Read: allow.ReadPartial},
			},
			[]cached{{Key: keyC, Read: allow.ReadPartial}, {Key: keyA, Read: allow.ReadFull}}},
	}
	for _, tc := range tests {
		got := cacheEntries(tc.facts, wire.Verdicts{Version: wire.Version, Verdicts: tc.verdicts}, reviewer)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
		// Whatever is remembered must be something a marker can carry.
		m := marker{Outcome: ActionWait, Head: headA, Fingerprint: reviewer, Cache: got}
		if _, ok := parseMarker(m.String()); !ok {
			t.Errorf("%s: the marker with these entries does not read back", tc.name)
		}
	}
	if veto.Quotes[0] != long || len(veto.Quotes) != 4 {
		t.Error("the verdict's own veto was changed")
	}
}

// TestCacheNotFromAnotherAuthor: the marker counts only in a comment the
// gate app wrote.
func TestCacheNotFromAnotherAuthor(t *testing.T) {
	_, reviewer := defaults(t)
	planted := marker{Outcome: ActionWait, Head: headA, Fingerprint: reviewer, Cache: []cached{{Key: keyA, Read: allow.ReadFull}}}
	body := planted.String() + "\n### dep-review: waiting\n"

	for _, tc := range []struct {
		author string
		want   int
	}{
		{"mallory", 0},
		{"dependabot[bot]", 0},
		{"gate", 0},
		{"other-gate[bot]", 0},
		{testBot, 1},
	} {
		f := newFake(t)
		f.comments[testPR] = []*fakeComment{{1, tc.author, body}}
		f.open = "[" + pullJSON(testPR, "open", headA, "main", "clean", false) + "]"
		cfg := f.config(t0, nil)

		v, err := Cached(context.Background(), cfg, testPR)
		if err != nil {
			t.Fatal(err)
		}
		if len(v.Verdicts) != tc.want {
			t.Errorf("a marker in a comment by %s gave %d cached verdicts, want %d", tc.author, len(v.Verdicts), tc.want)
		}
		if _, err := wire.EncodeVerdicts(v); err != nil {
			t.Errorf("author %s: what Cached returned is not a verdicts file: %v", tc.author, err)
		}
		waiting, err := Waiting(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if len(waiting) != tc.want {
			t.Errorf("a marker in a comment by %s made %d pull requests wait, want %d", tc.author, len(waiting), tc.want)
		}
		if w := f.writes(); len(w) != 0 {
			t.Errorf("reading the cache wrote: %+v", w)
		}
	}
}

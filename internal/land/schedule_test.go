package land

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/wire"
)

// TestSchedule: which pull requests the scheduled job is told to
// evaluate, and which it leaves alone. Besides the ones the gate left
// waiting, that is every one the gate has nothing for at its head once it
// has been quiet for UndecidedAfter: never evaluated, a comment this
// version cannot read, a decision for an older head (spec section 11,
// amendment 66).
func TestSchedule(t *testing.T) {
	_, reviewer := defaults(t)
	marked := func(outcome Action, deadline time.Time, change func(*marker)) string {
		m := marker{Outcome: outcome, Head: headA, NotBefore: t0.Add(-time.Hour), Deadline: deadline,
			Notified: []string{headA}, NotifiedFailed: []string{headA},
			Fingerprint: reviewer, Cache: []cached{{Key: keyA, Read: allow.ReadFull}}}
		if change != nil {
			change(&m)
		}
		return m.String() + "\n### dep-review\n"
	}
	body := func(outcome Action, deadline time.Time) string { return marked(outcome, deadline, nil) }
	listed := func(number int, author, head, headRepo string) string {
		p := pullJSON(number, "open", head, "main", "clean", false)
		p = strings.Replace(p, `"login":"dependabot[bot]"`, `"login":"`+author+`"`, 1)
		return strings.Replace(p, `"sha":"`+head+`","repo":{"full_name":"o/r"}`, `"sha":"`+head+`","repo":{"full_name":"`+headRepo+`"}`, 1)
	}
	// changed is a pull request that last changed at the given time.
	changed := func(p string, at time.Time) string {
		return strings.Replace(p, `"updated_at":"`+quietSince.Format(time.RFC3339)+`"`, `"updated_at":"`+at.Format(time.RFC3339)+`"`, 1)
	}
	untimed := func(p string) string {
		return strings.Replace(p, `"updated_at":"`+quietSince.Format(time.RFC3339)+`",`, "", 1)
	}

	f := newFake(t)
	f.open = "[" + strings.Join([]string{
		listed(2, "dependabot[bot]", headA, "o/r"),                                                // waits; its deadline is ahead
		listed(1, "dependabot[bot]", headB, "o/r"),                                                // waits; its deadline has passed; rebased since
		listed(3, "dependabot[bot]", headA, "o/r"),                                                // a person's, decided for this head
		listed(4, "dependabot[bot]", headA, "o/r"),                                                // merged, by its marker
		listed(5, "dependabot[bot]", headA, "o/r"),                                                // never evaluated
		listed(6, "dependabot[bot]", headA, "o/r"),                                                // "wait" in somebody else's comment only
		listed(8, "dependabot[bot]", headA, "o/r"),                                                // the first version's comment
		listed(12, "dependabot[bot]", headA, "o/r"),                                               // a marker with a member this version does not know
		listed(13, "dependabot[bot]", headA, "o/r"),                                               // a marker cut short
		listed(9, "mallory", headA, "o/r"),                                                        // not Dependabot's
		listed(10, "dependabot[bot]", headA, "x/r"),                                               // from a fork
		listed(11, "dependabot[bot]", "main", "o/r"),                                              // no commit ID
		listed(14, "dependabot[bot]", headB, "o/r"),                                               // a person's for an older head; this head has nothing
		listed(15, "dependabot[bot]", headA, "o/r"),                                               // a failed run that was reported for this head
		listed(16, "dependabot[bot]", headB, "o/r"),                                               // a failed run for an older head
		changed(listed(17, "dependabot[bot]", headA, "o/r"), t0.Add(-UndecidedAfter+time.Second)), // never evaluated, pushed too recently
		changed(listed(18, "dependabot[bot]", headA, "o/r"), t0.Add(-UndecidedAfter)),             // never evaluated, quiet just long enough
		untimed(listed(19, "dependabot[bot]", headA, "o/r")),                                      // never evaluated, and GitHub gives no time
		changed(listed(20, "dependabot[bot]", headA, "o/r"), t0),                                  // waits, and was pushed to this second
		listed(21, "dependabot[bot]", headA, "o/r"),                                               // a person's, and nobody was told
		listed(22, "dependabot[bot]", headA, "o/r"),                                               // a failed run, and nobody was told
		listed(23, "dependabot[bot]", headB, "o/r"),                                               // a person's for an older head, nobody told: evaluated, not told
		listed(24, "dependabot[bot]", headA, "o/r"),                                               // waits, and nobody was told about anything: nothing is owed
	}, ",") + "]"
	untold := func(m *marker) { m.Notified, m.NotifiedFailed = nil, nil }
	f.comments = map[int][]*fakeComment{
		1:  {{1, "someone", "nice"}, {2, testBot, body(ActionWait, t0.Add(-time.Minute))}},
		2:  {{3, testBot, body(ActionWait, t0.Add(time.Minute))}},
		3:  {{4, testBot, body(ActionPerson, time.Time{})}},
		4:  {{5, testBot, body(ActionMerged, time.Time{})}},
		6:  {{6, "mallory", body(ActionWait, t0.Add(time.Minute))}},
		8:  {{7, testBot, "<!-- dep-review:v1 -->\n### dep-review: waiting\n"}},
		9:  {{8, testBot, body(ActionWait, t0.Add(time.Minute))}},
		10: {{9, testBot, body(ActionWait, t0.Add(time.Minute))}},
		11: {{10, testBot, body(ActionWait, t0.Add(time.Minute))}},
		12: {{11, testBot, "<!-- dep-review:v2 " + base64.RawURLEncoding.EncodeToString([]byte(`{"outcome":"wait","head":"`+headA+`","later":1}`)) + " -->\n"}},
		13: {{12, testBot, body(ActionWait, t0.Add(time.Minute))[:60] + " -->\n"}},
		14: {{13, testBot, body(ActionPerson, time.Time{})}},
		15: {{14, testBot, body(ActionFailed, time.Time{})}},
		16: {{15, testBot, body(ActionFailed, time.Time{})}},
		20: {{16, testBot, body(ActionWait, time.Time{})}},
		21: {{17, testBot, marked(ActionPerson, time.Time{}, untold)}},
		22: {{18, testBot, marked(ActionFailed, time.Time{}, untold)}},
		23: {{19, testBot, marked(ActionPerson, time.Time{}, untold)}},
		24: {{20, testBot, marked(ActionWait, t0.Add(time.Minute), untold)}},
	}

	agenda, err := Schedule(context.Background(), f.config(t0, nil))
	if err != nil {
		t.Fatal(err)
	}
	type entry struct {
		number    int
		head      string
		undecided bool
		past      bool
	}
	var got []entry
	for _, r := range agenda.Evaluate {
		got = append(got, entry{r.Number, r.Head, r.Undecided, r.PastDeadline})
		if r.Undecided {
			// Nothing is believed from a comment that is not a wait for
			// this version to read, and no model is asked at first.
			if r.Ask || len(r.Answered) != 0 || !r.Deadline.IsZero() {
				t.Errorf("#%d has no decision and: %+v", r.Number, r)
			}
			continue
		}
		if !slices.Equal(r.Answered, []string{keyA}) {
			t.Errorf("#%d: answered reads %v, want the one the comment remembers", r.Number, r.Answered)
		}
		// The model is asked only for the head the comment was written
		// for: #1 was rebased since, and is evaluated without it first.
		if r.Ask != (r.Head == headA) {
			t.Errorf("#%d at %s: an ask is due: %t", r.Number, r.Head, r.Ask)
		}
	}
	want := []entry{
		{1, headB, false, true}, {2, headA, false, false},
		{5, headA, true, false}, {6, headA, true, false}, {8, headA, true, false}, {12, headA, true, false}, {13, headA, true, false},
		{14, headB, true, false}, {16, headB, true, false}, {18, headA, true, false}, {19, headA, true, false},
		{20, headA, false, false}, {23, headB, true, false}, {24, headA, false, false},
	}
	if !slices.Equal(got, want) {
		t.Errorf("to evaluate, lowest number first:\n got %+v\nwant %+v", got, want)
	}
	if !slices.Equal(agenda.Untold, []int{21, 22}) {
		t.Errorf("comments that owe a notification: %v, want #21 and #22", agenda.Untold)
	}
	if w := f.writes(); len(w) != 0 {
		t.Errorf("the scheduled listing wrote: %+v", w)
	}

	// Undecided is the same judgement for one pull request, as publish
	// asks it before it reports a scheduled evaluation that failed.
	for number, want := range map[int]bool{1: false, 3: false, 5: true, 8: true, 14: true, 15: false, 16: true, 21: false} {
		f.pulls = nil
		for _, p := range strings.Split(strings.Trim(f.open, "[]"), `,{"number"`) {
			p = `{"number"` + strings.TrimPrefix(p, `{"number"`)
			if strings.HasPrefix(p, fmt.Sprintf(`{"number":%d,`, number)) {
				f.pulls = []string{p}
			}
		}
		f.pullNumber = number
		head, ok, err := Undecided(context.Background(), f.config(t0, nil), number)
		if err != nil || ok != want || !strings.Contains(f.pulls[0], head) {
			t.Errorf("#%d: undecided %t at %s, %v; want %t", number, ok, head, err, want)
		}
	}
}

// TestScheduledReevaluation is the whole of a wait: publish says wait and
// remembers the verdict; the scheduled job finds the pull request, and a
// later publish, on a fresh facts file and what its own comment remembers,
// merges. Nothing but allow.Decide's answer to the fresh facts makes it
// merge, and nothing the refresh job could write stands in for a verdict.
func TestScheduledReevaluation(t *testing.T) {
	f := newFake(t)
	f.open = "[" + pullJSON(testPR, "open", headA, "main", "clean", false) + "]"
	facts := goodFacts(t)
	facts.Facts.Updates[0].FirstSeen = allow.At(t0.Add(-time.Hour), "index.golang.org")

	res, err := publish(t, f.config(t0, nil), files(t, facts, clean(t)))
	if err != nil || res.Action != ActionWait {
		t.Fatalf("first run: %+v, %v", res, err)
	}

	// Too early: the scheduled run decides again and still waits.
	later := t0.Add(24 * time.Hour)
	again := func(f *fakeGitHub, now time.Time, scheduled bool, change func(*wire.Facts)) Result {
		t.Helper()
		before := len(f.writes())
		agenda, err := Schedule(context.Background(), f.config(now, nil))
		waiting := agenda.Evaluate
		if err != nil || len(agenda.Untold) != 0 || len(waiting) != 1 || waiting[0].Number != testPR || waiting[0].Undecided || waiting[0].PastDeadline {
			t.Fatalf("to evaluate: %+v, %v", agenda, err)
		}
		// The read has an answer, so there is nothing to ask the model.
		if !slices.Equal(waiting[0].Answered, []string{keyA}) {
			t.Fatalf("answered reads %v, want the one the comment remembers", waiting[0].Answered)
		}
		if len(f.writes()) != before {
			t.Fatal("Schedule wrote something")
		}
		// The workflow's steps: fetch again, ask the model about nothing,
		// publish. There is no verdicts file.
		fresh := goodFacts(t)
		fresh.GatheredAt = now
		fresh.Facts.Updates[0].FirstSeen = facts.Facts.Updates[0].FirstSeen
		if change != nil {
			change(&fresh)
		}
		cfg := f.config(now, nil)
		cfg.Scheduled = scheduled
		res, err := publish(t, cfg, files(t, fresh, nil))
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := again(f, later, true, nil); res.Action != ActionWait || f.count("PUT", "/merge") != 0 {
		t.Fatalf("a day later: %+v, want a wait and no merge call", res)
	}

	// Old enough, but the fresh facts say the version was pulled: the
	// remembered wait and the remembered verdict count for nothing.
	due := t0.Add(72 * time.Hour)
	pulled := func(f *wire.Facts) { f.Facts.Updates[0].Clean = allow.No("retracted", "go list -m -retracted") }
	// This happens in a copy of the repository, so that the pull request
	// here can go on to merge.
	copyOf := func() *fakeGitHub {
		c := newFake(t)
		c.open, c.comments = f.open, map[int][]*fakeComment{testPR: {{1, testBot, f.gateComment(testPR)}}}
		return c
	}
	copied := copyOf()
	if res := again(copied, due, true, pulled); res.Action != ActionPerson || res.Decision.Reasons[0] != allow.ReasonNotClean || copied.count("PUT", "/merge") != 0 {
		t.Fatalf("pulled version: %+v, want a person and no merge call", res)
	}

	// An event's run that got no answer is not helped by the memory: it
	// asks the model itself (spec section 11, amendment 39).
	copied = copyOf()
	if res := again(copied, due, false, nil); res.Action != ActionWait || res.Decision.Reasons[0] != allow.ReasonReadPending || copied.count("PUT", "/merge") != 0 {
		t.Fatalf("an event's run without verdicts: %+v, want a wait for the read", res)
	}

	// Old enough and still clean: merged, with the remembered verdict and
	// no model call.
	if res := again(f, due, true, nil); res.Action != ActionMerged || f.count("PUT", "/merge") != 1 {
		t.Fatalf("when due: %+v, want a merge", res)
	}
	if posts := f.count("POST", "/issues/7/comments"); posts != 1 {
		t.Errorf("%d comments were created over three runs, want 1", posts)
	}
	// The pull request is closed after the merge and no longer listed.
	f.open = "[]"
	if agenda, err := Schedule(context.Background(), f.config(due, nil)); err != nil || len(agenda.Evaluate) != 0 || len(agenda.Untold) != 0 {
		t.Errorf("after the merge: %+v, %v", agenda, err)
	}
}

// TestPushover checks the one request a notification is.
func TestPushover(t *testing.T) {
	var form url.Values
	code := http.StatusOK
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		r.ParseForm()
		form = r.PostForm
		w.WriteHeader(code)
	}))
	defer srv.Close()

	p := &Pushover{Token: "app", User: "me", Endpoint: srv.URL}
	m := Message{Title: "dep-review: o/r#7", Body: "o/r#7 needs a person.", URL: "https://github.com/o/r/pull/7"}
	if err := p.Notify(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"token": "app", "user": "me", "title": m.Title, "message": m.Body, "url": m.URL} {
		if form.Get(k) != want {
			t.Errorf("form %s = %q, want %q", k, form.Get(k), want)
		}
	}

	// A refusal of the request itself is final and is not tried again.
	code, calls = http.StatusBadRequest, 0
	if err := p.Notify(context.Background(), m); err == nil || calls != 1 {
		t.Errorf("error %v after %d calls, want an error after 1", err, calls)
	}
}

// TestAskDue: when a scheduled run may ask the model about a pull request
// (spec section 11, amendment 64). Only for the head the gate's comment
// was written for, at once the first time, and then after a gap that
// doubles: nine asks fit before the wait deadline, not 336.
func TestAskDue(t *testing.T) {
	at := func(asks int, asked time.Time) marker {
		return marker{Outcome: ActionWait, Head: headA, Asks: asks, AskedAt: asked}
	}
	for _, tc := range []struct {
		name string
		m    marker
		head string
		now  time.Time
		want bool
	}{
		{"never asked", at(0, time.Time{}), headA, t0, true},
		{"a marker for another head", at(0, time.Time{}), headB, t0, false},
		{"asked once, 29 minutes ago", at(1, t0), headA, t0.Add(29 * time.Minute), false},
		{"asked once, 30 minutes ago", at(1, t0), headA, t0.Add(30 * time.Minute), true},
		{"asked twice, 59 minutes ago", at(2, t0), headA, t0.Add(59 * time.Minute), false},
		{"asked twice, an hour ago", at(2, t0), headA, t0.Add(time.Hour), true},
		{"asked three times, two hours ago", at(3, t0), headA, t0.Add(2 * time.Hour), true},
		{"asked nine times, five days ago", at(9, t0), headA, t0.Add(5 * 24 * time.Hour), false},
		{"asked nine times, 128 hours ago", at(9, t0), headA, t0.Add(128 * time.Hour), true},
		// A count no run makes: the gap does not wrap around to "now".
		{"asked as often as a marker can say", at(maxAsks, t0), headA, t0.Add(365 * 24 * time.Hour), false},
	} {
		if got := tc.m.askDue(tc.head, tc.now); got != tc.want {
			t.Errorf("%s: due %t, want %t", tc.name, got, tc.want)
		}
	}

	// With every ask unanswered, the asks of one head up to the wait
	// deadline, at the half-hourly schedule's ticks.
	conf, _ := defaults(t)
	m, asks := at(0, time.Time{}), 0
	for now := t0; now.Before(t0.Add(conf.Policy().WaitDeadline)); now = now.Add(30 * time.Minute) {
		if m.askDue(headA, now) {
			asks++
			m.Asks, m.AskedAt = m.Asks+1, now
		}
	}
	if asks != 9 {
		t.Errorf("%d asks before the wait deadline, want 9", asks)
	}
}

// TestAsked: a scheduled run that asked the model and then could not
// decide still counts the ask, by rewriting the marker line alone. What
// the comment remembers and says is left as it is.
func TestAsked(t *testing.T) {
	_, reviewer := defaults(t)
	veto := &allow.Veto{Category: "exfiltration", Quotes: []string{"x"}}
	old := marker{Outcome: ActionWait, Head: headA, NotBefore: t0.Add(time.Hour), Deadline: t0.Add(48 * time.Hour),
		Notified: []string{headB}, Fingerprint: reviewer, Cache: []cached{{Key: keyA, Read: allow.ReadFull, Veto: veto}},
		FirstSeen: []seen{{Pin: keyB, At: t0}}, Asks: 1, AskedAt: t0.Add(-time.Hour)}
	const rest = "\n### dep-review: waiting\n\nthe comment's text\n"

	f := newFake(t)
	f.comments[testPR] = []*fakeComment{{1, testBot, old.String() + rest}}
	cfg := f.config(t0, nil)
	cfg.ModelAsked = true
	if err := Asked(context.Background(), cfg, testPR, headA, Vetoes{}); err != nil {
		t.Fatal(err)
	}
	body := f.gateComment(testPR)
	got, ok := parseMarker(body)
	want := old
	want.Asks, want.AskedAt = 2, t0
	if !ok || got.String() != want.String() || !strings.HasSuffix(body, rest) {
		t.Errorf("after the ask: marker %+v (parsed %t), want %+v; the comment:\n%s", got, ok, want, body)
	}
	if w := f.writes(); len(w) != 1 || w[0].method != "PATCH" {
		t.Errorf("writes %+v, want the comment rewritten and nothing else", w)
	}

	// No model is asked for a head the comment was not written for, so
	// there is no count to add to; nor in a comment nobody can read.
	for name, body := range map[string]string{
		"a marker for another head": old.String() + rest,
		"no marker":                 "<!-- dep-review:v1 -->" + rest,
	} {
		f := newFake(t)
		f.comments[testPR] = []*fakeComment{{1, testBot, body}}
		head := headB
		if name == "no marker" {
			head = headA
		}
		if err := Asked(context.Background(), f.config(t0, nil), testPR, head, Vetoes{}); err != nil || len(f.writes()) != 0 {
			t.Errorf("%s: %v, writes %+v; want nothing", name, err, f.writes())
		}
	}
	f = newFake(t)
	if err := Asked(context.Background(), f.config(t0, nil), testPR, headA, Vetoes{}); err != nil || len(f.writes()) != 0 {
		t.Errorf("no comment: %v, writes %+v; want nothing", err, f.writes())
	}

	// A run that asked nobody counts nothing. It gives up the status Act
	// set, which the run may have replaced, and writes only for that
	// (spec section 11, amendment 74).
	for _, set := range []*lastStatus{nil, {State: "pending", Description: "waiting until 2026-11-25 11:00 UTC"}} {
		f := newFake(t)
		m := old
		m.Status = set
		f.comments[testPR] = []*fakeComment{{1, testBot, m.String() + rest}}
		if err := Asked(context.Background(), f.config(t0, nil), testPR, headA, Vetoes{}); err != nil {
			t.Fatal(err)
		}
		got, _ := parseMarker(f.gateComment(testPR))
		if got.Asks != old.Asks || got.Status != nil || len(f.writes()) != map[bool]int{true: 0, false: 1}[set == nil] {
			t.Errorf("with status %v: asks %d, status %v, writes %+v", set, got.Asks, got.Status, f.writes())
		}
	}
}

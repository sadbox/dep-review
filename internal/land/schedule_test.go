package land

import (
	"context"
	"encoding/base64"
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

// TestWaiting: which pull requests the scheduled job is told to evaluate
// again.
func TestWaiting(t *testing.T) {
	_, reviewer := defaults(t)
	body := func(outcome Action, deadline time.Time) string {
		m := marker{Outcome: outcome, Head: headA, NotBefore: t0.Add(-time.Hour), Deadline: deadline,
			Fingerprint: reviewer, Cache: []cached{{Key: keyA, Read: allow.ReadFull}}}
		return m.String() + "\n### dep-review\n"
	}
	listed := func(number int, author, head, headRepo string) string {
		p := pullJSON(number, "open", head, "main", "clean", false)
		p = strings.Replace(p, `"login":"dependabot[bot]"`, `"login":"`+author+`"`, 1)
		return strings.Replace(p, `"sha":"`+head+`","repo":{"full_name":"o/r"}`, `"sha":"`+head+`","repo":{"full_name":"`+headRepo+`"}`, 1)
	}

	f := newFake(t)
	f.open = "[" + strings.Join([]string{
		listed(1, "dependabot[bot]", headB, "o/r"),   // waits; its deadline has passed; rebased since
		listed(2, "dependabot[bot]", headA, "o/r"),   // waits; its deadline is ahead
		listed(3, "dependabot[bot]", headA, "o/r"),   // a person's
		listed(4, "dependabot[bot]", headA, "o/r"),   // merged, by its marker
		listed(5, "dependabot[bot]", headA, "o/r"),   // never evaluated
		listed(6, "dependabot[bot]", headA, "o/r"),   // "wait" in somebody else's comment
		listed(8, "dependabot[bot]", headA, "o/r"),   // the gate's comment says wait in words only: reported
		listed(12, "dependabot[bot]", headA, "o/r"),  // a marker with a member this version does not know: reported
		listed(13, "dependabot[bot]", headA, "o/r"),  // a marker cut short: reported
		listed(9, "mallory", headA, "o/r"),           // not Dependabot's
		listed(10, "dependabot[bot]", headA, "x/r"),  // from a fork
		listed(11, "dependabot[bot]", "main", "o/r"), // no commit ID
	}, ",") + "]"
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
	}

	got, unread, err := Waiting(context.Background(), f.config(t0, nil))
	if err != nil {
		t.Fatal(err)
	}
	// A gate comment whose marker does not parse is neither taken to wait
	// nor silently off the schedule: it is named.
	if !slices.Equal(unread, []int{8, 12, 13}) {
		t.Errorf("gate comments reported as unread: %v, want #8, #12 and #13", unread)
	}
	if len(got) != 2 {
		t.Fatalf("%d pull requests wait, want #1 and #2: %+v", len(got), got)
	}
	for i, want := range []struct {
		number int
		head   string
		past   bool
	}{{1, headB, true}, {2, headA, false}} {
		r := got[i]
		if r.Number != want.number || r.Head != want.head || r.PastDeadline != want.past {
			t.Errorf("entry %d: #%d at %s, past its deadline %t; want #%d at %s, %t", i, r.Number, r.Head, r.PastDeadline, want.number, want.head, want.past)
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
	if w := f.writes(); len(w) != 0 {
		t.Errorf("the scheduled listing wrote: %+v", w)
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
		waiting, unread, err := Waiting(context.Background(), f.config(now, nil))
		if err != nil || len(unread) != 0 || len(waiting) != 1 || waiting[0].Number != testPR || waiting[0].PastDeadline {
			t.Fatalf("waiting: %+v, unread %v, %v", waiting, unread, err)
		}
		// The read has an answer, so there is nothing to ask the model.
		if !slices.Equal(waiting[0].Answered, []string{keyA}) {
			t.Fatalf("answered reads %v, want the one the comment remembers", waiting[0].Answered)
		}
		if len(f.writes()) != before {
			t.Fatal("Waiting wrote something")
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
	waiting, unread, err := Waiting(context.Background(), f.config(due, nil))
	if err != nil || len(waiting) != 0 || len(unread) != 0 {
		t.Errorf("after the merge, still waiting: %+v, unread %v, %v", waiting, unread, err)
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
	if err := Asked(context.Background(), f.config(t0, nil), testPR, headA); err != nil {
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
		if err := Asked(context.Background(), f.config(t0, nil), testPR, head); err != nil || len(f.writes()) != 0 {
			t.Errorf("%s: %v, writes %+v; want nothing", name, err, f.writes())
		}
	}
	f = newFake(t)
	if err := Asked(context.Background(), f.config(t0, nil), testPR, headA); err != nil || len(f.writes()) != 0 {
		t.Errorf("no comment: %v, writes %+v; want nothing", err, f.writes())
	}
}

package land

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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
		listed(8, "dependabot[bot]", headA, "o/r"),   // the gate's comment says wait in words only
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
	}

	got, err := Waiting(context.Background(), f.config(t0, nil))
	if err != nil {
		t.Fatal(err)
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
		if len(r.Verdicts.Verdicts) != 1 || r.Verdicts.Verdicts[0] != (wire.Verdict{Key: keyA, Fingerprint: reviewer, Read: allow.ReadFull}) {
			t.Errorf("#%d: cached verdicts %+v", r.Number, r.Verdicts)
		}
		if _, err := wire.EncodeVerdicts(r.Verdicts); err != nil {
			t.Errorf("#%d: the cached verdicts are not a verdicts file: %v", r.Number, err)
		}
	}
	if w := f.writes(); len(w) != 0 {
		t.Errorf("the scheduled listing wrote: %+v", w)
	}
}

// TestScheduledReevaluation is the whole of a wait: publish says wait and
// remembers the verdict; the scheduled job finds the pull request, and a
// later publish, on a fresh facts file and the remembered verdict, merges.
// Nothing but allow.Decide's answer to the fresh facts makes it merge.
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
	again := func(f *fakeGitHub, now time.Time, change func(*wire.Facts)) Result {
		t.Helper()
		before := len(f.writes())
		waiting, err := Waiting(context.Background(), f.config(now, nil))
		if err != nil || len(waiting) != 1 || waiting[0].Number != testPR || waiting[0].PastDeadline {
			t.Fatalf("waiting: %+v, %v", waiting, err)
		}
		if len(f.writes()) != before {
			t.Fatal("Waiting wrote something")
		}
		// The workflow's three steps: fetch again, write the remembered
		// verdicts as the verdicts file, publish.
		fresh := goodFacts(t)
		fresh.GatheredAt = now
		fresh.Facts.Updates[0].FirstSeen = facts.Facts.Updates[0].FirstSeen
		if change != nil {
			change(&fresh)
		}
		dir := files(t, fresh, nil)
		b, err := wire.EncodeVerdicts(waiting[0].Verdicts)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, wire.VerdictsFile), b, 0o600); err != nil {
			t.Fatal(err)
		}
		res, err := publish(t, f.config(now, nil), dir)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	if res := again(f, later, nil); res.Action != ActionWait || f.count("PUT", "/merge") != 0 {
		t.Fatalf("a day later: %+v, want a wait and no merge call", res)
	}

	// Old enough, but the fresh facts say the version was pulled: the
	// remembered wait and the remembered verdict count for nothing.
	due := t0.Add(72 * time.Hour)
	pulled := func(f *wire.Facts) { f.Facts.Updates[0].Clean = allow.No("retracted", "go list -m -retracted") }
	// This happens in a copy of the repository, so that the pull request
	// here can go on to merge.
	copied := newFake(t)
	copied.open, copied.comments = f.open, map[int][]*fakeComment{testPR: {{1, testBot, f.gateComment(testPR)}}}
	if res := again(copied, due, pulled); res.Action != ActionPerson || res.Decision.Reasons[0] != allow.ReasonNotClean || copied.count("PUT", "/merge") != 0 {
		t.Fatalf("pulled version: %+v, want a person and no merge call", res)
	}

	// Old enough and still clean: merged, with the remembered verdict and
	// no model call.
	if res := again(f, due, nil); res.Action != ActionMerged || f.count("PUT", "/merge") != 1 {
		t.Fatalf("when due: %+v, want a merge", res)
	}
	if posts := f.count("POST", "/issues/7/comments"); posts != 1 {
		t.Errorf("%d comments were created over three runs, want 1", posts)
	}
	waiting, err := Waiting(context.Background(), f.config(due, nil))
	if err != nil || len(waiting) != 0 {
		t.Errorf("after the merge, still waiting: %+v, %v", waiting, err)
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

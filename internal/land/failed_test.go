package land

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/wire"
)

const (
	testRun  = "https://github.com/o/r/actions/runs/42"
	testWhat = "In this run the fetch job ended failure and the review job skipped."
)

// TestFailed: a run that ended without a decision says so on the pull
// request and tells the owner, once per head, and keeps what the comment
// remembered.
func TestFailed(t *testing.T) {
	_, reviewer := defaults(t)
	f := newFake(t)
	f.open = "[" + pullJSON(testPR, "open", headA, "main", "clean", false) + "]"
	f.comments[testPR] = []*fakeComment{{1, testBot, marker{
		Outcome: ActionWait, Head: headA, Deadline: t0.Add(time.Hour), Notified: []string{headB},
		Fingerprint: reviewer, Cache: []cached{{Key: keyA, Read: allow.ReadFull}},
		FirstSeen: []seen{{Pin: keyB, At: t0.Add(-time.Hour)}},
	}.String() + "\n### dep-review: waiting\n"}}

	// The notifier is down for the first run: the comment and the status
	// are written all the same, and the notification is not remembered.
	down := f.config(t0, &recorder{err: errors.New("pushover is down")})
	if err := Failed(context.Background(), down, testPR, headA, testWhat); err == nil || !strings.Contains(err.Error(), "pushover is down") {
		t.Fatalf("error %v, want the notifier's", err)
	}
	if m, ok := parseMarker(f.gateComment(testPR)); !ok || m.Outcome != ActionFailed || len(m.NotifiedFailed) != 0 {
		t.Fatalf("marker %+v (parsed: %t), want a failed run nobody was told about", m, ok)
	}

	rec := &recorder{}
	cfg := f.config(t0, rec)
	cfg.RunURL = testRun
	for run := 1; run <= 2; run++ {
		if err := Failed(context.Background(), cfg, testPR, headA, testWhat+" `x` | <b>\n### not a heading"); err != nil {
			t.Fatal(err)
		}
	}
	if s := f.statuses(headA); len(s) != 3 || s[2] != "error: the gate's run failed before it could decide; re-run all jobs" {
		t.Errorf("statuses %q", s)
	}
	body := f.gateComment(testPR)
	m, ok := parseMarker(body)
	if !ok || m.Outcome != ActionFailed || m.Head != headA || !slices.Equal(m.Notified, []string{headB}) ||
		!slices.Equal(m.NotifiedFailed, []string{headA}) || m.Fingerprint != reviewer || len(m.Cache) != 1 {
		t.Errorf("marker %+v (parsed: %t)", m, ok)
	}
	// A failed run does not start a pin's clock again.
	if len(m.FirstSeen) != 1 || m.FirstSeen[0].Pin != keyB || !m.FirstSeen[0].At.Equal(t0.Add(-time.Hour)) {
		t.Errorf("the marker remembers %+v, want the time it had", m.FirstSeen)
	}
	for _, want := range []string{"### dep-review: the run failed", "for head `" + headA + "`", testWhat + " 'x' \u00a6 \u2039b\u203a ### not a heading\n",
		"open the [workflow run](" + testRun + ") and re-run all jobs, not only the failed ones",
		"does not decide on facts gathered more than 4 hours before"} {
		if !strings.Contains(body, want) {
			t.Errorf("the comment lacks %q:\n%s", want, body)
		}
	}
	want := Message{
		Title: "dep-review: o/r#7",
		Body:  "o/r#7: the gate's run failed before it could decide. Re-run all jobs: " + testRun,
		URL:   "https://github.com/o/r/pull/7",
	}
	if len(rec.got) != 1 || rec.got[0] != want {
		t.Errorf("notifications %+v, want one: %+v", rec.got, want)
	}

	// The owner was told how to run the gate again: the scheduled job
	// does not take the pull request up.
	f.open = "[" + pullJSON(testPR, "open", headA, "main", "clean", false) + "]"
	if agenda, err := Schedule(context.Background(), cfg); err != nil || len(agenda.Evaluate) != 0 || len(agenda.Untold) != 0 {
		t.Errorf("the schedule after a failed run that was reported: %+v, %v", agenda, err)
	}
	// The run again decides, and what it decides is told although the
	// head was told about before.
	facts := goodFacts(t)
	facts.Facts.Updates[0].Bound = allow.No("h1:abc pinned, h1:xyz served", "go mod download")
	if res, err := publish(t, cfg, files(t, facts, clean(t))); err != nil || res.Action != ActionPerson {
		t.Fatalf("the run again: %+v, %v", res, err)
	}
	if m, _ := parseMarker(f.gateComment(testPR)); len(rec.got) != 2 || !slices.Equal(m.Notified, []string{headB, headA}) || !slices.Equal(m.NotifiedFailed, []string{headA}) {
		t.Errorf("%d notifications, marker %+v: want the decision told too, and both remembered", len(rec.got), m)
	}
}

// TestFailedWritesNothing: Failed leaves a pull request alone that is not
// the open one at the head the run was for.
func TestFailedWritesNothing(t *testing.T) {
	tests := []struct {
		name    string
		pull    string
		number  int
		head    string
		wantErr bool
	}{
		{name: "the head moved: the new one has a run of its own", pull: pullJSON(testPR, "open", headB, "main", "clean", false), number: testPR, head: headA},
		{name: "closed", pull: pullJSON(testPR, "closed", headA, "main", "clean", false), number: testPR, head: headA},
		{name: "merged, and a write after the merge failed", pull: pullJSON(testPR, "closed", headA, "main", "unknown", true), number: testPR, head: headA},
		{name: "a pull request GitHub does not have", number: 8, head: headA, wantErr: true},
		{name: "no pull request", number: 0, head: headA, wantErr: true},
		{name: "no commit", number: testPR, head: "main", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.lenient = true
			if tc.pull != "" {
				f.pulls = []string{tc.pull}
			}
			// A newer run's comment, which must stay.
			f.comments[testPR] = []*fakeComment{{1, testBot, marker{Outcome: ActionWait, Head: headB}.String() + "\n### dep-review: waiting\n"}}
			rec := &recorder{}
			if err := Failed(context.Background(), f.config(t0, rec), tc.number, tc.head, testWhat); (err != nil) != tc.wantErr {
				t.Errorf("error %v, want one: %t", err, tc.wantErr)
			}
			if w := f.writes(); len(w) != 0 || len(rec.got) != 0 {
				t.Errorf("writes %+v, notifications %+v; want none", w, rec.got)
			}
		})
	}
}

// TestReviewerSilent: a prepared read the model left without a verdict is
// a wait, and the scheduled run asks again by itself. The owner is told
// when the second scheduled run that asked also got no answer, once per
// head, and not by an event's run (spec section 11, amendment 64).
func TestReviewerSilent(t *testing.T) {
	young := func(f *wire.Facts) { f.Facts.Updates[0].FirstSeen = allow.At(t0.Add(-time.Hour), "index.golang.org") }
	// The kinds of run: an event's, a scheduled one in which the model was
	// asked about this pull request, and a scheduled one in which it was
	// not (no ask was due).
	const event, asked, quiet = "event", "asked", "quiet"
	tests := []struct {
		name     string
		runs     []string
		facts    func(*wire.Facts)
		verdicts func(*testing.T) *wire.Verdicts // nil: a clean read
		action   Action
		unread   int // notifications about the reviewer
		all      int // notifications of any kind
		asks     int // what the marker counts in the end
	}{
		{name: "an event's run and no verdicts: the schedule will ask", runs: []string{event, event}, verdicts: noVerdicts, action: ActionWait},
		{name: "one scheduled miss is not worth a notification", runs: []string{event, asked}, verdicts: noVerdicts, action: ActionWait, asks: 1},
		{name: "the second scheduled miss is", runs: []string{event, asked, asked}, verdicts: noVerdicts, action: ActionWait, unread: 1, all: 1, asks: 2},
		{name: "told once, however many more", runs: []string{event, asked, asked, asked, quiet, asked}, verdicts: noVerdicts, action: ActionWait, unread: 1, all: 1, asks: 4},
		{name: "a scheduled run that did not ask counts nothing", runs: []string{event, quiet, quiet, quiet}, verdicts: noVerdicts, action: ActionWait},
		{name: "an event's run starts the count again", runs: []string{asked, asked, event}, verdicts: noVerdicts, action: ActionWait, unread: 1, all: 1},
		{name: "every read answered, waiting on age", runs: []string{event, asked, asked}, facts: young, action: ActionWait, asks: 2},
		{name: "nothing was prepared: the download failed, not the reviewer", runs: []string{event, asked, asked}, verdicts: noVerdicts, action: ActionWait, asks: 2,
			facts: func(f *wire.Facts) {
				f.Facts.Updates[0].Prepared = wire.Read{Status: wire.Unavailable, Detail: "the artifact could not be downloaded"}
			}},
		{name: "unread and a person's for something else: told that", runs: []string{event, asked, asked}, verdicts: noVerdicts, action: ActionPerson, all: 1, asks: 2,
			facts: func(f *wire.Facts) {
				f.Facts.Updates[0].Bound = allow.No("h1:abc pinned, h1:xyz served", "go mod download")
			}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			facts := goodFacts(t)
			if tc.facts != nil {
				tc.facts(&facts)
			}
			verdicts := clean(t)
			if tc.verdicts != nil {
				verdicts = tc.verdicts(t)
			}
			rec := &recorder{}
			for _, run := range tc.runs {
				cfg := f.config(t0, rec)
				cfg.RunURL, cfg.Scheduled, cfg.ModelAsked = testRun, run != event, run != quiet
				res, err := publish(t, cfg, files(t, facts, verdicts))
				if err != nil || res.Action != tc.action {
					t.Fatalf("result %+v, %v; want %s", res, err, tc.action)
				}
			}
			want := message(Config{Repo: testRepo}, testPR, unreadNotice+" The run: "+testRun)
			unread := 0
			for _, m := range rec.got {
				if m == want {
					unread++
				}
			}
			if unread != tc.unread || len(rec.got) != tc.all {
				t.Errorf("%d notifications about the reviewer of %d, want %d of %d: %+v", unread, len(rec.got), tc.unread, tc.all, rec.got)
			}
			m, _ := parseMarker(f.gateComment(testPR))
			if len(m.NotifiedUnread) != tc.unread {
				t.Errorf("the marker remembers %v, want %d heads", m.NotifiedUnread, tc.unread)
			}
			if m.Asks != tc.asks || (m.Asks > 0) != m.AskedAt.Equal(t0) {
				t.Errorf("the marker counts %d asks, the last at %s; want %d", m.Asks, m.AskedAt, tc.asks)
			}
		})
	}
}

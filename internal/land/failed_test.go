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
	if s := f.statuses(headA); len(s) != 3 || s[2] != "error: the gate's run failed before it could decide; re-run the failed jobs" {
		t.Errorf("statuses %q", s)
	}
	body := f.gateComment(testPR)
	m, ok := parseMarker(body)
	if !ok || m.Outcome != ActionFailed || m.Head != headA || !slices.Equal(m.Notified, []string{headB}) ||
		!slices.Equal(m.NotifiedFailed, []string{headA}) || m.Fingerprint != reviewer || len(m.Cache) != 1 {
		t.Errorf("marker %+v (parsed: %t)", m, ok)
	}
	for _, want := range []string{"### dep-review: the run failed", "for head `" + headA + "`", testWhat + " 'x' \u00a6 \u2039b\u203a ### not a heading\n",
		"open the [workflow run](" + testRun + ") and re-run the failed jobs"} {
		if !strings.Contains(body, want) {
			t.Errorf("the comment lacks %q:\n%s", want, body)
		}
	}
	want := Message{
		Title: "dep-review: o/r#7",
		Body:  "o/r#7: the gate's run failed before it could decide. Re-run the failed jobs: " + testRun,
		URL:   "https://github.com/o/r/pull/7",
	}
	if len(rec.got) != 1 || rec.got[0] != want {
		t.Errorf("notifications %+v, want one: %+v", rec.got, want)
	}

	// The scheduled job asks no model and could not finish the run: it
	// does not take the pull request up.
	if waiting, err := Waiting(context.Background(), cfg); err != nil || len(waiting) != 0 {
		t.Errorf("waiting: %+v, %v", waiting, err)
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

// TestReviewerSilent: on an event's run a prepared read the model left
// without a verdict is a wait nothing ends before its deadline, since the
// scheduled job asks no model. The owner is told once per head, and never
// by a scheduled run.
func TestReviewerSilent(t *testing.T) {
	young := func(f *wire.Facts) { f.Facts.Updates[0].FirstSeen = allow.At(t0.Add(-time.Hour), "index.golang.org") }
	tests := []struct {
		name     string
		asked    []bool // one run each: an event's (true) or a scheduled one
		facts    func(*wire.Facts)
		verdicts func(*testing.T) *wire.Verdicts // nil: a clean read
		action   Action
		unread   int // notifications about the reviewer
		all      int // notifications of any kind
	}{
		{name: "an event's run and no verdicts", asked: []bool{true, true}, verdicts: noVerdicts, action: ActionWait, unread: 1, all: 1},
		{name: "then the schedule, then the run again", asked: []bool{true, false, true}, verdicts: noVerdicts, action: ActionWait, unread: 1, all: 1},
		{name: "a scheduled run and no verdicts", asked: []bool{false, false}, verdicts: noVerdicts, action: ActionWait},
		{name: "every read answered, waiting on age", asked: []bool{true}, facts: young, action: ActionWait},
		{name: "nothing was prepared: the download failed, not the reviewer", asked: []bool{true}, verdicts: noVerdicts, action: ActionWait,
			facts: func(f *wire.Facts) {
				f.Facts.Updates[0].Prepared = wire.Read{Status: wire.Unavailable, Detail: "the artifact could not be downloaded"}
			}},
		{name: "unread and a person's for something else: told that", asked: []bool{true}, verdicts: noVerdicts, action: ActionPerson, all: 1,
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
			for _, asked := range tc.asked {
				cfg := f.config(t0, rec)
				cfg.RunURL, cfg.ModelAsked = testRun, asked
				res, err := publish(t, cfg, files(t, facts, verdicts))
				if err != nil || res.Action != tc.action {
					t.Fatalf("result %+v, %v; want %s", res, err, tc.action)
				}
			}
			want := message(Config{Repo: testRepo}, testPR, " waits unread: the model did not answer for code the gate prepared, and the scheduled job asks no model. Re-run the review job: "+testRun)
			unread := 0
			for _, m := range rec.got {
				if m == want {
					unread++
				}
			}
			if unread != tc.unread || len(rec.got) != tc.all {
				t.Errorf("%d notifications about the reviewer of %d, want %d of %d: %+v", unread, len(rec.got), tc.unread, tc.all, rec.got)
			}
			if m, _ := parseMarker(f.gateComment(testPR)); len(m.NotifiedUnread) != tc.unread {
				t.Errorf("the marker remembers %v, want %d heads", m.NotifiedUnread, tc.unread)
			}
		})
	}
}

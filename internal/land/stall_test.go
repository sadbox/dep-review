package land

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
)

// waitingComment is a gate comment that says wait for headA until
// deadline and remembers a veto, a first-seen time and an earlier
// notification, as the fake's one comment on the pull request.
func waitingComment(t *testing.T, f *fakeGitHub, deadline time.Time) marker {
	t.Helper()
	_, reviewer := defaults(t)
	m := marker{Outcome: ActionWait, Head: headA, NotBefore: t0.Add(-time.Hour), Deadline: deadline,
		Notified: []string{headB}, Fingerprint: reviewer,
		Cache:     []cached{{Key: keyB, Read: allow.ReadFull, Veto: &allow.Veto{Category: "exfiltration", Quotes: []string{"x"}}}},
		FirstSeen: []seen{{Pin: keyA, At: t0.Add(-time.Hour)}}, Asks: 2, AskedAt: t0.Add(-time.Hour)}
	f.comments[testPR] = []*fakeComment{{1, testBot, m.String() + "\n### dep-review: waiting\n\nthe comment's text\n"}}
	return m
}

// TestExpired: a wait the scheduled run cannot evaluate again still
// reaches its deadline (spec section 11, amendment 67). Decide makes a
// wait a person's at the deadline only when it runs; when every refresh
// of the pull request fails, the comment said wait for good and nobody
// was told.
func TestExpired(t *testing.T) {
	f := newFake(t)
	f.open = "[" + pullJSON(testPR, "open", headA, "main", "clean", false) + "]"
	deadline := t0.Add(-time.Minute)
	old := waitingComment(t, f, deadline)
	rec := &recorder{}
	cfg := f.config(t0, rec)
	cfg.RunURL = testRun

	// What the scheduled run sees before: an overdue wait.
	agenda, err := Schedule(context.Background(), cfg)
	if err != nil || len(agenda.Evaluate) != 1 || !agenda.Evaluate[0].PastDeadline {
		t.Fatalf("before: %+v, %v", agenda, err)
	}
	if err := Expired(context.Background(), cfg, testPR, headA); err != nil {
		t.Fatal(err)
	}
	if s := f.statuses(headA); len(s) != 1 || !strings.HasPrefix(s[0], "failure: needs a person: the wait deadline passed") {
		t.Errorf("statuses %q", s)
	}
	body := f.gateComment(testPR)
	for _, want := range []string{"### dep-review: needs a person", "at most until " + stamp(deadline), "could not evaluate the pull request again", "merge or close the pull request by hand", testRun} {
		if !strings.Contains(body, want) {
			t.Errorf("the comment lacks %q:\n%s", want, body)
		}
	}
	m, ok := parseMarker(body)
	if !ok || m.Outcome != ActionPerson || m.Head != headA || !slices.Equal(m.Notified, []string{headB, headA}) {
		t.Fatalf("marker %+v (parsed %t), want a person's for this head, told", m, ok)
	}
	// What the comment remembered stays: the veto above all.
	if len(m.Cache) != 1 || m.Cache[0].Veto == nil || len(m.FirstSeen) != 1 || m.Fingerprint != old.Fingerprint || m.Asks != old.Asks {
		t.Errorf("the comment forgot something: %+v", m)
	}
	want := message(Config{Repo: testRepo}, testPR, " needs a person: its wait deadline has passed and the scheduled run could not evaluate it again. See the comment on the pull request. The run: "+testRun)
	if len(rec.got) != 1 || rec.got[0] != want {
		t.Errorf("notifications %+v, want one: %+v", rec.got, want)
	}
	// It has left the schedule, and a second call finds nothing to do.
	writes := len(f.writes())
	if agenda, err := Schedule(context.Background(), cfg); err != nil || len(agenda.Evaluate) != 0 || len(agenda.Untold) != 0 {
		t.Errorf("after: %+v, %v", agenda, err)
	}
	if err := Expired(context.Background(), cfg, testPR, headA); err != nil || len(f.writes()) != writes || len(rec.got) != 1 {
		t.Errorf("a second call: %v, %d more writes, %d notifications", err, len(f.writes())-writes, len(rec.got))
	}

	// A wait for an older head expires at the head the pull request has.
	t.Run("at the head the pull request has now", func(t *testing.T) {
		f := newFake(t)
		f.pulls = []string{pullJSON(testPR, "open", headB, "main", "clean", false)}
		waitingComment(t, f, deadline)
		if err := Expired(context.Background(), f.config(t0, nil), testPR, headB); err != nil {
			t.Fatal(err)
		}
		if m, ok := parseMarker(f.gateComment(testPR)); !ok || m.Outcome != ActionPerson || m.Head != headB || len(f.statuses(headB)) != 1 {
			t.Errorf("marker %+v (parsed %t), statuses %q", m, ok, f.statuses(headB))
		}
	})

	// What it leaves alone: everything that is not a wait past its
	// deadline on an open pull request at that head.
	for name, setup := range map[string]func(f *fakeGitHub){
		"the deadline is ahead":   func(f *fakeGitHub) { waitingComment(t, f, t0.Add(time.Second)) },
		"a wait with no deadline": func(f *fakeGitHub) { waitingComment(t, f, time.Time{}) },
		"no comment":              func(f *fakeGitHub) {},
		"a comment nobody can read": func(f *fakeGitHub) {
			f.comments[testPR] = []*fakeComment{{1, testBot, "<!-- dep-review:v1 -->\nwaiting\n"}}
		},
		"somebody else's comment": func(f *fakeGitHub) { waitingComment(t, f, deadline); f.comments[testPR][0].author = "mallory" },
		"the pull request was closed": func(f *fakeGitHub) {
			waitingComment(t, f, deadline)
			f.pulls = []string{pullJSON(testPR, "closed", headA, "main", "clean", false)}
		},
		"the pull request moved on": func(f *fakeGitHub) {
			waitingComment(t, f, deadline)
			f.pulls = []string{pullJSON(testPR, "open", headB, "main", "clean", false)}
		},
		"a run decided meanwhile": func(f *fakeGitHub) {
			m := waitingComment(t, f, deadline)
			m.Outcome = ActionPerson
			f.comments[testPR][0].body = m.String() + "\n### dep-review: needs a person\n"
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			setup(f)
			rec := &recorder{}
			if err := Expired(context.Background(), f.config(t0, rec), testPR, headA); err != nil || len(f.writes()) != 0 || len(rec.got) != 0 {
				t.Errorf("%v, writes %+v, notifications %+v; want nothing", err, f.writes(), rec.got)
			}
		})
	}
}

// TestTell: a notification that could not be delivered is sent by the
// next scheduled run (spec section 11, amendment 67). Act says so, and
// before this nothing did it: a person's pull request is not evaluated
// again, so the one notification for it was lost for good.
func TestTell(t *testing.T) {
	f := newFake(t)
	f.open = "[" + pullJSON(testPR, "open", headA, "main", "clean", false) + "]"
	facts := goodFacts(t)
	facts.Facts.Updates[0].Bound = allow.No("h1:abc pinned, h1:xyz served", "go mod download")

	// The run that decided could not notify. Everything else is written.
	down := &recorder{err: errors.New("pushover is down")}
	res, err := publish(t, f.config(t0, down), files(t, facts, vetoed("exfiltration", allow.ReadFull)(t)))
	if err == nil || res.Action != ActionPerson {
		t.Fatalf("the deciding run: %+v, %v; want a person and the notifier's error", res, err)
	}
	before := f.gateComment(testPR)

	// The next scheduled run finds the comment owing a notification...
	rec := &recorder{}
	cfg := f.config(t0.Add(30*time.Minute), rec)
	agenda, err := Schedule(context.Background(), cfg)
	if err != nil || len(agenda.Evaluate) != 0 || !slices.Equal(agenda.Untold, []int{testPR}) {
		t.Fatalf("the schedule: %+v, %v; want #%d owed a notification and nothing to evaluate", agenda, err, testPR)
	}
	// ...and while the notifier is still down, keeps owing it.
	if err := Tell(context.Background(), f.config(t0, down), testPR); err == nil || f.gateComment(testPR) != before {
		t.Fatalf("with the notifier down: %v; the comment changed: %t", err, f.gateComment(testPR) != before)
	}
	statuses := len(f.statuses(headA))
	if err := Tell(context.Background(), cfg, testPR); err != nil {
		t.Fatal(err)
	}
	want := message(Config{Repo: testRepo}, testPR, " needs a person. See the gate's comment on the pull request. An earlier notification about this could not be sent.")
	if len(rec.got) != 1 || rec.got[0] != want {
		t.Errorf("notifications %+v, want one: %+v", rec.got, want)
	}
	// Only the marker line changed: the comment still says why, the veto
	// is still remembered, and no status was set.
	after := f.gateComment(testPR)
	m, ok := parseMarker(after)
	if !ok || m.Outcome != ActionPerson || !slices.Equal(m.Notified, []string{headA}) || len(m.Cache) != 1 || m.Cache[0].Veto == nil {
		t.Errorf("marker %+v (parsed %t)", m, ok)
	}
	if rest := func(s string) string { return s[strings.Index(s, "\n"):] }; rest(after) != rest(before) || len(f.statuses(headA)) != statuses {
		t.Error("more than the marker line was written")
	}
	// Told: nothing is owed, and a second call sends nothing.
	if agenda, err := Schedule(context.Background(), cfg); err != nil || len(agenda.Untold) != 0 {
		t.Errorf("after: %+v, %v", agenda, err)
	}
	if err := Tell(context.Background(), cfg, testPR); err != nil || len(rec.got) != 1 {
		t.Errorf("a second call: %v, %d notifications", err, len(rec.got))
	}

	// A failed run's notification is owed and sent the same way, and
	// remembered apart from a decision's.
	t.Run("a run that failed", func(t *testing.T) {
		f := newFake(t)
		if err := Failed(context.Background(), f.config(t0, down), testPR, headA, "The fetch job ended failure."); err == nil {
			t.Fatal("Failed did not return the notifier's error")
		}
		rec := &recorder{}
		if err := Tell(context.Background(), f.config(t0, rec), testPR); err != nil {
			t.Fatal(err)
		}
		m, _ := parseMarker(f.gateComment(testPR))
		if len(rec.got) != 1 || !strings.Contains(rec.got[0].Body, "the gate's run failed before it could decide") ||
			!slices.Equal(m.NotifiedFailed, []string{headA}) || len(m.Notified) != 0 {
			t.Errorf("notifications %+v, marker %+v", rec.got, m)
		}
	})

	// What it leaves alone.
	owing := marker{Outcome: ActionPerson, Head: headA}
	for name, setup := range map[string]func(f *fakeGitHub){
		"no comment":                 func(f *fakeGitHub) {},
		"a wait":                     func(f *fakeGitHub) { waitingComment(t, f, t0.Add(-time.Minute)) },
		"a comment for another head": func(f *fakeGitHub) { f.pulls = []string{pullJSON(testPR, "open", headB, "main", "clean", false)} },
		"a closed pull request":      func(f *fakeGitHub) { f.pulls = []string{pullJSON(testPR, "closed", headA, "main", "clean", false)} },
		"somebody else's comment":    func(f *fakeGitHub) { f.comments[testPR][0].author = "mallory" },
		"a head that was told about": func(f *fakeGitHub) {
			f.comments[testPR][0].body = marker{Outcome: ActionPerson, Head: headA, Notified: []string{headA}}.String()
		},
		"a merge, which nobody is told of": func(f *fakeGitHub) { f.comments[testPR][0].body = marker{Outcome: ActionMerged, Head: headA}.String() },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			if name != "no comment" {
				f.comments[testPR] = []*fakeComment{{1, testBot, owing.String() + "\n### dep-review: needs a person\n"}}
			}
			setup(f)
			rec := &recorder{}
			if err := Tell(context.Background(), f.config(t0, rec), testPR); err != nil || len(f.writes()) != 0 || len(rec.got) != 0 {
				t.Errorf("%v, writes %+v, notifications %+v; want nothing", err, f.writes(), rec.got)
			}
		})
	}
}

// TestNotifierOff: with notifications turned off a head counts as told.
// Otherwise the gate's comment would read as owing a notification, and
// every scheduled run would come back for it.
func TestNotifierOff(t *testing.T) {
	f := newFake(t)
	f.open = "[" + pullJSON(testPR, "open", headA, "main", "clean", false) + "]"
	facts := goodFacts(t)
	facts.Facts.Updates[0].Bound = allow.No("h1:abc pinned, h1:xyz served", "go mod download")
	if res, err := publish(t, f.config(t0, nil), files(t, facts, clean(t))); err != nil || res.Action != ActionPerson {
		t.Fatalf("%+v, %v", res, err)
	}
	if m, _ := parseMarker(f.gateComment(testPR)); !slices.Equal(m.Notified, []string{headA}) {
		t.Errorf("notified heads %v, want this one", m.Notified)
	}
	if agenda, err := Schedule(context.Background(), f.config(t0, nil)); err != nil || len(agenda.Untold) != 0 {
		t.Errorf("the schedule: %+v, %v; want nothing owed", agenda, err)
	}
}

// TestFailedOnTheSchedule: a pull request the scheduled run tried to
// evaluate from scratch and could not is reported once, with a way out
// that works: there is no run of its own to run again, and the schedule
// does not try the head a second time (spec section 11, amendment 66).
func TestFailedOnTheSchedule(t *testing.T) {
	f := newFake(t)
	f.open = "[" + pullJSON(testPR, "open", headA, "main", "clean", false) + "]"
	rec := &recorder{}
	cfg := f.config(t0, rec)
	cfg.Scheduled, cfg.RunURL = true, testRun

	if agenda, err := Schedule(context.Background(), cfg); err != nil || len(agenda.Evaluate) != 1 || !agenda.Evaluate[0].Undecided {
		t.Fatalf("before: %+v, %v; want the pull request listed as one with no decision", agenda, err)
	}
	if _, ok, err := Undecided(context.Background(), cfg, testPR); err != nil || !ok {
		t.Fatalf("undecided: %t, %v", ok, err)
	}
	if err := Failed(context.Background(), cfg, testPR, headA, "The scheduled run could not evaluate this pull request."); err != nil {
		t.Fatal(err)
	}
	if s := f.statuses(headA); len(s) != 1 || s[0] != "error: the scheduled run could not evaluate this pull request; see the comment" {
		t.Errorf("statuses %q", s)
	}
	body := f.gateComment(testPR)
	for _, want := range []string{"### dep-review: the run failed", "have Dependabot rebase or recreate it", "The scheduled run does not try this head again", testRun} {
		if !strings.Contains(body, want) {
			t.Errorf("the comment lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "re-run all jobs") {
		t.Errorf("the comment of a scheduled run says to re-run its jobs, which evaluates nothing:\n%s", body)
	}
	if len(rec.got) != 1 || !strings.Contains(rec.got[0].Body, "the scheduled run could not evaluate this pull request and does not try this head again") {
		t.Errorf("notifications %+v", rec.got)
	}
	// Reported: it has a comment for its head now, and is not tried again.
	if agenda, err := Schedule(context.Background(), cfg); err != nil || len(agenda.Evaluate) != 0 || len(agenda.Untold) != 0 {
		t.Errorf("after: %+v, %v", agenda, err)
	}
	if _, ok, err := Undecided(context.Background(), cfg, testPR); err != nil || ok {
		t.Errorf("undecided after the report: %t, %v", ok, err)
	}
}

// TestCutOver: a pull request that carries the first version's comment is
// evaluated from scratch by the schedule (spec section 11, amendment 66).
// Nothing in that comment is believed, the gate's one comment is
// rewritten in place, and the model is asked at the run after, when this
// version's marker is there to count the ask in.
func TestCutOver(t *testing.T) {
	f := newFake(t)
	f.open = "[" + pullJSON(testPR, "open", headA, "main", "clean", false) + "]"
	f.comments[testPR] = []*fakeComment{{1, testBot, "<!-- dep-review:v1 notified=" + headA + " stuck= approved=" + headA + " -->\n### dep-review: approved\n"}}

	agenda, err := Schedule(context.Background(), f.config(t0, nil))
	if err != nil || len(agenda.Evaluate) != 1 || !agenda.Evaluate[0].Undecided || agenda.Evaluate[0].Ask {
		t.Fatalf("the first scheduled run: %+v, %v; want the pull request evaluated from scratch, with no model", agenda, err)
	}
	// The first run: fresh facts, no verdicts, no model.
	cfg := f.config(t0, nil)
	cfg.Scheduled = true
	res, err := publish(t, cfg, files(t, goodFacts(t), nil))
	if err != nil || res.Action != ActionWait || res.Decision.Reasons[0] != allow.ReasonReadPending || f.count("PUT", "/merge") != 0 {
		t.Fatalf("the first scheduled run: %+v, %v; want a wait for the read, whatever the old comment said", res, err)
	}
	if f.count("POST", "/issues/7/comments") != 0 || f.count("PATCH", "/issues/comments/1") != 1 {
		t.Error("the first version's comment was not rewritten in place")
	}
	m, ok := parseMarker(f.gateComment(testPR))
	if !ok || m.Outcome != ActionWait || m.Head != headA || m.Asks != 0 || len(m.Notified) != 0 {
		t.Fatalf("marker %+v (parsed %t)", m, ok)
	}

	// The second run asks, and decides on the answer.
	later := t0.Add(30 * time.Minute)
	agenda, err = Schedule(context.Background(), f.config(later, nil))
	if err != nil || len(agenda.Evaluate) != 1 || agenda.Evaluate[0].Undecided || !agenda.Evaluate[0].Ask || len(agenda.Evaluate[0].Answered) != 0 {
		t.Fatalf("the second scheduled run: %+v, %v; want the read asked about", agenda, err)
	}
	facts := goodFacts(t)
	facts.GatheredAt = later
	cfg = f.config(later, nil)
	cfg.Scheduled, cfg.ModelAsked = true, true
	if res, err := publish(t, cfg, files(t, facts, clean(t))); err != nil || res.Action != ActionMerged {
		t.Fatalf("the second scheduled run: %+v, %v; want a merge", res, err)
	}
}

// TestNoDecisionForTheHead: a pull request whose event's run died before
// publish, after a rebase of one the gate had decided, is found by the
// schedule and evaluated at the head it has. What the comment remembers
// for the same content still counts, a veto above all.
func TestNoDecisionForTheHead(t *testing.T) {
	f := newFake(t)
	facts := goodFacts(t)
	if res, err := publish(t, f.config(t0, nil), files(t, facts, vetoed("exfiltration", allow.ReadFull)(t))); err != nil || res.Action != ActionPerson {
		t.Fatalf("the veto: %+v, %v", res, err)
	}
	// Dependabot rebases; the run for the new head never reaches publish.
	moveTo(f, &facts, headB)
	f.open = "[" + f.pulls[0] + "]"
	later := quietSince.Add(UndecidedAfter)
	agenda, err := Schedule(context.Background(), f.config(later, nil))
	if err != nil || len(agenda.Evaluate) != 1 || !agenda.Evaluate[0].Undecided || agenda.Evaluate[0].Head != headB {
		t.Fatalf("the schedule: %+v, %v; want the new head evaluated", agenda, err)
	}
	facts.GatheredAt = later
	cfg := f.config(later, nil)
	cfg.Scheduled = true
	res, err := publish(t, cfg, files(t, facts, nil))
	if err != nil || res.Action != ActionPerson || !slices.Contains(res.Decision.Reasons, allow.ReasonVeto) {
		t.Fatalf("the scheduled run at the new head: %+v, %v; want the veto to stand", res, err)
	}
	if m, _ := parseMarker(f.gateComment(testPR)); m.Head != headB {
		t.Errorf("the comment is for %s", m.Head)
	}
}

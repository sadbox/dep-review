package land

import (
	"context"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/wire"
)

// notDated is what a gatherer makes of a registry that has no time the
// gate trusts.
var notDated = allow.TimeFact{Value: "release v1.3.0 is not immutable", Source: "GitHub: releases/tags/v1.3.0"}

// undated is goodFacts with its one update pinned at hash and dated by no
// registry.
func undated(t *testing.T, hash string) wire.Facts {
	t.Helper()
	f := goodFacts(t)
	f.Facts.Updates[0].FirstSeen = notDated
	f.Facts.Updates[0].Hash = hash
	return f
}

// image is a facts file for a listed image at tag@digest that the
// registry does not date.
func image(t *testing.T, to string) wire.Facts {
	t.Helper()
	f := goodFacts(t)
	u := goodUpdate("docker.io/library/golang")
	u.Listed = allow.Yes("docker.io/library/", "policy")
	u.From, u.To = "1.25@sha256:"+strings.Repeat("0", 64), to
	u.FirstSeen = allow.TimeFact{Value: "Docker Hub reports no usable tag_last_pushed for tag 1.25", Source: "GET hub.docker.com"}
	f.Facts.Ecosystem = allow.Docker
	f.Facts.Updates = []wire.Update{wire.NewUpdate(u, wire.Read{Status: wire.Nothing})}
	return f
}

// evaluate is one run of publish at now, and what the gate's comment
// remembers afterwards.
func evaluate(t *testing.T, f *fakeGitHub, now time.Time, facts wire.Facts) (Result, []seen) {
	t.Helper()
	res, err := publish(t, f.config(now, nil), files(t, facts, clean(t)))
	if err != nil {
		t.Fatal(err)
	}
	m, ok := parseMarker(f.gateComment(testPR))
	if !ok {
		t.Fatalf("the marker does not parse:\n%s", f.gateComment(testPR))
	}
	return res, m.FirstSeen
}

// wantWait checks that res waits for an age that is reached at until.
func wantWait(t *testing.T, what string, res Result, until time.Time) {
	t.Helper()
	if res.Action != ActionWait || len(res.Decision.Reasons) != 1 || res.Decision.Reasons[0] != allow.ReasonAge || !res.Decision.NotBefore.Equal(until) {
		t.Errorf("%s: %s %v until %s, want a wait for the age until %s", what, res.Action, res.Decision.Reasons, res.Decision.NotBefore, until)
	}
}

// wantSeen checks that the marker remembers exactly one pin, first
// evaluated at at.
func wantSeen(t *testing.T, what string, got []seen, eco string, u wire.Update, at time.Time) {
	t.Helper()
	if len(got) != 1 || got[0].Pin != pinKey(eco, u) || !got[0].At.Equal(at) {
		t.Errorf("%s: the marker remembers %+v, want the one pin, first evaluated %s", what, got, at)
	}
}

// TestFirstSeenIsTheGatesClock follows an update no registry dates (spec
// section 11, amendment 38): the first evaluation starts its age, the
// comment remembers when that was, and a later evaluation merges on the
// remembered time and not on its own.
func TestFirstSeenIsTheGatesClock(t *testing.T) {
	conf, _ := defaults(t)
	age := conf.Policy().MinAge
	f := newFake(t)
	facts := undated(t, "h1:new")
	pin := facts.Facts.Updates[0]

	res, remembered := evaluate(t, f, t0, facts)
	wantWait(t, "the first evaluation", res, t0.Add(age))
	wantSeen(t, "the first evaluation", remembered, allow.GoModules, pin, t0)
	body := f.gateComment(testPR)
	for _, want := range []string{
		"The fact: `FirstSeen` of `example.com/m` `v1.2.3` to `v1.3.0` is `yes`",
		"`2026-11-22T12:00:00Z; the registry's clock: release v1.3.0 is not immutable`",
		"(source: `" + firstSeenSource + "`)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the comment lacks %q:\n%s", want, body)
		}
	}

	// An hour short of the age it still waits, for the same moment: the
	// clock did not start again.
	res, remembered = evaluate(t, f, t0.Add(age-time.Hour), facts)
	wantWait(t, "an hour before the age", res, t0.Add(age))
	wantSeen(t, "an hour before the age", remembered, allow.GoModules, pin, t0)

	res, _ = evaluate(t, f, t0.Add(age), facts)
	if res.Action != ActionMerged {
		t.Errorf("at the age: %s %v, want merged", res.Action, res.Decision.Reasons)
	}
	if got := f.count("PUT", "/merge"); got != 1 {
		t.Errorf("%d merge calls, want 1", got)
	}
}

// TestFirstSeenOfANewPin: a pull request Dependabot rewrote to another
// pin is dated again, whatever stays the same about it, and the pin that
// is gone is forgotten.
func TestFirstSeenOfANewPin(t *testing.T) {
	conf, _ := defaults(t)
	age := conf.Policy().MinAge
	digest := func(c string) string { return "1.25@sha256:" + strings.Repeat(c, 64) }
	version := func(f wire.Facts, to string) wire.Facts {
		f.Facts.Updates[0].To = to
		return f
	}
	for _, tc := range []struct {
		name          string
		first, second wire.Facts
	}{
		{"the same version at another hash", undated(t, "h1:new"), undated(t, "h1:other")},
		{"another version at the same hash", undated(t, "h1:new"), version(undated(t, "h1:new"), "v1.3.1")},
		{"the same tag at another digest", image(t, digest("a")), image(t, digest("b"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			eco := tc.first.Facts.Ecosystem
			res, remembered := evaluate(t, f, t0, tc.first)
			wantWait(t, "the first pin", res, t0.Add(age))
			wantSeen(t, "the first pin", remembered, eco, tc.first.Facts.Updates[0], t0)

			// The first pin's age has passed. The second pin is new.
			later := t0.Add(age + time.Hour)
			res, remembered = evaluate(t, f, later, tc.second)
			wantWait(t, "the second pin", res, later.Add(age))
			wantSeen(t, "the second pin", remembered, eco, tc.second.Facts.Updates[0], later)

			// Back at the first pin, which the comment no longer knows.
			again := later.Add(time.Hour)
			res, remembered = evaluate(t, f, again, tc.first)
			wantWait(t, "the first pin again", res, again.Add(age))
			wantSeen(t, "the first pin again", remembered, eco, tc.first.Facts.Updates[0], again)
			if got := f.count("PUT", "/merge"); got != 0 {
				t.Errorf("%d merge calls, want none", got)
			}
		})
	}
}

// TestFirstSeenWithoutAHash: an update whose Bound does not hold has no
// hash in the facts file. A time taken for it then is not the bound
// pin's, so nothing merges on it; and such a run forgets none of the
// times the comment has, so an outage that takes Bound away does not
// start the bound pin's clock again.
func TestFirstSeenWithoutAHash(t *testing.T) {
	conf, _ := defaults(t)
	age := conf.Policy().MinAge
	bound := undated(t, "h1:new")
	boundPin := pinKey(allow.GoModules, bound.Facts.Updates[0])
	// unbound is the same update as fetch writes it when the registry did
	// not answer for the pin: no hash, and no artifact to read.
	unbound := func(firstSeen allow.TimeFact) wire.Facts {
		f := undated(t, "")
		u := &f.Facts.Updates[0]
		u.Bound = allow.Unavailable("the module proxy did not answer", "go mod download")
		u.FirstSeen = firstSeen
		u.Prepared = wire.Read{Status: wire.Nothing, Detail: "the gatherer named no artifact"}
		return f
	}
	at := func(remembered []seen, pin string) (time.Time, bool) {
		for _, s := range remembered {
			if s.Pin == pin {
				return s.At, true
			}
		}
		return time.Time{}, false
	}

	t.Run("a time taken without a hash is not the bound pin's", func(t *testing.T) {
		f := newFake(t)
		_, remembered := evaluate(t, f, t0, unbound(notDated))
		if len(remembered) != 1 || remembered[0].Pin == boundPin || !remembered[0].At.Equal(t0) {
			t.Fatalf("without a hash the marker remembers %+v, want one time for the pin without one", remembered)
		}
		// Its age has passed when the hash is first there. The bound pin is new.
		later := t0.Add(age + time.Hour)
		res, remembered := evaluate(t, f, later, bound)
		wantWait(t, "bound for the first time", res, later.Add(age))
		wantSeen(t, "bound for the first time", remembered, allow.GoModules, bound.Facts.Updates[0], later)
	})

	for name, outage := range map[string]allow.TimeFact{
		"the registry's clock did not answer either": allow.UnavailableTime("the module proxy did not answer", "go list"),
		"the registry's clock answered as before":    notDated,
	} {
		t.Run("an outage that takes the hash away, and "+name, func(t *testing.T) {
			f := newFake(t)
			res, _ := evaluate(t, f, t0, bound)
			wantWait(t, "bound", res, t0.Add(age))

			_, remembered := evaluate(t, f, t0.Add(24*time.Hour), unbound(outage))
			if got, ok := at(remembered, boundPin); !ok || !got.Equal(t0) {
				t.Fatalf("during the outage the marker remembers %+v, want the bound pin still first evaluated %s", remembered, t0)
			}
			if got := f.count("PUT", "/merge"); got != 0 {
				t.Fatalf("%d merge calls during the outage", got)
			}

			res, remembered = evaluate(t, f, t0.Add(age), bound)
			if res.Action != ActionMerged {
				t.Errorf("bound again at the age: %s %v, want merged on the first time", res.Action, res.Decision.Reasons)
			}
			// A run that knows the hash again forgets what was taken without it.
			wantSeen(t, "bound again", remembered, allow.GoModules, bound.Facts.Updates[0], t0)
		})
	}

	// What is carried through such a run is still held to the marker's size.
	t.Run("within the cap", func(t *testing.T) {
		f := newFake(t)
		_, reviewer := defaults(t)
		full := marker{Outcome: ActionWait, Head: headA, Fingerprint: reviewer}
		for i := 0; i < maxFirstSeen; i++ {
			full.FirstSeen = append(full.FirstSeen, seen{Pin: fmt.Sprintf("%064x", i), At: t0.Add(-time.Hour)})
		}
		f.comments[testPR] = []*fakeComment{{1, testBot, full.String() + "\n### dep-review: waiting\n"}}
		_, remembered := evaluate(t, f, t0, unbound(notDated))
		if len(remembered) != maxFirstSeen {
			t.Fatalf("the marker remembers %d times, want %d", len(remembered), maxFirstSeen)
		}
		// This run's own pin first, then as many of the others as fit.
		if got, ok := at(remembered, pinKey(allow.GoModules, unbound(notDated).Facts.Updates[0])); !ok || !got.Equal(t0) {
			t.Errorf("this run's pin is not remembered: %+v", remembered[:2])
		}
		if _, ok := parseMarker(f.gateComment(testPR)); !ok {
			t.Error("the marker does not parse")
		}
	})
}

// TestFirstSeenSurvivesARebase: a new head with the same pin keeps the
// pin's time.
func TestFirstSeenSurvivesARebase(t *testing.T) {
	conf, _ := defaults(t)
	age := conf.Policy().MinAge
	f := newFake(t)
	facts := undated(t, "h1:new")
	res, _ := evaluate(t, f, t0, facts)
	wantWait(t, "before the rebase", res, t0.Add(age))

	f.pulls = []string{pullJSON(testPR, "open", headB, "main", "clean", false)}
	facts.PullRequest.Head = headB
	res, remembered := evaluate(t, f, t0.Add(time.Hour), facts)
	wantWait(t, "after the rebase", res, t0.Add(age))
	wantSeen(t, "after the rebase", remembered, allow.GoModules, facts.Facts.Updates[0], t0)

	res, _ = evaluate(t, f, t0.Add(age), facts)
	if res.Action != ActionMerged {
		t.Errorf("at the age: %s %v, want merged", res.Action, res.Decision.Reasons)
	}
	if s := f.statuses(headB); len(s) == 0 || s[len(s)-1] != "success: merged" {
		t.Errorf("statuses on the new head: %q", s)
	}
}

// TestRegistryTimeWins: where a registry gave a time, the gate's clock is
// not looked at, and a time the comment has for that pin is dropped.
func TestRegistryTimeWins(t *testing.T) {
	conf, _ := defaults(t)
	age := conf.Policy().MinAge
	f := newFake(t)
	facts := undated(t, "h1:new")
	res, _ := evaluate(t, f, t0, facts)
	wantWait(t, "undated", res, t0.Add(age))

	// The registry dates the pin after all, an hour too young to merge by
	// its time though the gate's own has run out.
	facts.Facts.Updates[0].FirstSeen = allow.At(t0.Add(2*time.Hour), "registry clock")
	res, remembered := evaluate(t, f, t0.Add(age+time.Hour), facts)
	wantWait(t, "dated by the registry", res, t0.Add(2*time.Hour+age))
	if len(remembered) != 0 {
		t.Errorf("the marker still remembers %+v", remembered)
	}

	// And an old registry time merges at the first evaluation.
	f = newFake(t)
	facts.Facts.Updates[0].FirstSeen = allow.At(t0.Add(-age), "registry clock")
	if res, remembered = evaluate(t, f, t0, facts); res.Action != ActionMerged || len(remembered) != 0 {
		t.Errorf("an old registry time: %s %v, remembered %+v", res.Action, res.Decision.Reasons, remembered)
	}
	// Decide did not need the comment: the one read is Act's.
	if got := f.count("GET", "/comments"); got != 1 {
		t.Errorf("the comments were read %d times, want once", got)
	}
}

// TestFirstSeenWhileTheRegistryIsDown: a registry that was asked and did
// not answer is waited for, not replaced by the gate's clock. A time the
// comment already has for the pin is kept through the outage.
func TestFirstSeenWhileTheRegistryIsDown(t *testing.T) {
	conf, _ := defaults(t)
	age := conf.Policy().MinAge
	down := func(f wire.Facts) wire.Facts {
		f.Facts.Updates[0].FirstSeen = allow.UnavailableTime("index.golang.org: 503", "index.golang.org")
		return f
	}
	waitsForTheSource := func(what string, res Result) {
		t.Helper()
		if res.Action != ActionWait || !slices.Contains(res.Decision.Reasons, allow.ReasonSourceUnavailable) || slices.Contains(res.Decision.Reasons, allow.ReasonAge) {
			t.Errorf("%s: %s %v, want a wait for the source", what, res.Action, res.Decision.Reasons)
		}
	}

	// Down at the first evaluation: nothing is dated, nothing remembered.
	f := newFake(t)
	res, remembered := evaluate(t, f, t0, down(undated(t, "h1:new")))
	waitsForTheSource("down from the start", res)
	if len(remembered) != 0 {
		t.Errorf("down from the start: the marker remembers %+v", remembered)
	}
	if u := res.Decision.PerUpdate[0]; !u.NotBefore.IsZero() {
		t.Errorf("down from the start: old enough from %s", u.NotBefore)
	}

	// Dated, then down, then dated again: the first time stands.
	f = newFake(t)
	facts := undated(t, "h1:new")
	res, _ = evaluate(t, f, t0, facts)
	wantWait(t, "dated", res, t0.Add(age))
	res, remembered = evaluate(t, f, t0.Add(24*time.Hour), down(undated(t, "h1:new")))
	waitsForTheSource("down in between", res)
	wantSeen(t, "down in between", remembered, allow.GoModules, facts.Facts.Updates[0], t0)
	res, remembered = evaluate(t, f, t0.Add(age), facts)
	if res.Action != ActionMerged {
		t.Errorf("dated again at the age: %s %v, want merged", res.Action, res.Decision.Reasons)
	}
	wantSeen(t, "dated again", remembered, allow.GoModules, facts.Facts.Updates[0], t0)
}

// TestFirstSeenOnlyFromTheGatesComment: a remembered time counts only in
// a comment the gate app wrote, whatever that comment's outcome and head
// are, and a marker from before the gate remembered times has none.
func TestFirstSeenOnlyFromTheGatesComment(t *testing.T) {
	conf, reviewer := defaults(t)
	age := conf.Policy().MinAge
	facts := undated(t, "h1:new")
	old := []seen{{Pin: pinKey(allow.GoModules, facts.Facts.Updates[0]), At: t0.Add(-age)}}
	planted := func(outcome Action, head string) string {
		return marker{Outcome: outcome, Head: head, Fingerprint: reviewer, FirstSeen: old}.String() + "\n### dep-review: waiting\n"
	}
	before := "<!-- dep-review:v2 " + base64.RawURLEncoding.EncodeToString([]byte(
		`{"outcome":"wait","head":"`+headA+`","not_before":"2026-11-22T12:00:00Z","deadline":"2026-11-29T12:00:00Z",`+
			`"notified":[],"notified_failed":[],"notified_unread":[],"fingerprint":"`+reviewer+`","cache":[]}`)) + " -->\n### dep-review: waiting\n"
	if _, ok := parseMarker(before); !ok {
		t.Fatal("a marker without first-seen times does not parse")
	}

	for _, tc := range []struct {
		name    string
		comment *fakeComment
		// waits: the scheduled job takes the pull request up for the
		// comment. merged: publish used the time the comment has.
		waits, merged bool
	}{
		{"no comment", nil, false, false},
		{"the gate's comment, a wait at this head", &fakeComment{1, testBot, planted(ActionWait, headA)}, true, true},
		{"the gate's comment, a person's at another head", &fakeComment{1, testBot, planted(ActionPerson, headB)}, false, true},
		{"the gate's comment after a failed run", &fakeComment{1, testBot, planted(ActionFailed, headB)}, false, true},
		{"the gate's comment from before it remembered times", &fakeComment{1, testBot, before}, true, false},
		{"the gate's comment with a marker cut short", &fakeComment{1, testBot, planted(ActionWait, headA)[:80] + " -->\n"}, false, false},
		{"a comment by someone else", &fakeComment{1, "mallory", planted(ActionWait, headA)}, false, false},
		{"a comment by Dependabot", &fakeComment{1, "dependabot[bot]", planted(ActionWait, headA)}, false, false},
		{"a comment by another app", &fakeComment{1, "other-gate[bot]", planted(ActionWait, headA)}, false, false},
		{"a comment by a user named like the app", &fakeComment{1, "gate", planted(ActionWait, headA)}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.open = "[" + pullJSON(testPR, "open", headA, "main", "clean", false) + "]"
			if tc.comment != nil {
				f.comments[testPR] = []*fakeComment{tc.comment}
			}
			// What the scheduled job makes of the comment, before publish
			// writes its own: the marker's outcome, too, counts only from
			// the gate app.
			waiting, _, err := Waiting(context.Background(), f.config(t0, nil))
			if err != nil {
				t.Fatal(err)
			}
			if (len(waiting) == 1) != tc.waits {
				t.Errorf("%d pull requests wait for the comment, want one: %t", len(waiting), tc.waits)
			}
			if w := f.writes(); len(w) != 0 {
				t.Errorf("reading the comment wrote: %+v", w)
			}

			res, err := publish(t, f.config(t0, nil), files(t, facts, clean(t)))
			if err != nil {
				t.Fatal(err)
			}
			if tc.merged {
				if res.Action != ActionMerged {
					t.Errorf("%s %v, want merged on the remembered time", res.Action, res.Decision.Reasons)
				}
				return
			}
			wantWait(t, "first evaluated now", res, t0.Add(age))
		})
	}
}

// TestFirstSeenOfManyPins: two updates with one pin share one time, an
// update of each kind is treated on its own, and past maxFirstSeen pins
// an update gets no time, which is a person's.
func TestFirstSeenOfManyPins(t *testing.T) {
	conf, _ := defaults(t)
	age := conf.Policy().MinAge
	update := func(name, from string, seenAt allow.TimeFact) wire.Update {
		u := goodUpdate(name)
		u.From, u.FirstSeen = from, seenAt
		w := wire.NewUpdate(u, wire.Read{Status: wire.Prepared, Key: keyA, State: allow.ReadFull, Chunks: []wire.ChunkFile{}})
		w.Hash = "h1:" + name
		return w
	}

	f := newFake(t)
	facts := goodFacts(t)
	facts.Facts.Updates = []wire.Update{
		update("example.com/dated", "v1.2.3", allow.At(t0.Add(-age), "registry clock")),
		update("example.com/twice", "v1.2.2", notDated),
		update("example.com/twice", "v1.2.3", notDated),
		update("example.com/never", "v1.2.3", allow.TimeFact{}),
	}
	res, remembered := evaluate(t, f, t0, facts)
	wantWait(t, "four updates", res, t0.Add(age))
	want := []seen{{pinKey(allow.GoModules, facts.Facts.Updates[1]), t0}, {pinKey(allow.GoModules, facts.Facts.Updates[3]), t0}}
	if len(remembered) != 2 || remembered[0].Pin != want[0].Pin || remembered[1].Pin != want[1].Pin {
		t.Errorf("the marker remembers %+v, want the two pins no registry dates", remembered)
	}
	dir := files(t, facts, clean(t))
	ev, err := Decide(context.Background(), f.config(t0.Add(time.Hour), nil), filepath.Join(dir, wire.FactsFile), filepath.Join(dir, wire.VerdictsFile))
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []allow.TimeFact{
		allow.At(t0.Add(-age), "registry clock"),
		{OK: true, Time: t0, Value: "2026-11-22T12:00:00Z; the registry's clock: " + notDated.Value, Source: firstSeenSource},
		{OK: true, Time: t0, Value: "2026-11-22T12:00:00Z; the registry's clock: " + notDated.Value, Source: firstSeenSource},
		allow.At(t0, firstSeenSource),
	} {
		if got := ev.Facts.Updates[i].FirstSeen; !got.Time.Equal(want.Time) || got.OK != want.OK || got.Value != want.Value || got.Source != want.Source {
			t.Errorf("update %d: first seen %+v, want %+v", i, got, want)
		}
	}

	// One pin more than the marker holds: the last update is not dated.
	f = newFake(t)
	facts.Facts.Updates = nil
	for i := 0; i <= maxFirstSeen; i++ {
		facts.Facts.Updates = append(facts.Facts.Updates, update(fmt.Sprintf("example.com/m%d", i), "v1.2.3", notDated))
	}
	res, remembered = evaluate(t, f, t0, facts)
	if res.Action != ActionPerson || len(res.Decision.Reasons) != 1 || res.Decision.Reasons[0] != allow.ReasonFirstSeenUnknown {
		t.Fatalf("one pin too many: %s %v, want a person for first_seen_unknown", res.Action, res.Decision.Reasons)
	}
	for i, u := range res.Decision.PerUpdate {
		if person := u.Outcome == allow.Person; person != (i == maxFirstSeen) {
			t.Errorf("update %d: %s %v", i, u.Outcome, u.Reasons)
		}
	}
	if len(remembered) != maxFirstSeen {
		t.Errorf("the marker remembers %d pins, want %d", len(remembered), maxFirstSeen)
	}
	if body := f.gateComment(testPR); !strings.Contains(body, "remembers a first evaluation for no more than 50 pins") {
		t.Errorf("the comment does not say why the last update has no time:\n%s", body)
	}
}

// TestMarkerFitsEveryTime: with every list of notified heads full and
// every pin remembered, the marker fits its budget without a cached
// verdict in it, so a first-seen time is never what is dropped; and with
// a cache too large for the rest, only the cache gives way.
func TestMarkerFitsEveryTime(t *testing.T) {
	m := marker{Outcome: ActionRefused, Head: headA, Fingerprint: strings.Repeat("f", 64),
		NotBefore: t0.Add(123456789 * time.Nanosecond), Deadline: t0.Add(987654321 * time.Nanosecond)}
	for i := 0; i < maxNotified; i++ {
		head := fmt.Sprintf("%040x", i)
		m.Notified, m.NotifiedFailed, m.NotifiedUnread = append(m.Notified, head), append(m.NotifiedFailed, head), append(m.NotifiedUnread, head)
	}
	for i := 0; i < maxFirstSeen; i++ {
		m.FirstSeen = append(m.FirstSeen, seen{Pin: fmt.Sprintf("%064x", i), At: t0.Add(time.Duration(i)*time.Hour + 123456789*time.Nanosecond)})
	}
	check := func(what string, line string, cache bool) {
		t.Helper()
		payload := strings.TrimSuffix(strings.TrimPrefix(line, "<!-- dep-review:v2 "), " -->")
		if len(payload) > maxMarkerBytes {
			t.Fatalf("%s: a marker of %d bytes, want at most %d", what, len(payload), maxMarkerBytes)
		}
		got, ok := parseMarker(line)
		if !ok || len(got.FirstSeen) != maxFirstSeen || len(got.Notified) != maxNotified || (len(got.Cache) > 0) != cache {
			t.Fatalf("%s: read back %d times, %d notified heads and %d cached verdicts (ok %t)", what, len(got.FirstSeen), len(got.Notified), len(got.Cache), ok)
		}
		for i, s := range got.FirstSeen {
			if s.Pin != m.FirstSeen[i].Pin || !s.At.Equal(m.FirstSeen[i].At) {
				t.Fatalf("%s: time %d came back as %+v", what, i, s)
			}
		}
	}
	check("no cache", m.String(), false)

	long := strings.Repeat("q", maxCachedText)
	for i := 0; i < maxCached; i++ {
		m.Cache = append(m.Cache, cached{Key: fmt.Sprintf("%064x", i), Read: allow.ReadPartial,
			Veto: &allow.Veto{Category: "obfuscation", Quotes: []string{long, long, long}, Notes: long}})
	}
	check("a cache that does not fit", m.String(), true)
}

// TestPinKey: every part of a pin is part of its name, and no two pins
// run together into one.
func TestPinKey(t *testing.T) {
	base := wire.Update{Name: "example.com/m", From: "v1.2.3", To: "v1.3.0", Hash: "h1:abc"}
	key := pinKey(allow.GoModules, base)
	if !pinRE.MatchString(key) {
		t.Fatalf("key %q", key)
	}
	other := base
	other.From = "v1.0.0"
	if pinKey(allow.GoModules, other) != key {
		t.Error("the old version is part of the pin")
	}
	for what, u := range map[string]wire.Update{
		"the name":     {Name: "example.com/n", To: "v1.3.0", Hash: "h1:abc"},
		"the version":  {Name: "example.com/m", To: "v1.3.1", Hash: "h1:abc"},
		"the hash":     {Name: "example.com/m", To: "v1.3.0", Hash: "h1:abd"},
		"no hash":      {Name: "example.com/m", To: "v1.3.0"},
		"a moved join": {Name: "example.com/mv1.3.0", To: "", Hash: "h1:abc"},
		"a moved hash": {Name: "example.com/m", To: "v1.3.0h1:abc"},
	} {
		if pinKey(allow.GoModules, u) == key {
			t.Errorf("%s is not part of the pin", what)
		}
	}
	if pinKey(allow.NPM, base) == key {
		t.Error("the ecosystem is not part of the pin")
	}
}

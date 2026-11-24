package land

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/wire"
)

// TestFactsTooOld follows the path the gate's own advice opened (spec
// section 11, amendment 52). An event's run gathers at t0 and waits. A
// scheduled run, on fresh facts, finds a malware advisory: person. Then a
// job of the event's run is run again. GitHub hands it the first
// attempt's facts, and publish would decide on them with its own, later
// clock: old enough now, and clean as it was.
func TestFactsTooOld(t *testing.T) {
	f := newFake(t)
	first := goodFacts(t)
	first.GatheredAt = t0
	first.Facts.Updates[0].FirstSeen = allow.At(t0.Add(-70*time.Hour), "index.golang.org")

	cfg := f.config(t0.Add(time.Minute), nil)
	cfg.ModelAsked = true
	if res, err := publish(t, cfg, files(t, first, nil)); err != nil || res.Action != ActionWait {
		t.Fatalf("the first attempt: %+v, %v; want a wait", res, err)
	}

	fresh := goodFacts(t)
	fresh.GatheredAt = t0.Add(12 * time.Hour)
	fresh.Facts.Updates[0].FirstSeen = first.Facts.Updates[0].FirstSeen
	fresh.Facts.Updates[0].Clean = allow.No("malware advisory GHSA-xxxx-xxxx-xxxx", "advisories")
	if res, err := publish(t, f.config(t0.Add(12*time.Hour), nil), files(t, fresh, nil)); err != nil || res.Action != ActionPerson {
		t.Fatalf("the scheduled run: %+v, %v; want a person", res, err)
	}
	before, comment := len(f.writes()), f.gateComment(testPR)

	// The review job run again, twenty hours on: it answers now, and
	// publish gets the first attempt's facts.
	again := f.config(t0.Add(20*time.Hour), nil)
	again.ModelAsked = true
	res, err := publish(t, again, files(t, first, clean(t)))
	if !errors.Is(err, ErrFactsStale) {
		t.Fatalf("the re-run on the first attempt's facts: %+v, %v; want ErrFactsStale", res, err)
	}
	if len(f.writes()) != before || f.count("PUT", "/merge") != 0 || f.gateComment(testPR) != comment {
		t.Errorf("something was written on facts that are too old: %+v", f.writes()[before:])
	}
}

// The bound itself: facts are decided on up to MaxFactsAge after they
// were gathered and not a second later, and never before they were.
func TestFactsAgeBound(t *testing.T) {
	for _, tc := range []struct {
		name  string
		age   time.Duration // the publish job's clock, after GatheredAt
		stale bool
	}{
		{"a run's own facts", 2 * time.Minute, false},
		{"at the bound", MaxFactsAge, false},
		{"a second past the bound", MaxFactsAge + time.Second, true},
		{"a day old", 24 * time.Hour, true},
		{"the clocks of two runners", -30 * time.Second, false},
		{"gathered after the decision", -2 * time.Minute, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			facts := goodFacts(t)
			dir := files(t, facts, clean(t))
			_, err := Decide(context.Background(), f.config(facts.GatheredAt.Add(tc.age), nil),
				filepath.Join(dir, wire.FactsFile), filepath.Join(dir, wire.VerdictsFile))
			if errors.Is(err, ErrFactsStale) != tc.stale || (!tc.stale && err != nil) {
				t.Errorf("error %v, want stale: %t", err, tc.stale)
			}
			if tc.stale && !strings.Contains(err.Error(), "run all of the gate's jobs again") {
				t.Errorf("the error does not say what to do: %v", err)
			}
		})
	}

	// A pull request that was closed or moved on is nothing to do, however
	// old the facts: its newer head has a run of its own.
	t.Run("closed, with old facts", func(t *testing.T) {
		f := newFake(t)
		f.pulls = []string{pullJSON(testPR, "closed", headA, "main", "clean", false)}
		res, err := publish(t, f.config(t0.Add(24*time.Hour), nil), files(t, goodFacts(t), clean(t)))
		if err != nil || res.Action != ActionStale {
			t.Errorf("result %+v, %v; want stale and no error", res, err)
		}
	})
}

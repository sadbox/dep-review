package land

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/wire"
)

// failingWrites is the fake with the next n writes to a path under
// prefix answered 502, which GitHub can give and the client does not
// retry for a write.
func failingWrites(f *fakeGitHub, n int, prefix string) Config {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && strings.HasPrefix(r.URL.Path, prefix) && n > 0 {
			n--
			_, _ = io.ReadAll(r.Body) // read and dropped: the write fails
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, `{"message":"Server Error"}`) // a failed write is the client's to report
			return
		}
		f.ServeHTTP(w, r)
	}))
	f.t.Cleanup(srv.Close)
	c := gh.New("token")
	c.BaseURL = srv.URL + "/"
	c.MaxRetries = 0
	return Config{GitHub: c, Repo: testRepo, BotLogin: testBot}
}

// vetoOfKeyA is a verdicts file in which the model vetoes keyA.
func vetoOfKeyA(t *testing.T) *wire.Verdicts {
	t.Helper()
	_, reviewer := defaults(t)
	return &wire.Verdicts{Version: wire.Version, Verdicts: []wire.Verdict{{Key: keyA, Fingerprint: reviewer, Read: allow.ReadFull,
		Veto: &allow.Veto{Category: "exfiltration", Quotes: []string{"sends ~/.ssh to a host"}}}}}
}

// TestAVetoOutlivesAWriteThatFailed: a veto the model gave in a run whose
// publish then could not write the comment is in the marker that the run
// that failed writes, on the schedule (Asked) and on an event (Failed).
// Before, it was nowhere, the next ask sampled the model again, and one
// clean answer merged (spec section 11, amendment 73). The reviewer's
// reproduction failed the status write, after which Act now writes the
// comment itself (amendment 74).
func TestAVetoOutlivesAWriteThatFailed(t *testing.T) {
	decide := func(t *testing.T, cfg Config, f wire.Facts, v *wire.Verdicts) Evaluation {
		t.Helper()
		dir := files(t, f, v)
		ev, err := Decide(context.Background(), cfg, filepath.Join(dir, wire.FactsFile), filepath.Join(dir, wire.VerdictsFile))
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	for _, scheduled := range []bool{true, false} {
		name := map[bool]string{true: "on the schedule", false: "on an event"}[scheduled]
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			if scheduled {
				// What an event's run leaves when its review job did not
				// answer: a wait for the head, nothing remembered, no ask.
				m := waitingComment(t, f, t0.Add(72*time.Hour))
				m.Asks, m.AskedAt, m.Cache = 0, time.Time{}, nil
				f.comments[testPR][0].body = m.String() + "\n### dep-review: waiting\n"
			}
			cfg := failingWrites(f, 1, "/repos/o/r/issues/")
			cfg.Scheduled, cfg.ModelAsked = scheduled, true
			cfg.Now = func() time.Time { return t0 }

			// Run 1: the model vetoes keyA, and publish's comment write fails.
			ev := decide(t, cfg, goodFacts(t), vetoOfKeyA(t))
			if ev.Decision.Outcome != allow.Person {
				t.Fatalf("run 1 decided %v", ev.Decision)
			}
			if res, err := Act(context.Background(), cfg, ev); err == nil || res.Action != "" {
				t.Fatalf("run 1 acted: %+v, %v", res, err)
			}
			// What publish does when nothing was written.
			if scheduled {
				if err := Asked(context.Background(), cfg, testPR, headA, ev.Vetoes()); err != nil {
					t.Fatal(err)
				}
			} else if err := Failed(context.Background(), cfg, testPR, headA, "The fetch job ended success.", ev.Vetoes()); err != nil {
				t.Fatal(err)
			}
			remembersVeto(t, f, "after run 1", keyA)

			// Run 2, when the next ask is due: the model answers no_veto.
			later := t0.Add(31 * time.Minute)
			cfg.Now = func() time.Time { return later }
			facts := goodFacts(t)
			facts.GatheredAt = later.Add(-time.Minute)
			res, err := publish(t, cfg, files(t, facts, clean(t)))
			if err != nil || res.Action != ActionPerson || !slices.Contains(res.Decision.Reasons, allow.ReasonVeto) || f.count("PUT", "/merge") != 0 {
				t.Fatalf("run 2: %q %v, %v, %d merge calls; want a person's for the veto", res.Action, res.Decision.Reasons, err, f.count("PUT", "/merge"))
			}
		})
	}

	// Only the vetoes are carried. A clean answer of the run that failed is
	// not remembered: the next run asks again, as it did before.
	t.Run("a clean answer of the run that failed is not remembered", func(t *testing.T) {
		f := newFake(t)
		cfg := f.config(t0, nil)
		ev := decide(t, cfg, goodFacts(t), clean(t))
		if err := Failed(context.Background(), cfg, testPR, headA, "The fetch job ended success.", ev.Vetoes()); err != nil {
			t.Fatal(err)
		}
		if m, ok := parseMarker(f.gateComment(testPR)); !ok || len(m.Cache) != 0 {
			t.Errorf("the marker after: %+v", m.Cache)
		}
	})
	// A veto the run had to give up is recorded as given up.
	t.Run("a veto given up stays given up", func(t *testing.T) {
		f := newFake(t)
		cfg := f.config(t0, nil)
		ev := decide(t, cfg, goodFacts(t), vetoOfKeyA(t))
		ev.forgot = true
		if err := Failed(context.Background(), cfg, testPR, headA, "The fetch job ended success.", ev.Vetoes()); err != nil {
			t.Fatal(err)
		}
		if m, ok := parseMarker(f.gateComment(testPR)); !ok || !m.Forgot {
			t.Errorf("the marker after: %+v", m)
		}
	})
	// Under the reviewer's fingerprint the run's vetoes come first, and what
	// the marker had besides stays behind them, to maxCached in all.
	t.Run("the marker's own entries stay behind the run's vetoes", func(t *testing.T) {
		_, reviewer := defaults(t)
		old := marker{Outcome: ActionWait, Head: headA, Fingerprint: reviewer}
		for i := range maxCached {
			old.Cache = append(old.Cache, cached{Key: fmt.Sprintf("%064x", i), Read: allow.ReadFull})
		}
		v := Vetoes{fingerprint: reviewer, cache: []cached{{Key: keyA, Read: allow.ReadFull, Veto: &allow.Veto{Category: "exfiltration", Quotes: []string{}}}}}
		mk := old.next(ActionFailed, headA)
		v.keep(&mk)
		if len(mk.Cache) != maxCached || mk.Cache[0].Key != keyA || mk.Cache[1] != old.Cache[0] {
			t.Errorf("%d entries, first %+v", len(mk.Cache), mk.Cache[:2])
		}
		// Under another fingerprint nothing of the old is looked at, and the
		// run's vetoes take its place.
		mk = marker{Outcome: ActionWait, Head: headA, Fingerprint: strings.Repeat("0", 64), Cache: old.Cache}
		v.keep(&mk)
		if mk.Fingerprint != reviewer || len(mk.Cache) != 1 || mk.Cache[0].Key != keyA {
			t.Errorf("under another fingerprint: %s, %d entries", mk.Fingerprint, len(mk.Cache))
		}
	})
	// Every veto, the run's and the marker's, comes before any clean
	// entry, and one that does not fit is recorded as given up (spec
	// section 11, amendment 80).
	t.Run("vetoes first, and one cut is given up", func(t *testing.T) {
		_, reviewer := defaults(t)
		veto := func(i int) cached {
			return cached{Key: fmt.Sprintf("%064x", i), Read: allow.ReadFull, Veto: &allow.Veto{Category: "exfiltration", Quotes: []string{}}}
		}
		var v Vetoes
		v.fingerprint = reviewer
		for i := range maxCached - 1 {
			v.cache = append(v.cache, veto(i))
		}
		// A clean entry ahead of the marker's veto.
		mk := marker{Outcome: ActionWait, Head: headA, Fingerprint: reviewer,
			Cache: []cached{{Key: keyA, Read: allow.ReadFull}, veto(1000)}}
		v.keep(&mk)
		if len(mk.Cache) != maxCached || mk.Cache[maxCached-1].Key != veto(1000).Key || mk.Forgot {
			t.Errorf("%d entries, last %+v, forgot %t", len(mk.Cache), mk.Cache[len(mk.Cache)-1], mk.Forgot)
		}
		// More vetoes than a marker holds, across the run's and the marker's.
		mk = marker{Outcome: ActionWait, Head: headA, Fingerprint: reviewer, Cache: []cached{veto(1000), veto(1001)}}
		v.keep(&mk)
		if len(mk.Cache) != maxCached || !mk.Forgot {
			t.Errorf("%d entries, forgot %t", len(mk.Cache), mk.Forgot)
		}
	})
}

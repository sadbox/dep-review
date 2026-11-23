package land

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/wire"
)

// statusLimit is the fake behind GitHub's documented limit: after limit
// statuses on one commit for one context, a status write is a 422 ("There
// is a limit of 1000 statuses per sha and context within a repository.
// Attempts to create more than 1000 statuses will result in a validation
// error."). A status refused so never reaches the fake.
func statusLimit(f *fakeGitHub, limit int) Config {
	seen := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/repos/o/r/statuses/") {
			if seen[r.URL.Path] >= limit {
				io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnprocessableEntity)
				io.WriteString(w, `{"message":"Validation Failed","errors":[{"resource":"Status","code":"custom","message":"This SHA and context has reached the maximum number of statuses."}]}`)
				return
			}
			seen[r.URL.Path]++
		}
		f.ServeHTTP(w, r)
	}))
	f.t.Cleanup(srv.Close)
	c := gh.New("token")
	c.BaseURL = srv.URL + "/"
	c.MaxRetries = 0
	return Config{GitHub: c, Repo: testRepo, BotLogin: testBot}
}

// TestAStatusThatCannotBeWritten: a status write that fails does not stop
// the comment or the notification of Expired, Failed, or Act for anything
// but a merge, and its error comes back after them (spec section 11,
// amendment 74). Before, a head at GitHub's limit stayed a wait past its
// deadline, and nobody was told.
func TestAStatusThatCannotBeWritten(t *testing.T) {
	t.Run("Expired", func(t *testing.T) {
		f := newFake(t)
		f.open = "[" + pullJSON(testPR, "open", headA, "main", "clean", false) + "]"
		waitingComment(t, f, t0.Add(-time.Hour))
		cfg := statusLimit(f, 0)
		rec := &recorder{}
		cfg.Notifier, cfg.Scheduled, cfg.Now = rec, true, func() time.Time { return t0 }
		if err := Expired(context.Background(), cfg, testPR, headA); err == nil || !strings.Contains(err.Error(), "422") {
			t.Fatalf("err = %v, want the status write's", err)
		}
		body := f.gateComment(testPR)
		if m, ok := parseMarker(body); !ok || m.Outcome != ActionPerson || !strings.Contains(body, "That deadline has passed") || len(rec.got) != 1 {
			t.Errorf("marker %+v, %d notifications, comment:\n%s", m, len(rec.got), body)
		}
		// A second look finds a person's, and does nothing.
		if err := Expired(context.Background(), cfg, testPR, headA); err != nil || len(rec.got) != 1 {
			t.Errorf("a second look: %v, %d notifications", err, len(rec.got))
		}
	})
	t.Run("Failed", func(t *testing.T) {
		f := newFake(t)
		cfg := statusLimit(f, 0)
		rec := &recorder{}
		cfg.Notifier, cfg.Now = rec, func() time.Time { return t0 }
		dir := files(t, goodFacts(t), vetoOfKeyA(t))
		ev, err := Decide(context.Background(), cfg, dir+"/"+wire.FactsFile, dir+"/"+wire.VerdictsFile)
		if err != nil {
			t.Fatal(err)
		}
		if err := Failed(context.Background(), cfg, testPR, headA, "The fetch job ended success.", ev.Vetoes()); err == nil || !strings.Contains(err.Error(), "422") {
			t.Fatalf("err = %v, want the status write's", err)
		}
		// The veto of the run is kept (amendment 73) also when no status
		// can be written.
		remembersVeto(t, f, "after Failed", keyA)
		if body := f.gateComment(testPR); !strings.Contains(body, "### dep-review: the run failed") || len(rec.got) != 1 {
			t.Errorf("%d notifications, comment:\n%s", len(rec.got), body)
		}
	})
	t.Run("Act, for a person", func(t *testing.T) {
		f := newFake(t)
		cfg := statusLimit(f, 0)
		rec := &recorder{}
		cfg.Notifier, cfg.Now = rec, func() time.Time { return t0 }
		res, err := publish(t, cfg, files(t, goodFacts(t), vetoOfKeyA(t)))
		if err == nil || !strings.Contains(err.Error(), "422") || res.Action != ActionPerson {
			t.Fatalf("%+v, %v; want a person's and the status write's error", res, err)
		}
		remembersVeto(t, f, "after Act", keyA)
		if body := f.gateComment(testPR); !strings.Contains(body, "### dep-review: needs a person") || len(rec.got) != 1 {
			t.Errorf("%d notifications, comment:\n%s", len(rec.got), body)
		}
	})
	// The one exception: the success before a merge must be written, or
	// there is no merge.
	t.Run("Act, for a merge", func(t *testing.T) {
		f := newFake(t)
		cfg := statusLimit(f, 0)
		cfg.Now = func() time.Time { return t0 }
		res, err := publish(t, cfg, files(t, goodFacts(t), clean(t)))
		if err == nil || res.Action != "" || f.count("PUT", "/merge") != 0 || len(f.comments[testPR]) != 0 {
			t.Errorf("%+v, %v, %d merge calls, comments %d", res, err, f.count("PUT", "/merge"), len(f.comments[testPR]))
		}
	})
}

// TestStatusesThatSayNothingNew: Act does not set a status whose state and
// description are what it last set for the head (spec section 11,
// amendment 74). It does set the first of a head, a change, and the
// success before every merge it asks for.
func TestStatusesThatSayNothingNew(t *testing.T) {
	// A wait for an age that is not reached: the same status at every run.
	young := func(now time.Time) wire.Facts {
		facts := goodFacts(t)
		facts.GatheredAt = now.Add(-time.Minute)
		facts.Facts.Updates[0].FirstSeen = allow.At(t0.Add(-time.Hour), "index.golang.org")
		return facts
	}
	f := newFake(t)
	cfg := f.config(t0, nil)
	cfg.Scheduled = true
	for run := range 3 {
		now := t0.Add(time.Duration(run) * 30 * time.Minute)
		cfg.Now = func() time.Time { return now }
		if res, err := publish(t, cfg, files(t, young(now), clean(t))); err != nil || res.Action != ActionWait {
			t.Fatalf("run %d: %+v, %v", run, res, err)
		}
	}
	if s := f.statuses(headA); len(s) != 1 || !strings.HasPrefix(s[0], "pending: waiting until ") {
		t.Errorf("three runs that wait alike: statuses %q, want one", s)
	}
	// A change is set, and so is the first status of a new head. An
	// event's run with no verdicts leaves the read pending.
	cfg.Scheduled = false
	cfg.Now = func() time.Time { return t0.Add(2 * time.Hour) }
	if res, err := publish(t, cfg, files(t, young(t0.Add(2*time.Hour)), nil)); err != nil || res.Action != ActionWait {
		t.Fatalf("a read that is now pending: %+v, %v", res, err)
	}
	if s := f.statuses(headA); len(s) != 2 || !strings.HasPrefix(s[1], "pending: waiting (read_pending)") {
		t.Errorf("after a change: statuses %q", s)
	}
	facts := young(t0.Add(2 * time.Hour))
	moveTo(f, &facts, headB)
	if res, err := publish(t, cfg, files(t, facts, nil)); err != nil || res.Action != ActionWait {
		t.Fatalf("a new head: %+v, %v", res, err)
	}
	if s := f.statuses(headB); len(s) != 1 {
		t.Errorf("a new head: statuses %q", s)
	}

	// A run that could not write its decision gives up what the marker
	// says was set: it may have set another (a success before a merge
	// call that got no answer), and the next run sets its status again.
	t.Run("after a run that could not write", func(t *testing.T) {
		f := newFake(t)
		cfg := f.config(t0, nil)
		cfg.Scheduled = true
		if _, err := publish(t, cfg, files(t, young(t0), clean(t))); err != nil {
			t.Fatal(err)
		}
		if err := Asked(context.Background(), cfg, testPR, headA, Vetoes{}); err != nil {
			t.Fatal(err)
		}
		if _, err := publish(t, cfg, files(t, young(t0), clean(t))); err != nil {
			t.Fatal(err)
		}
		if s := f.statuses(headA); len(s) != 2 || s[0] != s[1] {
			t.Errorf("statuses %q, want the same one twice", s)
		}
	})
}

// TestAWaitDoesNotReachTheStatusLimit is the reviewer's simulation turned
// around: an update that needs 14 days (a major: here an indirect one,
// which needs no list entry) waits at every half-hourly scheduled run,
// then GitHub refuses each merge for a failing required check until the
// deadline, 21 days in all. Before, every run set a status and a refused
// merge two, and GitHub's limit was reached on day 17. Now the wait costs
// one, each refused merge two, and the deadline is reached and written.
func TestAWaitDoesNotReachTheStatusLimit(t *testing.T) {
	f := newFake(t)
	f.mergeCode, f.mergeBody = 405, `{"message":"Required status check \"test\" is failing."}`
	cfg := statusLimit(f, 1000)
	rec := &recorder{}
	cfg.Notifier, cfg.Scheduled = rec, true
	var res Result
	run := 0
	for ; run < 48*22 && res.Action != ActionPerson; run++ {
		now := t0.Add(time.Duration(run) * 30 * time.Minute)
		cfg.Now = func() time.Time { return now }
		facts := goodFacts(t)
		facts.GatheredAt = now.Add(-time.Minute)
		facts.Facts.Opened = t0
		u := goodUpdate("example.com/m")
		u.From, u.To = "v1.2.3", "v2.0.0"
		u.Increase = allow.Yes("v1.2.3 to v2.0.0", "x/mod/semver")
		u.Major = allow.Yes("v1 to v2", "x/mod/semver")
		u.Indirect = allow.Yes("// indirect", "go.mod")
		u.FirstSeen = allow.At(t0, "index.golang.org")
		facts.Facts.Updates[0] = wire.NewUpdate(u, facts.Facts.Updates[0].Prepared)
		var err error
		if res, err = publish(t, cfg, files(t, facts, clean(t))); err != nil {
			t.Fatalf("run %d, day %.1f: %v", run, now.Sub(t0).Hours()/24, err)
		}
	}
	n := len(f.statuses(headA))
	t.Logf("%d runs, %d statuses, last %q", run, n, f.statuses(headA)[n-1])
	if res.Action != ActionPerson || !strings.HasPrefix(f.statuses(headA)[n-1], "failure: needs a person: checks_deadline") || len(rec.got) != 1 {
		t.Fatalf("the deadline: %+v, %d notifications", res, len(rec.got))
	}
	// The wait for the age is one status; each of the 336 runs of the week
	// after it, and the one at the deadline, asks GitHub to merge and sets
	// success and then pending or, at the deadline, failure: 675.
	if n > 1+2*(7*48+1) {
		t.Errorf("%d statuses", n)
	}
}

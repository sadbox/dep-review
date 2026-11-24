package land

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

// youngFacts are facts of a wait for an age that is not reached at now:
// the same status at every run.
func youngFacts(t *testing.T, now time.Time) wire.Facts {
	facts := goodFacts(t)
	facts.GatheredAt = now.Add(-time.Minute)
	facts.Facts.Updates[0].FirstSeen = allow.At(t0.Add(-time.Hour), "index.golang.org")
	return facts
}

// TestStatusesThatSayNothingNew: Act does not set a status whose state and
// description are what GitHub shows for the gate's context on the head
// (spec section 11, amendment 79). It does set the first of a head, a
// change, and the success before every merge it asks for.
func TestStatusesThatSayNothingNew(t *testing.T) {
	f := newFake(t)
	cfg := f.config(t0, nil)
	cfg.Scheduled = true
	for run := range 3 {
		now := t0.Add(time.Duration(run) * 30 * time.Minute)
		cfg.Now = func() time.Time { return now }
		if res, err := publish(t, cfg, files(t, youngFacts(t, now), clean(t))); err != nil || res.Action != ActionWait {
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
	if res, err := publish(t, cfg, files(t, youngFacts(t, t0.Add(2*time.Hour)), nil)); err != nil || res.Action != ActionWait {
		t.Fatalf("a read that is now pending: %+v, %v", res, err)
	}
	if s := f.statuses(headA); len(s) != 2 || !strings.HasPrefix(s[1], "pending: waiting (read_pending)") {
		t.Errorf("after a change: statuses %q", s)
	}
	facts := youngFacts(t, t0.Add(2*time.Hour))
	moveTo(f, &facts, headB)
	if res, err := publish(t, cfg, files(t, facts, nil)); err != nil || res.Action != ActionWait {
		t.Fatalf("a new head: %+v, %v", res, err)
	}
	if s := f.statuses(headB); len(s) != 1 {
		t.Errorf("a new head: statuses %q", s)
	}

	// What GitHub shows counts, not what the comment remembers: a status
	// GitHub has is not set again for a run with no comment to go by.
	t.Run("GitHub shows it, the comment does not", func(t *testing.T) {
		f := newFake(t)
		cfg := f.config(t0, nil)
		cfg.Scheduled = true
		if _, err := publish(t, cfg, files(t, youngFacts(t, t0), clean(t))); err != nil {
			t.Fatal(err)
		}
		f.comments[testPR] = nil
		if _, err := publish(t, cfg, files(t, youngFacts(t, t0), clean(t))); err != nil {
			t.Fatal(err)
		}
		if s := f.statuses(headA); len(s) != 1 {
			t.Errorf("statuses %q, want one", s)
		}
	})
}

// TestAStatusIsSetWhenGitHubCannotSay: a read of the combined status that
// fails, or an answer without the gate's context, sets the status, and
// the read is never an error of the run (spec section 11, amendment 79).
func TestAStatusIsSetWhenGitHubCannotSay(t *testing.T) {
	for _, tc := range []struct {
		name          string
		readCode      int
		otherContexts int
		want          int
	}{
		{name: "the read fails", readCode: http.StatusBadGateway, want: 2},
		{name: "the read is refused", readCode: http.StatusForbidden, want: 2},
		// GitHub lists 100 contexts a page, and total_count says there are
		// more: the gate's is not among those listed.
		{name: "the gate's context is not on the first page", otherContexts: 100, want: 2},
		{name: "the gate's context is the hundredth", otherContexts: 99, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			cfg := f.config(t0, nil)
			cfg.Scheduled = true
			if _, err := publish(t, cfg, files(t, youngFacts(t, t0), clean(t))); err != nil {
				t.Fatal(err)
			}
			f.statusReadCode, f.otherContexts = tc.readCode, tc.otherContexts
			now := t0.Add(30 * time.Minute)
			cfg.Now = func() time.Time { return now }
			if res, err := publish(t, cfg, files(t, youngFacts(t, now), clean(t))); err != nil || res.Action != ActionWait {
				t.Fatalf("%+v, %v", res, err)
			}
			if s := f.statuses(headA); len(s) != tc.want || s[0] != s[len(s)-1] {
				t.Errorf("statuses %q, want the same one %d times", s, tc.want)
			}
		})
	}
}

// TestAStaleSuccessIsReplaced is the sequence above turned around: a
// wait, then a merge whose success is set and whose run then runs out of
// its time in the merge call, so that nothing records the success, then
// the same wait again. GitHub shows the success, so the wait's status is
// set over it. With the status the comment remembered (amendment 74) it
// was not, and a head that waits showed the gate's success.
func TestAStaleSuccessIsReplaced(t *testing.T) {
	f := newFake(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/merge") {
			io.ReadAll(r.Body)
			select { // GitHub is slow, and the job's time ends
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
			return
		}
		f.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	c := gh.New("token")
	c.BaseURL, c.MaxRetries = srv.URL+"/", 0
	cfg := Config{GitHub: c, Repo: testRepo, BotLogin: testBot, Scheduled: true}
	facts := func(now time.Time, unavailable bool) wire.Facts {
		facts := goodFacts(t)
		facts.GatheredAt = now.Add(-time.Minute)
		if unavailable {
			u := goodUpdate("example.com/m")
			u.Clean = allow.Unavailable("the advisories did not answer", "advisories")
			facts.Facts.Updates[0] = wire.NewUpdate(u, facts.Facts.Updates[0].Prepared)
		}
		return facts
	}

	cfg.Now = func() time.Time { return t0 }
	if res, err := publish(t, cfg, files(t, facts(t0, true), clean(t))); err != nil || res.Action != ActionWait {
		t.Fatalf("run 1: %+v, %v", res, err)
	}

	t2 := t0.Add(30 * time.Minute)
	cfg.Now = func() time.Time { return t2 }
	dir := files(t, facts(t2, false), clean(t))
	ev, err := Decide(context.Background(), cfg, filepath.Join(dir, wire.FactsFile), filepath.Join(dir, wire.VerdictsFile))
	if err != nil || ev.Decision.Outcome != allow.Merge {
		t.Fatalf("run 2 decided %v, %v", ev.Decision, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if res, err := Act(ctx, cfg, ev); err == nil || res.Action != "" {
		t.Fatalf("run 2: %+v, %v; want nothing written", res, err)
	}
	Asked(ctx, cfg, testPR, headA, ev.Vetoes()) // what publish does next, on the same context
	if s := f.statuses(headA); !strings.HasPrefix(s[len(s)-1], "success: ") {
		t.Fatalf("run 2 left %q", s)
	}

	t3 := t0.Add(time.Hour)
	cfg.Now = func() time.Time { return t3 }
	res, err := publish(t, cfg, files(t, facts(t3, true), clean(t)))
	if s := f.statuses(headA); err != nil || res.Action != ActionWait || !strings.HasPrefix(s[len(s)-1], "pending: waiting (source_unavailable)") {
		t.Errorf("run 3: %+v, %v; statuses %q", res, err, s)
	}
}

// TestAYearLongWaitSetsOneStatus: a wait that says the same at every run
// costs one status however long it lasts, here a year of 48 scheduled runs
// a day (spec section 11, amendment 79).
func TestAYearLongWaitSetsOneStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("17520 runs")
	}
	f := newFake(t)
	cfg := f.config(t0, nil)
	cfg.Scheduled = true
	// An age that is reached in a year: waiting for an age has no
	// deadline.
	firstSeen := t0.Add(365 * 24 * time.Hour)
	runs := 0
	for now := t0; now.Before(t0.Add(365 * 24 * time.Hour)); now = now.Add(30 * time.Minute) {
		cfg.Now = func() time.Time { return now }
		facts := goodFacts(t)
		facts.GatheredAt = now.Add(-time.Minute)
		facts.Facts.Updates[0].FirstSeen = allow.At(firstSeen, "index.golang.org")
		res, err := publish(t, cfg, files(t, facts, clean(t)))
		if err != nil || res.Action != ActionWait {
			t.Fatalf("run %d: %+v, %v", runs, res, err)
		}
		runs++
	}
	if s := f.statuses(headA); runs != 365*48 || len(s) != 1 {
		t.Errorf("%d runs, statuses %q", runs, s)
	}
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

// The read of the combined status has a short time of its own (amendment
// 79): one that hangs must not use up the time the write after it needs.
// Without that, the read ran until Act's context ended and the status was
// not set at all.
func TestAStatusReadThatHangsDoesNotStopTheWrite(t *testing.T) {
	f := newFake(t)
	hang := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-hang:
			if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/status") {
				<-r.Context().Done()
				return
			}
		default:
		}
		f.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	cfg := f.config(t0, nil)
	cfg.GitHub.BaseURL = srv.URL + "/"
	cfg.Scheduled = true
	if _, err := publish(t, cfg, files(t, youngFacts(t, t0), clean(t))); err != nil {
		t.Fatal(err)
	}
	close(hang)
	was := statusReadTime
	statusReadTime = 50 * time.Millisecond
	t.Cleanup(func() { statusReadTime = was })

	now := t0.Add(4 * time.Hour)
	cfg.Now = func() time.Time { return now }
	dir := files(t, youngFacts(t, now), clean(t))
	ev, err := Decide(context.Background(), cfg, filepath.Join(dir, wire.FactsFile), filepath.Join(dir, wire.VerdictsFile))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if res, err := Act(ctx, cfg, ev); err != nil || res.Action != ActionWait {
		t.Fatalf("%+v, %v", res, err)
	}
	if s := f.statuses(headA); len(s) != 2 {
		t.Errorf("statuses %q, want the second one set although the read never answered", s)
	}
}

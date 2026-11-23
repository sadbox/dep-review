package land

import (
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/wire"
)

// rebaseCommand is what has Dependabot rebuild a pull request. A comment
// by the gate's app must never hold it: it would itself be a command.
const rebaseCommand = "@dependabot rebase"

// TestHeldMergeTellsTheOwner: a merge the gate holds because the default
// branch changed a file of the pull request has a reason of its own, and
// the owner is told once per head: at once for a security fix, which
// would have merged on the fast path, and otherwise at the first
// scheduled run a day after the hold began (spec section 11, amendment
// 78). The notification names the file and Dependabot's command; the
// comment names neither command nor "@".
func TestHeldMergeTellsTheOwner(t *testing.T) {
	type run struct {
		after     time.Duration // since t0
		head      string
		scheduled bool
		told      bool // a notice about the hold goes out in this run
	}
	for _, tc := range []struct {
		name     string
		security bool
		runs     []run
	}{
		{name: "a security fix", security: true, runs: []run{
			{0, headA, false, true},
			{30 * time.Minute, headA, true, false},
			{25 * time.Hour, headA, true, false},
		}},
		{name: "any other update", runs: []run{
			{0, headA, false, false},
			{30 * time.Minute, headA, true, false},
			{23*time.Hour + 59*time.Minute, headA, true, false},
			// An event's run does not count the day.
			{24 * time.Hour, headA, false, false},
			{24*time.Hour + 30*time.Minute, headA, true, true},
			{25 * time.Hour, headA, true, false},
			// A new head starts over.
			{26 * time.Hour, headB, true, false},
			{49*time.Hour + 59*time.Minute, headB, true, false},
			{50 * time.Hour, headB, true, true},
			{50*time.Hour + 30*time.Minute, headB, true, false},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.compare = compared(1, named("go.sum")...)
			rec := &recorder{}
			for i, r := range tc.runs {
				now := t0.Add(r.after)
				facts := goodFacts(t)
				facts.GatheredAt = now.Add(-time.Minute)
				if tc.security {
					u := goodUpdate("example.com/m")
					u.SecurityFix = allow.Yes("GHSA-xxxx-xxxx-xxxx is fixed in v1.3.0", "advisories")
					facts.Facts.Updates[0] = wire.NewUpdate(u, facts.Facts.Updates[0].Prepared)
				}
				moveTo(f, &facts, r.head)
				cfg := f.config(now, rec)
				cfg.Scheduled = r.scheduled
				before := len(rec.got)
				res, err := publish(t, cfg, files(t, facts, clean(t)))
				if err != nil || res.Action != ActionWait || !res.Held || res.Decision.Reasons[0] != allow.ReasonBaseChanged {
					t.Fatalf("run %d: %+v, %v", i, res, err)
				}
				if told := len(rec.got) - before; told != map[bool]int{true: 1, false: 0}[r.told] {
					t.Fatalf("run %d (%s after, head %.1s): %d notifications, want told %t: %+v", i, r.after, r.head, told, r.told, rec.got)
				}
				if r.told {
					body := rec.got[len(rec.got)-1].Body
					for _, want := range []string{"`go.sum`", "comment `" + rebaseCommand + "` on the pull request", "did not ask GitHub to merge"} {
						if !strings.Contains(body, want) {
							t.Errorf("run %d: the notification lacks %q: %s", i, want, body)
						}
					}
				}
				if s := f.statuses(r.head); !strings.HasPrefix(s[len(s)-1], "pending: waiting (base_changed), at most until ") {
					t.Errorf("run %d: statuses %q", i, s)
				}
				if body := f.gateComment(testPR); strings.Contains(body[strings.Index(body, "\n"):], "@") {
					t.Errorf("run %d: the comment says \"@\":\n%s", i, body)
				}
			}
		})
	}

	// At the deadline the pull request is a person's, and the status, the
	// notification and the comment all say why: the hold, not checks.
	t.Run("the deadline", func(t *testing.T) {
		now := t0.Add(7 * 24 * time.Hour)
		f := newFake(t)
		f.compare = compared(1, named("go.sum")...)
		facts := goodFacts(t)
		facts.GatheredAt = now.Add(-time.Minute)
		rec := &recorder{}
		cfg := f.config(now, rec)
		cfg.Scheduled = true
		res, err := publish(t, cfg, files(t, facts, clean(t)))
		if err != nil || res.Action != ActionPerson || res.Decision.Reasons[0] != allow.ReasonBaseChangedDeadline {
			t.Fatalf("%+v, %v", res, err)
		}
		if s := f.statuses(headA); len(s) != 1 || s[0] != "failure: needs a person: base_changed_deadline" {
			t.Errorf("statuses %q", s)
		}
		if len(rec.got) != 1 || !strings.Contains(rec.got[0].Body, "(base_changed_deadline): "+allow.ReasonBaseChangedDeadline.Explain()) {
			t.Errorf("notifications %+v", rec.got)
		}
		if body := f.gateComment(testPR); strings.Contains(body[strings.Index(body, "\n"):], "@") || strings.Contains(body, allow.ReasonChecksDeadline.Explain()) {
			t.Errorf("the comment:\n%s", body)
		}
	})

	// The name is GitHub's, and whoever can push to the default branch
	// chose it: in a notification it is one capped line with no "@".
	t.Run("a file name in the notification", func(t *testing.T) {
		f := newFake(t)
		name := "a`b|@dependabot merge\n" + strings.Repeat("x", 500) + ".json"
		f.prFiles = `[{"filename":"` + strings.ReplaceAll(name, "\n", `\n`) + `"}]`
		f.compare = `{"ahead_by":1,"files":[{"filename":"` + strings.ReplaceAll(name, "\n", `\n`) + `"}]}`
		facts := goodFacts(t)
		u := goodUpdate("example.com/m")
		u.SecurityFix = allow.Yes("GHSA-xxxx-xxxx-xxxx is fixed in v1.3.0", "advisories")
		facts.Facts.Updates[0] = wire.NewUpdate(u, facts.Facts.Updates[0].Prepared)
		rec := &recorder{}
		if _, err := publish(t, f.config(t0, rec), files(t, facts, clean(t))); err != nil {
			t.Fatal(err)
		}
		if len(rec.got) != 1 {
			t.Fatalf("notifications %+v", rec.got)
		}
		body := rec.got[0].Body
		if strings.Contains(body, "@dependabot merge") || strings.Contains(body, "\n") || !strings.Contains(body, "[cut]") || len(body) > 1024 {
			t.Errorf("the notification: %q", body)
		}
	})
}

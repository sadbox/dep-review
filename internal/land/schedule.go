package land

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/gh"
)

// Reevaluation is one open Dependabot pull request the scheduled run is
// to evaluate: one the gate left waiting, or one it has no decision for.
// The scheduled workflow gathers its facts again, asks the model about
// the prepared reads that have no answer yet when an ask is due, and runs
// publish. Nothing here is an approval, and nothing here reaches publish
// as a verdict: publish reads the gate's comment itself, and whether the
// pull request merges is what allow.Decide then says about the fresh
// facts.
type Reevaluation struct {
	Number int
	// Head is its head commit now. It may be newer than the one the gate
	// last decided for; fetch works on the head it finds.
	Head string
	// Undecided says the gate has nothing for this head: no comment, a
	// comment whose marker this version does not read (an earlier
	// version's, a hand edit), or a marker for another head that does not
	// say wait. Such a pull request is evaluated from scratch. False: the
	// gate's comment says wait.
	Undecided bool
	// Answered is the content keys the gate's comment remembers a verdict
	// for under this build's reviewer fingerprint, clean or a veto: reads
	// the model need not be asked about again. It is a hint for the job
	// that asks. A wrong one costs a question or leaves a read waiting.
	Answered []string
	// Ask says a scheduled ask is due (marker.askDue). When it is not,
	// no read of this pull request is put before the model in this run.
	Ask bool
	// NotBefore and Deadline are the last decision's, for a wait.
	NotBefore time.Time
	Deadline  time.Time
	// PastDeadline: the last decision's deadline has passed and the pull
	// request is still open and waiting. A run that cannot evaluate it
	// again makes it a person's (Expired).
	PastDeadline bool
}

// Agenda is what a scheduled run has to do.
type Agenda struct {
	// Evaluate is the pull requests to evaluate, lowest number first.
	Evaluate []Reevaluation
	// Untold is the pull requests whose gate comment records, for their
	// head, an outcome the owner is told about (a person's, a merge
	// GitHub refused, a run that failed) and no notification as sent: the
	// one that was due could not be delivered (Tell).
	Untold []int
}

// UndecidedAfter is how long a pull request must have gone unchanged
// before the scheduled run evaluates it with nothing from the gate for
// its head. It is MaxFactsAge: a push starts an event's run, and after
// this long that run is not going to decide (publish would refuse its
// facts), so the schedule is not racing it. A pull request whose event's
// run died therefore waits four hours for the schedule.
const UndecidedAfter = MaxFactsAge

// standing is what the gate's comment says of a pull request at a head.
type standing int

const (
	// undecided: no comment, no marker this version reads, or a marker
	// for another head that does not say wait.
	undecided standing = iota
	// waits: the marker says wait, for this head or an older one.
	waits
	// decided: the marker is for this head and says anything but wait.
	// That includes a run that failed and was reported: the owner was
	// told how to run the gate again (spec section 11, amendment 15).
	decided
)

// stand reads what the gate's comment c, which may be nil, says of a pull
// request at head. The marker is the zero marker when undecided is for
// want of one.
func stand(c *comment, head string) (marker, standing) {
	if c == nil {
		return marker{}, undecided
	}
	m, ok := parseMarker(c.Body)
	switch {
	case !ok:
		return marker{}, undecided
	case m.Outcome == ActionWait:
		return m, waits
	case m.Head == head:
		return m, decided
	}
	return m, undecided
}

// dependabots reports whether pr is one the scheduled job looks at: by
// Dependabot, from a branch of this repository, with a head that is a
// commit ID.
func (pr pull) dependabots(repo string) bool {
	return pr.User != nil && pr.User.Login == dependabotLogin && pr.Number >= 1 && gh.ValidSHA(pr.Head.SHA) &&
		pr.Head.Repo != nil && strings.EqualFold(pr.Head.Repo.FullName, repo)
}

// Schedule lists what a scheduled run has to do, from the open Dependabot
// pull requests and the gate's comment on each. It only reads. What a
// comment "says" is the marker of a comment the gate app wrote, never the
// comment's visible text and never anyone else's comment.
//
// A pull request is evaluated when its comment says wait, and also when
// the gate has nothing for its head at all and it has not changed for
// UndecidedAfter: the event's run for that head died before publish, or
// publish failed before this binary ran, or the comment is an earlier
// version's (spec section 11, amendment 66). Without the second kind such
// a pull request has no status, no comment and nobody who looks at it
// again. A pull request with a decision for its head, or with the report
// of a failed run for it, is not evaluated.
//
// The refresh job calls this with its read-only token, to know what to
// gather. Publish calls it again with its own, for what it does on the
// list's word: making an overdue wait a person's, and sending a
// notification that was not delivered.
func Schedule(ctx context.Context, cfg Config) (Agenda, error) {
	if err := cfg.check(); err != nil {
		return Agenda{}, err
	}
	pulls, err := gh.List[pull](ctx, cfg.GitHub, fmt.Sprintf("repos/%s/pulls?state=open", cfg.Repo))
	if err != nil {
		return Agenda{}, err
	}
	now := cfg.now()
	fingerprint, err := reviewer()
	if err != nil {
		return Agenda{}, err
	}
	var agenda Agenda
	for _, pr := range pulls {
		if !pr.dependabots(cfg.Repo) {
			continue
		}
		c, err := findComment(ctx, cfg, pr.Number)
		if err != nil {
			return Agenda{}, err
		}
		m, standing := stand(c, pr.Head.SHA)
		switch standing {
		case waits:
			w := Reevaluation{
				Number: pr.Number, Head: pr.Head.SHA, Ask: m.askDue(pr.Head.SHA, now),
				NotBefore: m.NotBefore, Deadline: m.Deadline,
				PastDeadline: !m.Deadline.IsZero() && !now.Before(m.Deadline),
			}
			if m.Fingerprint == fingerprint {
				for _, c := range m.Cache {
					w.Answered = append(w.Answered, c.Key)
				}
			}
			agenda.Evaluate = append(agenda.Evaluate, w)
		case undecided:
			// An update time GitHub does not give is no reason to leave the
			// pull request unseen: it counts as long ago.
			if now.Sub(pr.UpdatedAt) >= UndecidedAfter {
				agenda.Evaluate = append(agenda.Evaluate, Reevaluation{Number: pr.Number, Head: pr.Head.SHA, Undecided: true})
			}
		case decided:
			if _, owed := m.untold(); owed {
				agenda.Untold = append(agenda.Untold, pr.Number)
			}
		}
	}
	slices.SortFunc(agenda.Evaluate, func(a, b Reevaluation) int { return a.Number - b.Number })
	slices.Sort(agenda.Untold)
	return agenda, nil
}

// Undecided reports whether pull request number is an open Dependabot
// pull request the gate has neither a wait nor anything else for at its
// head, and returns that head. Publish asks before it reports a scheduled
// evaluation that failed: the report replaces the gate's comment, and
// must not replace a decision or a wait.
func Undecided(ctx context.Context, cfg Config, number int) (head string, ok bool, err error) {
	if err := cfg.check(); err != nil {
		return "", false, err
	}
	pr, err := getPull(ctx, cfg, number)
	if err != nil {
		return "", false, err
	}
	if pr.State != "open" || !pr.dependabots(cfg.Repo) {
		return "", false, nil
	}
	c, err := findComment(ctx, cfg, number)
	if err != nil {
		return "", false, err
	}
	_, standing := stand(c, pr.Head.SHA)
	return pr.Head.SHA, standing == undecided, nil
}

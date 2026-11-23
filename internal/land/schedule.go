package land

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/gh"
)

// Reevaluation is one open Dependabot pull request the gate left waiting.
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
	// Answered is the content keys the gate's comment remembers a verdict
	// for under this build's reviewer fingerprint, clean or a veto: reads
	// the model need not be asked about again. It is a hint for the job
	// that asks. A wrong one costs a question or leaves a read waiting.
	Answered []string
	// Ask says a scheduled ask is due (marker.askDue). When it is not,
	// no read of this pull request is put before the model in this run.
	Ask bool
	// NotBefore and Deadline are the last decision's.
	NotBefore time.Time
	Deadline  time.Time
	// PastDeadline: the last decision's deadline has passed and the pull
	// request is still open and waiting. A report, not a decision: a pull
	// request that stays in this list is one the scheduled workflow is
	// failing to evaluate.
	PastDeadline bool
}

// Waiting lists the open Dependabot pull requests whose gate comment says
// wait. It only reads. "Says wait" is the marker of a comment the gate app
// wrote, never the comment's visible text and never anyone else's
// comment.
//
// unread are the pull requests whose gate comment has no marker this
// version reads (a hand edit, another version's marker). Nothing says
// whether they wait, so the caller reports them: left out silently, such a
// pull request would never be looked at again.
func Waiting(ctx context.Context, cfg Config) (waiting []Reevaluation, unread []int, err error) {
	if err := cfg.check(); err != nil {
		return nil, nil, err
	}
	pulls, err := gh.List[pull](ctx, cfg.GitHub, fmt.Sprintf("repos/%s/pulls?state=open", cfg.Repo))
	if err != nil {
		return nil, nil, err
	}
	now := cfg.now()
	fingerprint, err := reviewer()
	if err != nil {
		return nil, nil, err
	}
	for _, pr := range pulls {
		if pr.User == nil || pr.User.Login != dependabotLogin || pr.Number < 1 || !gh.ValidSHA(pr.Head.SHA) ||
			pr.Head.Repo == nil || !strings.EqualFold(pr.Head.Repo.FullName, cfg.Repo) {
			continue
		}
		c, err := findComment(ctx, cfg, pr.Number)
		if err != nil {
			return nil, nil, err
		}
		if c == nil {
			continue // no run has decided it yet
		}
		m, ok := parseMarker(c.Body)
		switch {
		case !ok:
			unread = append(unread, pr.Number)
		case m.Outcome == ActionWait:
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
			waiting = append(waiting, w)
		}
	}
	return waiting, unread, nil
}

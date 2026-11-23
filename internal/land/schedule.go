package land

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/wire"
)

// Reevaluation is one open Dependabot pull request the gate left waiting.
// The scheduled workflow gathers its facts again, writes Verdicts as the
// verdicts file (no model is called on a schedule, so a read with no
// verdict here stays Read none) and runs publish on the two. This is the
// one use of a remembered verdict: an event's run asks the model. Nothing
// here is an approval: whether the pull request merges is what
// allow.Decide then says about the fresh facts.
type Reevaluation struct {
	Number int `json:"number"`
	// Head is its head commit now. It may be newer than the one the gate
	// last decided for; fetch works on the head it finds.
	Head string `json:"head"`
	// Verdicts is what the gate's comment remembers of the model's
	// answers, by content key.
	Verdicts wire.Verdicts `json:"verdicts"`
	// NotBefore and Deadline are the last decision's.
	NotBefore time.Time `json:"not_before"`
	Deadline  time.Time `json:"deadline"`
	// PastDeadline: the last decision's deadline has passed and the pull
	// request is still open and waiting. A report, not a decision: a pull
	// request that stays in this list is one the scheduled workflow is
	// failing to evaluate.
	PastDeadline bool `json:"past_deadline"`
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
			waiting = append(waiting, Reevaluation{
				Number: pr.Number, Head: pr.Head.SHA, Verdicts: m.verdicts(),
				NotBefore: m.NotBefore, Deadline: m.Deadline,
				PastDeadline: !m.Deadline.IsZero() && !now.Before(m.Deadline),
			})
		}
	}
	return waiting, unread, nil
}

package land

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/wire"
)

// Reevaluation is one open Dependabot pull request the gate left waiting,
// and what the scheduled workflow does with it:
//
//  1. run fetch again for Number, so the facts are fresh;
//  2. write Verdicts as the verdicts file (wire.EncodeVerdicts). No model
//     is called on a schedule: a read with no verdict here stays Read
//     none, which waits until the deadline;
//  3. run publish (Decide, then Act) on the two files.
//
// Nothing here is an approval. Whether the pull request merges is what
// allow.Decide says in step 3 about the facts of step 1.
type Reevaluation struct {
	// Number is the pull request.
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
	// request is still open and waiting. It is a report, not a decision:
	// the pull request becomes a person's only when step 3 says so, and a
	// pull request that stays in this list is one the scheduled workflow
	// is failing to evaluate.
	PastDeadline bool `json:"past_deadline"`
}

// Waiting lists the open Dependabot pull requests whose gate comment says
// wait. It only reads. "Says wait" is the marker of a comment the gate app
// wrote, never the comment's visible text and never anyone else's
// comment.
func Waiting(ctx context.Context, cfg Config) ([]Reevaluation, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	pulls, err := gh.List[pull](ctx, cfg.GitHub, fmt.Sprintf("repos/%s/pulls?state=open", cfg.Repo))
	if err != nil {
		return nil, err
	}
	now := cfg.now()
	var out []Reevaluation
	for _, pr := range pulls {
		if pr.User == nil || pr.User.Login != dependabotLogin || pr.Number < 1 || !gh.ValidSHA(pr.Head.SHA) ||
			pr.Head.Repo == nil || !strings.EqualFold(pr.Head.Repo.FullName, cfg.Repo) {
			continue
		}
		m, ok, err := lastMarker(ctx, cfg, pr.Number)
		if err != nil {
			return nil, err
		}
		if !ok || m.Outcome != ActionWait {
			continue
		}
		out = append(out, Reevaluation{
			Number: pr.Number, Head: pr.Head.SHA, Verdicts: m.verdicts(),
			NotBefore: m.NotBefore, Deadline: m.Deadline,
			PastDeadline: !m.Deadline.IsZero() && !now.Before(m.Deadline),
		})
	}
	return out, nil
}

// Cached returns the verdicts the gate's comment on a pull request
// remembers, for a job that wants to spare a model call (fetch hands them
// to review). It only reads. With no comment by the gate app, or one whose
// marker does not parse, there are none.
//
// An entry counts only for a reader that computes the same reviewer
// fingerprint and prepares a read with the same content key; wire.Join
// checks both, so a stale or made-up entry answers nothing.
func Cached(ctx context.Context, cfg Config, number int) (wire.Verdicts, error) {
	if err := cfg.check(); err != nil {
		return wire.Verdicts{}, err
	}
	m, _, err := lastMarker(ctx, cfg, number)
	return m.verdicts(), err
}

// lastMarker is the marker of the gate's comment on a pull request.
func lastMarker(ctx context.Context, cfg Config, number int) (marker, bool, error) {
	c, err := findComment(ctx, cfg, number)
	if err != nil || c == nil {
		return marker{}, false, err
	}
	m, ok := parseMarker(c.Body)
	return m, ok, nil
}

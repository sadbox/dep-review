package publish

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
)

const dependabotLogin = "dependabot[bot]"

type ghStatus struct {
	Context string `json:"context"`
	State   string `json:"state"`
	Creator *struct {
		Login string `json:"login"`
	} `json:"creator"`
}

// Sweep merges Dependabot PRs whose current head the gate approved and
// whose CI has since finished green, and reports heads that have had no
// decision for too long. It never reviews anything and never decides:
// it acts only on a `success` status the gate app itself set on that
// exact head, and only after re-checking the approval record, the base
// branch and CI itself.
func Sweep(ctx context.Context, cfg Config, repo string) error {
	cfg.defaults()
	if cfg.TriggerPath == "" {
		return errNoTrigger
	}
	if !gh.ValidRepo(repo) {
		return fmt.Errorf("invalid repository %.100q", repo)
	}
	prs, err := gh.List[ghPull](ctx, cfg.GitHub, fmt.Sprintf("repos/%s/pulls?state=open", repo))
	if err != nil {
		return err
	}
	var errs []error
	for _, pr := range prs {
		if pr.User == nil || pr.User.Login != dependabotLogin || pr.Head.Repo == nil ||
			!strings.EqualFold(pr.Head.Repo.FullName, repo) || !gh.ValidSHA(pr.Head.SHA) || pr.Number <= 0 {
			continue
		}
		if err := sweepOne(ctx, cfg, repo, pr); err != nil {
			cfg.Logf("#%d: %v", pr.Number, err)
			errs = append(errs, fmt.Errorf("#%d: %w", pr.Number, err))
		}
	}
	return errors.Join(errs...)
}

// gateStatus returns the newest dep-review status the gate app set on sha,
// or nil. Statuses from anyone else are ignored.
func gateStatus(ctx context.Context, cfg Config, repo, sha string) (*ghStatus, error) {
	all, err := gh.List[ghStatus](ctx, cfg.GitHub, fmt.Sprintf("repos/%s/commits/%s/statuses", repo, sha))
	if err != nil {
		return nil, err
	}
	for i := range all { // newest first
		s := &all[i]
		if s.Context == statusContext && s.Creator != nil && s.Creator.Login == cfg.BotLogin {
			return s, nil
		}
	}
	return nil, nil
}

func sweepOne(ctx context.Context, cfg Config, repo string, pr ghPull) error {
	head := pr.Head.SHA
	st, err := gateStatus(ctx, cfg, repo, head)
	if err != nil {
		return err
	}
	switch {
	case st != nil && st.State == StateSuccess:
		// The status says publish approved this head. Sweep still checks
		// the rest itself: publish's own approval record names this head,
		// the base is still the default branch, and CI is green.
		prev, err := findComment(ctx, cfg, repo, pr.Number)
		if err != nil {
			return err
		}
		var mk marker
		if prev != nil {
			mk, _ = parseMarker(prev.Body)
		}
		if mk.Approved != head {
			cfg.Logf("#%d: approved status but the approval record names another head", pr.Number)
			return notifyOnce(ctx, cfg, repo, pr.Number, head, model.DecisionHuman, "approved but not merged: the gate's approval record does not match the head", false)
		}
		if why := baseProblem(&pr, repo, ""); why != "" {
			cfg.Logf("#%d: approved but %s", pr.Number, why)
			return notifyOnce(ctx, cfg, repo, pr.Number, head, model.DecisionHuman, "approved but not merged: "+why, false)
		}
		ci, note, err := ciState(ctx, cfg, repo, head, []string{cfg.TriggerPath})
		if err != nil {
			return err
		}
		switch ci {
		case ciPending:
			cfg.Logf("#%d: approved, %s", pr.Number, note)
			// Approved but never mergeable (no real CI, or CI that never
			// finishes) is reported like a stuck head, not left silent.
			old, err := headOlderThan(ctx, cfg, repo, head, cfg.StuckAfter)
			if err != nil || !old {
				return err
			}
			return notifyOnce(ctx, cfg, repo, pr.Number, head, model.DecisionPending, "approved but not merged: "+note, true)
		case ciRed:
			cfg.Logf("#%d: approved but %s", pr.Number, note)
			return notifyOnce(ctx, cfg, repo, pr.Number, head, model.DecisionHuman, "approved but not merged: "+note, false)
		}
		res, err := merge(ctx, cfg, repo, pr.Number, head, "")
		if err != nil {
			return err
		}
		cfg.Logf("#%d: %s", pr.Number, res.Note)
		if res.Failed {
			return notifyOnce(ctx, cfg, repo, pr.Number, head, model.DecisionHuman, "approved but not merged: "+res.Note, false)
		}
		return nil
	case st != nil && st.State == StateFailure:
		return nil // a person decides; publish already notified
	}
	// No decision (no status, or the gate's last attempt errored).
	old, err := headOlderThan(ctx, cfg, repo, head, cfg.StuckAfter)
	if err != nil || !old {
		return err
	}
	cfg.Logf("#%d: no decision for head %s", pr.Number, head[:12])
	return notifyOnce(ctx, cfg, repo, pr.Number, head, model.DecisionPending, "stuck without a decision", true)
}

// headOlderThan reports whether head was committed more than d ago.
func headOlderThan(ctx context.Context, cfg Config, repo, head string, d time.Duration) (bool, error) {
	var commit struct {
		Commit struct {
			Committer struct {
				Date time.Time `json:"date"`
			} `json:"committer"`
		} `json:"commit"`
	}
	if err := cfg.GitHub.Get(ctx, fmt.Sprintf("repos/%s/commits/%s", repo, head), &commit); err != nil {
		return false, err
	}
	return cfg.Now().Sub(commit.Commit.Committer.Date) >= d, nil
}

// notifyOnce records the notification in our comment's marker, so each
// head is reported once. stuck selects the "stuck" record and rewrites the
// comment, unless the comment records an approval of this head (that
// stays, with the new marker); otherwise only the marker changes.
func notifyOnce(ctx context.Context, cfg Config, repo string, pr int, head string, d model.Decision, reason string, stuck bool) error {
	prev, err := findComment(ctx, cfg, repo, pr)
	if err != nil {
		return err
	}
	var mk marker
	if prev != nil {
		mk, _ = parseMarker(prev.Body)
	}
	list := &mk.Notified
	if stuck {
		list = &mk.Stuck
	}
	if has(*list, head) {
		return nil
	}
	if cfg.Notifier != nil {
		if err := cfg.Notifier.Notify(ctx, notification(cfg, repo, pr, d, reason)); err != nil {
			return fmt.Errorf("notify: %w", err)
		}
	}
	*list = add(*list, head)
	var body string
	switch {
	case stuck && (prev == nil || mk.Approved != head):
		body = renderStuck(head, mk)
	case prev != nil:
		body = replaceMarker(prev.Body, mk)
	default:
		body = mk.String() + "\n### dep-review: " + Inline(reason) + "\n"
	}
	_, err = upsertComment(ctx, cfg, repo, pr, prev, body)
	return err
}

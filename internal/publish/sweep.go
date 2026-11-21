package publish

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/classify"
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
	if err != nil {
		return err
	}
	if !old {
		return recheck(ctx, cfg, repo, pr)
	}
	cfg.Logf("#%d: no decision for head %s", pr.Number, head[:12])
	return notifyOnce(ctx, cfg, repo, pr.Number, head, model.DecisionPending, "stuck without a decision", true)
}

// recheck classifies an undecided head again: a dependabot-pending PR
// (its branch's activity log had not caught up) or a gate run that failed.
// When it can now be decided it re-runs the head's trigger workflow run,
// which starts the gate again; a still-pending PR is left for the next
// sweep, and the stuck report takes over after StuckAfter.
func recheck(ctx context.Context, cfg Config, repo string, pr ghPull) error {
	head := pr.Head.SHA
	if old, err := headOlderThan(ctx, cfg, repo, head, cfg.RecheckAfter); err != nil || !old {
		return err
	}
	run, err := triggerRun(ctx, cfg, repo, head)
	if err != nil || run == nil {
		if run == nil && err == nil {
			cfg.Logf("#%d: no completed trigger run for head %s", pr.Number, head[:12])
		}
		return err
	}
	var meta struct {
		Private bool `json:"private"`
	}
	if err := cfg.GitHub.Get(ctx, "repos/"+repo, &meta); err != nil {
		return err
	}
	ev, err := json.Marshal(map[string]any{
		"action": "completed",
		"workflow_run": map[string]any{
			"event": run.Event, "path": run.Path, "head_sha": run.HeadSHA, "head_branch": run.HeadBranch,
			"head_repository": run.HeadRepository, "pull_requests": run.PullRequests,
		},
		"repository": map[string]any{"full_name": repo, "private": meta.Private},
	})
	if err != nil {
		return err
	}
	cl, err := cfg.Classify(ctx, cfg.GitHub, ev, classify.Options{TriggerPath: cfg.TriggerPath, ExpectRepo: repo, Logf: cfg.Logf, Sleep: cfg.Sleep})
	if err != nil {
		return err
	}
	switch cl.Kind {
	case model.KindDependabot, model.KindDependabotUnverified:
		if err := cfg.GitHub.Post(ctx, fmt.Sprintf("repos/%s/actions/runs/%d/rerun", repo, run.ID), map[string]any{}, nil); err != nil {
			return fmt.Errorf("re-running the trigger: %w", err)
		}
		cfg.Logf("#%d: now %s; re-ran trigger run %d", pr.Number, cl.Kind, run.ID)
	default:
		cfg.Logf("#%d: still %s: %s", pr.Number, cl.Kind, Inline(cl.Reason))
	}
	return nil
}

type workflowRun struct {
	ID             int64  `json:"id"`
	Event          string `json:"event"`
	Path           string `json:"path"`
	Status         string `json:"status"`
	HeadSHA        string `json:"head_sha"`
	HeadBranch     string `json:"head_branch"`
	HeadRepository *struct {
		FullName string `json:"full_name"`
	} `json:"head_repository"`
	PullRequests []struct {
		Number int `json:"number"`
		Head   struct {
			SHA string `json:"sha"`
		} `json:"head"`
	} `json:"pull_requests"`
}

// triggerRun is the newest completed pull_request run of the trigger
// workflow on head, or nil.
func triggerRun(ctx context.Context, cfg Config, repo, head string) (*workflowRun, error) {
	var found *workflowRun
	err := cfg.GitHub.Pages(ctx, fmt.Sprintf("repos/%s/actions/runs?head_sha=%s&event=pull_request", repo, head), func(body []byte) error {
		var page struct {
			WorkflowRuns []workflowRun `json:"workflow_runs"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		for i := range page.WorkflowRuns {
			r := page.WorkflowRuns[i]
			if found == nil && r.ID > 0 && r.Path == cfg.TriggerPath && r.Status == "completed" && r.HeadSHA == head {
				found = &r
			}
		}
		return nil
	})
	return found, err
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

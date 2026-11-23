package land

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/wire"
)

// Action is what Act did with a pull request. It is also what the gate's
// comment remembers, and what the scheduled job reads back.
type Action string

// The five things that can happen.
const (
	// ActionMerged: allow.Decide said merge and GitHub merged the head.
	ActionMerged Action = "merged"
	// ActionWait: the decision is wait. The scheduled job evaluates the
	// pull request again.
	ActionWait Action = "wait"
	// ActionPerson: the decision is person.
	ActionPerson Action = "person"
	// ActionRefused: allow.Decide said merge and GitHub refused, for
	// something other than required checks. It is reported and not
	// retried: nothing the gate knows of would change the answer.
	ActionRefused Action = "refused"
	// ActionStale: the pull request was closed or changed under the gate.
	// Nothing was merged and no comment was written.
	ActionStale Action = "stale"
)

// Result is what Act did.
type Result struct {
	// Action is which of the five it was.
	Action Action
	// Decision is the decision acted on: allow.Decide's, or
	// allow.ChecksRefused's when GitHub refused the merge because
	// required checks are pending or failing.
	Decision allow.Decision
	// Note says more about a stale pull request (the gate's words) or a
	// refusal (GitHub's words: third-party text).
	Note string
}

// Act carries out an evaluation: for a merge it asks GitHub to merge the
// exact head, then it sets the dep-review status to the outcome, notifies
// when a person is needed and writes the gate's one comment.
//
// The status is set to success before the merge call, because a
// repository may list dep-review itself among its required checks. It is
// set again, to the final outcome, as the first thing after the merge
// call, before the comment is touched. That success outlives an unmerged
// head in two cases only, both of which fail the job: the merge call got
// no answer and the pull request does not read as merged, or the status
// call that would replace it failed.
//
// A failed notification is returned as an error after everything else was
// written, and is not remembered as sent: the next run sends it.
func Act(ctx context.Context, cfg Config, ev Evaluation) (Result, error) {
	if err := cfg.check(); err != nil {
		return Result{}, err
	}
	if ev.Stale != "" {
		return Result{Action: ActionStale, Note: ev.Stale}, nil
	}
	if ev.branch == "" {
		return Result{}, errors.New("land: Act takes what Decide returned, and nothing else")
	}
	pr := ev.PullRequest
	res := Result{Decision: ev.Decision}

	if ev.Decision.Outcome == allow.Merge {
		if err := setStatus(ctx, cfg, pr.Head, "success", "every fact holds; asking GitHub to merge"); err != nil {
			return Result{}, err
		}
		kind, note, err := merge(ctx, cfg, pr, ev.branch)
		if err != nil {
			return Result{}, err
		}
		switch kind {
		case mergeDone:
			res.Action = ActionMerged
		case mergeChecks:
			res.Decision = allow.ChecksRefused(ev.Decision, ev.now)
		case mergeRefused:
			res.Action, res.Note = ActionRefused, note
		case mergeStale:
			// The facts no longer describe the pull request, so neither
			// does the success above.
			err := setStatus(ctx, cfg, pr.Head, "error", "the pull request changed before the merge; nothing was merged")
			return Result{Action: ActionStale, Decision: ev.Decision, Note: note}, err
		}
	}
	if res.Action == "" {
		// Not merged and not refused: the decision says which it is, and
		// anything that is not a wait is a person.
		res.Action = ActionPerson
		if res.Decision.Outcome == allow.Wait {
			res.Action = ActionWait
		}
	}

	state, description := status(res)
	if err := setStatus(ctx, cfg, pr.Head, state, description); err != nil {
		return Result{}, err
	}

	prev, err := findComment(ctx, cfg, pr.Number)
	if err != nil {
		return Result{}, err
	}
	mk := marker{Outcome: res.Action, Head: pr.Head, Fingerprint: ev.fingerprint, Cache: ev.cache}
	if res.Action == ActionWait {
		mk.NotBefore, mk.Deadline = res.Decision.NotBefore, res.Decision.Deadline
	}
	if prev != nil {
		old, _ := parseMarker(prev.Body)
		mk.Notified = old.Notified
	}
	var notifyErr error
	if msg, ok := notification(cfg, pr, res); ok && cfg.Notifier != nil && !slices.Contains(mk.Notified, pr.Head) {
		if err := cfg.Notifier.Notify(ctx, msg); err != nil {
			notifyErr = fmt.Errorf("land: notify: %w", err)
		} else if mk.Notified = append(mk.Notified, pr.Head); len(mk.Notified) > maxNotified {
			mk.Notified = mk.Notified[len(mk.Notified)-maxNotified:]
		}
	}

	if err := upsertComment(ctx, cfg, pr.Number, prev, render(view{res: res, ev: ev, marker: mk, runURL: cfg.RunURL})); err != nil {
		return Result{}, err
	}
	return res, notifyErr
}

// status is the commit status for a result, in the gate's own words: a
// reason's code, never anything a dependency or the model wrote.
func status(res Result) (state, description string) {
	d := res.Decision
	reason := ""
	if len(d.Reasons) > 0 {
		reason = string(d.Reasons[0])
	}
	switch res.Action {
	case ActionMerged:
		return "success", "merged"
	case ActionWait:
		if len(d.Reasons) > 0 && d.Reasons[0] == allow.ReasonAge {
			return "pending", "waiting until " + stamp(d.NotBefore)
		}
		return "pending", fmt.Sprintf("waiting (%s), at most until %s", reason, stamp(d.Deadline))
	case ActionRefused:
		return "error", "GitHub refused the merge; see the comment"
	}
	return "failure", "needs a person: " + reason
}

func setStatus(ctx context.Context, cfg Config, sha, state, description string) error {
	body := map[string]string{"state": state, "context": statusContext, "description": description}
	if cfg.RunURL != "" {
		body["target_url"] = cfg.RunURL
	}
	return cfg.GitHub.Post(ctx, fmt.Sprintf("repos/%s/statuses/%s", cfg.Repo, sha), body, nil)
}

// mergeKind is how an attempt to merge ended.
type mergeKind int

const (
	mergeDone    mergeKind = iota // merged, by this call or by another run
	mergeStale                    // the pull request is not what was decided on
	mergeChecks                   // GitHub refused: required checks pending or failing
	mergeRefused                  // GitHub refused for another reason
)

// merge asks GitHub to merge exactly pr.Head. It reads the pull request
// again first: it must still be open at that head with the default branch
// as its base. The merge call's sha guards only the head.
//
// The gate does not look at checks. Whether they allow the merge is
// GitHub's answer to the call.
func merge(ctx context.Context, cfg Config, pr wire.PullRequest, branch string) (mergeKind, string, error) {
	cur, err := getPull(ctx, cfg, pr.Number)
	if err != nil {
		return 0, "", err
	}
	if why := cur.changed(pr.Head); why != "" {
		return mergeStale, why, nil
	}
	if now, err := cur.defaultBranch(cfg.Repo); err != nil || now != branch || cur.Base.Ref != branch {
		return mergeStale, "the pull request's base is no longer the default branch", nil
	}

	var out struct {
		Merged bool `json:"merged"`
	}
	putErr := cfg.GitHub.Put(ctx, fmt.Sprintf("repos/%s/pulls/%d/merge", cfg.Repo, pr.Number),
		map[string]string{"sha": pr.Head, "merge_method": "squash"}, &out)
	if putErr == nil && out.Merged {
		return mergeDone, "", nil
	}

	// GitHub did not say "merged". Before concluding anything, look: a
	// write is never retried, so a call that failed on the way back may
	// have merged, and so may another run of the gate.
	after, err := getPull(ctx, cfg, pr.Number)
	if err != nil {
		return 0, "", errors.Join(putErr, err)
	}
	var refusal *gh.Error
	errors.As(putErr, &refusal)
	switch {
	case after.Merged:
		return mergeDone, "", nil
	case putErr == nil:
		return mergeRefused, "GitHub answered the merge call without merging", nil
	case refusal == nil || gh.Unavailable(putErr):
		// No answer at all. The job fails and is run again.
		return 0, "", putErr
	case refusal.StatusCode == http.StatusConflict || after.changed(pr.Head) != "":
		return mergeStale, "the pull request changed before the merge", nil
	case refusal.StatusCode == http.StatusMethodNotAllowed && (aboutChecksOnly(refusal.Message) || after.MergeableState == "blocked"):
		return mergeChecks, "", nil
	}
	return mergeRefused, fmt.Sprintf("HTTP %d: %s", refusal.StatusCode, refusal.Message), nil
}

// GitHub has no field that says why a merge was refused, only a sentence.
// These are the two shapes of a line about required status checks
// ("Required status check "test" is expected.", "2 of 3 required status
// checks are pending."), and the line a ruleset puts in front.
var checksLineRE = regexp.MustCompile(`^(?:Required status check "[^"]*" |[0-9]+ of [0-9]+ required status checks )`)

const rulesHeader = "Repository rule violations found"

// aboutChecksOnly reports whether a refusal's message is about required
// status checks and nothing else. A message of any other shape is not
// guessed at: the refusal is then reported, unless GitHub also calls the
// pull request blocked (see merge). Neither answer can merge anything;
// they differ in whether the gate looks again by itself.
func aboutChecksOnly(message string) bool {
	var lines []string
	for _, l := range strings.Split(message, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) > 0 && lines[0] == rulesHeader {
		lines = lines[1:]
	}
	// internal/gh keeps the first 200 bytes of a message, so the last line
	// of a long one may be cut short. It is judged by the lines before it.
	if len(message) >= 200 && len(lines) > 1 {
		lines = lines[:len(lines)-1]
	}
	for _, l := range lines {
		if !checksLineRE.MatchString(l) {
			return false
		}
	}
	return len(lines) > 0
}

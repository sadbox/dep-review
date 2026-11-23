package land

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/gather"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/wire"
)

// Action is what Act did with a pull request. It is also what the gate's
// comment remembers, and what the scheduled job reads back.
type Action string

// The six things that can happen.
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
	// ActionFailed is never Act's: it is what Failed leaves in the comment
	// for a run that ended without a decision.
	ActionFailed Action = "failed"
)

// Result is what Act did.
type Result struct {
	// Action is which it was; never ActionFailed.
	Action Action
	// Decision is the decision acted on: allow.Decide's, or
	// allow.ChecksRefused's when the merge it allowed has to wait because
	// GitHub refused it (required checks are pending or failing, or the
	// base branch moved under the call), or allow.BaseChanged's or
	// allow.ScriptsOffChanged's when the gate did not ask.
	Decision allow.Decision
	// Held says the gate did not ask GitHub to merge, because the default
	// branch has changed a file the pull request changes, or may have
	// (baseChanged).
	Held bool
	// Note says more about a stale pull request (the gate's words), about
	// a refusal, also one the gate waits on because the base branch moved
	// (GitHub's words: third-party text), or about a held merge: the file
	// both sides change, by the name GitHub gives it (third-party text),
	// and empty when GitHub's list of files was cut short.
	Note string
}

// Act carries out an evaluation: for a merge it asks GitHub to merge the
// exact head, then it sets the dep-review status to the outcome, notifies
// when a person is needed and writes the gate's one comment.
//
// A merge is not asked for while the default branch has changed one of
// the pull request's files (baseChanged): the pull request then waits
// like one GitHub refused. That is looked at first, before any status is
// set, so neither a held merge nor a look that failed leaves a success
// behind.
//
// The status is set to success before the merge call, because a
// repository may list dep-review itself among its required checks. It is
// set again, to the final outcome, as the first thing after the merge
// call, before the comment is touched. That success outlives an unmerged
// head in two cases only, both of which fail the job: the merge call got
// no answer and the pull request does not read as merged, or the status
// call that would replace it failed. On an event's run publish then calls
// Failed, which sets the status again.
//
// Any other final status is set only when its state or description is not
// the one Act last set on the head (marker.Status), and one that cannot be
// set (GitHub keeps 1000 statuses for a commit and context) stops neither
// the comment nor the notification: its error is returned after them,
// with the Result (spec section 11, amendment 74).
//
// A prepared read the model left without a verdict is a wait, and the
// scheduled run asks again by itself (askDue), so one miss needs nobody.
// The comment counts the scheduled runs that asked for this head. When
// the second of them also leaves a prepared read unanswered, the owner is
// told, once per head: the reviewer is not answering, and the gate goes
// on asking until the wait deadline. An event's run counts nothing and
// sends no such notice.
//
// A failed notification is returned as an error after everything else was
// written, and is not remembered as sent: the next scheduled run finds
// the comment owing it and sends it (Schedule, Tell). It and a status that
// could not be set are the errors that come with a Result whose Action is
// set.
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

	merging := ev.Decision.Outcome == allow.Merge
	if merging {
		held, file, err := baseChanged(ctx, cfg, pr, ev.branch)
		if err != nil {
			return Result{}, err
		}
		if held {
			// A wait the scheduled job tries again, with a reason of its own
			// and the deadline of "GitHub will not merge yet", a person's
			// from then on (spec section 11, amendment 78).
			res.Decision, res.Held, res.Note = allow.BaseChanged(ev.Decision, ev.now), true, file
			merging = false
		}
	}
	if merging && restsOnScriptsOff(ev.Facts) {
		still, err := scriptsOffAtTip(ctx, cfg, ev.branch)
		if err != nil {
			return Result{}, err
		}
		if !still {
			res.Decision = allow.ScriptsOffChanged(ev.Decision, ev.now)
			merging = false
		}
	}
	// merging stays what it is now: whether a success was set, and so
	// whether a status after it is set whatever it says.
	if merging {
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
		case mergeBase:
			// allow has one decision for "GitHub will not merge yet", and
			// it fits: a wait the scheduled job tries again, a person's
			// at the deadline. The note keeps what GitHub said.
			res.Decision, res.Note = allow.ChecksRefused(ev.Decision, ev.now), note
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
	set, statusErr := ev.status, error(nil)
	if now := (lastStatus{State: state, Description: description}); merging || set == nil || *set != now {
		if statusErr = setStatus(ctx, cfg, pr.Head, state, description); statusErr == nil {
			set = &now
		} else if merging {
			// The success is GitHub's status, and Failed sets another.
			return Result{}, statusErr
		}
	}

	prev, err := findComment(ctx, cfg, pr.Number)
	if err != nil {
		return Result{}, err
	}
	var old marker
	if prev != nil {
		old, _ = parseMarker(prev.Body)
	}
	// The verdicts and the first-seen times are Decide's, which made them
	// from what the comment remembered: no veto and no time is lost here.
	mk := old.next(res.Action, pr.Head)
	mk.Fingerprint, mk.Cache, mk.FirstSeen = ev.fingerprint, ev.cache, ev.firstSeen
	mk.Forgot, mk.Status = mk.Forgot || ev.forgot, set
	if res.Action == ActionWait {
		mk.NotBefore, mk.Deadline = res.Decision.NotBefore, res.Decision.Deadline
	}
	switch {
	case !cfg.Scheduled:
		// An event's run asked about every read itself. What the schedule
		// counts for this head starts again, so its first ask is not put
		// off for an outage that an earlier run sat through.
		mk.Asks, mk.AskedAt = 0, time.Time{}
	case cfg.ModelAsked:
		mk.Asks, mk.AskedAt = min(mk.Asks+1, maxAsks), ev.now
	}
	var notifyErr error
	if msg, ok := notification(cfg, pr, res); ok {
		notifyErr = notifyOnce(ctx, cfg, &mk.Notified, pr.Head, msg)
	}
	if cfg.Scheduled && mk.Asks >= unreadNoticeAfter && res.Action == ActionWait && unanswered(ev) {
		notifyErr = errors.Join(notifyErr, notifyOnce(ctx, cfg, &mk.NotifiedUnread, pr.Head, message(cfg, pr.Number, unreadNotice+runRef(cfg))))
	}
	if res.Held && res.Action == ActionWait {
		if mk.HeldSince.IsZero() {
			mk.HeldSince = ev.now
		}
		// A security fix would have merged on the fast path, so its owner
		// is told at once; any other once Dependabot has had a day to
		// rebuild it (spec section 11, amendment 78).
		if fix := securityFix(ev.Facts); fix || (cfg.Scheduled && !ev.now.Before(mk.HeldSince.Add(heldNoticeAfter))) {
			notifyErr = errors.Join(notifyErr, notifyOnce(ctx, cfg, &mk.NotifiedHeld, pr.Head, heldMessage(cfg, pr.Number, res.Note, fix)))
		}
	}

	if err := upsertComment(ctx, cfg, pr.Number, prev, render(view{res: res, ev: ev, marker: mk, runURL: cfg.RunURL})); err != nil {
		return Result{}, errors.Join(statusErr, err)
	}
	return res, errors.Join(statusErr, notifyErr)
}

// heldNoticeAfter is how long after a hold began the owner is told about
// a held merge that is not a security fix. Dependabot rebuilds most such
// pull requests within minutes; one it has not rebuilt in a day it may
// not rebuild at all.
const heldNoticeAfter = 24 * time.Hour

// securityFix reports whether an update of the pull request is a security
// fix: one that would have merged on the fast path.
func securityFix(f allow.PRFacts) bool {
	for _, u := range f.Updates {
		if u.SecurityFix.Holds() {
			return true
		}
	}
	return false
}

// unreadNoticeAfter is how many scheduled runs must have asked the model
// for a head, with a prepared read still unanswered, before the owner is
// told. One miss is a blip that the next ask ends. Two, half an hour
// apart, is a reviewer that is down or a rule that denies the token.
const unreadNoticeAfter = 2

// unreadNotice is that notification's sentence.
const unreadNotice = " waits unread: the model has not answered for code the gate prepared, in two scheduled runs that asked it. " +
	"The gate keeps asking, after twice as long each time, until the wait deadline. Nothing needs doing unless the reviewer is down for good."

// Asked counts one scheduled ask for a pull request that the run then
// could not decide: the model was asked, so the next ask has to wait its
// turn like any other, or a pull request that fails at every run would be
// asked about at every run. It rewrites the marker line of the gate's
// comment and nothing else. A comment whose marker is not for head has no
// count to add to, and is left alone: no model is asked for such a head
// (askDue). kept is the vetoes of the run's evaluation, when it got that
// far, which the marker keeps too: a veto must not hang on the write that
// failed (spec section 11, amendment 73).
//
// Publish calls it for every pull request of a scheduled run it could not
// decide, and it counts an ask only when the model was asked
// (Config.ModelAsked). Whatever it counts, it gives up the status Act last
// set, which the run may have replaced before it failed (a success before
// a merge call that got no answer): the next status is set (amendment 74).
// It writes nothing when that leaves the marker as it was.
func Asked(ctx context.Context, cfg Config, number int, head string, kept Vetoes) error {
	if err := cfg.check(); err != nil {
		return err
	}
	c, err := findComment(ctx, cfg, number)
	if err != nil || c == nil {
		return err
	}
	mk, ok := parseMarker(c.Body)
	if !ok || mk.Head != head {
		return nil
	}
	before := mk.String()
	if cfg.ModelAsked {
		mk.Asks, mk.AskedAt = min(mk.Asks+1, maxAsks), cfg.now()
	}
	mk.Status = nil
	kept.keep(&mk)
	if mk.String() == before {
		return nil
	}
	return remark(ctx, cfg, c, mk)
}

// unanswered reports whether fetch prepared a read that has no verdict.
func unanswered(ev Evaluation) bool {
	for i, u := range ev.file.Facts.Updates {
		if u.Prepared.Status == wire.Prepared && ev.Facts.Updates[i].Read == allow.ReadNone {
			return true
		}
	}
	return false
}

// Failed is for a run that ended without a decision. On an event's run:
// the fetch job left no facts, or Decide or Act returned an error before
// anything was written. On a scheduled run (Config.Scheduled): a pull
// request the gate had nothing for at its head, which the run tried to
// evaluate from scratch and could not. Without it such a pull request has
// no comment and no status, and nobody is told.
//
// It sets the dep-review status to error, replaces the gate's comment by
// one that says the run failed and what to do, and notifies once per
// head, remembered apart from a decision's notification. The marker's
// outcome is ActionFailed, which the scheduled job does not pick up: the
// owner has been told, and the schedule tries a head once.
//
// The way out an event's run names is always to run all jobs again, never
// the failed ones: a job that is not run again keeps what it made in the
// first attempt, and Decide refuses facts older than MaxFactsAge
// (ErrFactsStale), which is one of the failures reported here. A
// scheduled run has nothing to run again for one pull request, and names
// a new head or a person instead.
//
// A pull request that is closed or has a newer head is left alone: the
// newer head has a run of its own, whose comment this must not replace.
// what is the gate's own sentence about the run, never an error's text.
// kept is the vetoes of the run's evaluation, when Decide got that far:
// the marker keeps them with what it remembered (spec section 11,
// amendment 73).
func Failed(ctx context.Context, cfg Config, number int, head, what string, kept Vetoes) error {
	if err := cfg.check(); err != nil {
		return err
	}
	if number < 1 || !gh.ValidSHA(head) {
		return fmt.Errorf("land: #%d at %.80q is not a pull request and a commit ID", number, head)
	}
	cur, err := getPull(ctx, cfg, number)
	if err != nil || cur.changed(head) != "" {
		return err // nil for a pull request that changed
	}
	description, told := "the gate's run failed before it could decide; re-run all jobs", ": the gate's run failed before it could decide. Re-run all jobs"+runLink(cfg)
	if cfg.Scheduled {
		description = "the scheduled run could not evaluate this pull request; see the comment"
		told = ": the scheduled run could not evaluate this pull request and does not try this head again. See the comment on the pull request." + runRef(cfg)
	}
	// A status that cannot be set does not keep the owner from being told
	// (spec section 11, amendment 74).
	statusErr := setStatus(ctx, cfg, head, "error", description)
	prev, err := findComment(ctx, cfg, number)
	if err != nil {
		return errors.Join(statusErr, err)
	}
	// What earlier runs read, when they first saw a pin, and whom they
	// told, is still true. Which pins the pull request still has is for
	// the next run that decides to say.
	var old marker
	if prev != nil {
		old, _ = parseMarker(prev.Body)
	}
	mk := old.next(ActionFailed, head)
	kept.keep(&mk)
	mk.Status = nil // Act's to remember
	notifyErr := notifyOnce(ctx, cfg, &mk.NotifiedFailed, head, message(cfg, number, told))

	run := "this pull request's dep-review workflow run"
	if cfg.RunURL != "" {
		run = "the [workflow run](" + cfg.RunURL + ")"
	}
	wayOut := fmt.Sprintf("open %s and re-run all jobs, not only the failed ones: a job that is not run again keeps the facts of the first attempt, "+
		"and the gate does not decide on facts gathered more than %d hours before. "+
		"Until a run decides, the gate does not look at this pull request again by itself.", run, int(MaxFactsAge.Hours()))
	if cfg.Scheduled {
		wayOut = "look at the update and merge or close the pull request by hand, or have Dependabot rebase or recreate it: a new head gets a run of its own. " +
			"The scheduled run does not try this head again. The log of " + run + " says what failed."
	}
	body := fmt.Sprintf("%s\n### dep-review: the run failed\n\n"+
		"**The gate's run failed before it could decide.** Nothing was judged, merged or refused for head %s. %s\n\n"+
		"**Way out:** %s\n",
		mk.String(), code(head), inline(what), wayOut)
	if err := upsertComment(ctx, cfg, number, prev, body); err != nil {
		return errors.Join(statusErr, err)
	}
	return errors.Join(statusErr, notifyErr)
}

// Expired makes a waiting pull request a person's when its wait deadline
// has passed and the scheduled run could not evaluate it again: its facts
// could not be gathered, or publish could not decide on them. Decide
// answers person at the deadline by itself, but only when it runs; a wait
// whose every re-evaluation fails would otherwise stay a wait for good,
// with nobody told (spec section 11, amendment 67).
//
// It decides nothing about the update: the comment says that the deadline
// passed with nothing newer known, the status is failure, and the owner
// is notified once per head. The marker's outcome becomes ActionPerson
// for the head the pull request has now, so the scheduled job stops
// evaluating it, and what the comment remembered stays.
//
// It writes only when the gate's own comment still says wait with a
// deadline that has passed, and the pull request is open at head: a run
// that did decide, a new head or a closed pull request is left alone.
func Expired(ctx context.Context, cfg Config, number int, head string) error {
	if err := cfg.check(); err != nil {
		return err
	}
	if number < 1 || !gh.ValidSHA(head) {
		return fmt.Errorf("land: #%d at %.80q is not a pull request and a commit ID", number, head)
	}
	cur, err := getPull(ctx, cfg, number)
	if err != nil || cur.changed(head) != "" {
		return err // nil for a pull request that changed
	}
	prev, err := findComment(ctx, cfg, number)
	if err != nil || prev == nil {
		return err
	}
	old, ok := parseMarker(prev.Body)
	if !ok || old.Outcome != ActionWait || old.Deadline.IsZero() || cfg.now().Before(old.Deadline) {
		return nil
	}
	// A status that cannot be set does not keep the deadline from being
	// written or the owner from being told (spec section 11, amendment 74).
	statusErr := setStatus(ctx, cfg, head, "failure", "needs a person: the wait deadline passed and the gate could not evaluate the pull request again")
	mk := old.next(ActionPerson, head)
	mk.Status = nil // Act's to remember
	notifyErr := notifyOnce(ctx, cfg, &mk.Notified, head, message(cfg, number,
		" needs a person: its wait deadline has passed and the scheduled run could not evaluate it again. See the comment on the pull request."+runRef(cfg)))

	run := "the scheduled dep-review runs"
	if cfg.RunURL != "" {
		run = "the [workflow run](" + cfg.RunURL + ") and the scheduled runs before it"
	}
	body := fmt.Sprintf("%s\n### dep-review: %s\n\n"+
		"**Needs a person.** The gate left this pull request waiting, at most until %s. That deadline has passed, and the scheduled run could not evaluate the pull request again: "+
		"gathering its facts or deciding on them failed. So nothing newer is known about it than what the gate wrote before, and nothing was found against the update by this. "+
		"The logs of %s say what failed.\n\n"+
		"**Way out:** look at the update and merge or close the pull request by hand, or have Dependabot rebase or recreate it: a new head gets a run of its own.\n",
		mk.String(), headlines[ActionPerson], stamp(old.Deadline), run)
	if err := upsertComment(ctx, cfg, number, prev, body); err != nil {
		return errors.Join(statusErr, err)
	}
	return errors.Join(statusErr, notifyErr)
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
		if d.Deadline.IsZero() {
			return "pending", fmt.Sprintf("waiting (%s)", reason)
		}
		return "pending", fmt.Sprintf("waiting (%s), at most until %s", reason, stamp(d.Deadline))
	case ActionRefused:
		return "error", "GitHub refused the merge; see the comment"
	}
	return "failure", "needs a person: " + reason
}

func setStatus(ctx context.Context, cfg Config, sha, state, description string) error {
	body := map[string]string{"state": state, "context": gh.GateStatus, "description": description}
	if cfg.RunURL != "" {
		body["target_url"] = cfg.RunURL
	}
	return cfg.GitHub.Post(ctx, fmt.Sprintf("repos/%s/statuses/%s", cfg.Repo, sha), body, nil)
}

// compareFilesCap is the most files GitHub lists for one comparison,
// however many changed.
const compareFilesCap = 300

// baseChanged reports whether the default branch has changed a file the
// pull request changes, since the commit the pull request branches from
// (spec section 11, amendment 62). Every fact is about the head against
// that commit, and GitHub merges the head onto the branch as it is now.
// Two changes to one lock file can merge without a conflict into a lock
// that neither side wrote, and required checks can pass on such a lock.
// So that merge is not asked for. The gate does not rebase, update
// or comment to bring the pull request up to date: Dependabot rebuilds
// most such pull requests itself, and the new head gets a run of its own.
//
// Both answers are GitHub's: the pull request's files, and the comparison
// from the head to the branch, whose ahead_by counts the commits the
// branch has and the head lacks and whose files are what those commits
// changed. A name is a file's name now or the one it was renamed from, on
// either side. A pull request that is only behind is not held. GitHub
// lists compareFilesCap files at most, and a list that long may lack the
// one that matters, so it holds too; file is then empty.
//
// An error is an answer that did not come or does not say what changed.
// Nothing is merged on one.
func baseChanged(ctx context.Context, cfg Config, pr wire.PullRequest, branch string) (held bool, file string, err error) {
	type changed struct {
		Filename         string `json:"filename"`
		PreviousFilename string `json:"previous_filename"`
	}
	mine, err := gh.List[changed](ctx, cfg.GitHub, fmt.Sprintf("repos/%s/pulls/%d/files", cfg.Repo, pr.Number))
	if err != nil {
		return false, "", err
	}
	var theirs struct {
		AheadBy *int       `json:"ahead_by"`
		Files   *[]changed `json:"files"`
	}
	if err := cfg.GitHub.Get(ctx, fmt.Sprintf("repos/%s/compare/%s...%s", cfg.Repo, pr.Head, branch), &theirs); err != nil {
		return false, "", err
	}
	// A pull request the gate would merge changes at least one file, and
	// GitHub's comparison always has both members.
	if len(mine) == 0 || theirs.AheadBy == nil || *theirs.AheadBy < 0 || theirs.Files == nil {
		return false, "", fmt.Errorf("land: GitHub's file list for #%d or its comparison of %s with %s does not say what changed", pr.Number, pr.Head, branch)
	}
	switch {
	case *theirs.AheadBy == 0:
		return false, "", nil
	case len(*theirs.Files) >= compareFilesCap:
		return true, "", nil
	}
	names := map[string]bool{}
	for _, f := range mine {
		names[f.Filename], names[f.PreviousFilename] = true, true
	}
	// A file that was not renamed has no previous name, on either side.
	delete(names, "")
	for _, f := range *theirs.Files {
		for _, name := range []string{f.Filename, f.PreviousFilename} {
			if names[name] {
				return true, name, nil
			}
		}
	}
	return false, "", nil
}

// restsOnScriptsOff reports whether a decision on these facts rests on the
// root .npmrc that turns npm's install scripts off: whether an update's
// NoRegress was made with that fact.
func restsOnScriptsOff(f allow.PRFacts) bool {
	for _, u := range f.Updates {
		if gather.RestsOnScriptsOff(u.NoRegress) {
			return true
		}
	}
	return false
}

// scriptsOffAtTip reports whether the default branch, as it is now, has
// the root .npmrc that turns npm's install scripts off (spec section 11,
// amendment 70). The facts read that file at the base commit the pull
// request records, and GitHub moves that commit only when the pull
// request's branch is rebuilt, so every run that gathers the facts again
// reads the same old commit. A repository that turned install scripts back
// on since would have the update merged with install inputs nobody
// compared.
//
// The answer is GitHub's root tree of the branch, not recursive. It must
// have an entry for .npmrc that is a regular, non-executable file with
// exactly the blob gather.ScriptsOffBlob, and must not be cut short. A
// listing that does not say whether it was cut short counts as cut.
//
// An error is an answer that did not come or does not list the tree, and
// is handled as baseChanged's errors are: nothing is merged.
func scriptsOffAtTip(ctx context.Context, cfg Config, branch string) (bool, error) {
	var tree struct {
		Tree *[]struct {
			Path string `json:"path"`
			Mode string `json:"mode"`
			Type string `json:"type"`
			SHA  string `json:"sha"`
		} `json:"tree"`
		Truncated *bool `json:"truncated"`
	}
	if err := cfg.GitHub.Get(ctx, fmt.Sprintf("repos/%s/git/trees/%s", cfg.Repo, branch), &tree); err != nil {
		return false, err
	}
	if tree.Tree == nil {
		return false, fmt.Errorf("land: GitHub's root tree of %s does not list its entries", branch)
	}
	if tree.Truncated == nil || *tree.Truncated {
		return false, nil
	}
	for _, e := range *tree.Tree {
		if e.Path == ".npmrc" {
			return e.Mode == "100644" && e.Type == "blob" && e.SHA == gather.ScriptsOffBlob, nil
		}
	}
	return false, nil
}

// mergeKind is how an attempt to merge ended.
type mergeKind int

const (
	mergeDone    mergeKind = iota // merged, by this call or by another run
	mergeStale                    // the pull request is not what was decided on
	mergeChecks                   // GitHub refused: required checks pending or failing
	mergeBase                     // GitHub refused: the base branch moved while it merged
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
	case refusal.StatusCode == http.StatusMethodNotAllowed && strings.TrimSpace(refusal.Message) == baseModified:
		return mergeBase, baseModified, nil
	case refusal.StatusCode == http.StatusMethodNotAllowed && (aboutChecksOnly(refusal.Message) || after.MergeableState == "blocked"):
		return mergeChecks, "", nil
	}
	return mergeRefused, fmt.Sprintf("HTTP %d: %s", refusal.StatusCode, refusal.Message), nil
}

// baseModified is GitHub's whole answer when the base branch got a commit
// between its own check and its merge, which is what two merges at the
// same moment look like to the second. It says to try again, so the gate
// does, at its next scheduled run; any other sentence is not guessed at.
const baseModified = "Base branch was modified. Review and try the merge again."

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
	// internal/gh keeps the first gh.MaxMessage bytes of a message, so the
	// last line of a long one may be cut short. It is judged by the lines
	// before it.
	if len(message) >= gh.MaxMessage && len(lines) > 1 {
		lines = lines[:len(lines)-1]
	}
	for _, l := range lines {
		if !checksLineRE.MatchString(l) {
			return false
		}
	}
	return len(lines) > 0
}

// Package classify decides who a pull request belongs to (model.Kind):
// the proof that it is Dependabot's alone, which is the first half of the
// gate's Identity fact. It records nothing Dependabot declared about its
// updates; what a pull request changes is read from its commits
// (internal/gather). Everything read from the event or the API is
// untrusted: identifiers are validated before they are used in a request
// path, and nothing reaches a shell.
package classify

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
)

const (
	dependabotLogin = "dependabot[bot]"
	webFlowLogin    = "web-flow"
	branchPrefix    = "dependabot/"
)

// Event is the subset of a workflow_run event payload classify reads.
type Event struct {
	WorkflowRun struct {
		Event          string `json:"event"`
		Path           string `json:"path"`
		HeadSHA        string `json:"head_sha"`
		HeadRepository *repo  `json:"head_repository"`
		PullRequests   []struct {
			Number int `json:"number"`
			Head   struct {
				SHA string `json:"sha"`
			} `json:"head"`
		} `json:"pull_requests"`
	} `json:"workflow_run"`
	Repository repo `json:"repository"`
}

type repo struct {
	FullName string `json:"full_name"`
}

type user struct {
	Login string `json:"login"`
}

type pull struct {
	Number int    `json:"number"`
	State  string `json:"state"`
	User   *user  `json:"user"`
	Head   struct {
		SHA  string `json:"sha"`
		Ref  string `json:"ref"`
		Repo *repo  `json:"repo"`
	} `json:"head"`
	Base struct {
		SHA  string `json:"sha"`
		Repo *repo  `json:"repo"`
	} `json:"base"`
}

type commit struct {
	SHA       string `json:"sha"`
	Author    *user  `json:"author"`
	Committer *user  `json:"committer"`
	Commit    struct {
		Verification struct {
			Verified bool   `json:"verified"`
			Reason   string `json:"reason"`
		} `json:"verification"`
	} `json:"commit"`
}

// Options carries everything besides the event.
type Options struct {
	// TriggerPath is the caller's trigger workflow. Classify takes an
	// event for the gate's only when it is that workflow's run; Pull does
	// not look at it.
	TriggerPath string
	// ExpectRepo, if set (GITHUB_REPOSITORY), must equal the event's
	// repository.
	ExpectRepo string
	Logf       func(format string, args ...any)
	// Sleep waits between activity-log reads (tests replace it).
	Sleep func(ctx context.Context, d time.Duration) error
	// IgnoreEcosystems (the ignore_ecosystems input, model.ParseEcosystems)
	// turns a KindDependabot PR in one of these ecosystems into
	// KindIgnored.
	IgnoreEcosystems map[model.Ecosystem]bool
}

// Classify reads the workflow_run event and the API and returns the
// classification. An error means the gate could not decide (API failure,
// malformed event); the job fails and nothing downstream runs.
func Classify(ctx context.Context, c *gh.Client, eventJSON []byte, opt Options) (model.Classification, error) {
	logf := opt.Logf
	if logf == nil {
		logf = log.Printf
	}
	var ev Event
	if err := json.Unmarshal(eventJSON, &ev); err != nil {
		return model.Classification{}, fmt.Errorf("parsing event: %w", err)
	}
	other := func(why string) (model.Classification, error) {
		logf("kind=other: %s", why)
		return model.Classification{Repo: ev.Repository.FullName, Kind: model.KindOther, Reason: why}, nil
	}
	wr := ev.WorkflowRun
	repoName := ev.Repository.FullName
	if !gh.ValidRepo(repoName) {
		return model.Classification{}, fmt.Errorf("event repository %.100q is not a valid owner/name", repoName)
	}
	if opt.ExpectRepo != "" && !strings.EqualFold(opt.ExpectRepo, repoName) {
		return model.Classification{}, fmt.Errorf("event repository does not match GITHUB_REPOSITORY")
	}
	switch {
	case wr.Event == "" && wr.HeadSHA == "":
		return other("not a workflow_run event")
	case wr.Event != "pull_request":
		return other(fmt.Sprintf("upstream run was triggered by %.40q, not pull_request", wr.Event))
	case wr.Path != opt.TriggerPath:
		return other("upstream run is not the trigger workflow")
	case wr.HeadRepository == nil || !strings.EqualFold(wr.HeadRepository.FullName, repoName):
		return other("upstream run is for a fork")
	case !gh.ValidSHA(wr.HeadSHA):
		return model.Classification{}, fmt.Errorf("workflow_run.head_sha %.80q is not a commit ID", wr.HeadSHA)
	}
	headSHA := wr.HeadSHA

	num, err := findPR(ctx, c, &ev)
	if err != nil {
		return model.Classification{}, err
	}
	if num == 0 {
		return other("no single open same-repository pull request has this head")
	}
	return Pull(ctx, c, repoName, num, headSHA, opt)
}

// Pull is the identity proof for one pull request: whether pull request
// num of repoName is Dependabot's alone at headSHA. Classify calls it
// once the event has named the pull request; the scheduled job calls it
// for each pull request it evaluates again, where no event names one.
// Both get the same proof, so a pull request is never taken to be
// Dependabot's on anything less.
//
// An error means the gate could not decide (the API failed, or the
// arguments are not a repository, a number and a commit ID).
func Pull(ctx context.Context, c *gh.Client, repoName string, num int, headSHA string, opt Options) (model.Classification, error) {
	if !gh.ValidRepo(repoName) || num < 1 || !gh.ValidSHA(headSHA) {
		return model.Classification{}, fmt.Errorf("classify: %.100q #%d at %.80q is not a repository, a pull request and a commit ID", repoName, num, headSHA)
	}
	logf := opt.Logf
	if logf == nil {
		logf = log.Printf
	}
	sleep := opt.Sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	var pr pull
	if err := c.Get(ctx, fmt.Sprintf("repos/%s/pulls/%d", repoName, num), &pr); err != nil {
		return model.Classification{}, err
	}
	cl := model.Classification{Repo: repoName, PR: num, HeadSHA: headSHA}
	if gh.ValidSHA(pr.Base.SHA) {
		cl.BaseSHA = pr.Base.SHA
	}
	if pr.State != "open" {
		cl.Kind, cl.Reason = model.KindStale, "the pull request is no longer open"
		logf("kind=stale: %s", cl.Reason)
		return cl, nil
	}
	if pr.Head.SHA != headSHA {
		cl.Kind, cl.Reason = model.KindStale, "the pull request has a newer head than this run"
		logf("kind=stale: %s", cl.Reason)
		return cl, nil
	}

	byAuthor := pr.User != nil && pr.User.Login == dependabotLogin
	byBranch := strings.HasPrefix(pr.Head.Ref, branchPrefix)
	if !byAuthor && !byBranch {
		const why = "neither authored by dependabot[bot] nor on a dependabot/ branch"
		logf("kind=other: %s", why)
		return model.Classification{Repo: repoName, Kind: model.KindOther, Reason: why}, nil
	}
	unverified := func(why string) (model.Classification, error) {
		cl.Kind, cl.Reason = model.KindDependabotUnverified, why
		logf("kind=dependabot-unverified: %s", why)
		return cl, nil
	}
	switch {
	case !byAuthor:
		return unverified("on a dependabot/ branch but not authored by dependabot[bot]")
	case !byBranch:
		return unverified("authored by dependabot[bot] but not on a dependabot/ branch")
	case pr.Head.Repo == nil || !strings.EqualFold(pr.Head.Repo.FullName, repoName):
		return unverified("head branch is not in this repository")
	case cl.BaseSHA == "":
		return unverified("the base commit is malformed")
	}

	commits, err := gh.List[commit](ctx, c, fmt.Sprintf("repos/%s/pulls/%d/commits", repoName, num))
	if err != nil {
		return model.Classification{}, err
	}
	if len(commits) == 0 {
		return unverified("the pull request has no commits")
	}
	if commits[len(commits)-1].SHA != headSHA {
		return unverified("the commit list does not end at the head commit")
	}
	for _, cm := range commits {
		short := cm.SHA
		if len(short) > 12 {
			short = short[:12]
		}
		if !gh.ValidSHA(cm.SHA) {
			return unverified("a commit has a malformed ID")
		}
		if cm.Author == nil || cm.Author.Login != dependabotLogin {
			return unverified(fmt.Sprintf("commit %s is not authored by dependabot[bot]", short))
		}
		if cm.Committer == nil || (cm.Committer.Login != dependabotLogin && cm.Committer.Login != webFlowLogin) {
			return unverified(fmt.Sprintf("commit %s is not committed by dependabot[bot] or web-flow", short))
		}
		if !cm.Commit.Verification.Verified || cm.Commit.Verification.Reason != "valid" {
			return unverified(fmt.Sprintf("commit %s does not have a verified signature", short))
		}
	}
	// The commits cannot tell Dependabot's own pushes from a person
	// squash-merging another Dependabot PR into this branch: both are
	// authored by dependabot[bot], committed by web-flow and signed by
	// GitHub. Three reads make the rest of the proof. An answer that is
	// not proof ends it at once. A read that leaves it open (a log that
	// lags, GitHub not answering) does not: the reads after it are still
	// made, because a "no" from any of them is an answer, and a person's
	// now whatever else is still open.
	reads := []func() (string, answer, error){
		// The branch's activity log records who moved the ref. It lags the
		// push by a little; give it a moment.
		func() (string, answer, error) {
			why, got, err := branchHistoryProblem(ctx, c, repoName, pr.Head.Ref, headSHA)
			for try := 0; err == nil && got == lagging && try < len(historyBackoff); try++ {
				if err := sleep(ctx, historyBackoff[try]); err != nil {
					return "", 0, err
				}
				why, got, err = branchHistoryProblem(ctx, c, repoName, pr.Head.Ref, headSHA)
			}
			return why, got, err
		},
		// A PR retargeted to another base after Dependabot opened it is
		// not the update Dependabot proposed.
		func() (string, answer, error) { return timelineProblem(ctx, c, repoName, num) },
		// The log shows who moved the branch; a ruleset makes sure nobody
		// else could. Its bypass list (Dependabot only) is the owner's to
		// maintain: a read-only token cannot see it.
		func() (string, answer, error) { return rulesProblem(ctx, c, repoName, pr.Head.Ref) },
	}
	unfinished := "" // why the proof is still open: the first read that left it so
	for _, read := range reads {
		why, got, err := read()
		switch {
		case err != nil:
			return model.Classification{}, err
		case got == disproven:
			return unverified(why)
		case got != proven && unfinished == "":
			unfinished = why
		}
	}

	eco, ok := model.EcosystemFromBranch(pr.Head.Ref)
	if !ok {
		return unverified("the branch name does not name a supported ecosystem")
	}
	cl.Ecosystem = eco
	if unfinished != "" {
		// Not a verdict on the pull request (spec section 11, amendments 1
		// and 51). The ecosystem is the branch's to name whatever becomes
		// of the proof, and the fetch job needs it to gather the rest.
		cl.Kind, cl.Reason = model.KindPending, unfinished
		logf("kind=dependabot-pending: %s", unfinished)
		return cl, nil
	}

	// Only a PR that passed every check above is ever ignored; anything
	// else returned before this point and is handled as usual. The
	// ecosystem is the branch's, which the rules above keep Dependabot's
	// to name.
	if opt.IgnoreEcosystems[eco] {
		cl.Kind = model.KindIgnored
		cl.Reason = fmt.Sprintf("in ignored ecosystem %s (ignore_ecosystems): another process owns these pull requests", eco)
		logf("kind=dependabot-ignored: %s #%d: %s", repoName, num, cl.Reason)
		return cl, nil
	}
	cl.Kind = model.KindDependabot
	cl.Reason = "authored, committed and signed by Dependabot only"
	logf("kind=dependabot: %s #%d %s", repoName, num, eco)
	return cl, nil
}

type activity struct {
	Before       string `json:"before"`
	After        string `json:"after"`
	ActivityType string `json:"activity_type"`
	Actor        *user  `json:"actor"`
}

// historyBackoff is how long classify waits before each re-read of an
// activity log that has not reached the head yet: about two minutes in
// all, inside the classify job's timeout.
var historyBackoff = []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 45 * time.Second}

// answer is what one read of the proof came to.
type answer int

const (
	// proven: nothing GitHub answered speaks against the pull request.
	proven answer = iota
	// disproven: GitHub answered, and the answer is not proof. That
	// includes an answer that says nothing of what was asked for (a 404, a
	// 403 that is no rate limit, a body that does not decode).
	disproven
	// lagging: the activity log is clean and does not reach the head yet.
	// GitHub records activity shortly after a push, so it is read again.
	lagging
	// unanswered: GitHub was asked and did not answer (gh.Unavailable),
	// after the client's own retries. That says nothing about the pull
	// request, and it is not waited out here: the pull request waits and
	// the scheduled job runs the proof again.
	unanswered
)

// notRead is what a read of the proof that failed with err comes to.
// what names the thing read. The context is looked at first: to
// gh.Unavailable a deadline that ran out is a timeout like any other, and
// classify running out of time is an error, not GitHub's silence.
func notRead(ctx context.Context, what string, err error) (string, answer, error) {
	if ctx.Err() != nil {
		return "", 0, ctx.Err()
	}
	code := ""
	if n := gh.StatusCode(err); n != 0 {
		code = fmt.Sprintf(" (HTTP %d)", n)
	}
	if gh.Unavailable(err) {
		return what + " could not be read: GitHub did not answer" + code, unanswered, nil
	}
	return what + " could not be read" + code, disproven, nil
}

// branchHistoryProblem reads the head branch's activity log (oldest first)
// and says whether it proves that only Dependabot moved the branch since
// it was last created, and if not, why. Every entry from the last
// branch_creation on must be Dependabot's creation, push or force push,
// each starting where the previous one ended, and the last must end at
// head. Anything else GitHub answers, an incomplete log included, is not
// proof.
//
// It is lagging when the only problem is that the log, otherwise clean,
// does not reach head yet. The error is the context's.
func branchHistoryProblem(ctx context.Context, c *gh.Client, repo, branch, head string) (string, answer, error) {
	q := url.Values{"ref": {"refs/heads/" + branch}, "direction": {"asc"}}
	acts, err := gh.List[activity](ctx, c, fmt.Sprintf("repos/%s/activity?%s", repo, q.Encode()))
	if err != nil {
		return notRead(ctx, "the branch's push history", err)
	}
	if len(acts) == 0 {
		return "the branch has no push history yet", lagging, nil
	}
	start := -1
	for i, a := range acts {
		if a.ActivityType == "branch_creation" {
			start = i
		}
	}
	if start < 0 {
		return "the branch's push history does not include its creation", disproven, nil
	}
	prev := ""
	for i, a := range acts[start:] {
		switch {
		case a.Actor == nil || a.Actor.Login != dependabotLogin:
			return "someone other than dependabot[bot] changed the branch (" + safeType(a.ActivityType) + ")", disproven, nil
		case i == 0 && !zeroSHA(a.Before):
			return "the branch's creation does not start from nothing", disproven, nil
		case i > 0 && a.ActivityType != "push" && a.ActivityType != "force_push":
			return "the branch was changed by a " + safeType(a.ActivityType), disproven, nil
		case i > 0 && a.Before != prev:
			return "the branch's push history has a gap", disproven, nil
		case !gh.ValidSHA(a.After):
			return "the branch's push history has a malformed commit ID", disproven, nil
		}
		prev = a.After
	}
	if prev != head {
		return "the branch's push history does not reach the head commit yet", lagging, nil
	}
	return "", proven, nil
}

// timelineProblem reads the PR's timeline and says whether it disqualifies
// the PR (its base branch was changed). The error is the context's.
func timelineProblem(ctx context.Context, c *gh.Client, repo string, pr int) (string, answer, error) {
	events, err := gh.List[struct {
		Event string `json:"event"`
	}](ctx, c, fmt.Sprintf("repos/%s/issues/%d/timeline", repo, pr))
	if err != nil {
		return notRead(ctx, "the pull request's timeline", err)
	}
	for _, e := range events {
		if e.Event == "base_ref_changed" {
			return "the pull request's base branch was changed after it was opened", disproven, nil
		}
	}
	return "", proven, nil
}

// headRefRe is the shape of a Dependabot branch name the gate puts in a
// request path: letters, digits and ._/- only. Dependabot's own names fit
// it; a name that does not is not asked about, which is not proof.
var headRefRe = regexp.MustCompile(`^dependabot/[A-Za-z0-9._/-]{1,240}$`)

// rulesProblem says whether GitHub's rules for the pull request's head
// branch restrict creating, updating and deleting it, and if not, why.
//
// GitHub is asked which rules apply to the branch (rules/branches), and
// answers with every rule of every active ruleset whose conditions match
// it, repository and organization rulesets alike; rulesets that are
// disabled or only evaluated are left out. The gate matches no ref
// pattern itself: a matcher of its own is a second reading of GitHub's
// pattern rules, and v0.1.9's did not agree with them. The error is the
// context's.
func rulesProblem(ctx context.Context, c *gh.Client, repo, branch string) (string, answer, error) {
	const badName = "the branch's name is not one the gate asks GitHub's rules about"
	if !headRefRe.MatchString(branch) {
		return badName, disproven, nil
	}
	for _, el := range strings.Split(branch, "/") {
		if el == "" || el == "." || strings.Contains(el, "..") {
			return badName, disproven, nil
		}
	}
	rules, err := gh.List[struct {
		Type       string `json:"type"`
		Parameters struct {
			UpdateAllowsFetchAndMerge bool `json:"update_allows_fetch_and_merge"`
		} `json:"parameters"`
	}](ctx, c, fmt.Sprintf("repos/%s/rules/branches/%s", repo, branch))
	if err != nil {
		return notRead(ctx, "the branch's rules", err)
	}
	have := map[string]bool{}
	for _, r := range rules {
		// An update rule that lets anyone pull the base branch in does
		// not keep the branch Dependabot's alone.
		if r.Type == "update" && r.Parameters.UpdateAllowsFetchAndMerge {
			continue
		}
		have[r.Type] = true
	}
	if !have["creation"] || !have["update"] || !have["deletion"] {
		return "no active rule restricts creating, updating and deleting this dependabot/ branch", disproven, nil
	}
	return "", proven, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func zeroSHA(s string) bool { return len(s) == 40 && strings.Trim(s, "0") == "" }

var typeRe = regexp.MustCompile(`^[a-z_]{1,32}$`)

func safeType(s string) string {
	if typeRe.MatchString(s) {
		return s
	}
	return "change"
}

// findPR returns the open same-repository PR whose head is the run's head,
// or 0 when there is not exactly one.
func findPR(ctx context.Context, c *gh.Client, ev *Event) (int, error) {
	wr := ev.WorkflowRun
	var nums []int
	for _, p := range wr.PullRequests {
		if p.Number > 0 && p.Head.SHA == wr.HeadSHA {
			nums = append(nums, p.Number)
		}
	}
	if len(nums) == 0 {
		prs, err := gh.List[pull](ctx, c, fmt.Sprintf("repos/%s/commits/%s/pulls", ev.Repository.FullName, wr.HeadSHA))
		if err != nil {
			return 0, err
		}
		for _, p := range prs {
			if p.State == "open" && p.Number > 0 && p.Head.SHA == wr.HeadSHA &&
				p.Head.Repo != nil && p.Base.Repo != nil &&
				strings.EqualFold(p.Head.Repo.FullName, p.Base.Repo.FullName) &&
				strings.EqualFold(p.Base.Repo.FullName, ev.Repository.FullName) {
				nums = append(nums, p.Number)
			}
		}
	}
	if len(nums) != 1 {
		return 0, nil
	}
	return nums[0], nil
}

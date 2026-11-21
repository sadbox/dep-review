// Package classify decides who a pull request belongs to (model.Kind) and
// records what Dependabot declared it changes. Everything read from the
// event or the API is untrusted: identifiers are validated before they are
// used in a request path, and nothing reaches a shell.
package classify

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path"
	"regexp"
	"strings"
	"unicode"

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
	Action      string `json:"action"`
	WorkflowRun struct {
		Event          string `json:"event"`
		Path           string `json:"path"`
		HeadSHA        string `json:"head_sha"`
		HeadBranch     string `json:"head_branch"`
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
	Private  bool   `json:"private"`
}

type user struct {
	Login string `json:"login"`
}

type pull struct {
	Number int    `json:"number"`
	State  string `json:"state"`
	Body   string `json:"body"`
	User   *user  `json:"user"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
	Head struct {
		SHA  string `json:"sha"`
		Ref  string `json:"ref"`
		Repo *repo  `json:"repo"`
	} `json:"head"`
	Base struct {
		SHA  string `json:"sha"`
		Ref  string `json:"ref"`
		Repo *repo  `json:"repo"`
	} `json:"base"`
}

type commit struct {
	SHA       string `json:"sha"`
	Author    *user  `json:"author"`
	Committer *user  `json:"committer"`
	Commit    struct {
		Message      string `json:"message"`
		Verification struct {
			Verified bool   `json:"verified"`
			Reason   string `json:"reason"`
		} `json:"verification"`
	} `json:"commit"`
}

type file struct {
	Filename         string `json:"filename"`
	PreviousFilename string `json:"previous_filename"`
}

// Options carries everything besides the event.
type Options struct {
	TriggerPath string
	// ExpectRepo, if set (GITHUB_REPOSITORY), must equal the event's
	// repository.
	ExpectRepo string
	Logf       func(format string, args ...any)
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
	var pr pull
	if err := c.Get(ctx, fmt.Sprintf("repos/%s/pulls/%d", repoName, num), &pr); err != nil {
		return model.Classification{}, err
	}
	cl := model.Classification{
		Repo:        repoName,
		Private:     ev.Repository.Private,
		PR:          num,
		HeadSHA:     headSHA,
		TriggerPath: opt.TriggerPath,
	}
	if gh.ValidSHA(pr.Base.SHA) {
		cl.BaseSHA = pr.Base.SHA
	}
	cl.BaseRef = safeRef(pr.Base.Ref)
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
		return other("neither authored by dependabot[bot] nor on a dependabot/ branch")
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
	case cl.BaseSHA == "" || cl.BaseRef == "":
		return unverified("base branch or commit is malformed")
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
		if !cm.Commit.Verification.Verified {
			return unverified(fmt.Sprintf("commit %s does not have a verified signature", short))
		}
	}

	eco, ok := ecosystemFromBranch(pr.Head.Ref)
	if !ok {
		return unverified("the branch name does not name a supported ecosystem")
	}
	cl.Ecosystem = eco

	head := commits[len(commits)-1].Commit.Message
	decl, err := ParseDeclared(head)
	if err != nil {
		logf("updated-dependencies: %v", err)
		return unverified("Dependabot's commit metadata could not be read")
	}
	security, advisories := securityInfo(&pr)
	dir := subjectDirectory(head)
	for _, d := range decl {
		cl.Declared = append(cl.Declared, model.Update{
			Ecosystem: eco,
			Directory: dir,
			Name:      d.Name,
			From:      d.From,
			To:        d.Version,
			FromRef:   d.FromRef,
			ToRef:     d.ToRef,
			Type:      updateType(d.UpdateType),
			Direct:    strings.HasPrefix(d.DepType, "direct"),
			Security:  security,
			Advisory:  advisories,
		})
	}

	files, err := gh.List[file](ctx, c, fmt.Sprintf("repos/%s/pulls/%d/files", repoName, num))
	if err != nil {
		return model.Classification{}, err
	}
	for _, f := range files {
		for _, p := range []string{f.Filename, f.PreviousFilename} {
			if p == "" {
				continue
			}
			if !safePath(p) {
				return unverified("the pull request changes a file with an unsafe path")
			}
			cl.Files = append(cl.Files, p)
		}
	}
	if len(cl.Files) == 0 {
		return unverified("the pull request changes no files")
	}

	cl.Kind = model.KindDependabot
	cl.Reason = "authored, committed and signed by Dependabot only"
	logf("kind=dependabot: %s #%d %s (%d declared updates)", repoName, num, eco, len(cl.Declared))
	return cl, nil
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

var ecosystems = map[string]model.Ecosystem{
	string(model.GoModules):     model.GoModules,
	string(model.NPM):           model.NPM,
	string(model.UV):            model.UV,
	string(model.GitHubActions): model.GitHubActions,
	string(model.Docker):        model.Docker,
	string(model.GitSubmodule):  model.GitSubmodule,
}

func ecosystemFromBranch(ref string) (model.Ecosystem, bool) {
	rest, ok := strings.CutPrefix(ref, branchPrefix)
	if !ok {
		return "", false
	}
	name, _, ok := strings.Cut(rest, "/")
	if !ok {
		return "", false
	}
	e, ok := ecosystems[name]
	return e, ok
}

func updateType(s string) model.UpdateType {
	switch s {
	case "version-update:semver-patch":
		return model.Patch
	case "version-update:semver-minor":
		return model.Minor
	case "version-update:semver-major":
		return model.Major
	}
	return model.Unknown
}

var ghsaRe = regexp.MustCompile(`\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b`)

// securityInfo: a `security` label or a GHSA ID in the body marks the
// update as a security update. Only the IDs are kept from the body.
func securityInfo(pr *pull) (bool, []string) {
	sec := false
	for _, l := range pr.Labels {
		if l.Name == "security" {
			sec = true
		}
	}
	var ids []string
	seen := map[string]bool{}
	for _, id := range ghsaRe.FindAllString(pr.Body, 50) {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return sec || len(ids) > 0, ids
}

var refRe = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,255}$`)

func safeRef(s string) string {
	if !refRe.MatchString(s) || strings.Contains(s, "..") || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "/") {
		return ""
	}
	return s
}

// safePath accepts a relative, clean, slash-separated path without
// control characters.
func safePath(p string) bool {
	if p == "" || len(p) > 4096 || strings.HasPrefix(p, "/") || path.Clean(p) != p || p == "." {
		return false
	}
	for _, el := range strings.Split(p, "/") {
		if el == ".." {
			return false
		}
	}
	for _, r := range p {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return false
		}
	}
	return true
}

// Package actions gathers the facts for a GitHub Actions pull request.
// The change set is read without a YAML parser (shape.go): tag pins in
// workflows and their entries in actions.lock, by exact line shape. The
// facts about each pin come from GitHub's REST API (github.go), with GET
// requests only. A pin of a reusable workflow, a commit pin and a
// workflow without actions.lock make Shape not hold (spec section 11,
// amendments 6 and 7).
package actions

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"github.com/sadbox/dep-review/internal/advisory"
	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/facts"
	"github.com/sadbox/dep-review/internal/gh"
)

// Gatherer is the GitHub Actions fact gatherer.
type Gatherer struct{}

// New returns the GitHub Actions gatherer.
func New() *Gatherer { return &Gatherer{} }

// shapeSource is the Source of the Shape fact: it is read from the two
// commits' file contents and nothing else.
const shapeSource = "changed files at the base and head commits"

// policySource is the Source of the Listed fact.
const policySource = "policy list " + allow.GitHubActions

// Gather implements facts.Gatherer with in.GitHub, in.Advisories and
// in.Policy.
func (g *Gatherer) Gather(ctx context.Context, in facts.Input) (facts.Result, error) {
	if in.GitHub == nil {
		return facts.Result{}, errors.New("actions: no GitHub client")
	}
	if in.Advisories == nil {
		return facts.Result{}, errors.New("actions: no advisory checker")
	}
	pins, res := readFiles(in.Files, in.Policy)
	for i, p := range pins {
		u := &res.Updates[i]
		if err := gatherPin(ctx, in.GitHub, in.Advisories, p, u); err != nil {
			return facts.Result{}, err
		}
		// The model reads an artifact only at a commit Bound was
		// established for.
		if u.Bound.Holds() {
			res.Artifacts = append(res.Artifacts, artifact.Pair{
				Ecosystem: allow.GitHubActions,
				Name:      p.name,
				From:      p.from,
				To:        p.to,
				Old:       artifact.Ref{Kind: artifact.ActionTarball, Name: p.name, Version: p.from, Hash: p.oldCommit},
				New:       artifact.Ref{Kind: artifact.ActionTarball, Name: p.name, Version: p.to, Hash: p.newCommit},
				// The reader refuses an action that runs a container image
				// where the workflows use it (spec section 11, amendment
				// 55).
				Dirs: p.usedDirs(),
			})
		}
	}
	return res, nil
}

// Changes is the half of Gather that reads nothing but the pull request's
// files: Shape, and every pin with the facts the files and the policy
// list establish (Known, Listed, NewName, Increase and Major). The replay
// command runs this half alone.
func Changes(files []facts.File, policy allow.Policy) facts.Result {
	_, res := readFiles(files, policy)
	return res
}

// readFiles is Changes, with the pins its updates were made from: one
// update for each pin, in the same order. When Shape does not hold there
// are no pins.
func readFiles(files []facts.File, policy allow.Policy) ([]pin, facts.Result) {
	pins, problem := readChangeSet(files)
	if problem != "" {
		return nil, facts.Result{Shape: allow.No(problem, shapeSource)}
	}
	res := facts.Result{
		Shape: allow.Yes(fmt.Sprintf("%d action pin(s) replaced in place across %d file(s)", len(pins), len(files)), shapeSource),
	}
	for _, p := range pins {
		res.Updates = append(res.Updates, fileFacts(p, policy))
	}
	return pins, res
}

// fileFacts is one pin with what the files alone say. A pin is replaced
// in place, so its name is at the base commit by construction.
func fileFacts(p pin, policy allow.Policy) allow.UpdateFacts {
	u := allow.UpdateFacts{Name: p.name, From: p.from, To: p.to}
	u.Known = allow.Yes("replaced in place: the action is used at the base commit", p.where)
	u.NewName = allow.No("replaced in place: not a new name", p.where)
	if allow.Listed(policy, allow.GitHubActions, p.name) {
		u.Listed = allow.Yes(p.name+" matches the policy list", policySource)
	} else {
		u.Listed = allow.No(p.name+" does not match the policy list", policySource)
	}
	u.Increase = increase(p)
	u.Major = major(p)
	return u
}

// gatherPin fills in what GitHub and the advisory database say about one
// pin: every fact fileFacts left unset. The error is the context's.
func gatherPin(ctx context.Context, c *gh.Client, adv advisory.Checker, p pin, u *allow.UpdateFacts) error {
	repo, err := getRepo(ctx, c, p.name)
	if err != nil {
		return err
	}
	tag, err := resolveTag(ctx, c, p.name, p.to)
	if err != nil {
		return err
	}
	ahead, err := compare(ctx, c, p.name, p.oldCommit, p.newCommit)
	if err != nil {
		return err
	}
	branch, err := onBranch(ctx, c, p.name, repo, "releases/"+semver.Major(p.to), p.newCommit)
	if err != nil {
		return err
	}
	rel, err := getRelease(ctx, c, p.name, p.to)
	if err != nil {
		return err
	}
	advice, err := askAdvisories(ctx, adv, p, p.name)
	if err != nil {
		return err
	}

	// Each fact is its conditions combined with allow.Fact.And: a "no"
	// first, then an answer that could not be read, then an outage, so a
	// fact is a wait only when waiting could still make it hold.
	tagged := tagFact(p, tag)
	u.Bound = tagged.And(repoFact(p, repo))
	u.NoRegress = aheadFact(p, ahead).And(branch).And(tagged)
	u.Clean = releaseFact(p, rel).And(facts.AdvisoryClean(advice))
	// An action in a directory of its repository has a name of its own in
	// the advisory database (owner/repo/path), and an advisory can be
	// filed under that name alone. The pin is the repository's, so the
	// question above is about owner/repo; each directory a workflow line
	// uses the action from is asked about as well, and Clean holds only
	// when every answer is clean. These answers can only take Clean away:
	// SecurityFix is made from the repository's alone.
	for _, sub := range p.subPaths {
		inDir, err := askAdvisories(ctx, adv, p, p.name+sub)
		if err != nil {
			return err
		}
		u.Clean = u.Clean.And(facts.AdvisoryClean(inDir))
	}
	u.FirstSeen = firstSeen(p, rel)
	u.SecurityFix = securityFix(p, advice.SecurityFix)
	return nil
}

// securityFix is the SecurityFix fact, made from the advisory checker's.
// For an action it never holds (spec section 11, amendment 48).
//
// The database answers for a version: this tag is the first that an
// advisory does not affect. A registry's version is one set of bytes for
// good, so there the answer is about the bytes Bound checked. A tag is
// not. Whoever can push to the repository can move it after the advisory
// was reviewed; only an immutable release prevents that, and a release
// that was not immutable can be deleted and published again as one. A
// commit that the fix's tag was moved to would then need no age and
// merge at the gate's first evaluation of it, with the model's read as
// the only thing in its way, and the age is what gives a moved tag time
// to be noticed. So the checker's "yes" becomes a "no" that still names
// the advisory, for a person who wants to merge the fix by hand, and the
// update waits its age like any other.
//
// What the checker could not tell stays as it returned it: unavailable
// is a wait and never gathered is person, and neither is turned into an
// answer here.
func securityFix(p pin, advised allow.Fact) allow.Fact {
	if !advised.Holds() {
		return advised
	}
	return allow.No("no fast path for an action: tag "+p.to+" can be moved after the advisory was reviewed, so the update waits its age. The advisory database says: "+advised.Value, advised.Source)
}

// askAdvisories asks the advisory database about the pin under one name:
// the repository's, or that of an action in one of its directories. The
// checker puts whatever it learned, or failed to learn, into its facts.
// The error is the context's; any other error from a checker leaves the
// facts blank, which is person.
func askAdvisories(ctx context.Context, adv advisory.Checker, p pin, name string) (advisory.Result, error) {
	advice, err := adv.Check(ctx, advisory.Query{Ecosystem: allow.GitHubActions, Name: name, From: p.from, To: p.to})
	if ctx.Err() != nil {
		return advisory.Result{}, fmt.Errorf("actions: advisories for %s: %w", name, ctx.Err())
	}
	if err != nil {
		return advisory.Result{}, nil
	}
	return advice, nil
}

// increase is the Increase fact: both versions are plain releases and the
// new one is greater. The shapes already admit only vX.Y.Z; x/mod/semver
// does the comparison and is asked again whether they are plain.
func increase(p pin) allow.Fact {
	if !plainRelease(p.from) || !plainRelease(p.to) {
		return allow.No(p.from+" -> "+p.to+": not both plain vX.Y.Z releases", p.where)
	}
	if semver.Compare(p.to, p.from) <= 0 {
		return allow.No(p.from+" -> "+p.to+" is not an increase", p.where)
	}
	return allow.Yes(p.from+" -> "+p.to, p.where)
}

// plainRelease reports whether v is a canonical semantic version with no
// pre-release and no build suffix.
func plainRelease(v string) bool {
	return semver.IsValid(v) && semver.Canonical(v) == v && semver.Prerelease(v) == "" && semver.Build(v) == ""
}

// major is the Major fact: the leading version component changed.
func major(p pin) allow.Fact {
	from, to := semver.Major(p.from), semver.Major(p.to)
	if from == "" || to == "" {
		// Not a version: say it is a major, the answer that grants less.
		return allow.Yes(p.from+" -> "+p.to+": the major versions cannot be read", p.where)
	}
	if from != to {
		return allow.Yes(from+" -> "+to, p.where)
	}
	return allow.No("both "+to, p.where)
}

// tagFact is "the new tag resolves to the pinned commit", a part of Bound
// and of NoRegress.
func tagFact(p pin, tag tagAnswer) allow.Fact {
	source := "GitHub: repos/" + p.name + "/git/ref/tags/" + p.to
	switch {
	case tag.state == failed || tag.state == unreachable:
		return tag.unanswered("tag "+p.to+" could not be read", source)
	case tag.state == missing:
		return allow.No("tag "+p.to+" does not exist", source)
	case tag.problem != "":
		return allow.No(tag.problem, source)
	case tag.commit != p.newCommit:
		return allow.No("tag "+p.to+" is commit "+tag.commit+", the pin is "+p.newCommit, source)
	}
	return allow.Yes("tag "+p.to+" is commit "+p.newCommit, source)
}

// repoFact is the other part of Bound: the repository behind the name is
// the one the old pin was taken from, by the IDs actions.lock recorded.
// The IDs are the defence against a name that was registered again by
// someone else.
func repoFact(p pin, repo repoAnswer) allow.Fact {
	source := "GitHub: repos/" + p.name
	switch {
	case repo.state == failed || repo.state == unreachable:
		return repo.unanswered("the repository could not be read", source)
	case repo.state == missing:
		return allow.No("the repository was not found", source)
	case !strings.EqualFold(repo.FullName, p.name):
		// GitHub followed a redirect: the repository was renamed or
		// transferred, and the name in the workflow is free for someone
		// else to register.
		return allow.No("the name leads to a repository that is now called something else (renamed or transferred)", source)
	case repo.ID != p.repoID || repo.Owner.ID != p.ownerID:
		return allow.No(fmt.Sprintf("actions.lock records repository %d of owner %d, GitHub reports repository %d of owner %d", p.repoID, p.ownerID, repo.ID, repo.Owner.ID), source)
	}
	return allow.Yes(fmt.Sprintf("repository %d of owner %d, as actions.lock records", repo.ID, repo.Owner.ID), source)
}

// aheadFact is the first part of NoRegress: the new commit descends from
// the old one.
func aheadFact(p pin, ahead compareAnswer) allow.Fact {
	source := "GitHub: repos/" + p.name + "/compare/" + p.oldCommit + "..." + p.newCommit
	switch {
	case ahead.state == failed || ahead.state == unreachable:
		return ahead.unanswered("the old and new commits could not be compared", source)
	case ahead.state == missing:
		return allow.No("GitHub cannot compare the old and new commits: one of them is not in the repository", source)
	case !ahead.isAhead():
		return allow.No(fmt.Sprintf("the new commit does not descend from the old one (%s: %d ahead, %d behind)", compareStatus(ahead.Status), ahead.AheadBy, ahead.BehindBy), source)
	}
	return allow.Yes(fmt.Sprintf("%d commit(s) ahead of the old pin", ahead.AheadBy), source)
}

// compareStatus returns GitHub's comparison status when it is one of the
// four documented words, so nothing else from the answer reaches a Value.
func compareStatus(s string) string {
	switch s {
	case "ahead", "behind", "identical", "diverged":
		return s
	}
	return "unrecognised status"
}

// releaseFact is the release part of Clean: the version is a published
// release, not a draft or a prerelease.
func releaseFact(p pin, rel releaseAnswer) allow.Fact {
	source := "GitHub: repos/" + p.name + "/releases/tags/" + p.to
	switch {
	case rel.state == failed || rel.state == unreachable:
		return rel.unanswered("the release could not be read", source)
	case rel.state == missing:
		return allow.No("tag "+p.to+" has no release", source)
	case rel.TagName != p.to:
		return allow.No("GitHub answered with the release of another tag", source)
	case rel.Draft:
		return allow.No("release "+p.to+" is a draft", source)
	case rel.Prerelease:
		return allow.No("release "+p.to+" is a prerelease", source)
	}
	return allow.Yes("release "+p.to+" is published, not a draft or a prerelease", source)
}

// firstSeen is the FirstSeen fact. published_at of an immutable release
// is a clock the publisher cannot set: GitHub stamps it, and the release
// and its tag cannot be changed or published again. A release that is not
// immutable can be deleted and published again under the same tag with a
// new time, so its published_at proves nothing about when this commit
// became public. The fact is then unknown, with the release as its
// Source, and the publish job dates the pin from its own first
// evaluation of it (spec section 11, amendment 38).
func firstSeen(p pin, rel releaseAnswer) allow.TimeFact {
	source := "GitHub: repos/" + p.name + "/releases/tags/" + p.to
	switch {
	case rel.state == unreachable:
		return allow.UnavailableTime("the release could not be read: GitHub did not answer", source)
	case rel.state == failed:
		// An answer that could not be read: no Source either.
		return facts.NotEstablishedTime("the release could not be read")
	case rel.state != found || rel.TagName != p.to || rel.Draft || rel.Prerelease:
		return allow.TimeFact{Value: "tag " + p.to + " has no published release", Source: source}
	}
	at, err := time.Parse(time.RFC3339, rel.PublishedAt)
	if err != nil || at.IsZero() {
		return allow.TimeFact{Value: "release " + p.to + " has no readable published_at", Source: source}
	}
	if !rel.Immutable {
		return allow.TimeFact{Value: "release " + p.to + " is not immutable, so its published_at (" + at.UTC().Format("2006-01-02T15:04:05Z") + ") is not a time the publisher cannot set", Source: source}
	}
	return allow.At(at.UTC(), source+" published_at (immutable release)")
}

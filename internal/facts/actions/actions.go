// Package actions gathers the facts for a GitHub Actions pull request
// (docs/v0.2-spec.md, sections 3, 4 and 6).
//
// The change set is read without a YAML parser (shape.go): the changed
// files must be workflows, local action.yml files or
// .github/workflows/actions.lock, base and head must have the same number
// of lines, and every changed line must be one exact pin shape that
// differs only in its commit and version tokens. Anything else makes the
// Shape fact not hold, and nothing further is asked.
//
// The facts about each pin come from GitHub's REST API (github.go):
//
//   - Bound: the new tag resolves to the pinned commit, and the
//     repository and owner IDs GitHub reports are the ones actions.lock
//     recorded at the base commit. A commit-pinned line that no changed
//     lockfile entry records has no recorded IDs to compare with, so its
//     Bound does not hold and the update goes to a person.
//   - NoRegress: the new commit is ahead of the old one, a branch releases
//     are cut from (the default branch or releases/v<major>) holds it, and
//     the tag resolves to it.
//   - Clean: the tag has a published release that is not a draft or a
//     prerelease, and the advisory database has nothing against it.
//   - FirstSeen: the release's published_at, when the release is
//     immutable. For any other release it is left unknown with its Source
//     set to the release that was read: GitHub was asked and has no clock
//     for this version that the publisher cannot set again. The fetch
//     command then uses the pull request's creation time (spec section
//     11, amendment 4).
//
// Two kinds of change never merge, by rule (spec section 11, amendments 6
// and 7). A changed line that pins a reusable workflow makes Shape not
// hold, the gate's own pin included: the gate never approves its
// successor. And a commit pin that no changed actions.lock entry records
// has no baseline for the repository's IDs, so its Bound does not hold.
//
// A question GitHub did not answer (a server error, a rate limit, the
// network) leaves the facts that depend on it unavailable, which is a
// wait; an answer that could not be read leaves them without a source,
// which is person.
//
// The gatherer holds no state and makes only GET requests. It changes no
// setting anywhere. Where one of these facts depends on a setting of a
// repository the owner controls (immutable releases on an action or
// reusable-workflow repository of their own, so that FirstSeen can come
// from GitHub), that setting is applied like every other repository
// setting: where the owner keeps them as code, not with gh and not by
// hand.
package actions

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/sadbox/dep-review/internal/advisory"
	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/facts"
	"github.com/sadbox/dep-review/internal/gh"
)

// Gatherer is the GitHub Actions fact gatherer. The zero value is ready
// to use.
type Gatherer struct{}

// New returns the GitHub Actions gatherer.
func New() *Gatherer { return &Gatherer{} }

var _ facts.Gatherer = (*Gatherer)(nil)

// shapeSource is the Source of the Shape fact: it is read from the two
// commits' file contents and nothing else.
const shapeSource = "changed files at the base and head commits"

// policySource is the Source of the Listed fact.
const policySource = "policy list " + allow.GitHubActions

// Gather reads the change set from in.Files and gathers the facts of
// every pin it moves. It uses in.GitHub, in.Advisories and in.Policy.
//
// The error is for a run that cannot produce a result: no GitHub client
// or advisory checker, or a context that ended. A question GitHub did not
// answer is not an error: the facts that depend on it are returned
// unavailable, with the reason in their Value, and the next evaluation
// asks again.
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
			})
		}
	}
	return res, nil
}

// Changes is the half of Gather that reads nothing but the pull request's
// files: the Shape fact, and every pin the pull request moves with the
// facts the files and the policy list establish (Known, Listed, NewName,
// Increase and Major). Every other fact is left unset, Bound included:
// that a pin has no actions.lock entry is said by Gather, with what GitHub
// reports. Gather starts from the same reading; the replay command runs
// this half alone.
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
	branch, err := findBranch(ctx, c, p.name, repo, "releases/"+semver.Major(p.to), p.newCommit)
	if err != nil {
		return err
	}
	rel, err := getRelease(ctx, c, p.name, p.to)
	if err != nil {
		return err
	}
	// The checker puts whatever it learned, or failed to learn, into its
	// facts. Its error is the context's; from any other checker it leaves
	// the facts blank, which is person.
	advice, advErr := adv.Check(ctx, advisory.Query{Ecosystem: allow.GitHubActions, Name: p.name, From: p.from, To: p.to})
	if ctx.Err() != nil {
		return fmt.Errorf("actions: advisories for %s: %w", p.name, ctx.Err())
	}
	if advErr != nil {
		advice = advisory.Result{}
	}

	u.Bound = bound(p, repo, tag)
	u.NoRegress = noRegress(p, tag, ahead, branch)
	u.Clean = clean(p, rel, advice)
	u.FirstSeen = firstSeen(p, rel)
	// As the checker returned it: unavailable or never gathered when it
	// could not tell.
	u.SecurityFix = advice.SecurityFix
	return nil
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

// parts collects the conditions of one fact, in the order allow.Fact.And
// combines facts. A condition that is false makes the fact a gathered
// "no". Otherwise a condition whose answer could not be read leaves the
// fact ungathered: its Value says why and its Source stays empty, which
// allow reads as never gathered. Otherwise a condition GitHub did not
// answer for makes it unavailable, so the fact is a wait only when
// waiting could still make it hold.
type parts struct {
	yes, no, unknown, unavailable []string
}

func (p *parts) fact(source string) allow.Fact {
	switch {
	case len(p.no) > 0:
		return allow.No(strings.Join(p.no, "; "), source)
	case len(p.unknown) > 0:
		return allow.Fact{Value: "not established: " + strings.Join(p.unknown, "; ")}
	case len(p.unavailable) > 0:
		return allow.Unavailable(strings.Join(p.unavailable, "; "), source)
	}
	return allow.Yes(strings.Join(p.yes, "; "), source)
}

// unanswered files a lookup that has no usable answer under the bucket
// its state calls for.
func (p *parts) unanswered(state lookup, what string) {
	if state == unreachable {
		p.unavailable = append(p.unavailable, what)
	} else {
		p.unknown = append(p.unknown, what)
	}
}

// tagPart adds "the new tag resolves to the pinned commit" to a fact. It
// is part of Bound and of NoRegress.
func tagPart(ps *parts, p pin, tag tagAnswer) {
	switch {
	case tag.state == failed || tag.state == unreachable:
		ps.unanswered(tag.state, "tag "+p.to+" could not be read: "+tag.why())
	case tag.state == missing:
		ps.no = append(ps.no, "tag "+p.to+" does not exist")
	case tag.problem != "":
		ps.no = append(ps.no, tag.problem)
	case tag.commit != p.newCommit:
		ps.no = append(ps.no, "tag "+p.to+" is commit "+tag.commit+", the pin is "+p.newCommit)
	default:
		ps.yes = append(ps.yes, "tag "+p.to+" is commit "+p.newCommit)
	}
}

// bound is the Bound fact: the tag resolves to the pinned commit, and the
// repository behind the name is the one the old pin was taken from.
func bound(p pin, repo repoAnswer, tag tagAnswer) allow.Fact {
	var ps parts
	tagPart(&ps, p, tag)

	switch {
	case repo.state == failed || repo.state == unreachable:
		ps.unanswered(repo.state, "the repository could not be read: "+repo.why())
	case repo.state == missing:
		ps.no = append(ps.no, "the repository was not found")
	case !strings.EqualFold(repo.FullName, p.name):
		// GitHub followed a redirect: the repository was renamed or
		// transferred, and the name in the workflow is free for someone
		// else to register.
		ps.no = append(ps.no, "the name leads to a repository that is now called something else (renamed or transferred)")
	case !p.locked:
		// The IDs are the defence against a name that was registered
		// again by someone else, and a workflow line records none. Only
		// actions.lock does.
		ps.no = append(ps.no, fmt.Sprintf("no actions.lock entry records the repository's IDs for the old pin, so GitHub's (repository %d, owner %d) cannot be compared", repo.ID, repo.Owner.ID))
	case repo.ID != p.repoID || repo.Owner.ID != p.ownerID:
		ps.no = append(ps.no, fmt.Sprintf("actions.lock records repository %d of owner %d, GitHub reports repository %d of owner %d", p.repoID, p.ownerID, repo.ID, repo.Owner.ID))
	default:
		ps.yes = append(ps.yes, fmt.Sprintf("repository %d of owner %d, as actions.lock records", repo.ID, repo.Owner.ID))
	}
	return ps.fact("GitHub: repos/" + p.name + " and git/ref/tags/" + p.to)
}

// noRegress is the NoRegress fact: the new commit descends from the old
// one, a default or release branch holds it, and the tag resolves to it.
func noRegress(p pin, tag tagAnswer, ahead compareAnswer, branch reach) allow.Fact {
	var ps parts
	switch {
	case ahead.state == failed || ahead.state == unreachable:
		ps.unanswered(ahead.state, "the old and new commits could not be compared: "+ahead.why())
	case ahead.state == missing:
		ps.no = append(ps.no, "GitHub cannot compare the old and new commits: one of them is not in the repository")
	case !ahead.isAhead():
		ps.no = append(ps.no, fmt.Sprintf("the new commit does not descend from the old one (%s: %d ahead, %d behind)", compareStatus(ahead.Status), ahead.AheadBy, ahead.BehindBy))
	default:
		ps.yes = append(ps.yes, fmt.Sprintf("%d commit(s) ahead of the old pin", ahead.AheadBy))
	}
	switch branch.state {
	case failed, unreachable:
		ps.unanswered(branch.state, branch.detail)
	case missing:
		ps.no = append(ps.no, branch.detail)
	default:
		ps.yes = append(ps.yes, "on branch "+branch.branch)
	}
	tagPart(&ps, p, tag)
	return ps.fact("GitHub: repos/" + p.name + "/compare and git/ref/tags/" + p.to)
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

// clean is the Clean fact: the version is a published release, and the
// advisory database has no malware advisory and no new advisory for it.
func clean(p pin, rel releaseAnswer, adv advisory.Result) allow.Fact {
	var ps parts
	switch {
	case rel.state == failed || rel.state == unreachable:
		ps.unanswered(rel.state, "the release could not be read: "+rel.why())
	case rel.state == missing:
		ps.no = append(ps.no, "tag "+p.to+" has no release")
	case rel.TagName != p.to:
		ps.no = append(ps.no, "GitHub answered with the release of another tag")
	case rel.Draft:
		ps.no = append(ps.no, "release "+p.to+" is a draft")
	case rel.Prerelease:
		ps.no = append(ps.no, "release "+p.to+" is a prerelease")
	default:
		ps.yes = append(ps.yes, "release "+p.to+" is published, not a draft or a prerelease")
	}
	advisoryPart(&ps, adv.NoMalware, "malware advisory")
	advisoryPart(&ps, adv.NoNewAdvisory, "new advisory")
	return ps.fact("GitHub: repos/" + p.name + "/releases/tags/" + p.to + " and the advisory database")
}

// advisoryPart adds one of the advisory checker's facts to Clean. Its
// Value is the checker's own text (advisory IDs, or why it could not
// tell).
func advisoryPart(ps *parts, f allow.Fact, what string) {
	switch {
	case f.Unavailable && f.Source != "":
		ps.unavailable = append(ps.unavailable, what+": "+f.Value)
	case !f.Gathered() && f.Value != "":
		ps.unknown = append(ps.unknown, what+": "+f.Value)
	case !f.Gathered():
		ps.unknown = append(ps.unknown, "whether there is a "+what+" is not known")
	case !f.OK:
		ps.no = append(ps.no, what+": "+f.Value)
	default:
		ps.yes = append(ps.yes, "no "+what)
	}
}

// firstSeen is the FirstSeen fact. published_at of an immutable release
// is a clock the publisher cannot set: GitHub stamps it, and the release
// and its tag cannot be changed or published again. A release that is not
// immutable can be deleted and published again under the same tag with a
// new time, so its published_at proves nothing about when this commit
// became public. The fact is then unknown, with the release as its
// Source, and the fetch command falls back to the time the pull request
// was opened.
func firstSeen(p pin, rel releaseAnswer) allow.TimeFact {
	source := "GitHub: repos/" + p.name + "/releases/tags/" + p.to
	switch rel.state {
	case unreachable:
		return allow.UnavailableTime("the release could not be read: "+rel.why(), source)
	case failed:
		// An answer that could not be read: no Source either.
		return allow.TimeFact{Value: "not established: the release could not be read: " + rel.why()}
	}
	if !rel.published(p.to) {
		return allow.TimeFact{Value: "tag " + p.to + " has no published release", Source: source}
	}
	at, ok := rel.publishedAt()
	if !ok {
		return allow.TimeFact{Value: "release " + p.to + " has no readable published_at", Source: source}
	}
	if !rel.Immutable {
		return allow.TimeFact{Value: "release " + p.to + " is not immutable, so its published_at (" + at.Format("2006-01-02T15:04:05Z") + ") is not a time the publisher cannot set", Source: source}
	}
	return allow.At(at, source+" published_at (immutable release)")
}

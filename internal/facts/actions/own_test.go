package actions

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/advisory"
	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/facts"
	"github.com/sadbox/dep-review/internal/wire"
)

// Spec section 11, amendment 60: the commit pin of a reusable workflow in
// a repository on the policy's own list is an update, accepted on where
// its commit comes from. The repositories, IDs and commits here are made
// up, and GitHub's answers about them are canned: no test asks the
// network, and a request no test expects fails it (replay).
const (
	ownRepo    = "acme-infra/ci"
	ownGate    = "acme-infra/gate"
	ownOwnerID = 77
	ownRepoID  = 4242
	ownGateID  = 4343

	ownLint = ownRepo + "/.github/workflows/lint.yml"
	ownGo   = ownRepo + "/.github/workflows/go.yml"

	ownV122 = "0000000000000000000000000000000000000122"
	ownV123 = "0000000000000000000000000000000000000123"
	ownV130 = "0000000000000000000000000000000000000130"
	ownV200 = "0000000000000000000000000000000000000200"
	// A commit no tag of the repository names.
	ownOther = "00000000000000000000000000000000000000ff"

	ownCaller = ".github/workflows/lint.yaml"
)

// ownPolicy is testPolicy with an own list of two repositories.
func ownPolicy() allow.Policy {
	p := testPolicy()
	p.Own = []allow.OwnRepo{
		{Repository: ownRepo, RepositoryID: ownRepoID, OwnerID: ownOwnerID},
		{Repository: ownGate, RepositoryID: ownGateID, OwnerID: ownOwnerID},
	}
	return p
}

// calls is a workflow whose one job calls a reusable workflow: the uses
// line is line 5, a commit pin with its version in the comment.
func calls(workflow, commit, version string) string {
	return "name: lint\non: [pull_request]\njobs:\n  lint:\n    uses: " + workflow + "@" + commit + " # " + version + "\n    permissions:\n      contents: read\n"
}

// ownBump is the pull request Dependabot opens for a release of an own
// workflow: one line of one calling workflow, and no lockfile.
func ownBump(workflow, oldCommit, from, newCommit, to string) []facts.File {
	return []facts.File{file(ownCaller, calls(workflow, oldCommit, from), calls(workflow, newCommit, to))}
}

func lintBumpOwn() []facts.File { return ownBump(ownLint, ownV123, "v1.2.3", ownV130, "v1.3.0") }

func TestOwnWorkflowPin(t *testing.T) {
	want := pin{name: ownRepo, from: "v1.2.3", to: "v1.3.0", oldCommit: ownV123, newCommit: ownV130,
		ownerID: ownOwnerID, repoID: ownRepoID, where: ownCaller + ":5", own: true}
	pins, problem := readChangeSet(lintBumpOwn(), ownPolicy())
	if problem != "" || !reflect.DeepEqual(pins, []pin{want}) {
		t.Fatalf("pins %+v, problem %q; want %+v", pins, problem, want)
	}
	// Nothing of it is read, so it names no directory to look for an
	// action in.
	if dirs := pins[0].usedDirs(); dirs != nil {
		t.Errorf("usedDirs %q, want none", dirs)
	}

	// What the files and the policy alone say.
	res := Changes(lintBumpOwn(), ownPolicy())
	u := one(t, res)
	mustHold(t, "Own", u.Own)
	mustHold(t, "Known", u.Known)
	mustHold(t, "Increase", u.Increase)
	mustBeNo(t, "Listed", u.Listed, "does not match the policy list")
	mustBeNo(t, "Major", u.Major, "both v1")
	mustBeNo(t, "NewName", u.NewName, "not a new name")
	if u.Name != ownRepo || u.From != "v1.2.3" || u.To != "v1.3.0" || u.Own.Source != "policy list own_workflows" {
		t.Errorf("update %s %s -> %s, Own %+v", u.Name, u.From, u.To, u.Own)
	}

	// The same pull request under a policy that does not name the
	// repository is refused, as every reusable workflow was (amendment 6).
	for name, p := range map[string]allow.Policy{
		"no own list": testPolicy(),
		"another own repository": func() allow.Policy {
			p := ownPolicy()
			p.Own = p.Own[1:]
			return p
		}(),
		"on the owner-kept list only": func() allow.Policy {
			p := testPolicy()
			p.Listed[allow.GitHubActions] = append(p.Listed[allow.GitHubActions], "acme-infra/", ownRepo)
			return p
		}(),
	} {
		if pins, problem := readChangeSet(lintBumpOwn(), p); len(pins) != 0 || !strings.Contains(problem, "not a workflow file of a repository on the policy's own list") {
			t.Errorf("%s: pins %+v, problem %q", name, pins, problem)
		}
	}

	second := ownPolicy().Own[1]
	for _, tc := range []struct {
		name  string
		files []facts.File
		want  []pin
	}{
		{"the other entry, with its own IDs", ownBump(ownGate+"/.github/workflows/gate.yml", ownV123, "v1.2.3", ownV130, "v1.3.0"),
			[]pin{{name: ownGate, from: "v1.2.3", to: "v1.3.0", oldCommit: ownV123, newCommit: ownV130, ownerID: second.OwnerID, repoID: second.RepositoryID, where: ownCaller + ":5", own: true}}},
		{"a workflow file named .yaml", ownBump(ownRepo+"/.github/workflows/lint.yaml", ownV123, "v1.2.3", ownV130, "v1.3.0"), []pin{want}},
		// One release moves every line that calls the repository: lines
		// with the same versions are one update, whichever workflow file
		// they call and whichever file they are in.
		{"two workflow files of one release, in two files", []facts.File{
			file(ownCaller, calls(ownLint, ownV123, "v1.2.3"), calls(ownLint, ownV130, "v1.3.0")),
			file(".github/workflows/test.yaml", calls(ownGo, ownV123, "v1.2.3"), calls(ownGo, ownV130, "v1.3.0")),
		}, []pin{want}},
		{"callers that were on different versions", []facts.File{
			file(ownCaller, calls(ownLint, ownV123, "v1.2.3"), calls(ownLint, ownV130, "v1.3.0")),
			file(".github/workflows/test.yaml", calls(ownGo, ownV122, "v1.2.2"), calls(ownGo, ownV130, "v1.3.0")),
		}, []pin{
			{name: ownRepo, from: "v1.2.2", to: "v1.3.0", oldCommit: ownV122, newCommit: ownV130, ownerID: ownOwnerID, repoID: ownRepoID, where: ".github/workflows/test.yaml:5", own: true},
			want,
		}},
		// Dependabot moves a pin whose commit no tag names from commit to
		// commit and leaves the comment: the line is read, and Increase is
		// what does not hold (TestOwnWorkflowGather).
		{"the commit moves under an unchanged version", ownBump(ownLint, ownOther, "v1.2.3", ownV130, "v1.2.3"),
			[]pin{{name: ownRepo, from: "v1.2.3", to: "v1.2.3", oldCommit: ownOther, newCommit: ownV130, ownerID: ownOwnerID, repoID: ownRepoID, where: ownCaller + ":5", own: true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pins, problem := readChangeSet(tc.files, ownPolicy())
			if problem != "" || !reflect.DeepEqual(pins, tc.want) {
				t.Errorf("problem %q, pins\n got %+v\nwant %+v", problem, pins, tc.want)
			}
		})
	}

	// In a grouped pull request an action beside it is an update of its
	// own, read and held to its lockfile entry like any other.
	grouped := append(setupGoBump(t), lintBumpOwn()...)
	pins, problem = readChangeSet(grouped, ownPolicy())
	if problem != "" || len(pins) != 2 || pins[0].name != ownRepo || !pins[0].own || pins[1].name != "actions/setup-go" || pins[1].own || !pins[1].root {
		t.Errorf("grouped with an action: pins %+v, problem %q", pins, problem)
	}
	res = Changes(grouped, ownPolicy())
	if !res.Shape.Holds() || len(res.Updates) != 2 || !res.Updates[0].Own.Holds() || res.Updates[1].Own != (allow.Fact{}) {
		t.Errorf("grouped with an action: %+v", res)
	}
}

func TestOwnWorkflowPinRefuses(t *testing.T) {
	bump := func(base, head string) []facts.File { return []facts.File{file(ownCaller, base, head)} }
	// moved is the bump of TestOwnWorkflowPin with another workflow path.
	moved := func(workflow string) []facts.File { return ownBump(workflow, ownV123, "v1.2.3", ownV130, "v1.3.0") }
	base, head := calls(ownLint, ownV123, "v1.2.3"), calls(ownLint, ownV130, "v1.3.0")
	const (
		notOwn     = "not a workflow file of a repository on the policy's own list"
		notCommit  = "an own reusable workflow is read only as a commit pin"
		pinsCommit = "the line pins a commit; only a tag pin that actions.lock records is read"
		moreThan   = "more than the commit and version changed on the line"
		notShape   = "the changed line is not an action pin in an accepted shape"
	)
	for _, tc := range []struct {
		name  string
		files []facts.File
		want  string
	}{
		// Names that are not an entry, whole and byte for byte.
		{"a look-alike owner", moved("acme-1nfra/ci/.github/workflows/lint.yml"), notOwn},
		{"a look-alike repository", moved("acme-infra/c1/.github/workflows/lint.yml"), notOwn},
		{"a repository the entry is a prefix of", moved("acme-infra/ci-tools/.github/workflows/lint.yml"), notOwn},
		{"a repository that is a prefix of the entry", moved("acme-infra/c/.github/workflows/lint.yml"), notOwn},
		{"another repository of the same owner", moved("acme-infra/tools/.github/workflows/lint.yml"), notOwn},
		{"the owner in another case", moved("Acme-infra/ci/.github/workflows/lint.yml"), notOwn},
		{"the repository in another case", moved("acme-infra/CI/.github/workflows/lint.yml"), notOwn},
		{"an owner whose name ends like the entry's", moved("not-acme-infra/ci/.github/workflows/lint.yml"), notOwn},
		{"a third party's workflow", moved("octo-org/workflows/.github/workflows/lint.yml"), notOwn},
		{"a listed publisher's workflow", moved("actions/setup-go/.github/workflows/lint.yml"), notOwn},
		// The repository is own, and the path is not a workflow file of it.
		{"below the workflows directory", moved(ownRepo + "/.github/workflows/sub/lint.yml"), notOwn},
		{"not a YAML file", moved(ownRepo + "/.github/workflows/lint.yml.txt"), notOwn},
		{"the workflows directory itself", moved(ownRepo + "/.github/workflows/.yml/x"), notOwn},
		// An own repository used as an action is an action: a commit pin
		// of one is not read (amendment 29).
		{"the own repository as an action", moved(ownRepo), pinsCommit},
		{"an action in a directory of the own repository", moved(ownRepo + "/lint"), pinsCommit},
		{"a workflows directory that is not the repository's own", moved(ownRepo + "/sub/.github/workflows/lint.yml"), pinsCommit},

		// More than the commit and the version changes on the line.
		{"the repository changes to an own one", bump(calls("octo-org/workflows/.github/workflows/lint.yml", ownV123, "v1.2.3"), head), moreThan},
		{"the repository changes from an own one", bump(base, calls("acme-1nfra/ci/.github/workflows/lint.yml", ownV130, "v1.3.0")), moreThan},
		{"one own repository changes to the other", bump(base, calls(ownGate+"/.github/workflows/lint.yml", ownV130, "v1.3.0")), moreThan},
		{"the workflow file changes", bump(base, calls(ownGo, ownV130, "v1.3.0")), moreThan},
		{"the indentation changes", bump(base, strings.Replace(head, "    uses:", "      uses:", 1)), moreThan},

		// Pins that are not a commit with its version, at both commits.
		{"a tag pin", bump("jobs:\n  lint:\n    uses: "+ownLint+"@v1.2.3\n", "jobs:\n  lint:\n    uses: "+ownLint+"@v1.3.0\n"), notCommit},
		{"a tag pin becomes a commit pin", bump("jobs:\n  lint:\n    uses: "+ownLint+"@v1.2.3\n", "jobs:\n  lint:\n    uses: "+ownLint+"@"+ownV130+" # v1.3.0\n"), notCommit},
		{"a commit pin becomes a tag pin", bump("jobs:\n  lint:\n    uses: "+ownLint+"@"+ownV123+" # v1.2.3\n", "jobs:\n  lint:\n    uses: "+ownLint+"@v1.3.0\n"), notCommit},
		{"only the version in the comment changes", bump(base, calls(ownLint, ownV123, "v1.3.0")), notCommit},
		{"a commit with no version", bump("jobs:\n  lint:\n    uses: "+ownLint+"@"+ownV123+"\n", "jobs:\n  lint:\n    uses: "+ownLint+"@"+ownV130+"\n"), notShape},
		{"a short commit", bump(base, strings.Replace(head, ownV130, ownV130[:12], 1)), notShape},
		{"a branch", bump("jobs:\n  lint:\n    uses: "+ownLint+"@main\n", "jobs:\n  lint:\n    uses: "+ownLint+"@release\n"), notShape},
		{"a version that is not vX.Y.Z", bump(base, calls(ownLint, ownV130, "v1.3")), notShape},
		{"a pre-release", bump(base, calls(ownLint, ownV130, "v1.3.0-rc.1")), notShape},
		{"more in the comment than the version", bump(base, calls(ownLint, ownV130, "v1.3.0 reviewed")), notShape},
		{"a quoted value", bump("jobs:\n  lint:\n    uses: \""+ownLint+"@"+ownV123+"\" # v1.2.3\n", "jobs:\n  lint:\n    uses: \""+ownLint+"@"+ownV130+"\" # v1.3.0\n"), notShape},

		// A second changed line.
		{"the permissions change with it", bump(base, strings.Replace(head, "contents: read", "contents: write", 1)), notShape},
		{"a secret is passed with it", bump(base+"    secrets: {}\n", head+"    secrets: inherit\n"), notShape},
		{"the trigger changes with it", bump(base, strings.Replace(head, "on: [pull_request]", "on: [pull_request_target]", 1)), notShape},
		{"a line is added", bump(base, head+"    secrets: inherit\n"), "a different number of lines"},
		{"a second line moves to another repository's workflow", bump(
			base+"  test:\n    uses: "+ownGo+"@"+ownV123+" # v1.2.3\n",
			head+"  test:\n    uses: octo-org/workflows/.github/workflows/go.yml@"+ownV130+" # v1.3.0\n"), moreThan},
		{"a second line bumps a third party's workflow", bump(
			base+"  test:\n    uses: octo-org/workflows/.github/workflows/go.yml@"+ownV123+" # v1.2.3\n",
			head+"  test:\n    uses: octo-org/workflows/.github/workflows/go.yml@"+ownV130+" # v1.3.0\n"), ownCaller + ":9: the line pins a reusable workflow that is " + notOwn},
		{"another file changes with it", append(lintBumpOwn(), file("README.md", "a\n", "b\n")), "a changed file is not a workflow or actions.lock"},
		{"the workflow is added, not changed", []facts.File{{Path: ownCaller, HeadMode: facts.RegularFile, Head: []byte(head)}}, "not a regular file at both commits"},

		// Lines that disagree with each other.
		{"one release at two commits", []facts.File{
			file(ownCaller, base, head),
			file(".github/workflows/test.yaml", calls(ownGo, ownV123, "v1.2.3"), calls(ownGo, ownOther, "v1.3.0")),
		}, "pinned to other commits elsewhere"},
		{"one old version at two commits", []facts.File{
			file(ownCaller, base, head),
			file(".github/workflows/test.yaml", calls(ownGo, ownOther, "v1.2.3"), calls(ownGo, ownV130, "v1.3.0")),
		}, "pinned to other commits elsewhere"},
		// The same repository and versions as an action that actions.lock
		// records: one update cannot be both read and accepted unread.
		{"also pinned as an action", append(lockedBump(ownRepo, "v1.2.3", "v1.3.0", ownV123, ownV130, ownOwnerID, ownRepoID), lintBumpOwn()...),
			"pinned both as an action and as an own reusable workflow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pins, problem := readChangeSet(tc.files, ownPolicy())
			if problem == "" || len(pins) != 0 {
				t.Fatalf("the shape holds (pins %+v), want a problem with %q", pins, tc.want)
			}
			if !strings.Contains(problem, tc.want) {
				t.Errorf("problem %q, want it to contain %q", problem, tc.want)
			}
			// Shown in the comment as the gate's own text.
			for _, r := range problem {
				if r < 0x20 || r > 0x7e {
					t.Errorf("problem %q has a character outside printable ASCII", problem)
					break
				}
			}
			if res := Changes(tc.files, ownPolicy()); res.Shape.Holds() || len(res.Updates) != 0 {
				t.Errorf("Changes: %+v", res)
			}
		})
	}
}

// ownGitHub is what GitHub says about the own repository when everything
// about the pin from..to is in order: the repository has the list's IDs,
// the new tag is the new commit, the new commit is ahead of the old one
// and on the default branch. Nothing else has an answer: the release and
// the releases/ branch are not asked for an own workflow.
func ownGitHub(oldCommit, newCommit, to string) map[string]canned {
	const repo = "repos/" + ownRepo
	return map[string]canned{
		repo:                         {200, fmt.Sprintf(`{"id":%d,"full_name":%q,"default_branch":"main","owner":{"id":%d}}`, ownRepoID, ownRepo, ownOwnerID)},
		repo + "/git/ref/tags/" + to: {200, fmt.Sprintf(`{"ref":"refs/tags/%s","object":{"type":"commit","sha":%q}}`, to, newCommit)},
		repo + "/compare/" + oldCommit + "..." + newCommit: {200, `{"status":"ahead","ahead_by":4,"behind_by":0}`},
		repo + "/compare/main..." + newCommit:              {200, `{"status":"behind","ahead_by":0,"behind_by":2}`},
	}
}

// gatherOwn gathers for files under ownPolicy against canned answers.
func gatherOwn(t *testing.T, files []facts.File, policy allow.Policy, github map[string]canned, adv advisory.Checker) (facts.Result, *replay) {
	t.Helper()
	net := &replay{t: t, override: github}
	res, err := New().Gather(context.Background(), facts.Input{
		Repo: "example/caller", Base: strings.Repeat("a", 40), Head: strings.Repeat("b", 40),
		Files: files, Policy: policy, GitHub: net.client(), Advisories: adv,
	})
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	return res, net
}

// decideOwn is what becomes of a gathered result on its way to a
// decision: the fetch job writes each update into the facts file with no
// read prepared, publish joins that with a verdicts file that has nothing
// for it, and allow.Decide answers under the same policy. Nothing dates
// the update on the way.
func decideOwn(t *testing.T, res facts.Result, policy allow.Policy, now time.Time) allow.Decision {
	t.Helper()
	f := wire.Facts{
		Version:     wire.Version,
		PullRequest: wire.PullRequest{Repo: "example/caller", Number: 7, Head: strings.Repeat("b", 40)},
		GatheredAt:  now,
		Facts: wire.PRFacts{
			Ecosystem:        allow.GitHubActions,
			Identity:         allow.Yes("dependabot", "test"),
			Shape:            res.Shape,
			ChecksConfigured: allow.Yes("ruleset", "test"),
			Opened:           now.Add(-time.Minute),
		},
	}
	for _, u := range res.Updates {
		f.Facts.Updates = append(f.Facts.Updates, wire.NewUpdate(u, wire.Read{Status: wire.Nothing}))
	}
	b, err := wire.EncodeFacts(f)
	if err != nil {
		t.Fatalf("the facts file: %v", err)
	}
	if f, err = wire.DecodeFacts(b); err != nil {
		t.Fatalf("the facts file: %v", err)
	}
	return allow.Decide(wire.Join(f, wire.Verdicts{Version: wire.Version}, strings.Repeat("f", 64)), policy, now)
}

func TestOwnWorkflowGather(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	const (
		repo      = "repos/" + ownRepo
		refPath   = repo + "/git/ref/tags/v1.3.0"
		aheadPath = repo + "/compare/" + ownV123 + "..." + ownV130
		mainPath  = repo + "/compare/main..." + ownV130
		relBranch = repo + "/compare/releases/v1..." + ownV130
		release   = repo + "/releases/tags/v1.3.0"
		notFound  = `{"message":"Not Found","status":"404"}`
	)
	// with is the good answers, some replaced.
	with := func(change map[string]canned) map[string]canned {
		github := ownGitHub(ownV123, ownV130, "v1.3.0")
		for path, answer := range change {
			github[path] = answer
		}
		return github
	}
	repoJSON := func(id, ownerID int64, fullName string) canned {
		return canned{200, fmt.Sprintf(`{"id":%d,"full_name":%q,"default_branch":"main","owner":{"id":%d}}`, id, fullName, ownerID)}
	}
	compareJSON := func(status string, ahead, behind int) canned {
		return canned{200, fmt.Sprintf(`{"status":%q,"ahead_by":%d,"behind_by":%d}`, status, ahead, behind)}
	}

	t.Run("every fact holds: merged at once, unread and undated", func(t *testing.T) {
		adv := noAdvisories()
		res, net := gatherOwn(t, lintBumpOwn(), ownPolicy(), with(nil), adv)
		u := one(t, res)
		mustHold(t, "Own", u.Own)
		mustHold(t, "Bound", u.Bound)
		mustHold(t, "NoRegress", u.NoRegress)
		mustHold(t, "Clean", u.Clean)
		mustBeNo(t, "SecurityFix", u.SecurityFix, "")
		for _, want := range []string{"tag v1.3.0 is commit " + ownV130, "repository 4242 of owner 77, as the policy list own_workflows records"} {
			if !strings.Contains(u.Bound.Value, want) {
				t.Errorf("Bound value %q, want it to say %q", u.Bound.Value, want)
			}
		}
		if !strings.Contains(u.NoRegress.Value, "4 commit(s) ahead of the old pin") || !strings.Contains(u.NoRegress.Value, "on branch main") {
			t.Errorf("NoRegress value %q", u.NoRegress.Value)
		}
		// Clean is the advisories alone, asked under the repository's name.
		if strings.Contains(u.Clean.Value, "release") || !strings.Contains(u.Clean.Value, "no malware advisory") {
			t.Errorf("Clean value %q, want the advisories' and no word of a release", u.Clean.Value)
		}
		wantQuery := advisory.Query{Ecosystem: allow.GitHubActions, Name: ownRepo, From: "v1.2.3", To: "v1.3.0"}
		if len(adv.asked) != 1 || adv.asked[0] != wantQuery {
			t.Errorf("advisory queries %+v, want %+v", adv.asked, wantQuery)
		}
		// No age is asked, so nothing is asked about a release, and the
		// default branch is the only one looked at.
		if u.FirstSeen.Known() || u.FirstSeen.Unavailable || u.FirstSeen.Source != "" || !strings.Contains(u.FirstSeen.Value, "no age is asked of an own workflow") {
			t.Errorf("FirstSeen = %+v", u.FirstSeen)
		}
		if net.requested("/releases/") || net.requested("compare/releases/") {
			t.Errorf("a release or a release branch was asked for: %v", net.seen)
		}
		if len(net.seen) != 4 {
			t.Errorf("%d requests, want the four of ownGitHub: %v", len(net.seen), net.seen)
		}
		// The pair carries the commit; nothing of it is read.
		if len(res.Artifacts) != 1 || res.Artifacts[0].Name != ownRepo || res.Artifacts[0].New.Hash != ownV130 || res.Artifacts[0].Old.Hash != ownV123 {
			t.Errorf("artifacts %+v", res.Artifacts)
		}

		d := decideOwn(t, res, ownPolicy(), now)
		if d.Outcome != allow.Merge || d.PerUpdate[0].RequiredAge != 0 {
			t.Errorf("decided %s %v, required age %v; want a merge with no age", d.Outcome, d.Reasons, d.PerUpdate[0].RequiredAge)
		}
		// The policy the facts were gathered under is not the one that
		// decides: under one that does not name the repository it is a
		// person's.
		if d := decideOwn(t, res, testPolicy(), now); d.Outcome != allow.Person || !slices.Equal(d.Reasons, []allow.Reason{allow.ReasonListMismatch}) {
			t.Errorf("decided under a policy without the list: %s %v", d.Outcome, d.Reasons)
		}
	})

	type check func(t *testing.T, u allow.UpdateFacts)
	boundNo := func(want string) check {
		return func(t *testing.T, u allow.UpdateFacts) { mustBeNo(t, "Bound", u.Bound, want) }
	}
	regress := func(want string) check {
		return func(t *testing.T, u allow.UpdateFacts) { mustBeNo(t, "NoRegress", u.NoRegress, want) }
	}
	holds := func(names ...string) check {
		return func(t *testing.T, u allow.UpdateFacts) {
			for _, n := range names {
				mustHold(t, n, map[string]allow.Fact{"Bound": u.Bound, "NoRegress": u.NoRegress, "Clean": u.Clean, "Own": u.Own}[n])
			}
		}
	}
	malware := noAdvisories()
	malware.result.NoMalware = allow.No("GHSA-zzzz-zzzz-zzzz is a malware advisory", "advisories")

	for _, tc := range []struct {
		name    string
		github  map[string]canned
		adv     *advisories
		checks  []check
		outcome allow.Outcome
		reasons []allow.Reason
	}{
		// The right name with a wrong ID: the name was registered again,
		// or the repository was moved and another took its place.
		{"another repository under the name", with(map[string]canned{repo: repoJSON(9999, ownOwnerID, ownRepo)}), nil,
			[]check{boundNo("the policy list own_workflows records repository 4242 of owner 77, GitHub reports repository 9999 of owner 77"), holds("Own", "NoRegress", "Clean")},
			allow.Person, []allow.Reason{allow.ReasonNotBound}},
		{"another owner under the name", with(map[string]canned{repo: repoJSON(ownRepoID, 78, ownRepo)}), nil,
			[]check{boundNo("GitHub reports repository 4242 of owner 78")}, allow.Person, []allow.Reason{allow.ReasonNotBound}},
		{"the other own repository's IDs", with(map[string]canned{repo: repoJSON(ownGateID, ownOwnerID, ownRepo)}), nil,
			[]check{boundNo("GitHub reports repository 4343 of owner 77")}, allow.Person, []allow.Reason{allow.ReasonNotBound}},
		{"the name redirects to a renamed repository", with(map[string]canned{repo: repoJSON(ownRepoID, ownOwnerID, "acme-infra/ci-archive")}), nil,
			[]check{boundNo("renamed or transferred")}, allow.Person, []allow.Reason{allow.ReasonNotBound}},
		{"the repository is gone", with(map[string]canned{repo: {404, notFound}}), nil,
			[]check{boundNo("the repository was not found"), regress("the repository was not found")}, allow.Person, []allow.Reason{allow.ReasonNotBound, allow.ReasonRegress}},

		// The tag resolves elsewhere.
		{"the tag is another commit", with(map[string]canned{refPath: {200, `{"ref":"refs/tags/v1.3.0","object":{"type":"commit","sha":"` + ownOther + `"}}`}}), nil,
			[]check{boundNo("tag v1.3.0 is commit " + ownOther + ", the pin is " + ownV130), regress("tag v1.3.0 is commit")},
			allow.Person, []allow.Reason{allow.ReasonNotBound, allow.ReasonRegress}},
		{"there is no such tag", with(map[string]canned{refPath: {404, notFound}}), nil,
			[]check{boundNo("tag v1.3.0 does not exist")}, allow.Person, []allow.Reason{allow.ReasonNotBound, allow.ReasonRegress}},

		// The new commit does not descend from the old pin.
		{"the new commit is on another line of history", with(map[string]canned{aheadPath: compareJSON("diverged", 3, 2)}), nil,
			[]check{regress("the new commit does not descend from the old one (diverged: 3 ahead, 2 behind)"), holds("Bound")},
			allow.Person, []allow.Reason{allow.ReasonRegress}},
		{"the new commit is behind the old pin", with(map[string]canned{aheadPath: compareJSON("behind", 0, 5)}), nil,
			[]check{regress("the new commit does not descend from the old one (behind: 0 ahead, 5 behind)")}, allow.Person, []allow.Reason{allow.ReasonRegress}},
		{"the old pin is not in the repository", with(map[string]canned{aheadPath: {404, notFound}}), nil,
			[]check{regress("one of them is not in the repository")}, allow.Person, []allow.Reason{allow.ReasonRegress}},

		// The new commit is not on the default branch. It is on
		// releases/v1, which is enough for an action and is not looked at
		// here: the default branch's rules are what the trust rests on.
		{"the new commit is on a release branch only", with(map[string]canned{mainPath: compareJSON("diverged", 1, 6), relBranch: compareJSON("identical", 0, 0)}), nil,
			[]check{regress("the commit is not reachable from main, the default branch"), holds("Bound")}, allow.Person, []allow.Reason{allow.ReasonRegress}},
		// A commit only a fork has descends from the old pin for GitHub's
		// comparison and is ahead of every branch.
		{"the new commit is in a fork only", with(map[string]canned{mainPath: compareJSON("ahead", 1, 0), relBranch: compareJSON("behind", 0, 1)}), nil,
			[]check{regress("the commit is not reachable from main, the default branch")}, allow.Person, []allow.Reason{allow.ReasonRegress}},

		// An advisory names it.
		{"a malware advisory", with(nil), malware,
			[]check{func(t *testing.T, u allow.UpdateFacts) { mustBeNo(t, "Clean", u.Clean, "malware advisory") }, holds("Bound", "NoRegress")},
			allow.Person, []allow.Reason{allow.ReasonNotClean}},
		{"the advisory database was not asked", with(nil), &advisories{},
			[]check{func(t *testing.T, u allow.UpdateFacts) { mustBeUnknown(t, "Clean", u.Clean, "were not checked") }},
			allow.Person, []allow.Reason{allow.ReasonFactMissing}},

		// GitHub did not answer: a wait, like every fact but an action's
		// Bound, which has no read to wait with (amendment 41).
		{"the tag lookup fails", with(map[string]canned{refPath: {500, `{"message":"boom"}`}}), nil,
			[]check{func(t *testing.T, u allow.UpdateFacts) {
				mustBeUnavailable(t, "Bound", u.Bound, "tag v1.3.0 could not be read: GitHub answered HTTP 500")
			}}, allow.Wait, []allow.Reason{allow.ReasonSourceUnavailable}},
		{"the comparison with the default branch fails", with(map[string]canned{mainPath: {502, `{}`}, relBranch: compareJSON("identical", 0, 0)}), nil,
			[]check{func(t *testing.T, u allow.UpdateFacts) {
				mustBeUnavailable(t, "NoRegress", u.NoRegress, "the comparison with main failed: GitHub answered HTTP 502")
			}}, allow.Wait, []allow.Reason{allow.ReasonSourceUnavailable}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adv := tc.adv
			if adv == nil {
				adv = noAdvisories()
			}
			res, net := gatherOwn(t, lintBumpOwn(), ownPolicy(), tc.github, adv)
			u := one(t, res)
			for _, c := range tc.checks {
				c(t, u)
			}
			if net.requested("/releases/") || net.requested("compare/releases/") {
				t.Errorf("a release or a release branch was asked for: %v", net.seen)
			}
			d := decideOwn(t, res, ownPolicy(), now)
			if d.Outcome != tc.outcome || !slices.Equal(d.Reasons, tc.reasons) {
				t.Errorf("decided %s %v, want %s %v", d.Outcome, d.Reasons, tc.outcome, tc.reasons)
			}
		})
	}

	// A major, with every fact about where it comes from holding, is a
	// person's: also for a repository that is on the owner-kept list.
	t.Run("a major", func(t *testing.T) {
		files := ownBump(ownLint, ownV130, "v1.3.0", ownV200, "v2.0.0")
		for name, policy := range map[string]allow.Policy{
			"own": ownPolicy(),
			"own and listed": func() allow.Policy {
				p := ownPolicy()
				p.Listed[allow.GitHubActions] = append(p.Listed[allow.GitHubActions], "acme-infra/")
				return p
			}(),
		} {
			res, _ := gatherOwn(t, files, policy, ownGitHub(ownV130, ownV200, "v2.0.0"), noAdvisories())
			u := one(t, res)
			holds("Own", "Bound", "NoRegress", "Clean")(t, u)
			mustHold(t, "Major", u.Major)
			if d := decideOwn(t, res, policy, now); d.Outcome != allow.Person || !slices.Equal(d.Reasons, []allow.Reason{allow.ReasonMajorOwn}) {
				t.Errorf("%s: decided %s %v, want person for major_own", name, d.Outcome, d.Reasons)
			}
		}
	})

	// The commit moved and the version in the comment did not: nothing
	// says the new commit is a release.
	t.Run("no version moves", func(t *testing.T) {
		github := ownGitHub(ownOther, ownV130, "v1.2.3")
		res, _ := gatherOwn(t, ownBump(ownLint, ownOther, "v1.2.3", ownV130, "v1.2.3"), ownPolicy(), github, noAdvisories())
		u := one(t, res)
		mustBeNo(t, "Increase", u.Increase, "is not an increase")
		if d := decideOwn(t, res, ownPolicy(), now); d.Outcome != allow.Person || !slices.Equal(d.Reasons, []allow.Reason{allow.ReasonNotIncrease}) {
			t.Errorf("decided %s %v, want person for not_increase", d.Outcome, d.Reasons)
		}
	})

	// A shape that does not hold asks GitHub nothing and decides person.
	t.Run("a look-alike name asks nothing", func(t *testing.T) {
		files := ownBump("acme-1nfra/ci/.github/workflows/lint.yml", ownV123, "v1.2.3", ownV130, "v1.3.0")
		res, net := gatherOwn(t, files, ownPolicy(), nil, noAdvisories())
		mustBeNo(t, "Shape", res.Shape, "not a workflow file of a repository on the policy's own list")
		if len(res.Updates) != 0 || len(res.Artifacts) != 0 || len(net.seen) != 0 {
			t.Errorf("updates %+v, artifacts %+v, requests %v", res.Updates, res.Artifacts, net.seen)
		}
		if d := decideOwn(t, res, ownPolicy(), now); d.Outcome != allow.Person || !slices.Contains(d.Reasons, allow.ReasonShape) {
			t.Errorf("decided %s %v, want person for shape", d.Outcome, d.Reasons)
		}
	})

	// In a grouped pull request each update is held to its own rule: the
	// action beside the own workflow is asked about its release and its
	// release branch, is not own, and is unread until a model answers.
	t.Run("grouped with an action", func(t *testing.T) {
		res, net := gatherOwn(t, append(setupGoLockedBump(), lintBumpOwn()...), ownPolicy(), with(nil), noAdvisories())
		if !res.Shape.Holds() || len(res.Updates) != 2 {
			t.Fatalf("result %+v", res)
		}
		own, action := res.Updates[0], res.Updates[1]
		if own.Name != ownRepo || !own.Own.Holds() || action.Name != "actions/setup-go" || action.Own != (allow.Fact{}) {
			t.Fatalf("updates %+v", res.Updates)
		}
		holds("Bound", "NoRegress", "Clean")(t, action)
		if !action.FirstSeen.Known() || !net.requested("repos/actions/setup-go/releases/tags/v7.1.0") {
			t.Errorf("the action's release was not asked for: FirstSeen %+v", action.FirstSeen)
		}
		// Nothing was prepared for the action here, so it is unread: the
		// own workflow beside it does not carry it.
		d := decideOwn(t, res, ownPolicy(), now)
		if d.Outcome != allow.Person || !slices.Equal(d.Reasons, []allow.Reason{allow.ReasonReadUnknown}) ||
			d.PerUpdate[0].Outcome != allow.Merge || d.PerUpdate[1].Outcome != allow.Person {
			t.Errorf("decided %s %v, per update %+v", d.Outcome, d.Reasons, d.PerUpdate)
		}
	})
}

// The example a caller copies pins the gate in the one form the gate
// reads when Dependabot moves that pin, and this repository's own CI
// calls the shared workflows in it too. A pin in any other form would go
// to a person at every release.
func TestOwnWorkflowPinIsTheExamples(t *testing.T) {
	policy := testPolicy()
	policy.Own = []allow.OwnRepo{
		{Repository: "sadbox/ci", RepositoryID: 1, OwnerID: 2},
		{Repository: "sadbox/dep-review", RepositoryID: 3, OwnerID: 2},
	}
	pinRe := regexp.MustCompile(`@[0-9a-f]{40} # v[0-9A-Z.]+\n`)
	for path, name := range map[string]string{
		"../../../examples/dep-review.yaml": "sadbox/dep-review",
		"../../../.github/workflows/ci.yml": "sadbox/ci",
	} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("%s is not in this checkout: %v", path, err)
		}
		text := string(b)
		var lines []string
		for _, line := range strings.SplitAfter(text, "\n") {
			if strings.Contains(line, "uses: "+name+"/.github/workflows/") {
				lines = append(lines, line)
			}
		}
		if len(lines) == 0 {
			t.Fatalf("%s: no line calls a workflow of %s", path, name)
		}
		base, head := text, text
		for _, line := range lines {
			if len(pinRe.FindAllString(line, -1)) != 1 {
				t.Fatalf("%s: %q does not pin the workflow by commit with its version", path, line)
			}
			base = strings.Replace(base, line, pinRe.ReplaceAllString(line, "@"+ownV123+" # v1.2.3\n"), 1)
			head = strings.Replace(head, line, pinRe.ReplaceAllString(line, "@"+ownV130+" # v1.3.0\n"), 1)
		}
		pins, problem := readChangeSet([]facts.File{file(".github/workflows/"+filepath.Base(path), base, head)}, policy)
		if problem != "" || len(pins) != 1 || !pins[0].own || pins[0].name != name || pins[0].oldCommit != ownV123 || pins[0].newCommit != ownV130 {
			t.Errorf("%s: pins %+v, problem %q", path, pins, problem)
		}
	}
}

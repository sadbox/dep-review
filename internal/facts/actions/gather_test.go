package actions

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/advisory"
	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/facts"
)

// lockedBump is a pull request that moves one action in a repository
// that uses actions.lock: the tag on the workflow line, and the list
// line, key, ref and commit in the lockfile.
func lockedBump(name, from, to, oldCommit, newCommit string, ownerID, repoID int64) []facts.File {
	lock := func(tag, commit string) string {
		return fmt.Sprintf(`version: 'v0.0.3'
workflows:
    '.github/workflows/ci.yml':
        - '%[1]s@%[2]s'
dependencies:
    '%[1]s@%[2]s':
        ref: '%[2]s'
        commit: 'sha1-%[3]s'
        owner_id: %[4]d
        repo_id: %[5]d
`, strings.ToLower(name), tag, commit, ownerID, repoID)
	}
	workflow := func(tag string) string {
		return "jobs:\n  build:\n    steps:\n      - uses: " + name + "@" + tag + "\n"
	}
	return []facts.File{
		file(lockPath, lock(from, oldCommit), lock(to, newCommit)),
		file(ciPath, workflow(from), workflow(to)),
	}
}

// commitBump is a pull request that moves one commit-pinned line and has
// no lockfile: the form the gate does not read.
func commitBump(name, from, to, oldCommit, newCommit string) []facts.File {
	workflow := func(tag, commit string) string {
		return "jobs:\n  build:\n    steps:\n      - uses: " + name + "@" + commit + " # " + tag + "\n"
	}
	return []facts.File{file(ciPath, workflow(from, oldCommit), workflow(to, newCommit))}
}

func setupGoLockedBump() []facts.File {
	return lockedBump("actions/setup-go", "v7.0.0", "v7.1.0", setupGoV700, setupGoV710, actionsOwnerID, setupGoRepoID)
}

// run gathers for files against the recordings, with the given overrides.
func run(t *testing.T, files []facts.File, override map[string]canned, adv *advisories) (facts.Result, *replay) {
	t.Helper()
	net := &replay{t: t, override: override}
	in := facts.Input{
		Repo:       "example/caller",
		Base:       strings.Repeat("a", 40),
		Head:       strings.Repeat("b", 40),
		Files:      files,
		Policy:     testPolicy(),
		GitHub:     net.client(),
		Advisories: adv,
	}
	res, err := New().Gather(context.Background(), in)
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	return res, net
}

// one returns the single update of a result whose Shape holds.
func one(t *testing.T, res facts.Result) allow.UpdateFacts {
	t.Helper()
	if !res.Shape.Holds() {
		t.Fatalf("Shape does not hold: %+v", res.Shape)
	}
	if len(res.Updates) != 1 {
		t.Fatalf("%d updates, want 1: %+v", len(res.Updates), res.Updates)
	}
	return res.Updates[0]
}

func mustHold(t *testing.T, name string, f allow.Fact) {
	t.Helper()
	if !f.Holds() {
		t.Errorf("%s does not hold: %+v", name, f)
	}
}

// mustBeNo checks a gathered "no" whose Value contains want.
func mustBeNo(t *testing.T, name string, f allow.Fact, want string) {
	t.Helper()
	if f.OK || !f.Gathered() {
		t.Errorf("%s = %+v, want a gathered no", name, f)
	}
	if !strings.Contains(f.Value, want) {
		t.Errorf("%s value %q, want it to contain %q", name, f.Value, want)
	}
}

// mustBeUnknown checks a fact nothing established (no Source) whose Value
// says why: an answer arrived and could not be read. That is person.
func mustBeUnknown(t *testing.T, name string, f allow.Fact, want string) {
	t.Helper()
	if f.OK || f.Unavailable || f.Source != "" {
		t.Errorf("%s = %+v, want it never gathered", name, f)
	}
	if !strings.Contains(f.Value, want) {
		t.Errorf("%s value %q, want it to contain %q", name, f.Value, want)
	}
}

// mustBeUnavailable checks a fact whose source was asked and did not
// answer, with the request as its Source and why in its Value. That is a
// wait.
func mustBeUnavailable(t *testing.T, name string, f allow.Fact, want string) {
	t.Helper()
	if f.OK || !f.Unavailable || f.Source == "" || f.Gathered() {
		t.Errorf("%s = %+v, want it unavailable", name, f)
	}
	if !strings.Contains(f.Value, want) {
		t.Errorf("%s value %q, want it to contain %q", name, f.Value, want)
	}
}

// The recorded answers for a real, clean update: every fact holds.
func TestGatherSetupGo(t *testing.T) {
	adv := noAdvisories()
	res, _ := run(t, setupGoLockedBump(), nil, adv)
	u := one(t, res)

	if u.Name != "actions/setup-go" || u.From != "v7.0.0" || u.To != "v7.1.0" {
		t.Errorf("update is %s %s -> %s", u.Name, u.From, u.To)
	}
	mustHold(t, "Known", u.Known)
	mustHold(t, "Listed", u.Listed)
	mustHold(t, "Increase", u.Increase)
	mustHold(t, "Bound", u.Bound)
	mustHold(t, "NoRegress", u.NoRegress)
	mustHold(t, "Clean", u.Clean)
	mustBeNo(t, "NewName", u.NewName, "not a new name")
	mustBeNo(t, "Major", u.Major, "both v7")
	mustBeNo(t, "SecurityFix", u.SecurityFix, "")
	if !strings.Contains(u.NoRegress.Value, "20 commit(s) ahead") || !strings.Contains(u.NoRegress.Value, "on branch main") {
		t.Errorf("NoRegress value %q", u.NoRegress.Value)
	}
	if !strings.Contains(u.Bound.Value, "repository 192624594 of owner 44036562") {
		t.Errorf("Bound value %q", u.Bound.Value)
	}

	// The release is immutable, so published_at is the clock.
	want := time.Date(2026, 11, 17, 3, 1, 17, 0, time.UTC)
	if !u.FirstSeen.Known() || !u.FirstSeen.Time.Equal(want) {
		t.Errorf("FirstSeen = %+v, want %s", u.FirstSeen, want)
	}
	if u.NameCreated.Known() || u.Read != "" || u.Veto != nil {
		t.Errorf("NameCreated, Read and Veto are not this gatherer's: %+v %q %v", u.NameCreated, u.Read, u.Veto)
	}

	wantPair := artifact.Pair{
		Ecosystem: allow.GitHubActions, Name: "actions/setup-go", From: "v7.0.0", To: "v7.1.0",
		Old: artifact.Ref{Kind: artifact.ActionTarball, Name: "actions/setup-go", Version: "v7.0.0", Hash: setupGoV700},
		New: artifact.Ref{Kind: artifact.ActionTarball, Name: "actions/setup-go", Version: "v7.1.0", Hash: setupGoV710},
		// The workflow line names the repository: the reader looks at the
		// action in its root.
		Dirs: []string{"."},
	}
	if len(res.Artifacts) != 1 || !reflect.DeepEqual(res.Artifacts[0], wantPair) {
		t.Errorf("Artifacts = %+v, want %+v", res.Artifacts, wantPair)
	}
	wantQuery := advisory.Query{Ecosystem: allow.GitHubActions, Name: "actions/setup-go", From: "v7.0.0", To: "v7.1.0"}
	if len(adv.asked) != 1 || adv.asked[0] != wantQuery {
		t.Errorf("advisory queries %+v, want %+v", adv.asked, wantQuery)
	}
}

// What allow.Decide makes of the gathered facts, once the caller has
// added the pull request's own facts and the model's read.
func TestGatherThenDecide(t *testing.T) {
	policy := testPolicy()
	decide := func(u allow.UpdateFacts, now time.Time) allow.Decision {
		u.Read = allow.ReadFull
		return allow.Decide(allow.PRFacts{
			Ecosystem:        allow.GitHubActions,
			Identity:         allow.Yes("dependabot", "test"),
			Shape:            allow.Yes("in place", "test"),
			ChecksConfigured: allow.Yes("ruleset", "test"),
			Updates:          []allow.UpdateFacts{u},
		}, policy, now)
	}
	published := time.Date(2026, 11, 17, 3, 1, 17, 0, time.UTC)

	t.Run("immutable release: waits out min_age, then merges", func(t *testing.T) {
		res, _ := run(t, setupGoLockedBump(), nil, noAdvisories())
		u := one(t, res)
		if d := decide(u, published.Add(71*time.Hour)); d.Outcome != allow.Wait || len(d.Reasons) != 1 || d.Reasons[0] != allow.ReasonAge {
			t.Errorf("at 71 h: %s %v, want wait for age", d.Outcome, d.Reasons)
		}
		if d := decide(u, published.Add(73*time.Hour)); d.Outcome != allow.Merge {
			t.Errorf("at 73 h: %s %v, want merge", d.Outcome, d.Reasons)
		}
	})

	t.Run("release that is not immutable: person until the caller supplies its own first observation", func(t *testing.T) {
		res, _ := run(t, lockedBump("actions/checkout", "v7.0.0", "v7.0.1", checkoutV700, checkoutV701, actionsOwnerID, checkoutRepoID), nil, noAdvisories())
		u := one(t, res)
		now := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
		if d := decide(u, now); d.Outcome != allow.Person || len(d.Reasons) != 1 || d.Reasons[0] != allow.ReasonFirstSeenUnknown {
			t.Errorf("as gathered: %s %v, want person for first_seen_unknown alone", d.Outcome, d.Reasons)
		}
		u.FirstSeen = allow.At(now.Add(-80*time.Hour), "the gate's own first observation")
		if d := decide(u, now); d.Outcome != allow.Merge {
			t.Errorf("with an observation 80 h old: %s %v, want merge", d.Outcome, d.Reasons)
		}
	})
}

// An action takes no fast path (spec section 11, amendment 48). The
// advisory database vouches for a version, and a tag can be moved after
// the advisory was reviewed: with the checker's yes passed on, a pin the
// gate first saw a moment ago merged at once. The update waits its age
// like one that fixes nothing, a partial read gets the unread age, and
// no other update in the pull request rides along.
func TestGatherSecurityFixWaitsItsAge(t *testing.T) {
	now := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
	fix := noAdvisories()
	fix.result.SecurityFix = allow.Yes("GHSA-zzzz-zzzz-zzzz: affects v7.0.0, not v7.0.1, first patched version 7.0.1", "advisories")

	// The release is not immutable, so the publish job dates the pin from
	// its own first evaluation of it: now.
	gather := func(adv *advisories) allow.UpdateFacts {
		res, _ := run(t, lockedBump("actions/checkout", "v7.0.0", "v7.0.1", checkoutV700, checkoutV701, actionsOwnerID, checkoutRepoID), nil, adv)
		u := one(t, res)
		mustHold(t, "Bound", u.Bound)
		mustHold(t, "NoRegress", u.NoRegress)
		mustHold(t, "Clean", u.Clean)
		if u.FirstSeen.Known() {
			t.Fatalf("FirstSeen = %+v, want a release no registry dates", u.FirstSeen)
		}
		u.FirstSeen = allow.At(now, "the gate's own clock")
		return u
	}
	decide := func(at time.Time, updates ...allow.UpdateFacts) allow.Decision {
		return allow.Decide(allow.PRFacts{
			Ecosystem:        allow.GitHubActions,
			Identity:         allow.Yes("dependabot", "test"),
			Shape:            allow.Yes("in place", "test"),
			ChecksConfigured: allow.Yes("ruleset", "test"),
			Updates:          updates,
		}, testPolicy(), at)
	}
	read := func(u allow.UpdateFacts, r allow.ReadState) allow.UpdateFacts {
		u.Read = r
		return u
	}
	waitsFor := func(t *testing.T, d allow.Decision, age time.Duration) {
		t.Helper()
		if d.Outcome != allow.Wait || !slices.Equal(d.Reasons, []allow.Reason{allow.ReasonAge}) {
			t.Fatalf("%s %v, want a wait for age", d.Outcome, d.Reasons)
		}
		for _, u := range d.PerUpdate {
			if u.RequiredAge != age {
				t.Errorf("%s needs %s, want %s", u.Name, u.RequiredAge, age)
			}
		}
	}

	t.Run("read in full: min_age, as without the advisory", func(t *testing.T) {
		waitsFor(t, decide(now, read(gather(fix), allow.ReadFull)), 72*time.Hour)
		waitsFor(t, decide(now, read(gather(noAdvisories()), allow.ReadFull)), 72*time.Hour)
		if d := decide(now.Add(73*time.Hour), read(gather(fix), allow.ReadFull)); d.Outcome != allow.Merge {
			t.Errorf("at 73 h: %s %v, want merge", d.Outcome, d.Reasons)
		}
	})
	t.Run("read in part: unread_age", func(t *testing.T) {
		waitsFor(t, decide(now, read(gather(fix), allow.ReadPartial)), 14*24*time.Hour)
	})
	t.Run("no companion rides along", func(t *testing.T) {
		other := read(gather(noAdvisories()), allow.ReadFull)
		other.Name = "actions/setup-go"
		waitsFor(t, decide(now, read(gather(fix), allow.ReadFull), other), 72*time.Hour)
	})
}

// More recorded updates, each for the one thing it shows.
func TestGatherRecorded(t *testing.T) {
	t.Run("release that is not immutable has no first-seen time, and says where it looked", func(t *testing.T) {
		res, _ := run(t, lockedBump("actions/checkout", "v7.0.0", "v7.0.1", checkoutV700, checkoutV701, actionsOwnerID, checkoutRepoID), nil, noAdvisories())
		u := one(t, res)
		mustHold(t, "Bound", u.Bound)
		mustHold(t, "NoRegress", u.NoRegress)
		mustHold(t, "Clean", u.Clean)
		fs := u.FirstSeen
		if fs.Known() || fs.OK || !fs.Time.IsZero() {
			t.Errorf("FirstSeen = %+v, want unknown with no time", fs)
		}
		if fs.Source != "GitHub: repos/actions/checkout/releases/tags/v7.0.1" || !strings.Contains(fs.Value, "not immutable") || !strings.Contains(fs.Value, "2026-07-20T15:10:05Z") {
			t.Errorf("FirstSeen = %+v, want the release as its source and the reason as its value", fs)
		}
	})

	t.Run("commit on releases/v6 and not on main", func(t *testing.T) {
		res, net := run(t, lockedBump("actions/checkout", "v6.0.2", "v6.1.0", checkoutV602, checkoutV610, actionsOwnerID, checkoutRepoID), nil, noAdvisories())
		u := one(t, res)
		mustHold(t, "NoRegress", u.NoRegress)
		if !strings.Contains(u.NoRegress.Value, "on branch releases/v6") {
			t.Errorf("NoRegress value %q, want the release branch", u.NoRegress.Value)
		}
		if !net.requested("compare/main..."+checkoutV610) || !net.requested("compare/releases/v6..."+checkoutV610) {
			t.Errorf("requests %v: want the default branch asked first, then releases/v6", net.seen)
		}
	})

	t.Run("annotated tag is followed to its commit", func(t *testing.T) {
		res, net := run(t, lockedBump("actions/checkout", "v6.0.2", "v6.0.3", checkoutV602, checkoutV603, actionsOwnerID, checkoutRepoID), nil, noAdvisories())
		u := one(t, res)
		mustHold(t, "Bound", u.Bound)
		mustHold(t, "NoRegress", u.NoRegress)
		if !net.requested("git/tags/9f698171ed81b15d1823a05fc7211befd50c8ae0") {
			t.Errorf("requests %v: the tag object was not read", net.seen)
		}
	})

	t.Run("default branch called master", func(t *testing.T) {
		res, _ := run(t, lockedBump("docker/login-action", "v4.7.0", "v4.8.0", loginV470, loginV480, dockerOwnerID, loginRepoID), nil, noAdvisories())
		u := one(t, res)
		mustHold(t, "Bound", u.Bound)
		mustHold(t, "NoRegress", u.NoRegress)
		mustHold(t, "Clean", u.Clean)
		if !strings.Contains(u.NoRegress.Value, "on branch master") {
			t.Errorf("NoRegress value %q", u.NoRegress.Value)
		}
		if !u.FirstSeen.Known() {
			t.Errorf("FirstSeen = %+v, want the immutable release's time", u.FirstSeen)
		}
	})

	// A workflow line records no repository IDs for Bound to compare, so
	// a commit pin is refused where the files are read (spec section 11,
	// amendment 7): nothing is asked and nothing is given to the model.
	t.Run("commit pin with no lockfile does not have the shape", func(t *testing.T) {
		res, net := run(t, commitBump("docker/login-action", "v4.7.0", "v4.8.0", loginV470, loginV480), nil, noAdvisories())
		mustBeNo(t, "Shape", res.Shape, "the line pins a commit; only a tag pin that actions.lock records is read")
		if len(res.Updates) != 0 || len(res.Artifacts) != 0 || len(net.seen) != 0 {
			t.Errorf("updates %+v, artifacts %+v, requests %v; want none", res.Updates, res.Artifacts, net.seen)
		}
	})

	// The tj-actions pattern. 16a9d454 exists only in a fork of
	// actions/setup-go; GitHub serves it through the parent repository and
	// its recorded comparison with the commit the fork branched from says
	// "ahead". Suppose the tag had been moved onto it. The tag check and
	// the ancestry check both pass; only the branch check refuses.
	t.Run("commit that only a fork has", func(t *testing.T) {
		files := lockedBump("actions/setup-go", "v7.0.0", "v7.1.0", setupGoForkBase, setupGoForkOnly, actionsOwnerID, setupGoRepoID)
		res, net := run(t, files, map[string]canned{
			"repos/actions/setup-go/git/ref/tags/v7.1.0": {200, `{"ref":"refs/tags/v7.1.0","object":{"type":"commit","sha":"` + setupGoForkOnly + `"}}`},
		}, noAdvisories())
		u := one(t, res)
		mustHold(t, "Bound", u.Bound)
		mustBeNo(t, "NoRegress", u.NoRegress, "the commit is not reachable from main or releases/v7")
		if strings.Contains(u.NoRegress.Value, "does not descend") {
			t.Errorf("NoRegress value %q: the recording says ahead, so the ancestry part should have passed", u.NoRegress.Value)
		}
		if !net.requested("compare/releases/v7..." + setupGoForkOnly) {
			t.Errorf("requests %v: the release branch was not tried", net.seen)
		}
	})
}

// What GitHub could answer for the setup-go update that must not pass.
// Each case overrides the recorded answers it names; the rest are real.
func TestGatherRefuses(t *testing.T) {
	const (
		repoPath    = "repos/actions/setup-go"
		refPath     = repoPath + "/git/ref/tags/v7.1.0"
		aheadPath   = repoPath + "/compare/" + setupGoV700 + "..." + setupGoV710
		mainPath    = repoPath + "/compare/main..." + setupGoV710
		relBranch   = repoPath + "/compare/releases/v7..." + setupGoV710
		releasePath = repoPath + "/releases/tags/v7.1.0"
		notFound    = `{"message":"Not Found","status":"404"}`
		tagObject   = "1111111111111111111111111111111111111111"
	)
	repoJSON := func(id, ownerID int64, fullName, branch string) canned {
		return canned{200, fmt.Sprintf(`{"id":%d,"full_name":%q,"default_branch":%q,"owner":{"id":%d}}`, id, fullName, branch, ownerID)}
	}
	refJSON := func(typ, sha string) canned {
		return canned{200, fmt.Sprintf(`{"ref":"refs/tags/v7.1.0","object":{"type":%q,"sha":%q}}`, typ, sha)}
	}
	compareJSON := func(status string, ahead, behind int) canned {
		return canned{200, fmt.Sprintf(`{"status":%q,"ahead_by":%d,"behind_by":%d}`, status, ahead, behind)}
	}
	releaseJSON := func(tag string, draft, prerelease, immutable bool, published string) canned {
		return canned{200, fmt.Sprintf(`{"tag_name":%q,"draft":%t,"prerelease":%t,"immutable":%t,"published_at":%s}`, tag, draft, prerelease, immutable, published)}
	}

	type check func(t *testing.T, u allow.UpdateFacts)
	bound := func(want string) check {
		return func(t *testing.T, u allow.UpdateFacts) { mustBeNo(t, "Bound", u.Bound, want) }
	}
	regress := func(want string) check {
		return func(t *testing.T, u allow.UpdateFacts) { mustBeNo(t, "NoRegress", u.NoRegress, want) }
	}
	notClean := func(want string) check {
		return func(t *testing.T, u allow.UpdateFacts) { mustBeNo(t, "Clean", u.Clean, want) }
	}
	noFirstSeen := func(wantSource bool) check {
		return func(t *testing.T, u allow.UpdateFacts) {
			if u.FirstSeen.Known() || !u.FirstSeen.Time.IsZero() || (u.FirstSeen.Source != "") != wantSource {
				t.Errorf("FirstSeen = %+v, want unknown, source set: %t", u.FirstSeen, wantSource)
			}
		}
	}
	holds := func(names ...string) check {
		return func(t *testing.T, u allow.UpdateFacts) {
			for _, n := range names {
				mustHold(t, n, map[string]allow.Fact{"Bound": u.Bound, "NoRegress": u.NoRegress, "Clean": u.Clean}[n])
			}
		}
	}

	tests := []struct {
		name     string
		override map[string]canned
		adv      *advisories
		checks   []check
	}{
		// The tag.
		{"tag moved to another commit", map[string]canned{refPath: refJSON("commit", checkoutV701)}, nil,
			[]check{bound("tag v7.1.0 is commit " + checkoutV701 + ", the pin is " + setupGoV710), regress("tag v7.1.0 is commit"), holds("Clean")}},
		{"tag deleted", map[string]canned{refPath: {404, notFound}}, nil,
			[]check{bound("tag v7.1.0 does not exist"), regress("tag v7.1.0 does not exist")}},
		{"GitHub answers with another ref", map[string]canned{refPath: {200, `{"ref":"refs/tags/v7.1.0-evil","object":{"type":"commit","sha":"` + setupGoV710 + `"}}`}}, nil,
			[]check{bound("another ref than refs/tags/v7.1.0")}},
		{"tag points at a tree", map[string]canned{refPath: refJSON("tree", setupGoV710)}, nil,
			[]check{bound("does not point at a commit")}},
		{"annotated tag of another commit", map[string]canned{
			refPath:                             refJSON("tag", tagObject),
			repoPath + "/git/tags/" + tagObject: {200, `{"object":{"type":"commit","sha":"` + checkoutV701 + `"}}`},
		}, nil, []check{bound("tag v7.1.0 is commit " + checkoutV701)}},
		{"annotated tags without end", map[string]canned{
			refPath:                             refJSON("tag", tagObject),
			repoPath + "/git/tags/" + tagObject: {200, `{"object":{"type":"tag","sha":"` + tagObject + `"}}`},
		}, nil, []check{bound("more than 3 annotated tags deep")}},
		{"tag object with an ID that is not one", map[string]canned{refPath: refJSON("tag", "../../../user")}, nil,
			[]check{bound("unreadable ID")}},
		// GitHub did not answer (spec section 11, amendment 1): the facts
		// that needed the answer are unavailable, which waits. It is not a
		// "no" about the pin and not a person's yet.
		{"tag lookup fails", map[string]canned{refPath: {500, `{"message":"boom"}`}}, nil,
			[]check{func(t *testing.T, u allow.UpdateFacts) {
				mustBeUnavailable(t, "Bound", u.Bound, "tag v7.1.0 could not be read: GitHub answered HTTP 500")
				mustBeUnavailable(t, "NoRegress", u.NoRegress, "tag v7.1.0 could not be read")
			}, holds("Clean")}},
		{"tag lookup is rate limited", map[string]canned{refPath: {403, `{"message":"You have exceeded a secondary rate limit. boom"}`}}, nil,
			[]check{func(t *testing.T, u allow.UpdateFacts) {
				mustBeUnavailable(t, "Bound", u.Bound, "tag v7.1.0 could not be read: GitHub answered HTTP 403")
			}, holds("Clean")}},
		{"tag lookup gets no answer", map[string]canned{refPath: {}}, nil,
			[]check{func(t *testing.T, u allow.UpdateFacts) {
				mustBeUnavailable(t, "Bound", u.Bound, "tag v7.1.0 could not be read: GitHub did not answer")
			}}},
		{"annotated tag whose object cannot be read", map[string]canned{
			refPath:                             refJSON("tag", tagObject),
			repoPath + "/git/tags/" + tagObject: {500, ``},
		}, nil, []check{func(t *testing.T, u allow.UpdateFacts) {
			mustBeUnavailable(t, "Bound", u.Bound, "tag v7.1.0 could not be read: GitHub answered HTTP 500")
		}}},
		// GitHub answered, and not with what was asked for: asking again
		// gets the same, so nothing is established and that is person.
		{"tag lookup is forbidden", map[string]canned{refPath: {403, `{"message":"Repository access blocked. boom"}`}}, nil,
			[]check{func(t *testing.T, u allow.UpdateFacts) {
				mustBeUnknown(t, "Bound", u.Bound, "tag v7.1.0 could not be read: GitHub answered HTTP 403")
				mustBeUnknown(t, "NoRegress", u.NoRegress, "tag v7.1.0 could not be read")
			}, holds("Clean")}},
		{"tag lookup answers something that is not JSON", map[string]canned{refPath: {200, `<html>boom`}}, nil,
			[]check{func(t *testing.T, u allow.UpdateFacts) {
				mustBeUnknown(t, "Bound", u.Bound, "tag v7.1.0 could not be read: GitHub's answer could not be read")
			}}},
		// One fact, several conditions: a "no" is the answer whatever
		// went unanswered, and an unreadable answer is not waited out
		// because another question got none.
		{"tag deleted while the repository lookup fails", map[string]canned{refPath: {404, notFound}, repoPath: {502, ``}}, nil,
			[]check{bound("tag v7.1.0 does not exist"), regress("tag v7.1.0 does not exist")}},
		{"tag lookup forbidden while the repository lookup fails", map[string]canned{refPath: {403, `{"message":"blocked"}`}, repoPath: {502, ``}}, nil,
			[]check{func(t *testing.T, u allow.UpdateFacts) {
				mustBeUnknown(t, "Bound", u.Bound, "tag v7.1.0 could not be read: GitHub answered HTTP 403")
			}}},
		{"annotated tag whose object is missing", map[string]canned{
			refPath:                             refJSON("tag", tagObject),
			repoPath + "/git/tags/" + tagObject: {404, notFound},
		}, nil, []check{func(t *testing.T, u allow.UpdateFacts) {
			mustBeUnknown(t, "Bound", u.Bound, "tag v7.1.0 could not be read: GitHub answered HTTP 404")
		}}},

		// The repository's identity.
		{"repository ID is not the lockfile's", map[string]canned{repoPath: repoJSON(999, actionsOwnerID, "actions/setup-go", "main")}, nil,
			[]check{bound("actions.lock records repository 192624594 of owner 44036562, GitHub reports repository 999 of owner 44036562"), holds("NoRegress", "Clean")}},
		{"owner ID is not the lockfile's", map[string]canned{repoPath: repoJSON(setupGoRepoID, 999, "actions/setup-go", "main")}, nil,
			[]check{bound("GitHub reports repository 192624594 of owner 999")}},
		{"name redirects to a renamed repository", map[string]canned{repoPath: repoJSON(setupGoRepoID, actionsOwnerID, "octo/setup-go", "main")}, nil,
			[]check{bound("renamed or transferred")}},
		{"repository gone", map[string]canned{repoPath: {404, notFound}}, nil,
			[]check{bound("the repository was not found"), regress("the repository was not found")}},
		{"repository lookup fails", map[string]canned{repoPath: {502, ``}}, nil,
			[]check{func(t *testing.T, u allow.UpdateFacts) {
				mustBeUnavailable(t, "Bound", u.Bound, "the repository could not be read: GitHub answered HTTP 502")
				mustBeUnavailable(t, "NoRegress", u.NoRegress, "the default branch is unknown")
			}, holds("Clean")}},

		// Ancestry.
		{"new commit diverged from the old", map[string]canned{aheadPath: compareJSON("diverged", 3, 2)}, nil,
			[]check{regress("does not descend from the old one (diverged: 3 ahead, 2 behind)"), holds("Bound", "Clean")}},
		{"new commit is behind the old", map[string]canned{aheadPath: compareJSON("behind", 0, 4)}, nil,
			[]check{regress("behind: 0 ahead, 4 behind")}},
		{"old commit is not in the repository", map[string]canned{aheadPath: {404, notFound}}, nil,
			[]check{regress("one of them is not in the repository")}},
		{"comparison status GitHub does not document", map[string]canned{aheadPath: compareJSON("<b>ahead</b>", 1, 0)}, nil,
			[]check{regress("unrecognised status")}},
		{"new commit is the old one", map[string]canned{aheadPath: compareJSON("identical", 0, 0)}, nil,
			[]check{regress("does not descend from the old one (identical: 0 ahead, 0 behind)"), holds("Bound", "Clean")}},
		{"comparison fails", map[string]canned{aheadPath: {503, ``}}, nil,
			[]check{func(t *testing.T, u allow.UpdateFacts) {
				mustBeUnavailable(t, "NoRegress", u.NoRegress, "could not be compared: GitHub answered HTTP 503")
			}, holds("Bound", "Clean")}},
		{"on no branch", map[string]canned{mainPath: compareJSON("diverged", 1, 30), relBranch: {404, notFound}}, nil,
			[]check{regress("the commit is not reachable from main or releases/v7"), holds("Bound")}},
		{"on the release branch only", map[string]canned{mainPath: compareJSON("diverged", 1, 30), relBranch: compareJSON("behind", 0, 2)}, nil,
			[]check{holds("Bound", "NoRegress", "Clean")}},
		{"ahead of the release branch is not on it", map[string]canned{mainPath: compareJSON("diverged", 1, 30), relBranch: compareJSON("ahead", 1, 0)}, nil,
			[]check{regress("not reachable")}},
		{"branch comparison fails", map[string]canned{mainPath: {500, ``}, relBranch: {404, notFound}}, nil,
			[]check{func(t *testing.T, u allow.UpdateFacts) {
				mustBeUnavailable(t, "NoRegress", u.NoRegress, "the comparison with main failed")
			}}},
		{"release branch comparison fails", map[string]canned{mainPath: compareJSON("diverged", 1, 30), relBranch: {500, ``}}, nil,
			[]check{func(t *testing.T, u allow.UpdateFacts) {
				mustBeUnavailable(t, "NoRegress", u.NoRegress, "the comparison with releases/v7 failed")
			}}},
		{"one branch comparison unreadable, the other unanswered", map[string]canned{mainPath: {500, ``}, relBranch: {403, `{"message":"blocked"}`}}, nil,
			[]check{func(t *testing.T, u allow.UpdateFacts) {
				mustBeUnknown(t, "NoRegress", u.NoRegress, "the comparison with releases/v7 failed: GitHub answered HTTP 403")
			}}},
		{"default branch comparison fails and the release branch holds the commit", map[string]canned{mainPath: {500, ``}, relBranch: compareJSON("identical", 0, 0)}, nil,
			[]check{holds("NoRegress")}},
		{"default branch name that is not put in a request", map[string]canned{repoPath: repoJSON(setupGoRepoID, actionsOwnerID, "actions/setup-go", "main..."+checkoutV701)}, nil,
			[]check{regress("a name the gate does not put in a request"), holds("Bound")}},

		// The release.
		{"no release for the tag", map[string]canned{releasePath: {404, notFound}}, nil,
			[]check{notClean("tag v7.1.0 has no release"), noFirstSeen(true), holds("Bound", "NoRegress")}},
		{"draft release", map[string]canned{releasePath: releaseJSON("v7.1.0", true, false, true, `null`)}, nil,
			[]check{notClean("is a draft"), noFirstSeen(true)}},
		{"prerelease", map[string]canned{releasePath: releaseJSON("v7.1.0", false, true, true, `"2026-11-17T03:01:17Z"`)}, nil,
			[]check{notClean("is a prerelease"), noFirstSeen(true)}},
		{"release of another tag", map[string]canned{releasePath: releaseJSON("v7.1.1", false, false, true, `"2026-11-17T03:01:17Z"`)}, nil,
			[]check{notClean("the release of another tag"), noFirstSeen(true)}},
		{"immutable release with no published_at", map[string]canned{releasePath: releaseJSON("v7.1.0", false, false, true, `null`)}, nil,
			[]check{holds("Clean"), noFirstSeen(true)}},
		{"immutable release with an unreadable published_at", map[string]canned{releasePath: releaseJSON("v7.1.0", false, false, true, `"yesterday"`)}, nil,
			[]check{holds("Clean"), noFirstSeen(true)}},
		{"release without the immutable field", map[string]canned{releasePath: {200, `{"tag_name":"v7.1.0","draft":false,"prerelease":false,"published_at":"2026-11-17T03:01:17Z"}`}}, nil,
			[]check{holds("Clean"), noFirstSeen(true)}},
		{"release lookup fails", map[string]canned{releasePath: {500, ``}}, nil,
			[]check{func(t *testing.T, u allow.UpdateFacts) {
				mustBeUnavailable(t, "Clean", u.Clean, "the release could not be read: GitHub answered HTTP 500")
				if !u.FirstSeen.Unavailable || u.FirstSeen.Known() || u.FirstSeen.Source == "" {
					t.Errorf("FirstSeen = %+v, want it unavailable", u.FirstSeen)
				}
			}, holds("Bound", "NoRegress")}},
		{"release lookup is forbidden", map[string]canned{releasePath: {403, `{"message":"blocked"}`}}, nil,
			[]check{func(t *testing.T, u allow.UpdateFacts) {
				mustBeUnknown(t, "Clean", u.Clean, "the release could not be read: GitHub answered HTTP 403")
				if u.FirstSeen.Unavailable {
					t.Errorf("FirstSeen = %+v: an answer that arrived is not an outage", u.FirstSeen)
				}
			}, noFirstSeen(false), holds("Bound", "NoRegress")}},

		// Advisories.
		{"malware advisory", nil, &advisories{result: advisory.Result{
			SecurityFix:   allow.No("none", "advisories"),
			NoMalware:     allow.No("GHSA-xxxx-xxxx-xxxx", "advisories"),
			NoNewAdvisory: allow.Yes("none", "advisories"),
		}}, []check{notClean("GHSA-xxxx-xxxx-xxxx"), holds("Bound", "NoRegress")}},
		{"new advisory on the new version", nil, &advisories{result: advisory.Result{
			SecurityFix:   allow.No("none", "advisories"),
			NoMalware:     allow.Yes("none", "advisories"),
			NoNewAdvisory: allow.No("GHSA-yyyy-yyyy-yyyy", "advisories"),
		}}, []check{notClean("GHSA-yyyy-yyyy-yyyy")}},
		{"advisory checker could not tell", nil, &advisories{result: advisory.Result{}}, []check{func(t *testing.T, u allow.UpdateFacts) {
			mustBeUnknown(t, "Clean", u.Clean, "not established: malware advisories were not checked")
			if u.SecurityFix.Gathered() {
				t.Errorf("SecurityFix = %+v, want it left as the checker returned it", u.SecurityFix)
			}
		}}},
		{"advisory database did not answer", nil, &advisories{result: advisory.Result{
			SecurityFix:   allow.Unavailable("GitHub's Advisory Database did not answer (HTTP 503, after retries)", "GET api.github.com/advisories"),
			NoMalware:     allow.Unavailable("GitHub's Advisory Database did not answer (HTTP 503, after retries)", "GET api.github.com/advisories"),
			NoNewAdvisory: allow.Unavailable("GitHub's Advisory Database did not answer (HTTP 503, after retries)", "GET api.github.com/advisories"),
		}}, []check{func(t *testing.T, u allow.UpdateFacts) {
			mustBeUnavailable(t, "Clean", u.Clean, "GitHub's Advisory Database did not answer (HTTP 503")
			mustBeUnavailable(t, "SecurityFix", u.SecurityFix, "did not answer")
		}, holds("Bound", "NoRegress")}},
		{"advisory database did not answer, and the release is a draft", map[string]canned{releasePath: releaseJSON("v7.1.0", true, false, true, `null`)}, &advisories{result: advisory.Result{
			SecurityFix:   allow.Unavailable("no answer", "advisories"),
			NoMalware:     allow.Unavailable("no answer", "advisories"),
			NoNewAdvisory: allow.Unavailable("no answer", "advisories"),
		}}, []check{notClean("is a draft")}},
		{"advisory checker says why it could not tell", nil, &advisories{result: advisory.Result{
			SecurityFix:   allow.Fact{Value: "the answer is not a list"},
			NoMalware:     allow.Fact{Value: "the answer is not a list"},
			NoNewAdvisory: allow.Yes("none", "advisories"),
		}}, []check{func(t *testing.T, u allow.UpdateFacts) {
			mustBeUnknown(t, "Clean", u.Clean, "the answer is not a list")
		}}},
		{"a checker that fails without the context ending", nil, &advisories{err: errors.New("down"), result: advisory.Result{SecurityFix: allow.Yes("stale", "advisories")}}, []check{func(t *testing.T, u allow.UpdateFacts) {
			mustBeUnknown(t, "Clean", u.Clean, "not established: malware advisories were not checked")
			if u.SecurityFix != (allow.Fact{}) {
				t.Errorf("SecurityFix = %+v, want it blank after an error", u.SecurityFix)
			}
		}, holds("Bound", "NoRegress")}},
		// An action's tag can be moved after the advisory was reviewed, so
		// the checker's yes grants nothing; the advisory is still named.
		{"a security fix is recorded as a no that names the advisory", nil, &advisories{result: advisory.Result{
			SecurityFix:   allow.Yes("GHSA-zzzz-zzzz-zzzz", "advisories"),
			NoMalware:     allow.Yes("none", "advisories"),
			NoNewAdvisory: allow.Yes("none", "advisories"),
		}}, []check{holds("Bound", "NoRegress", "Clean"), func(t *testing.T, u allow.UpdateFacts) {
			mustBeNo(t, "SecurityFix", u.SecurityFix, "GHSA-zzzz-zzzz-zzzz")
			mustBeNo(t, "SecurityFix", u.SecurityFix, "no fast path for an action: tag v7.1.0 can be moved")
			if u.SecurityFix.Source != "advisories" {
				t.Errorf("SecurityFix source %q, want the checker's", u.SecurityFix.Source)
			}
		}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adv := tt.adv
			if adv == nil {
				adv = noAdvisories()
			}
			res, _ := run(t, setupGoLockedBump(), tt.override, adv)
			u := one(t, res)
			for _, c := range tt.checks {
				c(t, u)
			}
			// Whatever GitHub answered, none of its free text reaches a
			// Value: these are the strings the overrides above plant.
			for _, f := range []allow.Fact{u.Known, u.Listed, u.NewName, u.Increase, u.Major, u.Bound, u.Clean, u.NoRegress} {
				for _, planted := range []string{"<b>", "boom", "-evil", "octo/", "../", "yesterday"} {
					if strings.Contains(f.Value, planted) {
						t.Errorf("fact value %q carries %q from an answer", f.Value, planted)
					}
				}
			}
			if strings.Contains(u.FirstSeen.Value, "yesterday") {
				t.Errorf("FirstSeen value %q carries text from an answer", u.FirstSeen.Value)
			}
			// An update that is not bound gives the model nothing to read.
			if !u.Bound.Holds() && len(res.Artifacts) != 0 {
				t.Errorf("Artifacts = %+v for an update that is not bound", res.Artifacts)
			}
		})
	}
}

// inDirectory is files with the workflow's line using the action from a
// directory of its repository: owner/repo/sub@tag. The lockfile records
// the repository, and is left as it is.
func inDirectory(t *testing.T, files []facts.File, name, sub string) []facts.File {
	t.Helper()
	for i, f := range files {
		if f.Path == ciPath {
			files[i] = file(ciPath, edit(t, string(f.Base), name+"@", name+sub+"@"), edit(t, string(f.Head), name+"@", name+sub+"@"))
		}
	}
	return files
}

// An action in a directory has a name of its own in the advisory
// database, and an advisory can be filed under that name alone. The pin,
// the facts about it and the code the model reads are the repository's;
// the database is asked under both names, and an answer under the
// directory's name takes Clean away like one under the repository's.
func TestGatherAsksAboutAnActionInADirectory(t *testing.T) {
	const repo, dir = "actions/setup-go", "actions/setup-go/sub"
	clean := noAdvisories().result
	unavailable := allow.Unavailable("GitHub's Advisory Database did not answer (HTTP 503, after retries)", "GET api.github.com/advisories")
	tests := []struct {
		name string
		// under is what the checker answers for the directory's name; the
		// repository's name always gets a clean answer.
		under advisory.Result
		check func(t *testing.T, u allow.UpdateFacts)
	}{
		{"nothing under either name", clean, func(t *testing.T, u allow.UpdateFacts) {
			mustHold(t, "Clean", u.Clean)
		}},
		{"a malware advisory under the directory's name alone", advisory.Result{
			SecurityFix:   allow.No("none", "advisories"),
			NoMalware:     allow.No("GHSA-xxxx-xxxx-xxxx", "advisories for "+dir),
			NoNewAdvisory: allow.Yes("none", "advisories"),
		}, func(t *testing.T, u allow.UpdateFacts) {
			mustBeNo(t, "Clean", u.Clean, "GHSA-xxxx-xxxx-xxxx")
		}},
		{"a new advisory under the directory's name alone", advisory.Result{
			SecurityFix:   allow.No("none", "advisories"),
			NoMalware:     allow.Yes("none", "advisories"),
			NoNewAdvisory: allow.No("GHSA-yyyy-yyyy-yyyy", "advisories for "+dir),
		}, func(t *testing.T, u allow.UpdateFacts) {
			mustBeNo(t, "Clean", u.Clean, "GHSA-yyyy-yyyy-yyyy")
		}},
		{"the database did not answer for the directory's name", advisory.Result{SecurityFix: unavailable, NoMalware: unavailable, NoNewAdvisory: unavailable},
			func(t *testing.T, u allow.UpdateFacts) {
				mustBeUnavailable(t, "Clean", u.Clean, "did not answer")
			}},
		{"the checker could not tell for the directory's name", advisory.Result{}, func(t *testing.T, u allow.UpdateFacts) {
			mustBeUnknown(t, "Clean", u.Clean, "not established: malware advisories were not checked")
		}},
		// What the directory's name is said to fix grants nothing: the
		// repository's answer is the update's SecurityFix.
		{"a security fix under the directory's name alone", advisory.Result{
			SecurityFix:   allow.Yes("GHSA-zzzz-zzzz-zzzz", "advisories for "+dir),
			NoMalware:     allow.Yes("none", "advisories"),
			NoNewAdvisory: allow.Yes("none", "advisories"),
		}, func(t *testing.T, u allow.UpdateFacts) {
			mustHold(t, "Clean", u.Clean)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adv := &advisories{result: clean, byName: map[string]advisory.Result{dir: tt.under}}
			res, _ := run(t, inDirectory(t, setupGoLockedBump(), repo, "/sub"), nil, adv)
			u := one(t, res)
			tt.check(t, u)

			// Everything else is the repository's, as for a line that names
			// no directory.
			if u.Name != repo {
				t.Errorf("update is named %q, want the repository", u.Name)
			}
			mustHold(t, "Bound", u.Bound)
			mustHold(t, "NoRegress", u.NoRegress)
			mustBeNo(t, "SecurityFix", u.SecurityFix, "no advisory names this update as the fix")
			// The reader is told the directory: what the action there runs
			// is the one other thing that is about it alone (spec section
			// 11, amendment 55).
			if len(res.Artifacts) != 1 || res.Artifacts[0].Name != repo || !slices.Equal(res.Artifacts[0].Dirs, []string{"sub"}) {
				t.Errorf("Artifacts = %+v, want the repository's tarball, used from the directory", res.Artifacts)
			}
			want := []advisory.Query{
				{Ecosystem: allow.GitHubActions, Name: repo, From: "v7.0.0", To: "v7.1.0"},
				{Ecosystem: allow.GitHubActions, Name: dir, From: "v7.0.0", To: "v7.1.0"},
			}
			if !slices.Equal(adv.asked, want) {
				t.Errorf("advisory queries %+v, want %+v", adv.asked, want)
			}
		})
	}
}

// A tag object that points at itself must not keep the gatherer asking.
func TestTagChainIsBounded(t *testing.T) {
	const tagObject = "1111111111111111111111111111111111111111"
	res, net := run(t, setupGoLockedBump(), map[string]canned{
		"repos/actions/setup-go/git/ref/tags/v7.1.0":   {200, `{"ref":"refs/tags/v7.1.0","object":{"type":"tag","sha":"` + tagObject + `"}}`},
		"repos/actions/setup-go/git/tags/" + tagObject: {200, `{"object":{"type":"tag","sha":"` + tagObject + `"}}`},
	}, noAdvisories())
	mustBeNo(t, "Bound", one(t, res).Bound, "more than 3 annotated tags deep")
	n := 0
	for _, s := range net.seen {
		if strings.Contains(s, "/git/tags/") {
			n++
		}
	}
	if n != maxTagHops {
		t.Errorf("%d tag objects read, want %d", n, maxTagHops)
	}
}

// A move the line shapes admit and the facts refuse.
func TestGatherDowngrade(t *testing.T) {
	const repoPath = "repos/actions/setup-go"
	// The answers for v7.0.0 as a new version are not recorded; say what
	// GitHub would for the real tag and release.
	res, _ := run(t, lockedBump("actions/setup-go", "v7.1.0", "v7.0.0", setupGoV710, setupGoV700, actionsOwnerID, setupGoRepoID), map[string]canned{
		repoPath + "/git/ref/tags/v7.0.0":                          {200, `{"ref":"refs/tags/v7.0.0","object":{"type":"commit","sha":"` + setupGoV700 + `"}}`},
		repoPath + "/compare/" + setupGoV710 + "..." + setupGoV700: {200, `{"status":"behind","ahead_by":0,"behind_by":20}`},
		repoPath + "/compare/main..." + setupGoV700:                {200, `{"status":"behind","ahead_by":0,"behind_by":25}`},
		repoPath + "/releases/tags/v7.0.0":                         {200, `{"tag_name":"v7.0.0","draft":false,"prerelease":false}`},
	}, noAdvisories())
	u := one(t, res)
	mustBeNo(t, "Increase", u.Increase, "v7.1.0 -> v7.0.0 is not an increase")
	mustBeNo(t, "Major", u.Major, "both v7")
	mustHold(t, "Bound", u.Bound)
	mustBeNo(t, "NoRegress", u.NoRegress, "does not descend from the old one (behind: 0 ahead, 20 behind)")
}

func TestVersionFacts(t *testing.T) {
	tests := []struct {
		from, to     string
		increase     bool
		major        bool
		majorMessage string
	}{
		{"v7.0.0", "v7.1.0", true, false, "both v7"},
		{"v7.0.9", "v7.0.10", true, false, "both v7"}, // numeric, not text, order
		{"v6.4.0", "v7.0.0", true, true, "v6 -> v7"},
		{"v0.9.0", "v1.0.0", true, true, "v0 -> v1"},
		{"v9.0.0", "v10.0.0", true, true, "v9 -> v10"},
		{"v7.1.0", "v7.0.0", false, false, "both v7"},
		{"v8.0.0", "v7.9.9", false, true, "v8 -> v7"},
		{"v7.1.0", "v7.1.0", false, false, "both v7"},
		// Nothing the line shapes admit, but the facts do not depend on
		// that: a version that is not a plain release never increases,
		// and one that cannot be read counts as a major.
		{"v7.0.0", "v7.1.0-rc.1", false, false, "both v7"},
		{"v7.0.0", "v7.1.0+build", false, false, "both v7"},
		{"v7.0.0", "v7.1", false, false, "both v7"},
		{"v7.0.0", "7.1.0", false, true, "cannot be read"},
		{"v7.0.0", "main", false, true, "cannot be read"},
	}
	for _, tt := range tests {
		t.Run(tt.from+" to "+tt.to, func(t *testing.T) {
			p := pin{name: "actions/setup-go", from: tt.from, to: tt.to, where: ciPath + ":1"}
			inc, maj := increase(p), major(p)
			if !inc.Gathered() || inc.OK != tt.increase {
				t.Errorf("Increase = %+v, want %t", inc, tt.increase)
			}
			if !maj.Gathered() || maj.OK != tt.major || !strings.Contains(maj.Value, tt.majorMessage) {
				t.Errorf("Major = %+v, want %t with %q", maj, tt.major, tt.majorMessage)
			}
		})
	}
}

func TestListedFollowsThePolicy(t *testing.T) {
	// docker/ is on the test policy's list; a name outside it is not, and
	// the list is matched byte for byte, so another spelling is not either.
	tests := []struct {
		name string
		want bool
	}{
		{"docker/login-action", true},
		{"Docker/login-action", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, _ := run(t, lockedBump(tt.name, "v4.7.0", "v4.8.0", loginV470, loginV480, dockerOwnerID, loginRepoID), map[string]canned{}, noAdvisories())
			u := one(t, res)
			if u.Name != tt.name || !u.Listed.Gathered() || u.Listed.OK != tt.want {
				t.Errorf("%s: Listed = %+v, want %t", u.Name, u.Listed, tt.want)
			}
			if u.Listed.OK != allow.Listed(testPolicy(), allow.GitHubActions, u.Name) {
				t.Errorf("Listed disagrees with allow.Listed, which Decide would refuse")
			}
			// The repository is the same one however the name is spelled.
			mustHold(t, "Bound", u.Bound)
		})
	}
}

func TestGatherShapeFailureAsksNothing(t *testing.T) {
	files := append(setupGoLockedBump(), file("go.mod", "module a\n", "module b\n"))
	res, net := run(t, files, nil, noAdvisories())
	if res.Shape.OK || !res.Shape.Gathered() || !strings.Contains(res.Shape.Value, "go.mod") {
		t.Errorf("Shape = %+v, want a gathered no naming go.mod", res.Shape)
	}
	if len(res.Updates) != 0 || len(res.Artifacts) != 0 {
		t.Errorf("updates %+v and artifacts %+v from a change set that cannot be trusted", res.Updates, res.Artifacts)
	}
	if len(net.seen) != 0 {
		t.Errorf("requests %v, want none", net.seen)
	}
}

func TestGatherSeveralUpdates(t *testing.T) {
	files := []facts.File{
		file(lockPath, lockText, edit(t, lockText,
			"setup-go@v7.0.0", "setup-go@v7.1.0", "ref: 'v7.0.0'\n        commit: 'sha1-"+setupGoV700, "ref: 'v7.1.0'\n        commit: 'sha1-"+setupGoV710,
			"checkout@v7.0.0", "checkout@v7.0.1", "ref: 'v7.0.0'\n        commit: 'sha1-"+checkoutV700, "ref: 'v7.0.1'\n        commit: 'sha1-"+checkoutV701)),
		file(ciPath, ciTags, edit(t, ciTags, "setup-go@v7.0.0", "setup-go@v7.1.0", "checkout@v7.0.0", "checkout@v7.0.1")),
	}
	adv := noAdvisories()
	res, _ := run(t, files, nil, adv)
	if !res.Shape.Holds() || len(res.Updates) != 2 {
		t.Fatalf("Shape %+v, %d updates", res.Shape, len(res.Updates))
	}
	if res.Updates[0].Name != "actions/checkout" || res.Updates[1].Name != "actions/setup-go" {
		t.Errorf("updates are %s, %s; want them sorted by name", res.Updates[0].Name, res.Updates[1].Name)
	}
	for _, u := range res.Updates {
		mustHold(t, u.Name+" Bound", u.Bound)
	}
	if len(adv.asked) != 2 || len(res.Artifacts) != 2 {
		t.Errorf("%d advisory queries and %d artifact pairs, want one of each per update", len(adv.asked), len(res.Artifacts))
	}
}

func TestGatherErrors(t *testing.T) {
	files := setupGoLockedBump()
	t.Run("no GitHub client", func(t *testing.T) {
		_, err := New().Gather(context.Background(), facts.Input{Files: files, Advisories: noAdvisories()})
		if err == nil {
			t.Error("no error")
		}
	})
	t.Run("no advisory checker", func(t *testing.T) {
		net := &replay{t: t}
		_, err := New().Gather(context.Background(), facts.Input{Files: files, GitHub: net.client()})
		if err == nil {
			t.Error("no error")
		}
	})
	t.Run("context ended", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		net := &replay{t: t, override: map[string]canned{}}
		res, err := New().Gather(ctx, facts.Input{Files: files, Policy: testPolicy(), GitHub: net.client(), Advisories: noAdvisories()})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
		if len(res.Updates) != 0 || res.Shape.Gathered() {
			t.Errorf("a result came back with the error: %+v", res)
		}
	})
	t.Run("context ends while the advisory database is asked", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		net := &replay{t: t}
		adv := &cancelling{cancel: cancel}
		_, err := New().Gather(ctx, facts.Input{Files: files, Policy: testPolicy(), GitHub: net.client(), Advisories: adv})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	})
}

// cancelling is an advisory checker that ends the context it is called in.
type cancelling struct{ cancel context.CancelFunc }

func (c *cancelling) Check(ctx context.Context, _ advisory.Query) (advisory.Result, error) {
	c.cancel()
	return advisory.Result{}, ctx.Err()
}

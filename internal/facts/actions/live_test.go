package actions

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/facts"
	"github.com/sadbox/dep-review/internal/gh"
)

// TestLive asks api.github.com the questions the recorded tests replay,
// about the same public updates, to show the recordings still match what
// GitHub answers. It is opt-in: DEP_REVIEW_LIVE=1. GH_TOKEN, when set,
// is sent (a token raises the rate limit; none of the repositories needs
// one). About 40 requests.
//
// Tags and releases of other people's repositories can change. A failure
// here that the recorded tests do not share means GitHub's answer moved,
// not that the gatherer broke: run testdata/record.sh and read the diff.
func TestLive(t *testing.T) {
	if os.Getenv("DEP_REVIEW_LIVE") == "" {
		t.Skip("network test; set DEP_REVIEW_LIVE=1")
	}
	client := gh.New(os.Getenv("GH_TOKEN"))
	gather := func(t *testing.T, files []facts.File) allow.UpdateFacts {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		res, err := New().Gather(ctx, facts.Input{Files: files, Policy: testPolicy(), GitHub: client, Advisories: noAdvisories()})
		if err != nil {
			t.Fatal(err)
		}
		return one(t, res)
	}
	allHold := func(t *testing.T, u allow.UpdateFacts) {
		t.Helper()
		mustHold(t, "Bound", u.Bound)
		mustHold(t, "NoRegress", u.NoRegress)
		mustHold(t, "Clean", u.Clean)
	}

	t.Run("setup-go v7.1.0, immutable release", func(t *testing.T) {
		u := gather(t, setupGoLockedBump())
		allHold(t, u)
		if want := time.Date(2026, 11, 17, 3, 1, 17, 0, time.UTC); !u.FirstSeen.Known() || !u.FirstSeen.Time.Equal(want) {
			t.Errorf("FirstSeen = %+v, want %s", u.FirstSeen, want)
		}
	})
	t.Run("checkout v7.0.1, release not immutable", func(t *testing.T) {
		u := gather(t, lockedBump("actions/checkout", "v7.0.0", "v7.0.1", checkoutV700, checkoutV701, actionsOwnerID, checkoutRepoID))
		allHold(t, u)
		if u.FirstSeen.Known() || u.FirstSeen.Source == "" {
			t.Errorf("FirstSeen = %+v, want unknown with a source", u.FirstSeen)
		}
	})
	t.Run("checkout v6.1.0, on releases/v6", func(t *testing.T) {
		u := gather(t, lockedBump("actions/checkout", "v6.0.2", "v6.1.0", checkoutV602, checkoutV610, actionsOwnerID, checkoutRepoID))
		allHold(t, u)
		if !strings.Contains(u.NoRegress.Value, "on branch releases/v6") {
			t.Errorf("NoRegress value %q", u.NoRegress.Value)
		}
	})
	t.Run("checkout v6.0.3, annotated tag", func(t *testing.T) {
		allHold(t, gather(t, lockedBump("actions/checkout", "v6.0.2", "v6.0.3", checkoutV602, checkoutV603, actionsOwnerID, checkoutRepoID)))
	})
	t.Run("login-action v4.8.0, default branch master", func(t *testing.T) {
		u := gather(t, lockedBump("docker/login-action", "v4.7.0", "v4.8.0", loginV470, loginV480, dockerOwnerID, loginRepoID))
		allHold(t, u)
		if !u.FirstSeen.Known() {
			t.Errorf("FirstSeen = %+v", u.FirstSeen)
		}
	})
	t.Run("a wrong repository ID in the lockfile", func(t *testing.T) {
		u := gather(t, lockedBump("actions/setup-go", "v7.0.0", "v7.1.0", setupGoV700, setupGoV710, actionsOwnerID, checkoutRepoID))
		mustBeNo(t, "Bound", u.Bound, "actions.lock records repository")
	})
	t.Run("a commit only a fork has", func(t *testing.T) {
		// Live, the tag is where it belongs, so Bound refuses as well.
		u := gather(t, lockedBump("actions/setup-go", "v7.0.0", "v7.1.0", setupGoForkBase, setupGoForkOnly, actionsOwnerID, setupGoRepoID))
		mustBeNo(t, "Bound", u.Bound, "tag v7.1.0 is commit "+setupGoV710)
		mustBeNo(t, "NoRegress", u.NoRegress, "the commit is not reachable from main or releases/v7")
		if strings.Contains(u.NoRegress.Value, "does not descend") {
			t.Errorf("NoRegress value %q: GitHub was expected to call the fork's commit ahead of the old pin", u.NoRegress.Value)
		}
	})
}

// TestPullRequestDir reads the change set of a pull request someone
// saved to disk: DEP_REVIEW_PR_DIR names a directory with the changed
// files as they are at the two commits, under base/ and head/ (the same
// relative paths in both). It is for trying the line shapes on a real
// Dependabot pull request without putting its files in this repository,
// which is the only way to try one from a private repository. Every file
// is taken to be a regular one (mode 100644): the directory cannot say.
//
// With DEP_REVIEW_LIVE=1 as well it goes on to ask GitHub and prints the
// facts.
func TestPullRequestDir(t *testing.T) {
	dir := os.Getenv("DEP_REVIEW_PR_DIR")
	if dir == "" {
		t.Skip("set DEP_REVIEW_PR_DIR to a directory with base/ and head/")
	}
	var files []facts.File
	base := filepath.Join(dir, "base")
	err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(base, p)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		h, err := os.ReadFile(filepath.Join(dir, "head", rel))
		if err != nil {
			return err
		}
		files = append(files, file(filepath.ToSlash(rel), string(b), string(h)))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	pins, problem := readChangeSet(files, testPolicy())
	if problem != "" {
		t.Fatalf("Shape does not hold: %s", problem)
	}
	for _, p := range pins {
		t.Logf("%+v", p)
	}
	if os.Getenv("DEP_REVIEW_LIVE") == "" {
		return
	}
	res, err := New().Gather(context.Background(), facts.Input{Files: files, Policy: testPolicy(), GitHub: gh.New(os.Getenv("GH_TOKEN")), Advisories: noAdvisories()})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range res.Updates {
		t.Logf("%s %s -> %s\n  bound      %+v\n  no regress %+v\n  clean      %+v\n  first seen %+v", u.Name, u.From, u.To, u.Bound, u.NoRegress, u.Clean, u.FirstSeen)
	}
}

// TestLiveOwn asks api.github.com about the two repositories the built-in
// policy calls the gate owner's own (spec section 11, amendment 60), with
// the IDs that policy records and tags they had on 2026-11-23. Both are
// public. It is opt-in like TestLive: DEP_REVIEW_LIVE=1. About 20
// requests, none for a release or a release branch.
func TestLiveOwn(t *testing.T) {
	if os.Getenv("DEP_REVIEW_LIVE") == "" {
		t.Skip("network test; set DEP_REVIEW_LIVE=1")
	}
	const (
		owner       = 2502941
		ciID        = 1465779983
		depReviewID = 1465738661

		gate = "sadbox/dep-review/.github/workflows/gate.yml"
		lint = "sadbox/ci/.github/workflows/lint.yml"

		gateV017 = "c0f8afd3c0d85bede7bd0780b0a797c15152fda4"
		gateV018 = "0672ce19fdc12cfa66ce9e836cf0f2156ff8947f"
		gateV019 = "86f983bd3183934ea41f7ef7e89724a9546f7df7"
		ciV040   = "9b561c32073a80e3972e8c07fd028358e58732b0"
		ciV050   = "fbff0f9c424ef3ce793702959ecd1e858861d4b0"
	)
	policy := func(ciRepo, depReviewRepo int64) allow.Policy {
		p := testPolicy()
		p.Own = []allow.OwnRepo{
			{Repository: "sadbox/ci", RepositoryID: ciRepo, OwnerID: owner},
			{Repository: "sadbox/dep-review", RepositoryID: depReviewRepo, OwnerID: owner},
		}
		return p
	}
	client := gh.New(os.Getenv("GH_TOKEN"))
	gather := func(t *testing.T, files []facts.File, p allow.Policy) allow.UpdateFacts {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		res, err := New().Gather(ctx, facts.Input{Files: files, Policy: p, GitHub: client, Advisories: noAdvisories()})
		if err != nil {
			t.Fatal(err)
		}
		u := one(t, res)
		t.Logf("bound      %+v\nno regress %+v\nclean      %+v\nfirst seen %+v", u.Bound, u.NoRegress, u.Clean, u.FirstSeen)
		return u
	}
	real := policy(ciID, depReviewID)

	t.Run("gate v0.1.8 to v0.1.9", func(t *testing.T) {
		u := gather(t, ownBump(gate, gateV018, "v0.1.8", gateV019, "v0.1.9"), real)
		mustHold(t, "Own", u.Own)
		mustHold(t, "Bound", u.Bound)
		mustHold(t, "NoRegress", u.NoRegress)
		mustHold(t, "Clean", u.Clean)
		if u.FirstSeen.Known() || u.FirstSeen.Source != "" {
			t.Errorf("FirstSeen = %+v, want it not asked", u.FirstSeen)
		}
	})
	t.Run("ci v0.4.0 to v0.5.0", func(t *testing.T) {
		u := gather(t, ownBump(lint, ciV040, "v0.4.0", ciV050, "v0.5.0"), real)
		mustHold(t, "Bound", u.Bound)
		mustHold(t, "NoRegress", u.NoRegress)
		mustHold(t, "Clean", u.Clean)
	})
	t.Run("the tag names another commit", func(t *testing.T) {
		// The comment says v0.1.9 and the commit is v0.1.8's.
		u := gather(t, ownBump(gate, gateV017, "v0.1.7", gateV018, "v0.1.9"), real)
		mustBeNo(t, "Bound", u.Bound, "tag v0.1.9 is commit "+gateV019)
		mustBeNo(t, "NoRegress", u.NoRegress, "tag v0.1.9 is commit")
	})
	t.Run("a move back that the comments call an increase", func(t *testing.T) {
		// From v0.1.9's commit, labelled v0.1.6, to v0.1.7's.
		u := gather(t, ownBump(gate, gateV019, "v0.1.6", gateV017, "v0.1.7"), real)
		mustHold(t, "Bound", u.Bound)
		mustBeNo(t, "NoRegress", u.NoRegress, "the new commit does not descend from the old one")
	})
	t.Run("the policy records another repository's ID", func(t *testing.T) {
		u := gather(t, ownBump(gate, gateV018, "v0.1.8", gateV019, "v0.1.9"), policy(ciID, ciID))
		mustBeNo(t, "Bound", u.Bound, "the policy list own_workflows records repository")
	})
}

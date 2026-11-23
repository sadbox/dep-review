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
	pins, problem := readChangeSet(files)
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

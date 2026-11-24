package land

import (
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/wire"
)

// ownDetail is the fetch job's sentence for a read it did not prepare
// because the update is the gate owner's own workflow.
const ownDetail = "nothing of the gate owner's own workflow is read: it is accepted on where its commit comes from, and no model is asked"

// ownUpdate is the commit pin of a workflow of name as the fetch job
// writes it when the Actions gatherer calls it own: every fact about
// where the commit comes from holds, nothing dates it, nothing was
// prepared. The built-in policy names sadbox/ci and sadbox/dep-review.
func ownUpdate(name string) wire.Update {
	u := goodUpdate(name)
	u.Known = allow.Yes("replaced in place: the action is used at the base commit", ".github/workflows/lint.yaml:5")
	u.NewName = allow.No("replaced in place: not a new name", ".github/workflows/lint.yaml:5")
	u.Bound = allow.Yes("tag v1.3.0 is commit "+strings.Repeat("1", 40)+"; repository 1465779983 of owner 2502941, as the policy list own_workflows records", "GitHub")
	u.NoRegress = allow.Yes("4 commit(s) ahead of the old pin; on branch main", "GitHub")
	u.Own = allow.Yes(name+" is on the policy's own list, and the line pins one of its workflow files by commit", "policy list own_workflows")
	u.FirstSeen = allow.TimeFact{Value: "not asked: no age is asked of an own workflow"}
	out := wire.NewUpdate(u, wire.Read{Status: wire.Nothing, Detail: ownDetail})
	out.Hash = strings.Repeat("1", 40)
	return out
}

// ownFacts is goodFacts for an Actions pull request with the given
// updates.
func ownFacts(t *testing.T, updates ...wire.Update) wire.Facts {
	t.Helper()
	f := goodFacts(t)
	f.Facts.Ecosystem = allow.GitHubActions
	f.Facts.Shape = allow.Yes("1 action pin(s) replaced in place across 1 file(s)", "changed files at the base and head commits")
	f.Facts.Updates = updates
	return f
}

// The comment of a pull request that moves the gate owner's own workflow
// says in plain words that the update was accepted unread (spec section
// 11, amendment 60): in the lead of a merge, in the update's own section
// whatever becomes of the pull request, and never for an update that was
// not accepted.
func TestCommentSaysOwnWorkflowWasNotRead(t *testing.T) {
	const (
		ownLead  = "**Own workflow, not read.** `sadbox/ci` `v1.2.3` to `v1.3.0`: accepted as the gate owner's own workflow, unread: nothing of it was read, no model was asked about it and no age was asked of it."
		ownLine  = "Does not hold the pull request back: accepted as the gate owner's own workflow, unread: nothing of it was read"
		ownRow   = "| Own | `yes` | `sadbox/ci is on the policy's own list, and the line pins one of its workflow files by commit` | `policy list own_workflows` |"
		readRow  = "| Read | `not-applicable` | `nothing: " + ownDetail + "` | `the facts file` |"
		accepted = "accepted as the gate owner's own workflow"
	)
	// An action in the same pull request, read under keyA.
	action := func(age time.Duration) wire.Update {
		u := goodUpdate("octo-tools/setup")
		u.FirstSeen = allow.At(t0.Add(-age), "GitHub release published_at (immutable release)")
		return wire.NewUpdate(u, preparedRead(1, keyA))
	}
	major := ownUpdate("sadbox/ci")
	major.From, major.To = "v1.9.0", "v2.0.0"
	major.Major = allow.Yes("v1 -> v2", ".github/workflows/lint.yaml:5")

	for _, tc := range []struct {
		name     string
		updates  []wire.Update
		verdicts func(*testing.T) *wire.Verdicts
		refuse   bool // GitHub refuses the merge call
		action   Action
		has, not []string
	}{
		{name: "merged", updates: []wire.Update{ownUpdate("sadbox/ci")}, verdicts: noVerdicts, action: ActionMerged,
			has: []string{"Every fact below holds, no model was asked, and GitHub's required checks allowed the merge.", ownLead, ownLine, ownRow, readRow},
			// No age was asked, so no time is given as the one it was old
			// enough from.
			not: []string{"the gate had nothing to show one", "the model raised no veto", "| Veto |", "the verdicts file", "Old enough from"}},
		{name: "merged, the gate's own pin", updates: []wire.Update{ownUpdate("sadbox/dep-review")}, verdicts: noVerdicts, action: ActionMerged,
			has: []string{"**Own workflow, not read.** `sadbox/dep-review` `v1.2.3` to `v1.3.0`: " + accepted + ", unread"}},
		// The model's clause is about the action it was asked about; the
		// own workflow beside it gets its own paragraph.
		{name: "merged beside an action that was read", updates: []wire.Update{ownUpdate("sadbox/ci"), action(100 * time.Hour)}, verdicts: clean, action: ActionMerged,
			has: []string{"Every fact below holds, the model raised no veto, and", ownLead, ownLine, ownRow, readRow, "| Veto | `none` |  | `the model` |",
				"Does not hold the pull request back. Old enough from"},
			not: []string{"no model was asked,", "not what it does. Old enough from"}},
		{name: "GitHub refused the merge", updates: []wire.Update{ownUpdate("sadbox/ci")}, verdicts: noVerdicts, refuse: true, action: ActionRefused,
			has: []string{"Every fact below holds and no model was asked, so the gate asked GitHub to merge", ownLead, "**Way out:**"},
			not: []string{"the gate had nothing to show one"}},
		// The pull request waits for the action; the own workflow's
		// section still says what it is.
		{name: "waiting for an action beside it", updates: []wire.Update{ownUpdate("sadbox/ci"), action(time.Hour)}, verdicts: clean, action: ActionWait,
			has: []string{"**Waiting until", ownLine, ownRow},
			not: []string{"**Own workflow, not read.**"}},

		// Not accepted: nothing says it was.
		{name: "a major", updates: []wire.Update{major}, verdicts: noVerdicts, action: ActionPerson,
			has: []string{"**Needs a person.** " + allow.ReasonMajorOwn.Explain(), "The fact: `Major` of `sadbox/ci` `v1.9.0` to `v2.0.0` is `yes`: `v1 -› v2`", ownRow, readRow},
			not: []string{accepted + ", unread", "Does not hold the pull request back"}},
		{name: "a name the policy does not call own", updates: []wire.Update{ownUpdate("sadb0x/ci")}, verdicts: noVerdicts, action: ActionPerson,
			has: []string{"**Needs a person.** " + allow.ReasonListMismatch.Explain()},
			not: []string{accepted + ", unread", "Does not hold the pull request back"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			if tc.refuse {
				f.mergeCode, f.mergeBody = 405, `{"message":"Merge commits are not allowed on this repository."}`
			}
			cfg := f.config(t0, nil)
			cfg.ModelAsked = true
			res, err := publish(t, cfg, files(t, ownFacts(t, tc.updates...), tc.verdicts(t)))
			if err != nil || res.Action != tc.action {
				t.Fatalf("result %+v, %v; want %s", res, err, tc.action)
			}
			body := f.gateComment(testPR)
			for _, want := range tc.has {
				if !strings.Contains(body, want) {
					t.Errorf("the comment lacks %q:\n%s", want, body)
				}
			}
			for _, bad := range tc.not {
				if strings.Contains(body, bad) {
					t.Errorf("the comment says %q:\n%s", bad, body)
				}
			}
		})
	}

	// An update whose Own holds in another ecosystem is not an own
	// workflow, and no comment calls it one.
	f := newFake(t)
	facts := goodFacts(t)
	facts.Facts.Updates[0].Own = allow.Yes("own", "policy")
	cfg := f.config(t0, nil)
	cfg.ModelAsked = true
	if res, err := publish(t, cfg, files(t, facts, clean(t))); err != nil || res.Action != ActionMerged {
		t.Fatalf("result %+v, %v", res, err)
	}
	if body := f.gateComment(testPR); strings.Contains(body, accepted) || !strings.Contains(body, "the model raised no veto") {
		t.Errorf("a Go module is called an own workflow, or the model's clause is gone:\n%s", body)
	}
}

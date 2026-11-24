package land

import (
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/wire"
)

// TestCommentSaysWhoRead: the comment's Read row is the verdicts file's,
// and its Veto row the model's, only for a read a model was asked about.
// Two artifacts that hold the same files are read in full by nobody, and
// a change with nothing readable in it is refused; the comment says both
// in the fetch job's words (spec section 11, amendment 53).
func TestCommentSaysWhoRead(t *testing.T) {
	const (
		same = "the old and the new artifact hold the same files: there is nothing to read, and no model is asked"
		none = "nothing that changed is text the model is shown: every changed file is not text or did not fit, so no model was asked and nothing was read"
	)
	for _, tc := range []struct {
		name     string
		read     *wire.Read // nil: the prepared read of goodFacts
		docker   bool       // the update is a listed image
		verdicts func(*testing.T) *wire.Verdicts
		action   Action
		has, not []string
	}{
		// An image's code did change, and nothing of an image is read: the
		// lead must not say otherwise.
		{name: "an image", read: &wire.Read{Status: wire.Nothing, Detail: "nothing of an image is read"}, docker: true,
			verdicts: noVerdicts, action: ActionMerged,
			has: []string{"| Read | `not-applicable` | `nothing: nothing of an image is read` | `the facts file` |",
				"Every fact below holds, no model was asked (the gate had nothing to show one), and"},
			not: []string{"| Veto |", "the model raised no veto", "the verdicts file", "no changed code"}},
		{name: "a prepared read the model answered", verdicts: clean, action: ActionMerged,
			has: []string{"| Read | `full` | `chunks prepared: 1; changed files not shown: 0` | `the verdicts file` |", "| Veto | `none` |  | `the model` |",
				"Every fact below holds, the model raised no veto, and"}},
		{name: "the same files, and a verdicts file that says nothing of them", read: &wire.Read{Status: wire.Identical, Detail: same},
			verdicts: clean, action: ActionMerged,
			has: []string{"| Read | `full` | `identical: " + same + "` | `the facts file` |",
				"Every fact below holds, no model was asked (the gate had nothing to show one), and"},
			not: []string{"| Veto |", "the verdicts file", "the model raised no veto"}},
		{name: "the same files, and no review job ran", read: &wire.Read{Status: wire.Identical, Detail: same},
			verdicts: noVerdicts, action: ActionMerged,
			has: []string{"| Read | `full` | `identical: " + same + "` | `the facts file` |"},
			not: []string{"| Veto |"}},
		{name: "nothing readable changed", read: &wire.Read{Status: wire.Refused, Detail: none},
			verdicts: clean, action: ActionPerson,
			has: []string{"The fact: `Read` of `example.com/m` `v1.2.3` to `v1.3.0` is `refused`: `refused: " + none + "` (source: `the facts file`).",
				allow.ReasonReadRefused.Explain()},
			not: []string{"| Veto |"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			facts := goodFacts(t)
			if tc.docker {
				u := goodUpdate("docker.io/library/golang")
				u.Listed = allow.Yes("docker.io/library/", "policy")
				u.From, u.To = "1.25@sha256:"+strings.Repeat("0", 64), "1.25@sha256:"+strings.Repeat("1", 64)
				facts.Facts.Ecosystem = allow.Docker
				facts.Facts.Updates = []wire.Update{wire.NewUpdate(u, wire.Read{})}
			}
			if tc.read != nil {
				facts.Facts.Updates[0].Prepared = *tc.read
			}
			cfg := f.config(t0, nil)
			cfg.ModelAsked = true
			res, err := publish(t, cfg, files(t, facts, tc.verdicts(t)))
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
}

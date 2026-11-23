package gather

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/veto"
	"github.com/sadbox/dep-review/internal/wire"
)

// Dependabot's names for the ecosystems are not the gate's.
func TestEcosystem(t *testing.T) {
	for _, tc := range []struct {
		dependabot model.Ecosystem
		want       string
		rule       bool
	}{
		{model.GoModules, allow.GoModules, true},
		{model.NPM, allow.NPM, true},
		{"npm_and_yarn", "npm", true},
		{model.GitHubActions, allow.GitHubActions, true},
		{model.Docker, allow.Docker, true},
		{model.UV, "uv", false},
		{model.GitSubmodule, "submodules", false},
		{"terraform", "terraform", false},
		// The gate's own name for npm is not what Dependabot writes.
		{"npm", "npm", false},
		{"", "", false},
	} {
		got, rule := ecosystem(tc.dependabot)
		if got != tc.want || rule != tc.rule {
			t.Errorf("ecosystem(%q) = %q, %v; want %q, %v", tc.dependabot, got, rule, tc.want, tc.rule)
		}
		// A name with a rule is one allow.Decide has a rule for, and one
		// that has a gatherer.
		if rule && (!allow.HasRule(got) || Gatherers()[got] == nil) {
			t.Errorf("ecosystem(%q) = %q, which has no rule or no gatherer", tc.dependabot, got)
		}
	}
	if n := len(Gatherers()); n != 4 {
		t.Errorf("%d gatherers, want one for each of the four ecosystems with a rule", n)
	}
}

// A pull request in each ecosystem that has a rule reaches that
// ecosystem's gatherer under the gate's name, and one whose facts all
// hold merges once its reads have clean verdicts.
func TestFetchByEcosystem(t *testing.T) {
	for _, tc := range []struct {
		dependabot model.Ecosystem
		want       string
	}{
		{model.GoModules, allow.GoModules},
		{model.NPM, allow.NPM},
		{model.GitHubActions, allow.GitHubActions},
		{model.Docker, allow.Docker},
	} {
		t.Run(tc.want, func(t *testing.T) {
			j := newJob(t, tc.dependabot, goodUpdate(t, tc.want, listedName[tc.want]))
			// The npm reader looks at the tarballs.
			j.preparer.answers[listedName[allow.NPM]] = func(p artifact.Pair) (artifact.Prepared, error) {
				out := preparedRead(p, "+x\n")
				out.Inspected = allow.Yes("no install script", "the tarballs")
				return out, nil
			}
			if tc.want == allow.Docker {
				// Even a gatherer that names an artifact for an image does
				// not get one downloaded.
				j.gatherer.res.Artifacts = append(j.gatherer.res.Artifacts, pairFor(allow.Docker, j.gatherer.res.Updates[0]))
			}
			dir, f := j.run(t)

			if f.Facts.Ecosystem != tc.want {
				t.Errorf("ecosystem %q, want %q", f.Facts.Ecosystem, tc.want)
			}
			if len(j.gatherer.inputs) != 1 {
				t.Fatalf("the gatherer ran %d times", len(j.gatherer.inputs))
			}
			in := j.gatherer.inputs[0]
			if in.Repo != testRepo || in.Base != mergeSHA || in.Head != headSHA || len(in.Files) != 1 ||
				in.HTTP != j.fetch.HTTP || in.GitHub != j.fetch.GitHub || !in.Now().Equal(now) {
				t.Errorf("the gatherer was given %+v", in)
			}
			if !reflect.DeepEqual(in.Policy, defaults(t).Policy()) {
				t.Errorf("the gatherer was given another policy: %+v", in.Policy)
			}
			if !f.GatheredAt.Equal(now) || !f.Facts.Opened.Equal(created) ||
				f.PullRequest != (wire.PullRequest{Repo: testRepo, Number: testNumber, Head: headSHA}) {
				t.Errorf("header %+v, gathered %s, opened %s", f.PullRequest, f.GatheredAt, f.Facts.Opened)
			}

			read := f.Facts.Updates[0].Prepared
			if tc.want == allow.Docker {
				// Nothing of an image is read, so nothing is fetched for it.
				if read.Status != wire.Nothing || len(j.preparer.pairs) != 0 || len(chunkFiles(t, dir)) != 0 {
					t.Errorf("an image was prepared: %+v, %d calls", read, len(j.preparer.pairs))
				}
			} else {
				if read.Status != wire.Prepared || len(read.Chunks) != 1 || len(j.preparer.pairs) != 1 {
					t.Fatalf("read %+v after %d calls", read, len(j.preparer.pairs))
				}
				// The budget is the one the review job's client is built with.
				if want := veto.FromConfig(defaults(t)).Limits(); j.preparer.limits[0] != want {
					t.Errorf("limits %+v, want %+v", j.preparer.limits[0], want)
				}
			}
			wantOutcome(t, decide(t, f, cleanVerdicts(f)), allow.Merge, "")
			// Without a verdict nothing was read, and that is never a merge.
			if tc.want != allow.Docker {
				wantOutcome(t, decide(t, f, nil), allow.Wait, allow.ReasonReadPending)
			}
		})
	}
}

// An ecosystem without a rule gets a facts file and nothing else: no
// request to GitHub, no gatherer, no download.
func TestFetchNoRule(t *testing.T) {
	for _, eco := range []model.Ecosystem{model.UV, model.GitSubmodule, "terraform", ""} {
		t.Run(string(eco), func(t *testing.T) {
			j := newJob(t, eco, goodUpdate(t, allow.GoModules, "example.com/m"))
			// Even a gatherer registered under that name is not run.
			j.fetch.Gatherers[string(eco)] = j.gatherer
			dir, f := j.run(t)

			if f.Facts.Ecosystem != string(eco) {
				t.Errorf("ecosystem %q, want Dependabot's %q", f.Facts.Ecosystem, eco)
			}
			if n := len(j.api.asked()) + len(j.gatherer.inputs) + len(j.preparer.pairs) + len(chunkFiles(t, dir)); n != 0 {
				t.Errorf("something was fetched: GitHub %v, gatherer %d, reader %d", j.api.asked(), len(j.gatherer.inputs), len(j.preparer.pairs))
			}
			// The base branch was not asked about, so Identity is classify's
			// word in a fact that does not hold.
			id := f.Facts.Identity
			if id.Holds() || id.Gathered() || id.Unavailable || !strings.Contains(id.Value, j.fetch.Class.Reason) || len(f.Facts.Updates) != 0 {
				t.Errorf("identity %+v, %d updates", id, len(f.Facts.Updates))
			}
			wantOutcome(t, decide(t, f, nil), allow.Person, allow.ReasonNoRule)
		})
	}
}

// Classify's kinds: an unverified pull request is recorded as such with
// nothing fetched, and the kinds the gate does nothing for are an error.
func TestFetchKinds(t *testing.T) {
	t.Run("unverified", func(t *testing.T) {
		j := newJob(t, model.GoModules, goodUpdate(t, allow.GoModules, "example.com/m"))
		j.fetch.Class.Kind = model.KindDependabotUnverified
		j.fetch.Class.Reason = "someone other than dependabot[bot] changed the branch (push)"
		_, f := j.run(t)
		if want := allow.No(j.fetch.Class.Reason, "classify"); f.Facts.Identity != want {
			t.Errorf("identity %+v, want %+v", f.Facts.Identity, want)
		}
		if n := len(j.api.asked()) + len(j.gatherer.inputs) + len(j.preparer.pairs); n != 0 {
			t.Errorf("something was fetched for a pull request that is not Dependabot's alone")
		}
		wantOutcome(t, decide(t, f, nil), allow.Person, allow.ReasonIdentity)
	})
	// A proof classify could not finish is a source that did not answer:
	// everything else is gathered, and the pull request waits whatever
	// the model says. It never merges on it.
	t.Run("pending", func(t *testing.T) {
		j := newJob(t, model.GoModules, goodUpdate(t, allow.GoModules, "example.com/m"))
		j.fetch.Class.Kind = model.KindPending
		j.fetch.Class.Reason = "the branch's push history does not reach the head commit yet"
		_, f := j.run(t)
		if want := allow.Unavailable(j.fetch.Class.Reason, "classify"); f.Facts.Identity != want {
			t.Errorf("identity %+v, want %+v", f.Facts.Identity, want)
		}
		if len(j.gatherer.inputs) != 1 || len(j.preparer.pairs) != 1 || !f.Facts.Shape.Holds() {
			t.Errorf("the rest was not gathered: %d gatherer calls, %d reads, shape %+v", len(j.gatherer.inputs), len(j.preparer.pairs), f.Facts.Shape)
		}
		wantOutcome(t, decide(t, f, cleanVerdicts(f)), allow.Wait, allow.ReasonSourceUnavailable)
		// The same facts with the proof finished would merge, so the wait
		// above is Identity's and nothing else's.
		f.Facts.Identity = allow.Yes("authored, committed and signed by Dependabot only", "classify")
		wantOutcome(t, decide(t, f, cleanVerdicts(f)), allow.Merge, "")
	})
	// The wait is one the schedule retries and the deadline ends: at the
	// deadline an unfinished proof is a person's (spec section 11,
	// amendments 1 and 51).
	t.Run("pending until the deadline", func(t *testing.T) {
		j := newJob(t, model.GoModules, goodUpdate(t, allow.GoModules, "example.com/m"))
		j.fetch.Class.Kind = model.KindPending
		j.fetch.Class.Reason = "the branch's rules could not be read: GitHub did not answer (HTTP 503)"
		_, f := j.run(t)
		joined := wire.Join(f, wire.Verdicts{Version: wire.Version, Verdicts: cleanVerdicts(f)}, finger)
		d := allow.Decide(joined, defaults(t).Policy(), now)
		wantOutcome(t, d, allow.Wait, allow.ReasonSourceUnavailable)
		if d.Deadline.IsZero() {
			t.Fatal("the wait has no deadline")
		}
		wantOutcome(t, allow.Decide(joined, defaults(t).Policy(), d.Deadline.Add(-time.Second)), allow.Wait, allow.ReasonSourceUnavailable)
		wantOutcome(t, allow.Decide(joined, defaults(t).Policy(), d.Deadline), allow.Person, allow.ReasonSourceDeadline)
	})
	// classify names the branch's ecosystem with an unfinished proof. A
	// classification that does not is not one it writes, and is not
	// written up as an ecosystem without a rule.
	t.Run("pending and no ecosystem", func(t *testing.T) {
		j := newJob(t, "", goodUpdate(t, allow.GoModules, "example.com/m"))
		j.fetch.Class.Kind = model.KindPending
		dir := filepath.Join(t.TempDir(), "facts")
		if _, err := j.fetch.Run(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "names no ecosystem") {
			t.Fatalf("error %v, want one about the missing ecosystem", err)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("something was written: %v", err)
		}
	})
	// In an ecosystem without a rule the answer does not hang on the
	// proof: it is a person's either way, and is said at once.
	t.Run("pending in an ecosystem without a rule", func(t *testing.T) {
		j := newJob(t, model.UV, goodUpdate(t, allow.GoModules, "example.com/m"))
		j.fetch.Class.Kind = model.KindPending
		j.fetch.Class.Reason = "the branch's push history does not reach the head commit yet"
		_, f := j.run(t)
		if f.Facts.Identity.Holds() || len(j.api.asked())+len(j.gatherer.inputs) != 0 {
			t.Errorf("identity %+v, GitHub %v, gatherer %d", f.Facts.Identity, j.api.asked(), len(j.gatherer.inputs))
		}
		wantOutcome(t, decide(t, f, nil), allow.Person, allow.ReasonNoRule)
	})
	for _, kind := range []model.Kind{model.KindOther, model.KindStale, model.KindIgnored, ""} {
		t.Run("kind "+string(kind), func(t *testing.T) {
			j := newJob(t, model.GoModules)
			j.fetch.Class.Kind = kind
			dir := filepath.Join(t.TempDir(), "facts")
			if _, err := j.fetch.Run(context.Background(), dir); err == nil {
				t.Fatal("the fetch job ran")
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Errorf("something was written: %v", err)
			}
		})
	}
}

// What GitHub says about the pull request itself: the base branch (part
// of Identity), the required checks and the creation time. An answer
// "no" stops the job; GitHub not answering does not, so that the outcome
// is a wait.
func TestFetchPullRequestFacts(t *testing.T) {
	const (
		yes = iota
		no
		missing
		unavailable
	)
	state := func(f allow.Fact) int {
		switch {
		case f.Holds():
			return yes
		case f.Gathered():
			return no
		case f.Unavailable && f.Source != "":
			return unavailable
		}
		return missing
	}
	for _, tc := range []struct {
		name             string
		change           func(*fakeGitHub)
		identity, checks int
		opened           bool
		gathered         bool
		rulesAsked       bool
		outcome          allow.Outcome
		reason           allow.Reason
	}{
		{name: "all good", change: func(*fakeGitHub) {},
			identity: yes, checks: yes, opened: true, gathered: true, rulesAsked: true, outcome: allow.Merge},
		{name: "base is not the default branch", change: func(g *fakeGitHub) {
			g.pull = strings.Replace(pullBody, `"ref":"main"`, `"ref":"release"`, 1)
		}, identity: no, checks: missing, opened: true, outcome: allow.Person, reason: allow.ReasonIdentity},
		{name: "the pull request of another repository", change: func(g *fakeGitHub) {
			g.pull = strings.Replace(pullBody, `"full_name":"sadbox/linkclean"`, `"full_name":"someone/fork"`, 1)
		}, identity: missing, checks: missing, opened: true, gathered: true, outcome: allow.Person, reason: allow.ReasonFactMissing},
		{name: "no base repository in the answer", change: func(g *fakeGitHub) {
			g.pull = `{"created_at":"2026-11-14T08:30:00Z","base":{"ref":"main","repo":null}}`
		}, identity: missing, checks: missing, opened: true, gathered: true, outcome: allow.Person, reason: allow.ReasonFactMissing},
		{name: "GitHub does not answer for the pull request", change: func(g *fakeGitHub) {
			g.pullStatus = http.StatusServiceUnavailable
		}, identity: unavailable, checks: unavailable, gathered: true, outcome: allow.Wait, reason: allow.ReasonSourceUnavailable},
		{name: "the pull request is not found", change: func(g *fakeGitHub) {
			g.pullStatus = http.StatusNotFound
		}, identity: missing, checks: missing, gathered: true, outcome: allow.Person, reason: allow.ReasonFactMissing},
		{name: "an answer that is not JSON", change: func(g *fakeGitHub) {
			g.pull = `<html>`
		}, identity: missing, checks: missing, gathered: true, outcome: allow.Person, reason: allow.ReasonFactMissing},
		{name: "no rule requires a check", change: func(g *fakeGitHub) {
			g.rules = `[{"type":"deletion","ruleset_id":1},{"type":"required_status_checks","parameters":{"required_status_checks":[]},"ruleset_id":1}]`
		}, identity: yes, checks: no, opened: true, gathered: true, rulesAsked: true, outcome: allow.Person, reason: allow.ReasonChecksNotConfigured},
		{name: "the only required check is the gate's own status", change: func(g *fakeGitHub) {
			g.rules = `[{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"dep-review"}]},"ruleset_id":1},` +
				`{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"dep-review","integration_id":7},{"context":""}]},"ruleset_id":2}]`
		}, identity: yes, checks: no, opened: true, gathered: true, rulesAsked: true, outcome: allow.Person, reason: allow.ReasonChecksNotConfigured},
		{name: "the gate's own status and one other check", change: func(g *fakeGitHub) {
			g.rules = `[{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"dep-review"},{"context":"test"}]},"ruleset_id":1}]`
		}, identity: yes, checks: yes, opened: true, gathered: true, rulesAsked: true, outcome: allow.Merge},
		{name: "a check whose name only starts like the gate's", change: func(g *fakeGitHub) {
			g.rules = `[{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"dep-review / build"}]},"ruleset_id":1}]`
		}, identity: yes, checks: yes, opened: true, gathered: true, rulesAsked: true, outcome: allow.Merge},
		{name: "no rules at all", change: func(g *fakeGitHub) {
			g.rules = `[]`
		}, identity: yes, checks: no, opened: true, gathered: true, rulesAsked: true, outcome: allow.Person, reason: allow.ReasonChecksNotConfigured},
		{name: "GitHub does not answer for the rules", change: func(g *fakeGitHub) {
			g.rulesStatus = http.StatusBadGateway
		}, identity: yes, checks: unavailable, opened: true, gathered: true, rulesAsked: true, outcome: allow.Wait, reason: allow.ReasonSourceUnavailable},
		{name: "the rules may not be read", change: func(g *fakeGitHub) {
			g.rulesStatus = http.StatusForbidden
		}, identity: yes, checks: missing, opened: true, gathered: true, rulesAsked: true, outcome: allow.Person, reason: allow.ReasonFactMissing},
		{name: "a default branch name the gate puts in no request", change: func(g *fakeGitHub) {
			g.pull = strings.NewReplacer(`"ref":"main"`, `"ref":"release/1.x"`, `"default_branch":"main"`, `"default_branch":"release/1.x"`).Replace(pullBody)
			g.rulesPath = "/repos/sadbox/linkclean/rules/branches/release/1.x"
		}, identity: yes, checks: missing, opened: true, gathered: true, outcome: allow.Person, reason: allow.ReasonFactMissing},
		{name: "no creation time", change: func(g *fakeGitHub) {
			g.pull = strings.Replace(pullBody, `"created_at":"2026-11-14T08:30:00Z",`, ``, 1)
		}, identity: yes, checks: yes, gathered: true, rulesAsked: true, outcome: allow.Merge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := newJob(t, model.GoModules, goodUpdate(t, allow.GoModules, "example.com/m"))
			tc.change(j.api)
			_, f := j.run(t)

			if got := state(f.Facts.Identity); got != tc.identity {
				t.Errorf("identity %+v", f.Facts.Identity)
			}
			if got := state(f.Facts.ChecksConfigured); got != tc.checks {
				t.Errorf("checks configured %+v", f.Facts.ChecksConfigured)
			}
			if want := map[bool]time.Time{true: created}[tc.opened]; !f.Facts.Opened.Equal(want) {
				t.Errorf("opened %s, want %s", f.Facts.Opened, want)
			}
			if gathered := len(j.gatherer.inputs) == 1; gathered != tc.gathered {
				t.Errorf("the gatherer ran %d times", len(j.gatherer.inputs))
			}
			rulesAsked := false
			for _, path := range j.api.asked() {
				rulesAsked = rulesAsked || strings.Contains(path, "/rules/")
			}
			if rulesAsked != tc.rulesAsked {
				t.Errorf("requests %v", j.api.asked())
			}
			wantOutcome(t, decide(t, f, cleanVerdicts(f)), tc.outcome, tc.reason)
		})
	}
}

// Fetch does not date an update itself (spec section 11, amendment 38):
// a first-seen time the registry did not give stays as the gatherer left
// it, whatever the pull request's creation time is, and publish dates the
// pin. What fetch adds is the hash that tells one pin from another.
func TestFetchLeavesFirstSeenAndNamesTheHash(t *testing.T) {
	known := goodUpdate(t, allow.GoModules, "example.com/known")
	gap := goodUpdate(t, allow.GoModules, "example.com/gap")
	gap.FirstSeen = allow.TimeFact{Value: "unknown: not in the index", Source: "index.golang.org"}
	down := goodUpdate(t, allow.GoModules, "example.com/down")
	down.FirstSeen = allow.UnavailableTime("index.golang.org: 503", "index.golang.org")
	// An update the gatherer named no artifact for: its Bound does not hold.
	unbound := goodUpdate(t, allow.GoModules, "example.com/unbound")
	unbound.Bound = allow.No("go.sum pins another hash", "go mod download")

	j := newJob(t, model.GoModules, known, gap, down, unbound)
	j.gatherer.res.Artifacts = j.gatherer.res.Artifacts[:3]
	_, f := j.run(t)
	for i, want := range []allow.UpdateFacts{known, gap, down, unbound} {
		if got := f.Facts.Updates[i].FirstSeen; got != want.FirstSeen {
			t.Errorf("%s: first seen %+v, want what the gatherer returned, %+v", want.Name, got, want.FirstSeen)
		}
	}
	for i, want := range []string{"new", "new", "new", ""} {
		if got := f.Facts.Updates[i].Hash; got != want {
			t.Errorf("%s: hash %q, want %q", f.Facts.Updates[i].Name, got, want)
		}
	}
	// Without publish's clock a time nobody established is still a person's.
	wantOutcome(t, decide(t, f, cleanVerdicts(f)), allow.Person, allow.ReasonFirstSeenUnknown)

	// An image names no artifact: its digest is in To.
	j = newJob(t, model.Docker, goodUpdate(t, allow.Docker, listedName[allow.Docker]))
	if _, f = j.run(t); f.Facts.Updates[0].Hash != "" {
		t.Errorf("an image's hash is %q", f.Facts.Updates[0].Hash)
	}
}

// One read that cannot be prepared is recorded for its update and costs
// no other update its read (spec section 11, amendment 9).
func TestFetchPrepareFailures(t *testing.T) {
	// Text a publisher could have put into an error. It must not reach
	// the facts file.
	const theirs = "PUBLISHER-TEXT\n::error::"
	fail := func(err error) func(artifact.Pair) (artifact.Prepared, error) {
		return func(artifact.Pair) (artifact.Prepared, error) { return artifact.Prepared{}, err }
	}
	cases := []struct {
		name    string
		answer  func(artifact.Pair) (artifact.Prepared, error)
		noPair  bool
		status  wire.ReadStatus
		chunks  int
		outcome allow.Outcome
		reason  allow.Reason
		detail  string // part of the read's detail, where a person acts on it
	}{
		{name: "example.com/first", status: wire.Prepared, chunks: 1, outcome: allow.Merge},
		{name: "example.com/down", answer: fail(fmt.Errorf("fetching: %w: %s", artifact.ErrUnavailable, theirs)),
			status: wire.Unavailable, outcome: allow.Wait, reason: allow.ReasonReadPending},
		{name: "example.com/mismatch", answer: fail(fmt.Errorf("%w: %s", artifact.ErrHashMismatch, theirs)),
			status: wire.Refused, outcome: allow.Person, reason: allow.ReasonReadRefused},
		{name: "example.com/unsafe", answer: fail(fmt.Errorf("%w: %s", artifact.ErrUnsafeArchive, theirs)),
			status: wire.Refused, outcome: allow.Person, reason: allow.ReasonReadRefused},
		{name: "example.com/badref", answer: fail(fmt.Errorf("%w: %s", artifact.ErrBadRef, theirs)),
			status: wire.Refused, outcome: allow.Person, reason: allow.ReasonReadRefused},
		{name: "example.com/container", answer: fail(fmt.Errorf("%w: %s", artifact.ErrActionKind, theirs)),
			status: wire.Refused, outcome: allow.Person, reason: allow.ReasonReadRefused, detail: "A container action runs an image, and nothing of an image is read"},
		{name: "example.com/pathname", answer: fail(fmt.Errorf("%w: %s", artifact.ErrPathName, theirs)),
			status: wire.Refused, outcome: allow.Person, reason: allow.ReasonReadRefused, detail: "a path with characters other than letters, digits and ._/@+-"},
		// An error without a name is a person, never a wait.
		{name: "example.com/disk", answer: fail(errors.New("no space left on device: " + theirs)),
			status: wire.Refused, outcome: allow.Person, reason: allow.ReasonReadRefused},
		{name: "example.com/crash", answer: func(artifact.Pair) (artifact.Prepared, error) { panic("index out of range: " + theirs) },
			status: wire.Refused, outcome: allow.Person, reason: allow.ReasonReadRefused},
		// No artifact named: nothing to read, nothing verified.
		{name: "example.com/unnamed", noPair: true, status: wire.Nothing, outcome: allow.Person, reason: allow.ReasonReadUnknown},
		{name: "example.com/big", answer: func(p artifact.Pair) (artifact.Prepared, error) {
			return preparedRead(p, "+one\n", "+two\n", "+three\n"), nil
		}, status: wire.Prepared, chunks: 3, outcome: allow.Merge},
		{name: "example.com/last", status: wire.Prepared, chunks: 1, outcome: allow.Merge},
	}

	var updates []allow.UpdateFacts
	for _, tc := range cases {
		updates = append(updates, goodUpdate(t, allow.GoModules, tc.name))
	}
	j := newJob(t, model.GoModules, updates...)
	j.gatherer.res.Artifacts = nil
	for i, tc := range cases {
		if tc.answer != nil {
			j.preparer.answers[tc.name] = tc.answer
		}
		if !tc.noPair {
			j.gatherer.res.Artifacts = append(j.gatherer.res.Artifacts, pairFor(allow.GoModules, updates[i]))
		}
	}
	dir, f := j.run(t)

	if len(f.Facts.Updates) != len(cases) {
		t.Fatalf("%d updates, want %d", len(f.Facts.Updates), len(cases))
	}
	d := decide(t, f, cleanVerdicts(f))
	wantFiles := 0
	for i, tc := range cases {
		read := f.Facts.Updates[i].Prepared
		if read.Status != tc.status || len(read.Chunks) != tc.chunks {
			t.Errorf("%s: read %+v, want status %s with %d chunks", tc.name, read, tc.status, tc.chunks)
		}
		if (read.Detail == "") != (tc.status == wire.Prepared) || !strings.Contains(read.Detail, tc.detail) {
			t.Errorf("%s: detail %q, want one with %q", tc.name, read.Detail, tc.detail)
		}
		// A chunk file is named by the update's position among the
		// updates, not among the artifacts.
		for n, c := range read.Chunks {
			if c.Name != wire.ChunkName(i, n) {
				t.Errorf("%s: chunk %d is named %s", tc.name, n, c.Name)
			}
		}
		wantFiles += tc.chunks
		got := d.PerUpdate[i]
		if got.Outcome != tc.outcome || (tc.reason != "" && !reflect.DeepEqual(got.Reasons, []allow.Reason{tc.reason})) {
			t.Errorf("%s: decided %s %v, want %s %q", tc.name, got.Outcome, got.Reasons, tc.outcome, tc.reason)
		}
	}
	if got := chunkFiles(t, dir); len(got) != wantFiles {
		t.Errorf("chunk files %v, want %d", got, wantFiles)
	}
	if len(j.preparer.pairs) != len(cases)-1 {
		t.Errorf("the reader was called %d times, want once for each named artifact", len(j.preparer.pairs))
	}
	b, err := os.ReadFile(filepath.Join(dir, wire.FactsFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "PUBLISHER-TEXT") {
		t.Error("an error's text reached the facts file")
	}
	// Go's NoRegress is the gatherer's alone.
	for i, u := range f.Facts.Updates {
		if u.NoRegress != updates[i].NoRegress {
			t.Errorf("%s: no regress %+v", u.Name, u.NoRegress)
		}
	}
}

// The context ending is the run ending: no update is blamed for it and
// no file is written.
func TestFetchContextEnds(t *testing.T) {
	j := newJob(t, model.GoModules, goodUpdate(t, allow.GoModules, "example.com/a"), goodUpdate(t, allow.GoModules, "example.com/b"))
	ctx, cancel := context.WithCancel(context.Background())
	j.preparer.answers["example.com/a"] = func(artifact.Pair) (artifact.Prepared, error) {
		cancel()
		return artifact.Prepared{}, fmt.Errorf("fetching: %w", context.Canceled)
	}
	dir := filepath.Join(t.TempDir(), "facts")
	if _, err := j.fetch.Run(ctx, dir); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: %v, want the context's error", err)
	}
	if _, err := os.Stat(filepath.Join(dir, wire.FactsFile)); !os.IsNotExist(err) {
		t.Errorf("a facts file was written: %v", err)
	}
	if len(j.preparer.pairs) != 1 {
		t.Errorf("the reader was called %d times after the context ended", len(j.preparer.pairs))
	}
}

// A gatherer's error is the run's: facts.Gatherer returns one only where
// there is no result to decide on.
func TestFetchGathererError(t *testing.T) {
	j := newJob(t, model.NPM)
	j.gatherer.err = errors.New("npm is not installed")
	dir := filepath.Join(t.TempDir(), "facts")
	if _, err := j.fetch.Run(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "npm is not installed") {
		t.Fatalf("Run: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, wire.FactsFile)); !os.IsNotExist(err) {
		t.Errorf("a facts file was written: %v", err)
	}
}

// npm's NoRegress is made in the fetch job and nowhere else (spec section
// 11, amendments 5 and 21): from what the gatherer hands over beside the
// update and what the reader found in the tarballs. Every row is a pull
// request that merges but for its NoRegress: old enough, read in full, no
// veto. It merges only when both halves hold.
func TestFetchNPMInspection(t *testing.T) {
	const (
		yes = iota
		no
		missing
		unavailable
	)
	inspected := func(f allow.Fact) func(artifact.Pair) (artifact.Prepared, error) {
		return func(p artifact.Pair) (artifact.Prepared, error) {
			out := preparedRead(p, "+x\n")
			out.Inspected = f
			return out, nil
		}
	}
	fail := func(err error) func(artifact.Pair) (artifact.Prepared, error) {
		return func(artifact.Pair) (artifact.Prepared, error) { return artifact.Prepared{}, err }
	}
	clean := allow.Yes("no install script in 3 package.json", "the tarballs")
	for _, tc := range []struct {
		name string
		eco  model.Ecosystem
		// soFar is the gatherer's half; the zero Fact means it holds.
		soFar allow.Fact
		// inUpdate is what a gatherer wrongly put in the update itself.
		inUpdate  allow.Fact
		answer    func(artifact.Pair) (artifact.Prepared, error)
		noPair    bool
		want      int
		wantValue string
		merges    bool
	}{
		{name: "both hold", eco: model.NPM, answer: inspected(clean), want: yes,
			wantValue: "nothing lost; no install script in 3 package.json", merges: true},
		// The reader gives nothing, could not get the tarballs, or says no.
		{name: "a reader that does not inspect", eco: model.NPM, answer: inspected(allow.Fact{}), want: missing},
		{name: "the tarballs could not be read back", eco: model.NPM, answer: inspected(allow.Fact{Value: "the tarballs could not be read"}), want: missing},
		{name: "an inspection that is unavailable", eco: model.NPM, answer: inspected(allow.Unavailable("the tarballs could not be downloaded", "the tarballs")), want: unavailable},
		{name: "the tarball has a new install script", eco: model.NPM,
			answer: inspected(allow.No("node_modules/inner/package.json is new and has an install script", "the tarballs")), want: no},
		// The gatherer's half does not hold, whatever the tarballs say.
		{name: "the registry already said no", eco: model.NPM, soFar: allow.No("a new postinstall script", "registry"),
			answer: inspected(clean), want: no, wantValue: "a new postinstall script"},
		{name: "the registry's answer could not be used", eco: model.NPM, soFar: allow.Fact{Value: "the registry's answer could not be used"},
			answer: inspected(clean), want: missing},
		// A NoRegress in the update itself is not read.
		{name: "a gatherer that says yes in the update, and the tarballs say no", eco: model.NPM, inUpdate: allow.Yes("nothing lost", "registry"),
			answer: inspected(allow.No("binding.gyp is new", "the tarballs")), want: no},
		{name: "a gatherer that says yes in the update, and no beside it", eco: model.NPM, inUpdate: allow.Yes("nothing lost", "registry"),
			soFar: allow.No("a new postinstall script", "registry"), answer: inspected(clean), want: no},
		{name: "a gatherer that says yes in the update, and nothing was inspected", eco: model.NPM, inUpdate: allow.Yes("nothing lost", "registry"),
			answer: inspected(allow.Fact{}), want: missing},
		// No read was prepared at all. These wait or go to a person for
		// the read as well.
		{name: "the registry did not deliver the tarball", eco: model.NPM, answer: fail(fmt.Errorf("%w", artifact.ErrUnavailable)), want: unavailable},
		{name: "the registry said no and did not deliver", eco: model.NPM, soFar: allow.No("a new postinstall script", "registry"),
			answer: fail(fmt.Errorf("%w", artifact.ErrUnavailable)), want: no},
		{name: "the tarball does not match its hash", eco: model.NPM, answer: fail(fmt.Errorf("%w", artifact.ErrHashMismatch)), want: missing},
		{name: "no artifact was named", eco: model.NPM, noPair: true, want: missing},
		// Only npm has this third source.
		{name: "a Go module is not inspected", eco: model.GoModules, answer: inspected(allow.Fact{}), want: yes, wantValue: "nothing lost", merges: true},
		{name: "an action is not inspected", eco: model.GitHubActions, answer: fail(fmt.Errorf("%w", artifact.ErrUnavailable)), want: yes, wantValue: "nothing lost"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name, _ := ecosystem(tc.eco)
			u := goodUpdate(t, name, "example-package")
			if tc.soFar != (allow.Fact{}) {
				u.NoRegress = tc.soFar
			}
			j := newJob(t, tc.eco, u)
			if tc.inUpdate != (allow.Fact{}) {
				j.gatherer.res.Updates[0].NoRegress = tc.inUpdate
			}
			if tc.noPair {
				j.gatherer.res.Artifacts = nil
			}
			j.preparer.answers[u.Name] = tc.answer
			_, f := j.run(t)

			got := f.Facts.Updates[0].NoRegress
			state := missing
			switch {
			case got.Holds():
				state = yes
			case got.Gathered():
				state = no
			case got.Unavailable && got.Source != "":
				state = unavailable
			}
			if state != tc.want || (tc.wantValue != "" && got.Value != tc.wantValue) {
				t.Errorf("no regress %+v", got)
			}
			if d := decide(t, f, cleanVerdicts(f)); (d.Outcome == allow.Merge) != tc.merges {
				t.Errorf("decision %s %v, want merge: %v", d.Outcome, d.Reasons, tc.merges)
			}
		})
	}

	// A gatherer that hands over nothing beside its updates is a broken
	// one, and the run fails: no facts file, so no decision.
	j := newJob(t, model.NPM, goodUpdate(t, allow.NPM, "example-package"))
	j.gatherer.res.NoRegressSoFar = nil
	j.gatherer.res.Updates[0].NoRegress = allow.Yes("nothing lost", "registry")
	if _, err := j.fetch.Run(context.Background(), filepath.Join(t.TempDir(), "facts")); err == nil {
		t.Error("an npm result without the registry's half of NoRegress was accepted")
	}
}

// When Shape does not hold the change set is not to be trusted, and
// nothing it names is downloaded.
func TestFetchShapeDoesNotHold(t *testing.T) {
	j := newJob(t, model.GoModules, goodUpdate(t, allow.GoModules, "example.com/m"))
	j.gatherer.res.Shape = allow.No("vendor/modules.txt also changed", "manifests")
	_, f := j.run(t)
	if len(j.preparer.pairs) != 0 || f.Facts.Updates[0].Prepared.Status != wire.Nothing {
		t.Errorf("an artifact was fetched: %+v", f.Facts.Updates[0].Prepared)
	}
	wantOutcome(t, decide(t, f, nil), allow.Person, allow.ReasonShape)
}

// A change set too large to read is a Shape that does not hold, not a
// failed job.
func TestFetchChangesRefused(t *testing.T) {
	j := newJob(t, model.GoModules, goodUpdate(t, allow.GoModules, "example.com/m"))
	j.fetch.Changes = Changes{Base: mergeSHA, Head: headSHA, Refused: "the pull request changes 4000 paths, more than 1000"}
	_, f := j.run(t)
	if len(j.gatherer.inputs) != 0 || len(j.preparer.pairs) != 0 {
		t.Error("the gatherer or the reader ran")
	}
	if f.Facts.Shape.Holds() || !f.Facts.Shape.Gathered() || f.Facts.Shape.Value != j.fetch.Changes.Refused {
		t.Errorf("shape %+v", f.Facts.Shape)
	}
	// The pull request's own facts are still there.
	if !f.Facts.Identity.Holds() || !f.Facts.ChecksConfigured.Holds() {
		t.Errorf("identity %+v, checks %+v", f.Facts.Identity, f.Facts.ChecksConfigured)
	}
	wantOutcome(t, decide(t, f, nil), allow.Person, allow.ReasonShape)
}

// Facts the file cannot carry do not fail the job: the file that is
// written sends the pull request to a person.
func TestFetchTooMuch(t *testing.T) {
	t.Run("more updates than the file holds", func(t *testing.T) {
		var updates []allow.UpdateFacts
		for i := range 1001 {
			updates = append(updates, goodUpdate(t, allow.GoModules, fmt.Sprintf("example.com/m%d", i)))
		}
		j := newJob(t, model.GoModules, updates...)
		dir, f := j.run(t)
		// Found before anything was downloaded.
		if len(j.preparer.pairs) != 0 || len(f.Facts.Updates) != 0 || len(chunkFiles(t, dir)) != 0 {
			t.Errorf("%d reads prepared, %d updates written", len(j.preparer.pairs), len(f.Facts.Updates))
		}
		if f.Facts.Shape.Holds() || f.Facts.Shape.Gathered() || !f.Facts.Identity.Holds() {
			t.Errorf("shape %+v, identity %+v", f.Facts.Shape, f.Facts.Identity)
		}
		wantOutcome(t, decide(t, f, nil), allow.Person, allow.ReasonFactMissing)
	})
	t.Run("a read the file does not carry", func(t *testing.T) {
		j := newJob(t, model.GoModules, goodUpdate(t, allow.GoModules, "example.com/a"), goodUpdate(t, allow.GoModules, "example.com/b"))
		j.preparer.answers["example.com/b"] = func(p artifact.Pair) (artifact.Prepared, error) {
			out := preparedRead(p, "+x\n")
			out.Key = "not a content key"
			return out, nil
		}
		dir, f := j.run(t)
		// The chunks that were written are gone with the updates: the
		// directory holds what the file lists.
		if len(f.Facts.Updates) != 0 || len(chunkFiles(t, dir)) != 0 {
			t.Errorf("%d updates, chunk files %v", len(f.Facts.Updates), chunkFiles(t, dir))
		}
		wantOutcome(t, decide(t, f, nil), allow.Person, allow.ReasonFactMissing)
	})
}

// A read can be partial with nothing unread: the note that names the
// removed files did not fit (internal/artifact). The facts file carries
// that, and the update waits like any other partial read.
func TestFetchPartialWithNothingUnread(t *testing.T) {
	j := newJob(t, model.GoModules, goodUpdate(t, allow.GoModules, "example.com/m"))
	j.preparer.answers["example.com/m"] = func(p artifact.Pair) (artifact.Prepared, error) {
		out := preparedRead(p, "== file: a.go (changed)\n+new\n")
		out.State = allow.ReadPartial
		return out, nil
	}
	_, f := j.run(t)
	read := f.Facts.Updates[0].Prepared
	if read.Status != wire.Prepared || read.State != allow.ReadPartial || len(read.Unread) != 0 {
		t.Fatalf("read %+v", read)
	}
	// The reviewer read all it was sent; the prepared state is the ceiling.
	wantOutcome(t, decide(t, f, cleanVerdicts(f)), allow.Wait, allow.ReasonAge)
}

// The output directory's chunks are this run's and nothing else.
func TestFetchFreshOutput(t *testing.T) {
	j := newJob(t, model.GoModules, goodUpdate(t, allow.GoModules, "example.com/m"))
	dir, _ := j.run(t)
	if _, err := j.fetch.Run(context.Background(), dir); err == nil {
		t.Error("a second run wrote into the first one's directory")
	}
}

// What the job cannot work with at all is an error.
func TestFetchBadInput(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Fetch)
	}{
		{"no repository", func(f *Fetch) { f.Class.Repo = "" }},
		{"a repository that is a path", func(f *Fetch) { f.Class.Repo = "../../x" }},
		{"no pull request", func(f *Fetch) { f.Class.PR = 0 }},
		{"a short head", func(f *Fetch) { f.Class.HeadSHA = "abc123" }},
		{"changes of another head", func(f *Fetch) { f.Changes.Head = strings.Repeat("e", 40) }},
		{"changes without a merge base", func(f *Fetch) { f.Changes.Base = "" }},
		{"no gatherer for the ecosystem", func(f *Fetch) { f.Gatherers = nil }},
		{"no GitHub client", func(f *Fetch) { f.GitHub = nil }},
		{"no reader", func(f *Fetch) { f.Preparer = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := newJob(t, model.GoModules, goodUpdate(t, allow.GoModules, "example.com/m"))
			tc.change(&j.fetch)
			dir := filepath.Join(t.TempDir(), "facts")
			if _, err := j.fetch.Run(context.Background(), dir); err == nil {
				t.Fatal("Run succeeded")
			}
			if _, err := os.Stat(filepath.Join(dir, wire.FactsFile)); !os.IsNotExist(err) {
				t.Errorf("a facts file was written: %v", err)
			}
		})
	}
}

// NeedsChanges says exactly when Run looks at the change set: without
// one, Run succeeds where it says no and fails where it says yes.
func TestNeedsChanges(t *testing.T) {
	for _, tc := range []struct {
		kind model.Kind
		eco  model.Ecosystem
		want bool
	}{
		{model.KindDependabot, model.GoModules, true},
		{model.KindDependabot, model.Docker, true},
		{model.KindPending, model.NPM, true},
		{model.KindDependabotUnverified, model.GoModules, false},
		{model.KindDependabot, model.UV, false},
		{model.KindPending, model.GitSubmodule, false},
	} {
		t.Run(string(tc.kind)+" "+string(tc.eco), func(t *testing.T) {
			name := allow.GoModules
			if gate, ok := ecosystem(tc.eco); ok {
				name = gate
			}
			j := newJob(t, tc.eco, goodUpdate(t, name, "example.com/m"))
			j.fetch.Class.Kind = tc.kind
			j.fetch.Changes = Changes{}
			if got := NeedsChanges(j.fetch.Class); got != tc.want {
				t.Errorf("NeedsChanges = %v, want %v", got, tc.want)
			}
			_, err := j.fetch.Run(context.Background(), filepath.Join(t.TempDir(), "facts"))
			if failed := err != nil; failed != tc.want {
				t.Errorf("Run without a change set: %v", err)
			}
		})
	}
}

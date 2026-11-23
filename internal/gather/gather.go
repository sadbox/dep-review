// Package gather is the fetch job and the review job as library code
// (docs/v0.2-spec.md, section 8). The commands around it only read flags
// and files.
//
//   - Fetch establishes everything deterministic code can know about one
//     pull request: the pull request's own facts, the ecosystem's facts
//     for every update, and the text the model is to read. It writes the
//     facts file and the chunk files (internal/wire). It holds nothing
//     but the job's read-only token, and it is the code that reads what a
//     pull request and its dependencies wrote, so it never runs anything
//     from the checkout: the changed files come from git objects
//     (ReadChanges).
//   - Review reads that directory back, believing it only as far as
//     internal/wire verified it, puts each prepared read before the
//     reviewer and writes the verdicts file. To it a chunk is bytes.
//
// Neither decides anything, and neither writes to GitHub. Publish joins
// the two files (wire.Join) and calls allow.Decide.
//
// One rule runs through both: a failure that belongs to one update is
// recorded for that update, in the state that says what becomes of it
// (wait or person), and the job goes on. A job that fails the same way
// every time it meets one bad archive would leave a pull request with no
// answer at all.
package gather

import (
	"net/http"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/facts"
	"github.com/sadbox/dep-review/internal/facts/actions"
	"github.com/sadbox/dep-review/internal/facts/docker"
	"github.com/sadbox/dep-review/internal/facts/gomod"
	"github.com/sadbox/dep-review/internal/facts/npm"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
)

// ecosystem maps Dependabot's name for an ecosystem, the one in its
// branch names, to the gate's (the keys of the policy list), and reports
// whether the gate has a rule for it. An ecosystem without one keeps
// Dependabot's name, so the comment can say which it was.
func ecosystem(e model.Ecosystem) (string, bool) {
	switch e {
	case model.GoModules:
		return allow.GoModules, true
	case model.NPM:
		return allow.NPM, true
	case model.GitHubActions:
		return allow.GitHubActions, true
	case model.Docker:
		return allow.Docker, true
	}
	return string(e), false
}

// NeedsChanges reports whether Fetch.Run looks at the change set of the
// pull request class describes. It does not for a pull request that is
// not Dependabot's alone, nor in an ecosystem without a rule: nothing is
// gathered for those, so the caller need not read a change set, and a
// checkout it cannot read one from is no reason to fail.
func NeedsChanges(class model.Classification) bool {
	_, hasRule := ecosystem(class.Ecosystem)
	return hasRule && class.Kind != model.KindDependabotUnverified
}

// Gatherers returns the fact gatherer of every ecosystem that has a rule,

// by the gate's name for it. It is Fetch.Gatherers outside tests.
func Gatherers() map[string]facts.Gatherer {
	return map[string]facts.Gatherer{
		allow.GoModules:     gomod.New(),
		allow.NPM:           npm.Gatherer{},
		allow.GitHubActions: actions.New(),
		allow.Docker:        docker.New(),
	}
}

// NewPreparer returns the artifact reader the fetch job uses. It is
// internal/artifact's, told to run npm's own look at the verified
// tarballs (spec section 11, amendment 5): internal/artifact cannot
// import the npm gatherer, so the function is handed over here, and
// Fetch ANDs its answer into NoRegress. scratch, hc and github are
// artifact.Options' fields of those names.
func NewPreparer(scratch string, hc *http.Client, github *gh.Client) (artifact.Preparer, error) {
	return artifact.New(artifact.Options{
		Scratch: scratch,
		HTTP:    hc,
		GitHub:  github,
		Inspect: map[artifact.Kind]artifact.Inspect{artifact.NPMTarball: npm.InspectTarballs},
	})
}

// Package facts is what every ecosystem's fact gatherer has in common
// (docs/v0.2-spec.md, sections 3 and 6): what a gatherer is given, and
// what it hands back. The gatherers themselves are the subpackages
// (gomod, npm, actions, docker).
//
// This file is the package's API. A gatherer runs in a job with no
// secrets. It reads formats with the real tool or a vetted library, or
// matches one exact anchored line shape; anything it does not recognise
// is a fact that does not hold, never a guess.
//
// Every fact a gatherer returns is in one of allow.Fact's states, and
// which one is the gatherer's most important choice (spec section 11,
// amendment 1):
//
//   - The source answered: allow.Yes or allow.No. A 404, a hash that
//     differs and a deprecation notice are all answers.
//   - The source was asked and did not answer (a network error, a
//     timeout, a 429 or a 5xx on a request the gatherer made itself,
//     after its retries): allow.Unavailable, or allow.UnavailableTime for
//     a clock. allow.Decide waits and the next evaluation asks again. An
//     unreachable source is this, never a Gather error and never a "no".
//   - Nothing could be established, and asking again would not help (an
//     answer in a shape the gatherer does not know, a name it will not
//     put in a URL): the fact is left without a Source, with the reason
//     in its Value. That is person.
//
// When several conditions make one fact they are combined with
// allow.Fact.And, or in its order: a "no" first, then never gathered,
// then unavailable.
package facts

import (
	"context"
	"net/http"
	"time"

	"github.com/sadbox/dep-review/internal/advisory"
	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/gh"
)

// File is one path the pull request changes, as it is at both commits.
type File struct {
	// Path is relative to the repository root, with "/" separators.
	Path string
	// BaseMode and HeadMode are git's file modes ("100644", "100755",
	// "120000", "160000"), and empty when the path does not exist at that
	// commit. A gatherer needs them to tell a regular file from a symlink
	// or a submodule, which the content alone does not show.
	BaseMode string
	HeadMode string
	// Base and Head are the blob contents. For a path that does not exist
	// at a commit the content is nil; use the mode, not nil, to tell
	// "absent" from "empty".
	Base []byte
	Head []byte
}

// Input is what every gatherer receives.
type Input struct {
	// Repo is the repository, owner/name.
	Repo string
	// Base and Head are the two commits the pull request is between, as
	// full hex IDs. Base is the merge base on the default branch.
	Base string
	Head string
	// Files is every path that differs between Base and Head, not only
	// the ones this ecosystem expects: Shape is about there being no
	// others. It comes from git, never from the pull request's metadata.
	Files []File
	// Policy is the resolved policy, from the default branch. A gatherer
	// needs it for the Listed fact (allow.Listed) and nothing else: ages
	// and outcomes are allow.Decide's business.
	Policy allow.Policy
	// HTTP is the client for registries and indexes that take no
	// credentials (the Go index, the npm registry, Docker Hub). Tests
	// give it a transport that replays recorded fixtures.
	HTTP *http.Client
	// GitHub is the REST client holding the job's read-only token, for
	// facts GitHub itself is the source of (tags, comparisons, releases).
	// Nil for a gatherer that needs none.
	GitHub *gh.Client
	// Advisories answers SecurityFix and the advisory half of Clean.
	Advisories advisory.Checker
	// Now is the clock. A gatherer never calls time.Now itself, so a
	// test can pin the time a fact was read at.
	Now func() time.Time
	// Opened is when GitHub created the pull request (its created_at),
	// and the zero time when that is not known. It is the first-seen
	// fallback of spec section 11, amendment 4: the pinned artifact
	// existed when Dependabot proposed it, and no publisher sets that
	// time. The fetch command applies the fallback, not the gatherer: a
	// gatherer returns FirstSeen as its registry's clock gave it (known,
	// unavailable, or not established with the reason in Value), and
	// where it is not known the fetch command puts Opened there with the
	// source "pull request opened". A gatherer may use Opened to bound a
	// search of its own (the Go index is read forward from a time).
	Opened time.Time
}

// Result is what every gatherer returns.
type Result struct {
	// Shape is the pull request's Shape fact for this ecosystem: only its
	// manifest and lock files changed, and only version or hash tokens in
	// them.
	Shape allow.Fact
	// Updates is every package the pull request moves, computed from the
	// base and head manifests. Each entry has every fact filled in except
	// Read and Veto, which are set from the model's verdict much later,
	// by the job that decides; the file the fetch job writes
	// (internal/wire) cannot even carry them. A gatherer leaves both
	// zero. For Docker, where nothing can be read, the deciding job sets
	// Read to allow.ReadNotApplicable from the ecosystem alone. The npm
	// gatherer leaves NoRegress unset as well; see NoRegressSoFar.
	//
	// When Shape does not hold the change set cannot be trusted either,
	// and Updates may be empty.
	Updates []allow.UpdateFacts
	// NoRegressSoFar is npm's alone. Whether an npm update brings a new
	// install step is settled only by the files in its verified tarball,
	// which the gatherer never sees. So the npm gatherer puts what the
	// registry and the lock say here, one fact for each of Updates in the
	// same order, and leaves every update's NoRegress unset: nothing it
	// returns can hold by itself. The fetch command is the one place that
	// makes NoRegress, from this fact and the artifact reader's
	// inspection of the tarballs (artifact.Prepared.Inspected), and
	// without an inspection it does not hold.
	NoRegressSoFar []allow.Fact
	// Artifacts lists what the model is to read: for each update with
	// something readable, the old and the new artifact, each with the
	// hash the Bound fact was established for. An entry belongs to the
	// update with the same Name, From and To. Empty for Docker.
	Artifacts []artifact.Pair
}

// Gatherer establishes one ecosystem's facts for one pull request.
type Gatherer interface {
	// Gather reads the change set and gathers the facts.
	//
	// A fact that could not be established is returned as such, in the
	// state that says why (see the package comment): unavailable when its
	// source did not answer, without a Source when nothing can establish
	// it. An error is for a failure of the run itself (the context ended,
	// a tool is not installed, the Input is incomplete), where there is
	// no result to decide on and the job should fail and be run again. A
	// registry, an index or an API that is down is not such a failure.
	Gather(ctx context.Context, in Input) (Result, error)
}

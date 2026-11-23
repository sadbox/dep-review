// Package facts is what every ecosystem's fact gatherer has in common
// (docs/v0.2-spec.md, sections 3 and 6): what a gatherer is given, and
// what it hands back. The gatherers themselves are the subpackages
// (gomod, npm, actions, docker).
//
// This file is the package's API. A gatherer runs in a job with no
// secrets. It reads formats with the real tool or a vetted library, or
// matches one exact anchored line shape; anything it does not recognise
// is a fact that does not hold, never a guess.
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
}

// Result is what every gatherer returns.
type Result struct {
	// Shape is the pull request's Shape fact for this ecosystem: only its
	// manifest and lock files changed, and only version or hash tokens in
	// them.
	Shape allow.Fact
	// Updates is every package the pull request moves, computed from the
	// base and head manifests. Each entry has every fact filled in except
	// Read and Veto, which the caller sets from the model's verdict.
	// Docker is the exception: nothing can be read, so its gatherer sets
	// Read to allow.ReadNotApplicable itself.
	//
	// When Shape does not hold the change set cannot be trusted either,
	// and Updates may be empty.
	Updates []allow.UpdateFacts
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
	// A fact that could not be established is returned as such: left
	// ungathered (the zero allow.Fact), or gathered as not holding, with
	// what was seen in its Value. Either way allow.Decide answers person.
	// An error is for a failure of the run itself (the context ended, a
	// tool is not installed), where there is no result to decide on and
	// the job should fail and be run again.
	Gather(ctx context.Context, in Input) (Result, error)
}

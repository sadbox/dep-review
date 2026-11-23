// Package advisory asks GitHub's Advisory Database about one update: is
// it a security fix, and is anything known against the new version
// (docs/v0.2-spec.md, sections 3 and 4).
//
// This file is the package's API. GitHub evaluates the version ranges;
// nothing here compares versions except the one string comparison the
// definition of a security fix needs.
package advisory

import (
	"context"

	"github.com/sadbox/dep-review/internal/allow"
)

// Query names one update.
type Query struct {
	// Ecosystem is one of allow's ecosystem constants. The checker maps
	// it to the database's own name ("go", "npm", "actions").
	Ecosystem string
	// Name is the package as allow.UpdateFacts names it: the module path,
	// the npm package name, or for Actions owner/repo. An action in a
	// directory (owner/repo/path) is accepted too, and is then asked
	// about under both the repository's name and its own.
	Name string
	// From is the version at the base commit; empty for a new name. Go
	// and Actions versions are given as the manifests spell them, with
	// their leading "v".
	From string
	// To is the version at the head commit.
	To string
}

// Result is what the database says about one update. Every fact carries
// the query it came from as its Source and the advisory IDs as its Value,
// so the pull request comment can show them.
//
// Each fact is in one of allow.Fact's four states:
//
//   - gathered, yes or no: the database answered;
//   - unavailable (allow.Unavailable): the database was asked and did not
//     answer: no response, a server error or a rate limit. A gatherer
//     passes that on, and allow.Decide waits;
//   - never gathered (no Source, the reason in Value): the database
//     could not be asked about this name or version, or what it answered
//     is not what the API documents. That is person. It is never
//     reported as a "no advisory" answer.
//
// For Docker nothing is asked, because the database has no container
// image ecosystem: SecurityFix is a gathered "no", and NoMalware and
// NoNewAdvisory are gathered as holding, with a Value that says nothing
// was asked. For an ecosystem that is not one of allow's four, the two
// are left ungathered.
type Result struct {
	// SecurityFix holds when the database has a reviewed, non-withdrawn
	// advisory that affects From, does not affect To, and names To as the
	// first patched version. For Go and Actions "v1.2.3" and "1.2.3" are
	// the same version in that comparison (spec section 11, amendment 8);
	// nothing else about a version is normalised. It is a gathered "no"
	// (allow.No) when no such advisory exists, when From is empty, and
	// for an ecosystem the database does not cover.
	SecurityFix allow.Fact
	// NoMalware holds when no malware advisory affects To. This is one
	// input to the Clean fact.
	NoMalware allow.Fact
	// NoNewAdvisory holds when no reviewed, non-withdrawn advisory
	// affects To that did not also affect From. This is the other input
	// to the Clean fact this package can know. For a new name every
	// advisory on To is new.
	NoNewAdvisory allow.Fact
}

// Checker answers for one update.
type Checker interface {
	// Check queries the database. Whatever it learned, or failed to
	// learn, is in the three facts; see Result. The error is for a run
	// that is over (the context ended), where there is no result at all.
	Check(ctx context.Context, q Query) (Result, error)
}

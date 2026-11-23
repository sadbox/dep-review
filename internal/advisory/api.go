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
	// Name is the package as allow.UpdateFacts names it.
	Name string
	// From is the version at the base commit; empty for a new name.
	From string
	// To is the version at the head commit.
	To string
}

// Result is what the database says about one update. Every fact carries
// the query it came from as its Source and the advisory IDs as its Value,
// so the pull request comment can show them.
type Result struct {
	// SecurityFix holds when the database has a reviewed, non-withdrawn
	// advisory that affects From, does not affect To, and names To as the
	// first patched version. It is a gathered "no" (allow.No) when no
	// such advisory exists, when From is empty, and for an ecosystem the
	// database does not cover.
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
	// Check queries the database. An error means the database could not
	// be asked at all, and the caller has no result. An answer that could
	// not be established for one of the three facts is that fact left
	// ungathered (the zero allow.Fact), which allow.Decide turns into
	// person; it is never reported as a "no advisory" answer.
	Check(ctx context.Context, q Query) (Result, error)
}

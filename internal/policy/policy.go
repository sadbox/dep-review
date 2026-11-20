// Package policy is the version policy: which update sizes may be merged
// without a human. It is deliberately small and table-tested; everything
// ecosystem-specific lives in the fetchers and arrives here as Findings.
package policy

import (
	"strings"

	"github.com/sadbox/dep-review/internal/model"
)

// RouteFor returns the least automatic route the version policy allows for
// one update, before any evidence is looked at.
//
//   - major, unknown: human.
//   - 0.x minor (0.19 -> 0.20): treated as major, except golang.org/x/*,
//     which the Go project keeps at v0 by policy.
//   - a Go module major (new /vN path) shows up as a different Name and is
//     caught by the fetcher, not here.
//   - proven no-op (Update.NoOp): auto.
//   - patch, minor, digest: review. Security updates follow the same rules;
//     they are ordered first, not waved through.
func RouteFor(u model.Update) model.Route {
	if u.NoOp {
		return model.RouteAuto
	}
	switch u.Type {
	case model.Major, model.Unknown:
		return model.RouteHuman
	case model.Minor:
		if zeroMajor(u.From) && !strings.HasPrefix(u.Name, "golang.org/x/") {
			return model.RouteHuman
		}
		return model.RouteReview
	case model.Patch, model.Digest:
		return model.RouteReview
	}
	return model.RouteHuman
}

// Combine folds the version policy over every update and every finding.
// A PR with no updates at all is refused: Dependabot never opens one.
func Combine(updates []model.Update, findings []model.Finding, truncated bool) model.Route {
	if len(updates) == 0 {
		return model.RouteRefuse
	}
	r := model.RouteAuto
	for _, u := range updates {
		r = model.Worse(r, RouteFor(u))
	}
	for _, f := range findings {
		r = model.Worse(r, f.Route)
	}
	if truncated {
		r = model.Worse(r, model.RouteHuman)
	}
	return r
}

func zeroMajor(v string) bool {
	v = strings.TrimPrefix(v, "v")
	return strings.HasPrefix(v, "0.")
}

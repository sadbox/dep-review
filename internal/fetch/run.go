package fetch

import (
	"context"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/policy"
)

// Registry maps each ecosystem to its fetcher (see cmd/dep-review).
type Registry map[model.Ecosystem]Ecosystem

// NotVerified is the placeholder for an ecosystem the gate cannot verify
// yet: it passes Dependabot's declaration through and forces RouteHuman.
type NotVerified struct{}

func (NotVerified) Fetch(_ context.Context, env Env) (Result, error) {
	return Result{
		Updates: slices.Clone(env.Class.Declared),
		Findings: []model.Finding{{
			Code:   "ecosystem.not-verified",
			Route:  model.RouteHuman,
			Detail: fmt.Sprintf("ecosystem %q not verified yet", env.Class.Ecosystem),
		}},
	}, nil
}

// EvidenceDir is what Run needs from the evidence writer beyond Writer.
type EvidenceDir interface {
	Writer
	Files() []model.EvidenceFile
	Truncated() bool
	Findings() []model.Finding
	WriteEvidence(model.Evidence) error
}

// Run fetches one classified PR: it picks the ecosystem's fetcher, checks
// the real change set against Dependabot's declaration, flags new
// dependencies, combines the route and writes evidence.json. An error means
// the gate could not finish (infrastructure); everything that is a property
// of the PR comes back as a Finding instead.
func Run(ctx context.Context, env Env, reg Registry, ev EvidenceDir) (model.Evidence, error) {
	if env.Class.Kind != model.KindDependabot {
		return model.Evidence{}, fmt.Errorf("classification kind %q: fetch runs only for %q", env.Class.Kind, model.KindDependabot)
	}
	env.Evidence = ev
	var res Result
	if eco, ok := reg[env.Class.Ecosystem]; ok {
		var err error
		if res, err = eco.Fetch(ctx, env); err != nil {
			return model.Evidence{}, fmt.Errorf("%s: %w", env.Class.Ecosystem, err)
		}
	} else {
		res = Result{
			Updates: slices.Clone(env.Class.Declared),
			Findings: []model.Finding{{
				Code: "ecosystem.unknown", Route: model.RouteHuman,
				Detail: fmt.Sprintf("no fetcher for ecosystem %q", env.Class.Ecosystem),
			}},
		}
	}
	updates, findings := CompareDeclared(env.Class.Declared, res.Updates)
	findings = append(res.Findings, findings...)
	findings = append(findings, NewDependencies(updates)...)
	findings = append(findings, ev.Findings()...)

	out := model.Evidence{
		Classification: env.Class,
		Updates:        updates,
		Findings:       findings,
		Files:          ev.Files(),
		Truncated:      ev.Truncated(),
	}
	if out.Updates == nil {
		out.Updates = []model.Update{}
	}
	if out.Findings == nil {
		out.Findings = []model.Finding{}
	}
	if out.Files == nil {
		out.Files = []model.EvidenceFile{}
	}
	out.Route = policy.Combine(out.Updates, out.Findings, out.Truncated)
	if err := ev.WriteEvidence(out); err != nil {
		return model.Evidence{}, err
	}
	return out, nil
}

// CompareDeclared matches Dependabot's declared updates to the real change
// set. A declared update missing from the real set, or declared with a
// different target version, refuses the PR. A different "from" version
// needs a person. Undeclared real updates are expected (transitive
// changes) and are simply reviewed. Matched updates inherit the declared
// security flag and advisories, which only Dependabot knows.
func CompareDeclared(declared, real []model.Update) ([]model.Update, []model.Finding) {
	updates := slices.Clone(real)
	var findings []model.Finding
	for _, d := range declared {
		i := -1
		var matches []int
		for j, u := range updates {
			if u.Name == d.Name && sameDir(u.Directory, d.Directory) {
				matches = append(matches, j)
			}
		}
		if len(matches) > 0 {
			i = matches[0]
		} else {
			findings = append(findings, model.Finding{
				Code: "declared.missing", Route: model.RouteRefuse, Update: d.Name,
				Detail: fmt.Sprintf("Dependabot declares %s %s -> %s in %s, but the manifests and lockfiles do not change it", d.Name, d.From, d.To, dirOrRoot(d.Directory)),
			})
			continue
		}
		// Several copies (lockfile duplicates): prefer the one with the declared target.
		for _, j := range matches {
			if sameVersion(updates[j].To, d.To) {
				i = j
				break
			}
		}
		u := &updates[i]
		if !sameVersion(u.To, d.To) {
			findings = append(findings, model.Finding{
				Code: "declared.to-mismatch", Route: model.RouteRefuse, Update: d.Name,
				Detail: fmt.Sprintf("Dependabot declares %s -> %s, but the change set has %s -> %s", d.Name, d.To, u.From, u.To),
			})
		} else if d.From != "" && !sameVersion(u.From, d.From) {
			findings = append(findings, model.Finding{
				Code: "declared.from-mismatch", Route: model.RouteHuman, Update: d.Name,
				Detail: fmt.Sprintf("Dependabot declares %s from %s, but the base has %s", d.Name, d.From, u.From),
			})
		}
		u.Security = u.Security || d.Security
		for _, a := range d.Advisory {
			if !slices.Contains(u.Advisory, a) {
				u.Advisory = append(u.Advisory, a)
			}
		}
	}
	return updates, findings
}

// NewDependencies flags every update that introduces a package name the
// base did not have at all (From == ""). Fetchers report a new copy of an
// existing package with From set to the version it already had.
func NewDependencies(updates []model.Update) []model.Finding {
	var out []model.Finding
	for _, u := range updates {
		if u.From == "" {
			out = append(out, model.Finding{
				Code: "new-dependency", Route: model.RouteHuman, Update: u.Name,
				Detail: fmt.Sprintf("%s %s is new: the base had no version of it (%s)", u.Name, u.To, dirOrRoot(u.Directory)),
			})
		}
	}
	return out
}

// sameDir compares manifest directories; a declaration without one
// (Dependabot's commit metadata often omits it) matches any directory.
func sameDir(real, declared string) bool {
	return declared == "" || dirOrRoot(real) == dirOrRoot(declared)
}

func dirOrRoot(d string) string { return path.Clean("/" + strings.Trim(d, "/")) }

// sameVersion ignores a leading "v": Dependabot writes "1.2.3" for Go's "v1.2.3".
func sameVersion(a, b string) bool { return strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v") }

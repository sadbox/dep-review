package fetch

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/policy"
)

// Registry maps each ecosystem to its fetcher (see cmd/dep-review).
type Registry map[model.Ecosystem]Ecosystem

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
	updates, findings := CompareDeclared(env.Class.Ecosystem, env.Class.Declared, res.Updates)
	findings = append(res.Findings, findings...)
	findings = append(findings, NewDependencies(updates)...)
	findings = append(findings, ev.Findings()...)
	if len(res.Flagged) > model.MaxFlagged {
		findings = append(findings, model.Finding{
			Code: "flagged.too-many", Route: model.RouteHuman,
			Detail: fmt.Sprintf("checks flagged %d items for the reviewer to assess one by one; more than %d is too many to review", len(res.Flagged), model.MaxFlagged),
		})
	}

	out := model.Evidence{
		Classification: env.Class,
		Updates:        updates,
		Findings:       findings,
		Files:          ev.Files(),
		Truncated:      ev.Truncated(),
		Flagged:        res.Flagged,
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
	if out.Flagged == nil {
		out.Flagged = []model.FlaggedItem{}
	}
	out.Route = policy.Combine(out.Updates, out.Findings, out.Truncated)
	if err := ev.WriteEvidence(out); err != nil {
		return model.Evidence{}, err
	}
	return out, nil
}

// CompareDeclared matches Dependabot's declared updates to the real change
// set. A declared update missing from the real set, or declared with a
// different target, refuses the PR. A different "from" needs a person.
// Undeclared real updates are expected where a lockfile carries transitive
// changes (Go, npm, uv) and are simply reviewed. GitHub Actions and Docker
// have no transitive changes Dependabot declares, so there every real
// update must be named by a declaration with its target, or a person looks
// at it; the one exception is a changed transitive actions.lock entry,
// which the actions fetcher reports as a Direct=false update it analyzed
// like a bump. Matched updates inherit the declared security flag and
// advisories, which only Dependabot knows. Names match per NormalizeName.
//
// Each side is compared on what Dependabot declared for it: the version
// (To/From) and, when its prose names one, the pin (ToRef/FromRef, usually
// abbreviated). A Docker digest bump declares only the tag as its version
// and the two digests as pins, so it matches the fetcher's tag -> tag
// with full digests, and a different digest still refuses.
func CompareDeclared(eco model.Ecosystem, declared, real []model.Update) ([]model.Update, []model.Finding) {
	updates := slices.Clone(real)
	var findings []model.Finding
	covered := make([]bool, len(updates))    // real updates a declaration names, with its target
	coveredBy := make([][]int, len(updates)) // the declarations whose target each real update matches
	for di, d := range declared {
		i := -1
		var matches []int
		for j, u := range updates {
			if SameName(eco, u.Name, d.Name) && sameDir(u.Directory, d.Directory) {
				matches = append(matches, j)
			}
		}
		if len(matches) > 0 {
			i = matches[0]
		} else {
			findings = append(findings, model.Finding{
				Code: "declared.missing", Route: model.RouteRefuse, Update: d.Name,
				Detail: fmt.Sprintf("Dependabot declares %s %s -> %s in %s, but the manifests and lockfiles do not change it", d.Name, side(d.From, d.FromRef), side(d.To, d.ToRef), dirOrRoot(d.Directory)),
			})
			continue
		}
		// Several copies (lockfile duplicates, one image in two Dockerfiles,
		// one action in two workflows): every copy with the declared target
		// is declared, and the first of them is the one compared below.
		chosen := false
		for _, j := range matches {
			if (d.To != "" || d.ToRef != "") && sideMatches(updates[j].To, updates[j].ToRef, d.To, d.ToRef) {
				covered[j] = true
				coveredBy[j] = append(coveredBy[j], di)
				if !chosen {
					i, chosen = j, true
				}
			}
		}
		covered[i] = true // compared below; a wrong target is its own finding
		u := &updates[i]
		if (d.To == "" && d.ToRef == "") || !sideMatches(u.To, u.ToRef, d.To, d.ToRef) {
			findings = append(findings, model.Finding{
				Code: "declared.to-mismatch", Route: model.RouteRefuse, Update: d.Name,
				Detail: fmt.Sprintf("Dependabot declares %s -> %s, but the change set has %s -> %s", d.Name, side(d.To, d.ToRef), side(u.From, u.FromRef), side(u.To, u.ToRef)),
			})
		} else if !sideMatches(u.From, u.FromRef, d.From, d.FromRef) {
			findings = append(findings, model.Finding{
				Code: "declared.from-mismatch", Route: model.RouteHuman, Update: d.Name,
				Detail: fmt.Sprintf("Dependabot declares %s from %s, but the base has %s", d.Name, side(d.From, d.FromRef), side(u.From, u.FromRef)),
			})
		}
		u.Security = u.Security || d.Security
		for _, a := range d.Advisory {
			if !slices.Contains(u.Advisory, a) {
				u.Advisory = append(u.Advisory, a)
			}
		}
	}
	if eco == model.Docker {
		findings = append(findings, inconsistentDigests(declared, updates, coveredBy)...)
	}
	if eco == model.GitHubActions || eco == model.Docker {
		for j, u := range updates {
			// A transitive action (actions.lock) is never declared; the
			// fetcher analyzed it as a bump of its own.
			if !covered[j] && (eco != model.GitHubActions || u.Direct) {
				findings = append(findings, model.Finding{
					Code: "undeclared.update", Route: model.RouteHuman, Update: u.Name,
					Detail: fmt.Sprintf("the change set has %s %s -> %s in %s, which Dependabot's metadata does not declare", u.Name, side(u.From, u.FromRef), side(u.To, u.ToRef), dirOrRoot(u.Directory)),
				})
			}
		}
	}
	return updates, findings
}

// inconsistentDigests works from what each declaration matched, the same
// comparison CompareDeclared made (so "v1.2" and "1.2", or a tag and a
// digest, are one group). Every copy a declaration covers must move to
// the same new digest: a tag-only declaration ("golang 1.27.2 -> 1.27.3")
// matches any digest, so two copies pinned to two digests would otherwise
// both count as declared. A copy covered by more than one declaration is
// flagged too, since it is unclear which one it fulfils.
func inconsistentDigests(declared, updates []model.Update, coveredBy [][]int) []model.Finding {
	var out []model.Finding
	refs := make([][]string, len(declared))
	for j, ds := range coveredBy {
		for _, di := range ds {
			if !slices.Contains(refs[di], updates[j].ToRef) {
				refs[di] = append(refs[di], updates[j].ToRef)
			}
		}
		if len(ds) > 1 {
			u := updates[j]
			out = append(out, model.Finding{
				Code: "docker.inconsistent-digests", Route: model.RouteHuman, Update: u.Name,
				Detail: fmt.Sprintf("%s %s in %s matches %d of Dependabot's declarations", u.Name, side(u.To, u.ToRef), dirOrRoot(u.Directory), len(ds)),
			})
		}
	}
	for di, rs := range refs {
		if len(rs) > 1 {
			d := declared[di]
			var short []string
			for _, r := range rs {
				short = append(short, side("", r))
			}
			out = append(out, model.Finding{
				Code: "docker.inconsistent-digests", Route: model.RouteHuman, Update: d.Name,
				Detail: fmt.Sprintf("Dependabot declares %s -> %s in %s once, but its copies are pinned to %d different new digests: %s", d.Name, side(d.To, d.ToRef), dirOrRoot(d.Directory), len(rs), strings.Join(short, ", ")),
			})
		}
	}
	return out
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

// sideMatches reports whether one side (from or to) of a real update
// agrees with what Dependabot declared for it. A declared version may also
// be a pin (an untagged image's digest, a submodule commit), so it matches
// the real pin too.
func sideMatches(realVer, realRef, declVer, declRef string) bool {
	verOK := declVer == "" || sameVersion(realVer, declVer) || sameRef(realRef, declVer)
	refOK := declRef == "" || sameRef(realRef, declRef)
	return verOK && refOK
}

var (
	fullRefRe   = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	abbrevRefRe = regexp.MustCompile(`^[0-9a-f]{7,64}$`)
)

// sameRef reports whether abbrev (Dependabot's, often 7 hex) is a prefix
// of the full commit SHA or sha256 digest real. Both may carry "sha256:".
func sameRef(real, abbrev string) bool {
	real, abbrev = strings.TrimPrefix(real, "sha256:"), strings.TrimPrefix(abbrev, "sha256:")
	return fullRefRe.MatchString(real) && abbrevRefRe.MatchString(abbrev) && strings.HasPrefix(real, abbrev)
}

// side renders a version and pin for a finding: "1.27@205c7636d74e".
func side(ver, ref string) string {
	ref = strings.TrimPrefix(ref, "sha256:")
	if len(ref) > 12 {
		ref = ref[:12]
	}
	switch {
	case ref == "":
		return ver
	case ver == "":
		return ref
	}
	return ver + "@" + ref
}

// sameVersion ignores a leading "v": Dependabot writes "1.2.3" for Go's "v1.2.3".
func sameVersion(a, b string) bool { return strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v") }

// Package npm gathers the facts for a Dependabot npm pull request
// (docs/v0.2-spec.md, sections 3, 4 and 6).
//
// The change set is npm's own reading of package-lock.json at the base and
// at the head commit: the gatherer runs
//
//	npm ls --all --json --long --package-lock-only --ignore-scripts --offline
//
// twice, each time in a scratch directory that holds nothing but that
// commit's package.json and package-lock.json, and compares the two trees
// npm prints. npm install, npm ci and lifecycle scripts are never run, and
// npm gets a minimal environment with no user or project npmrc.
//
// npm ls prints only the lock entries it can reach from the root, so the
// gatherer also requires the lock's "packages" keys to be exactly the
// paths npm printed. Without that an entry nothing depends on would be
// installed by npm ci and never seen here.
//
// Everything else comes from registry.npmjs.org: the hash the lock pins
// (Bound), when the version and the name appeared (FirstSeen,
// NameCreated), whether the version is still published and not deprecated
// (Clean), and its install scripts and provenance (NoRegress).
//
// Which fact says no for what:
//
//   - Shape: any file other than one directory's package.json and
//     package-lock.json, a lock that is not lockfileVersion 2 or 3, npm
//     reporting a problem, a lock entry npm did not print, a lock entry
//     that carries scripts, a package that keeps its version while its
//     hash, source or flags change, or a package.json change other than
//     the version range of a package that moved.
//   - Bound: a source that is not the registry's own tarball for that name
//     and version (git, file, link, another host, an alias), a hash that
//     is not one sha512, or a hash the registry does not report.
//   - NoRegress: a new or changed install script, or a provenance identity
//     that changed or was lost. The registry and the lock are two of the
//     three sources for install scripts and are read here. The third is
//     the tarball's own files, which InspectTarballs reads once the
//     artifact reader has verified and extracted the tarballs. So the
//     gatherer never returns a NoRegress: what the registry and the lock
//     say goes into facts.Result.NoRegressSoFar, and the fetch command
//     makes the fact from that and the inspection.
//
// Bundled dependencies are part of their parent's artifact, not updates
// of their own (spec section 11, amendment 5). They have no source and no
// hash in the lock: their bytes are the parent's tarball, so the model
// reads them with it and InspectTarballs looks at their package.json and
// binding.gyp files like the parent's. Shape still requires that a
// bundled entry changes only together with the package that carries it.
//
// Every JSON document is read with encoding/json/v2: names match case
// sensitively and a duplicate name is an error. npm copies unknown lock
// fields into its output, so a reader that folded case could be shown one
// "integrity" while npm installs another.
package npm

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/sadbox/dep-review/internal/advisory"
	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/facts"
)

// Gatherer is the npm fact gatherer. The zero value runs the npm found on
// PATH.
type Gatherer struct {
	// NPM is the npm executable to run. Empty means the one on PATH.
	NPM string

	// tool stands in for the real npm in tests that replay recorded
	// output. Nil means run NPM.
	tool tool
}

var _ facts.Gatherer = Gatherer{}

// Gather reads the change set with npm and gathers the facts.
//
// It returns an error only when the run itself failed: the context ended,
// npm or node is not installed, npm is a version this package was not
// tested with, or the scratch directory could not be written. A registry
// or an advisory database that does not answer is not an error: the facts
// it feeds are unavailable, with what failed in their Value, and the next
// evaluation asks again.
func (g Gatherer) Gather(ctx context.Context, in facts.Input) (facts.Result, error) {
	if in.HTTP == nil {
		return facts.Result{}, errors.New("npm: no HTTP client for the registry")
	}
	cs, res, err := g.changes(ctx, in.Files, in.Policy)
	if err != nil {
		return facts.Result{}, err
	}
	reg := &registry{client: in.HTTP, packuments: map[string]packumentAnswer{}}
	for i, u := range cs.updates {
		pair, soFar, err := gatherUpdate(ctx, in, reg, u, &res.Updates[i])
		if err != nil {
			return facts.Result{}, err
		}
		res.NoRegressSoFar = append(res.NoRegressSoFar, soFar)
		if pair != nil {
			res.Artifacts = append(res.Artifacts, *pair)
		}
	}
	return res, nil
}

// Changes is the half of Gather that asks no registry: the Shape fact,
// and every update with the facts npm's reading of the two locks and the
// policy list establish (Known, Listed, NewName, Increase, Major and
// Indirect).
// Every other fact is left unset. It runs npm, which reads the lock
// offline, and returns an error when Gather would for the same reason.
// Gather starts from the same reading; the replay command runs this half
// alone.
func (g Gatherer) Changes(ctx context.Context, files []facts.File, policy allow.Policy) (facts.Result, error) {
	_, res, err := g.changes(ctx, files, policy)
	return res, err
}

// changes is Changes, with the change set its updates were made from: one
// update for each of cs.updates, in the same order. When Shape does not
// hold there are no updates.
func (g Gatherer) changes(ctx context.Context, files []facts.File, policy allow.Policy) (changeSet, facts.Result, error) {
	t := g.tool
	if t == nil {
		real, err := findNPM(g.NPM)
		if err != nil {
			return changeSet{}, facts.Result{}, err
		}
		t = real
	}
	version, err := t.Version(ctx)
	if err != nil {
		return changeSet{}, facts.Result{}, fmt.Errorf("npm --version: %w", err)
	}
	if err := supportedNPM(version); err != nil {
		return changeSet{}, facts.Result{}, err
	}
	// The npm version is part of the source: it is npm's reading the
	// facts rest on, and the reading is only as good as that npm.
	lockSource := "npm " + version + ": " + lsCommand + " at base and head"

	cs, err := readChangeSet(ctx, t, files)
	if err != nil {
		return changeSet{}, facts.Result{}, err
	}
	if len(cs.problems) > 0 {
		// The change set cannot be trusted, so no update is reported and
		// the registry is not asked about names from a lock nobody
		// understood.
		return changeSet{}, facts.Result{Shape: allow.No(summarise(cs.problems), lockSource)}, nil
	}

	res := facts.Result{Shape: allow.Yes(cs.summary, lockSource)}
	for _, u := range cs.updates {
		res.Updates = append(res.Updates, lockFacts(u, policy, lockSource))
	}
	return cs, res, nil
}

// lockFacts is one update with the facts the two locks and the policy
// list establish.
func lockFacts(u update, policy allow.Policy, lockSource string) allow.UpdateFacts {
	uf := allow.UpdateFacts{Name: u.Name, From: u.From, To: u.To}

	const listSource = "policy list (npm)"
	listed := allow.Listed(policy, allow.NPM, u.Name)
	if listed {
		uf.Listed = allow.Yes("on the list", listSource)
	} else {
		uf.Listed = allow.No("not on the list", listSource)
	}
	switch {
	case u.NewName:
		uf.NewName = allow.Yes("no package of this name in the lock at base", lockSource)
	default:
		uf.NewName = allow.No("in the lock at base", lockSource)
	}
	switch {
	case listed:
		uf.Known = allow.Yes("on the list", listSource)
	case !u.NewName:
		uf.Known = allow.Yes("in the lock at base", lockSource)
	default:
		uf.Known = allow.No("not in the lock at base and not on the list", lockSource)
	}
	uf.Increase = increaseFact(u.From, u.To, lockSource)
	uf.Major = majorFact(u.From, u.To, lockSource)
	uf.Indirect = u.Indirect
	return uf
}

// gatherUpdate fills in the facts of one update that the registry and the
// advisory database are the source of: every fact lockFacts left unset,
// except Read, Veto and NoRegress. What the registry and the lock say
// about NoRegress is returned beside the update, never in it (see
// facts.Result.NoRegressSoFar). The pair is nil when Bound does not hold:
// there is then no verified hash to read an artifact against.
func gatherUpdate(ctx context.Context, in facts.Input, reg *registry, u update, uf *allow.UpdateFacts) (*artifact.Pair, allow.Fact, error) {
	// One packument answers Bound, FirstSeen, NameCreated, half of Clean
	// and most of NoRegress. A name the gate will not put in a URL gets no
	// request at all.
	var doc packumentAnswer
	if !validName(u.Name) || !validVersion(u.To) || (u.From != "" && !validVersion(u.From)) {
		doc = packumentAnswer{failed: "the name or a version is not a shape the gate asks the registry about"}
	} else {
		var err error
		doc, err = reg.packument(ctx, u.Name)
		if err != nil {
			return nil, allow.Fact{}, err
		}
	}
	source := packumentURL(u.Name)

	uf.Bound = boundFact(u, doc, source)
	uf.FirstSeen, uf.NameCreated = timeFacts(u, doc, source)

	soFar, err := noRegressFact(ctx, reg, u, doc, source)
	if err != nil {
		return nil, allow.Fact{}, err
	}

	// The advisory database is the other half of Clean and all of
	// SecurityFix. The checker puts whatever it learned, or failed to
	// learn, into its facts: unavailable when the database did not
	// answer, without a source when it could not tell. Its error is the
	// context's. A fact it left blank, and all three when there is no
	// checker or it failed some other way, is given a reason here and
	// stays never gathered, which is person.
	var adv advisory.Result
	blank := "no advisory checker was configured"
	if in.Advisories != nil {
		res, err := in.Advisories.Check(ctx, advisory.Query{Ecosystem: allow.NPM, Name: u.Name, From: u.From, To: u.To})
		switch {
		case ctx.Err() != nil:
			return nil, allow.Fact{}, ctx.Err()
		case err != nil:
			blank = "the advisory checker failed: " + quote(err.Error())
		default:
			adv, blank = res, "the advisory database gave no answer"
		}
	}
	for _, f := range []*allow.Fact{&adv.SecurityFix, &adv.NoMalware, &adv.NoNewAdvisory} {
		if *f == (allow.Fact{}) {
			*f = allow.Fact{Value: blank}
		}
	}
	uf.SecurityFix = adv.SecurityFix
	uf.Clean = cleanFact(u, doc, source, adv)

	var pair *artifact.Pair
	if uf.Bound.Holds() {
		p, ok := artifactPair(u)
		if ok {
			pair = &p
		}
	}
	return pair, soFar, nil
}

// artifactPair names the two tarballs of an update whose Bound holds, each
// with the lock's own hash for it. It reports false when the old version's
// hash in the base lock is not one sha512: the reader could not check that
// tarball, and an update that cannot be read stays unread.
func artifactPair(u update) (artifact.Pair, bool) {
	p := artifact.Pair{Ecosystem: allow.NPM, Name: u.Name, From: u.From, To: u.To}
	p.New = artifact.Ref{Kind: artifact.NPMTarball, Name: u.Name, Version: u.To, Hash: u.New[0].Integrity}
	if u.From == "" {
		return p, true
	}
	old, ok := oneIntegrity(u.Old)
	if !ok {
		return artifact.Pair{}, false
	}
	p.Old = artifact.Ref{Kind: artifact.NPMTarball, Name: u.Name, Version: u.From, Hash: old}
	return p, true
}

// oneIntegrity returns the sha512 integrity every copy agrees on.
func oneIntegrity(copies []node) (string, bool) {
	if len(copies) == 0 {
		return "", false
	}
	first := copies[0].Integrity
	if _, ok := sha512Of(first); !ok {
		return "", false
	}
	for _, c := range copies[1:] {
		if c.Integrity != first {
			return "", false
		}
	}
	return first, true
}

// summarise turns the list of Shape problems into one Value: the first
// problem, and how many more there are.
func summarise(problems []string) string {
	if len(problems) == 1 {
		return problems[0]
	}
	return fmt.Sprintf("%s (and %d more)", problems[0], len(problems)-1)
}

// sortedKeys returns m's keys in order, so everything the gatherer reports
// is the same from run to run.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// list renders up to max items for a Value.
func list(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:max], ", "), len(items)-max)
}

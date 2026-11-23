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
// installed by npm ci and never seen here. Reading the keys, it also
// refuses an entry with a member npm does not write (entryKeys).
//
// Everything else comes from registry.npmjs.org, except NoRegress, which
// the gatherer never returns. The registry and the lock are two of the
// three sources for install scripts and are read here; the third is the
// files in the verified tarballs (InspectTarballs), which the gatherer
// does not have. What the registry and the lock say goes into
// facts.Result.NoRegressSoFar, and the fetch command makes the fact from
// that and the inspection.
//
// Bundled dependencies are part of their parent's artifact, not updates
// of their own (spec section 11, amendment 5). They have no source and no
// hash in the lock: their bytes are the parent's tarball, so the model
// reads them with it and InspectTarballs looks at them like the parent's.
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
	"strings"

	"github.com/sadbox/dep-review/internal/advisory"
	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/facts"
)

// rootLock is the path of the lock a root .npmrc is read for.
const rootLock = "package-lock.json"

// Gatherer is the npm fact gatherer. It runs the npm found on PATH.
type Gatherer struct {
	// tool stands in for the real npm in tests that replay recorded
	// output.
	tool tool
}

var _ facts.Gatherer = Gatherer{}

// Gather reads the change set with npm and gathers the facts. Besides the
// errors of every gatherer, it fails when npm or node is not installed or
// npm is a version this package was not tested with.
func (g Gatherer) Gather(ctx context.Context, in facts.Input) (facts.Result, error) {
	if in.HTTP == nil || in.Advisories == nil {
		return facts.Result{}, errors.New("npm: Input.HTTP and Input.Advisories must be set")
	}
	cs, res, err := g.changes(ctx, in.Files, in.Policy)
	if err != nil {
		return facts.Result{}, err
	}
	// A root .npmrc is the project file of the root package.json and of
	// no other: npm run in a directory reads the .npmrc there. So the
	// fact covers the root's lock only, and for any other lock the
	// install inputs are compared as if there were no such file (spec
	// section 11, amendment 59). A pull request without a Shape has no
	// lock path and no updates.
	if in.ScriptsOff.Holds() && cs.lockPath == rootLock {
		res.ScriptsOff = in.ScriptsOff
	}
	reg := &registry{client: in.HTTP, packuments: map[string]packumentAnswer{}}
	for i, u := range cs.updates {
		pair, soFar, err := gatherUpdate(ctx, in, reg, u, res.ScriptsOff.Holds(), &res.Updates[i])
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
// Indirect). Every other fact is left unset. It runs npm, and returns an
// error when Gather would for the same reason. The replay command runs
// this half alone.
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
		real, err := findNPM()
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
// there is then no verified hash to read an artifact against. scriptsOff
// is whether facts.Result.ScriptsOff holds.
func gatherUpdate(ctx context.Context, in facts.Input, reg *registry, u update, scriptsOff bool, uf *allow.UpdateFacts) (*artifact.Pair, allow.Fact, error) {
	// A name the gate will not put in a URL gets no request at all.
	var doc packumentAnswer
	if !artifact.ValidNPMName(u.Name) || !artifact.ValidNPMVersion(u.To) || (u.From != "" && !artifact.ValidNPMVersion(u.From)) {
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

	soFar, err := noRegressFact(ctx, reg, u, doc, source, scriptsOff)
	if err != nil {
		return nil, allow.Fact{}, err
	}

	// The checker's error is the context's. From any other checker it
	// leaves the facts blank, which is person.
	adv, err := in.Advisories.Check(ctx, advisory.Query{Ecosystem: allow.NPM, Name: u.Name, From: u.From, To: u.To})
	if ctx.Err() != nil {
		return nil, allow.Fact{}, ctx.Err()
	}
	if err != nil {
		adv = advisory.Result{}
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
	if _, ok := artifact.NPMIntegrity(first); !ok {
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

// list renders up to max items for a Value.
func list(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:max], ", "), len(items)-max)
}

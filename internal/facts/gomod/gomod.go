// Package gomod gathers the facts for a Go modules pull request
// (docs/v0.2-spec.md, sections 3, 4 and 6).
//
// The change set and the Shape fact come from go.mod and go.sum at the
// base and head commits: go.mod through golang.org/x/mod/modfile, go.sum
// by one exact line shape. Everything about a module version itself is
// the go command's answer or the module index's, never this package's
// reading of a module:
//
//   - Bound: "go mod download -json" in an empty module with an empty
//     module cache, so sum.golang.org vouches for both hashes go.sum pins.
//   - FirstSeen and NameCreated: the Timestamp of the version's line in
//     index.golang.org, which is the proxy's clock. The commit time only
//     chooses where in the index to start reading.
//   - Clean: "go list -m -u -retracted -json" for the retraction and the
//     deprecation notice, "go list -m -versions -json" as the proof that
//     the retractions were really loaded, and the advisory checker.
//
// A fact the package could not establish is returned as not holding,
// with a value that starts "unknown:". It is never guessed.
package gomod

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

	"github.com/sadbox/dep-review/internal/advisory"
	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/facts"
)

// nameCandidates is how many of a new module's earliest versions are
// looked up in the index to date its name. Any one of them is proof the
// name existed by then; the earliest is tried first because it gives the
// oldest date.
const nameCandidates = 3

// Gatherer gathers the Go modules facts. The zero value is ready to use.
type Gatherer struct {
	// Go is the go command to run. Empty means the one on PATH.
	Go string

	// tool replaces the go command in tests.
	tool goTool
	// indexURL and indexLimit replace the module index and its page size
	// in tests.
	indexURL   string
	indexLimit int
}

var _ facts.Gatherer = (*Gatherer)(nil)

// New returns a Gatherer that runs the go command found on PATH.
func New() *Gatherer { return &Gatherer{} }

// Gather implements facts.Gatherer.
//
// It returns an error only when the run itself failed: the input is
// incomplete, the go command is missing or printed nothing usable, or
// the context ended. A registry that did not answer is an unknown fact,
// not an error.
func (g *Gatherer) Gather(ctx context.Context, in facts.Input) (facts.Result, error) {
	if in.HTTP == nil || in.Advisories == nil || in.Now == nil {
		return facts.Result{}, errors.New("gomod: Input.HTTP, Input.Advisories and Input.Now must be set")
	}

	cs, problem := readChange(in.Files)
	if problem != "" {
		return facts.Result{Shape: allow.No(problem, sourceManifests)}, nil
	}
	res := facts.Result{Shape: allow.Yes(shapeValue(cs), sourceManifests)}
	if len(cs.updates) == 0 {
		return res, nil
	}

	tool := g.tool
	if tool == nil {
		bin := g.Go
		if bin == "" {
			var err error
			if bin, err = exec.LookPath("go"); err != nil {
				return facts.Result{}, fmt.Errorf("gomod: %w", err)
			}
		}
		// A scratch directory per run: the module cache in it starts
		// empty, so the checksum database is asked about every module.
		scratch, err := os.MkdirTemp("", "dep-review-gomod-")
		if err != nil {
			return facts.Result{}, fmt.Errorf("gomod: %w", err)
		}
		defer os.RemoveAll(scratch)
		if tool, err = newGoCommand(bin, scratch); err != nil {
			return facts.Result{}, fmt.Errorf("gomod: %w", err)
		}
	}

	targets := make([]module.Version, len(cs.updates))
	names := make([]module.Version, len(cs.updates))
	for i, up := range cs.updates {
		targets[i] = module.Version{Path: up.name, Version: up.to}
		names[i] = module.Version{Path: up.name}
	}
	downloads, err := download(ctx, tool, targets)
	if err != nil {
		return facts.Result{}, fmt.Errorf("gomod: %w", err)
	}
	infos, err := list(ctx, tool, []string{"-u", "-retracted"}, targets)
	if err != nil {
		return facts.Result{}, fmt.Errorf("gomod: %w", err)
	}
	// Without -retracted the version list leaves retracted versions out,
	// and the go command fails loudly when it cannot load the
	// retractions. With -retracted it reports "not retracted" in silence
	// when the proxy answers "not found" for the go.mod that holds them.
	unretracted, err := list(ctx, tool, []string{"-versions"}, names)
	if err != nil {
		return facts.Result{}, fmt.Errorf("gomod: %w", err)
	}

	ix := &index{client: in.HTTP, url: g.indexURL, limit: g.indexLimit, perVersion: indexPagesPerVersion, left: indexPagesPerRun}
	if ix.url == "" {
		ix.url = defaultIndexURL
	}
	if ix.limit == 0 {
		ix.limit = indexPageLimit
	}
	now := in.Now()

	for i, up := range cs.updates {
		u := allow.UpdateFacts{Name: up.name, From: up.from, To: up.to}
		setManifestFacts(&u, up, cs, in.Policy)

		d, downloadedOK := downloads[targets[i]]
		info, infoOK := infos[targets[i]]
		versions, versionsOK := unretracted[names[i]]

		u.Bound = boundFact(up, cs, d, downloadedOK)

		adv, advErr := in.Advisories.Check(ctx, advisory.Query{Ecosystem: allow.GoModules, Name: up.name, From: up.from, To: up.to})
		if advErr == nil {
			u.SecurityFix = adv.SecurityFix
		}
		u.Clean = cleanFact(up, d, downloadedOK, info, infoOK, versions, versionsOK, adv, advErr)

		if infoOK && info.Error == nil && info.Time != nil {
			u.FirstSeen = seenFact(ctx, ix, up.name, up.to, *info.Time, now)
		} else {
			u.FirstSeen = unknownTime("go list reported no commit time to start reading the index from")
		}
		// The age of the name is asked for only where the decision needs
		// it: a new name that is not on the list.
		if u.NewName.Holds() && !u.Listed.Holds() {
			if u.NameCreated, err = nameCreated(ctx, tool, ix, up.name, versions, versionsOK, now); err != nil {
				return facts.Result{}, fmt.Errorf("gomod: %w", err)
			}
		}

		res.Updates = append(res.Updates, u)
		if pair, ok := artifactPair(up, cs, u.Bound); ok {
			res.Artifacts = append(res.Artifacts, pair)
		}
	}

	// A context that ended part-way leaves facts unknown that a second
	// run would have established. That is a failed run, not a result.
	if err := ctx.Err(); err != nil {
		return facts.Result{}, fmt.Errorf("gomod: %w", err)
	}
	return res, nil
}

// shapeValue describes a change set that has the Go shape.
func shapeValue(cs changeSet) string {
	v := fmt.Sprintf("only go.mod and go.sum change: %d require lines moved or added, %d removed", len(cs.updates), len(cs.removed))
	if len(cs.removed) > 0 {
		shown := cs.removed
		if len(shown) > 5 {
			shown = shown[:5]
		}
		v += " (" + show(strings.Join(shown, ", ")) + ")"
	}
	return v
}

// setManifestFacts fills in the facts that come from go.mod alone:
// NewName, Listed, Known, Increase, Major and NoRegress.
func setManifestFacts(u *allow.UpdateFacts, up update, cs changeSet, policy allow.Policy) {
	isNew := up.from == ""
	if isNew {
		u.NewName = allow.Yes("not required by go.mod at base", sourceManifests)
	} else {
		u.NewName = allow.No("required by go.mod at base at "+up.from, sourceManifests)
	}

	listed := allow.Listed(policy, allow.GoModules, up.name)
	if listed {
		u.Listed = allow.Yes("matches the go_modules list", "policy")
	} else {
		u.Listed = allow.No("not on the go_modules list", "policy")
	}

	switch {
	case !isNew:
		u.Known = allow.Yes("required by go.mod at base", sourceManifests)
	case listed:
		u.Known = allow.Yes("new, and on the go_modules list", "policy")
	default:
		u.Known = allow.No("not required by go.mod at base and not on the go_modules list", sourceManifests)
	}

	u.Increase = increaseFact(up)

	// A module's path carries its major version from v2 on, so a major
	// update of something go.mod already required shows up as one path
	// removed and another added. The added one has no old version to
	// compare with; it is recognised by the path it replaces.
	replaced := ""
	if isNew {
		replaced = replacedPath(up.name, cs.removed)
	}
	switch {
	case replaced != "" && pathMajor(replaced) != pathMajor(up.name):
		u.Major = allow.Yes(fmt.Sprintf("replaces %s: the major version in the module path changed", replaced), sourceManifests)
	case isNew:
		u.Major = allow.No("a new requirement has no previous version", sourceManifests)
	case semver.Major(up.from) != semver.Major(up.to):
		u.Major = allow.Yes(semver.Major(up.from)+" to "+semver.Major(up.to), sourceManifests)
	default:
		u.Major = allow.No("stays on "+semver.Major(up.to), sourceManifests)
	}

	// Go modules run nothing at install time and carry no provenance
	// attestation, so there is nothing of that kind to lose. What can
	// change under an existing requirement is which module it is.
	if replaced != "" {
		u.NoRegress = allow.No(fmt.Sprintf("the module path of an existing requirement changed: %s to %s", replaced, up.name), sourceManifests)
	} else {
		u.NoRegress = allow.Yes("Go modules have no install scripts, and no existing requirement changed its module path", sourceManifests)
	}
}

// increaseFact is the Increase fact: plain releases, and to above from.
func increaseFact(up update) allow.Fact {
	for _, v := range []string{up.from, up.to} {
		switch {
		case v == "":
			// A new requirement has no from.
		case module.IsPseudoVersion(v):
			return allow.No(v+" is a pseudo-version (a commit, not a release)", sourceManifests)
		case !plainRelease(v):
			return allow.No(v+" is not a plain release", sourceManifests)
		}
	}
	switch {
	case up.from == "":
		return allow.Yes("new at "+up.to, sourceManifests)
	case semver.Compare(up.to, up.from) > 0:
		return allow.Yes(up.from+" to "+up.to, sourceManifests)
	}
	return allow.No(up.from+" to "+up.to+" is not an increase", sourceManifests)
}

// plainRelease reports whether v is vX.Y.Z with no pre-release part.
// "+incompatible" is how Go names a v2 or later release of a module
// without a go.mod; it is a release like any other.
func plainRelease(v string) bool {
	build := semver.Build(v)
	return semver.IsValid(v) && semver.Prerelease(v) == "" && (build == "" || build == "+incompatible")
}

// replacedPath returns the base requirement that name takes the place
// of: one that head no longer has and that is the same module at another
// major version (example.com/m/v2 and example.com/m/v3) or in another
// spelling (upper and lower case). Empty when there is none.
func replacedPath(name string, removed []string) string {
	prefix, _, ok := module.SplitPathVersion(name)
	if !ok {
		return ""
	}
	for _, old := range removed {
		if oldPrefix, _, ok := module.SplitPathVersion(old); ok && strings.EqualFold(prefix, oldPrefix) {
			return old
		}
	}
	return ""
}

// pathMajor is the major version suffix of a module path ("/v2", ".v2"
// for gopkg.in), empty for v0 and v1.
func pathMajor(name string) string {
	_, major, _ := module.SplitPathVersion(name)
	return major
}

// boundFact is the Bound fact: both hashes go.sum pins at head for the
// new version are the ones the go command got from the proxy and checked
// against the checksum database just now.
func boundFact(up update, cs changeSet, d downloaded, reported bool) allow.Fact {
	target := up.name + "@" + up.to
	if cs.headSum == nil {
		return allow.No("the pull request does not change go.sum, so it pins nothing new for "+target, sourceManifests)
	}
	zip, haveZip := cs.headSum[sumKey(up.name, up.to, false)]
	mod, haveMod := cs.headSum[sumKey(up.name, up.to, true)]
	switch {
	case !haveZip:
		return allow.No("go.sum at head has no hash for the module zip of "+target, sourceManifests)
	case !haveMod:
		return allow.No("go.sum at head has no hash for the go.mod of "+target, sourceManifests)
	case !reported:
		return allow.No("unknown: go mod download did not report "+target, sourceDownload)
	case d.Error != "":
		return allow.No("unknown: go mod download failed: "+show(d.Error), sourceDownload)
	case d.Sum != zip:
		return allow.No(fmt.Sprintf("go.sum pins %s for the module zip; the go command got %s", zip, show(d.Sum)), sourceDownload)
	case d.GoModSum != mod:
		return allow.No(fmt.Sprintf("go.sum pins %s for go.mod; the go command got %s", mod, show(d.GoModSum)), sourceDownload)
	}
	return allow.Yes(zip+" (zip) and "+mod+" (go.mod) match the checksum database", sourceDownload)
}

// cleanFact is the Clean fact: the proxy still serves the version, it is
// not retracted, the module is not deprecated, and the advisory database
// has nothing new against it. The first part that fails is the value.
func cleanFact(up update, d downloaded, downloadedOK bool, info listed, infoOK bool, versions listed, versionsOK bool, adv advisory.Result, advErr error) allow.Fact {
	const sourceAll = "go mod download, go list -m -u -retracted, go list -m -versions, advisory database"
	switch {
	case !downloadedOK:
		return allow.No("unknown: go mod download did not report the version", sourceDownload)
	case d.Error != "":
		return allow.No("unknown: the proxy did not serve the version: "+show(d.Error), sourceDownload)

	case !infoOK:
		return allow.No("unknown: go list did not report the version", sourceList)
	case info.Error != nil:
		return allow.No("unknown: go list failed: "+show(info.Error.Err), sourceList)
	case len(info.Retracted) > 0:
		return allow.No("retracted: "+show(strings.Join(info.Retracted, "; ")), sourceList)
	case info.Deprecated != "":
		return allow.No("the module is deprecated: "+show(info.Deprecated), sourceList)

	// An empty Retracted is not enough: see the comment in Gather.
	case !versionsOK:
		return allow.No("unknown: go list did not report the module's versions", sourceList)
	case versions.Error != nil:
		return allow.No("unknown: the module's retractions could not be loaded: "+show(versions.Error.Err), sourceList)
	case module.IsPseudoVersion(up.to):
		return allow.No("unknown: "+up.to+" is not a tagged version, so the version list cannot confirm it is not retracted", sourceList)
	case !slices.Contains(versions.Versions, up.to):
		return allow.No("unknown: "+up.to+" is not in the module's list of versions that are not retracted", sourceList)

	case advErr != nil:
		return allow.No("unknown: the advisory database could not be asked: "+show(advErr.Error()), "advisory database")
	case !adv.NoMalware.Holds():
		return advisoryNo(adv.NoMalware, "unknown: malware advisories were not checked")
	case !adv.NoNewAdvisory.Holds():
		return advisoryNo(adv.NoNewAdvisory, "unknown: new advisories were not checked")
	}
	return allow.Yes("served by the proxy, not retracted, not deprecated, no malware advisory, no new advisory", sourceAll)
}

// advisoryNo turns one of the advisory checker's facts that does not
// hold into the Clean fact. A fact the checker left ungathered has no
// value or source of its own.
func advisoryNo(f allow.Fact, ungathered string) allow.Fact {
	if !f.Gathered() {
		return allow.No(ungathered, "advisory database")
	}
	return allow.No(f.Value, f.Source)
}

// unknownTime is a time fact that could not be established.
func unknownTime(why string) allow.TimeFact {
	return allow.TimeFact{Value: "unknown: " + why, Source: sourceIndex}
}

// seenFact looks a version up in the index, starting a little before its
// commit time.
func seenFact(ctx context.Context, ix *index, name, version string, commit, now time.Time) allow.TimeFact {
	seen, why := ix.firstSeen(ctx, name, version, commit.Add(-indexStartMargin))
	switch {
	case seen.IsZero():
		return unknownTime(why)
	case seen.After(now):
		return unknownTime("the index dates it " + seen.UTC().Format(time.RFC3339) + ", which is in the future")
	}
	return allow.At(seen, sourceIndex)
}

// nameCreated dates a module name by the first-seen time of its earliest
// version that can be found in the index. The name existed by then at
// the latest, so the answer can make a name look younger than it is and
// never older.
func nameCreated(ctx context.Context, tool goTool, ix *index, name string, versions listed, versionsOK bool, now time.Time) (allow.TimeFact, error) {
	if !versionsOK || versions.Error != nil || len(versions.Versions) == 0 {
		return unknownTime("the module's version list could not be read"), nil
	}
	earliest := slices.Clone(versions.Versions)
	semver.Sort(earliest)
	if len(earliest) > nameCandidates {
		earliest = earliest[:nameCandidates]
	}
	queries := make([]module.Version, len(earliest))
	for i, v := range earliest {
		queries[i] = module.Version{Path: name, Version: v}
	}
	infos, err := list(ctx, tool, nil, queries)
	if err != nil {
		return allow.TimeFact{}, err
	}
	why := "go list reported no commit time for the module's earliest versions"
	for _, q := range queries {
		info, ok := infos[q]
		if !ok || info.Error != nil || info.Time == nil {
			continue
		}
		f := seenFact(ctx, ix, name, q.Version, *info.Time, now)
		if f.Known() {
			f.Value += " (" + q.Version + ", the earliest version found in the index)"
			return f, nil
		}
		why = q.Version + ": " + strings.TrimPrefix(f.Value, "unknown: ")
	}
	return unknownTime(why), nil
}

// artifactPair names the two module zips the model is to read for one
// update, each with the go.sum hash it must match. There is none unless
// Bound holds, and none when go.sum at base has no hash for the old zip.
func artifactPair(up update, cs changeSet, bound allow.Fact) (artifact.Pair, bool) {
	if !bound.Holds() {
		return artifact.Pair{}, false
	}
	pair := artifact.Pair{
		Ecosystem: allow.GoModules,
		Name:      up.name,
		From:      up.from,
		To:        up.to,
		New:       artifact.Ref{Kind: artifact.GoModuleZip, Name: up.name, Version: up.to, Hash: cs.headSum[sumKey(up.name, up.to, false)]},
	}
	if up.from == "" {
		return pair, true
	}
	oldHash, ok := cs.baseSum[sumKey(up.name, up.from, false)]
	if !ok {
		return artifact.Pair{}, false
	}
	pair.Old = artifact.Ref{Kind: artifact.GoModuleZip, Name: up.name, Version: up.from, Hash: oldHash}
	return pair, true
}

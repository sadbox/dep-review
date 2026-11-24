package npm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
)

// installHooks are the scripts npm runs when it installs a dependency
// from the registry.
var installHooks = []string{"preinstall", "install", "postinstall"}

// readHooks returns the install scripts of a package.json "scripts"
// value, by hook. An empty script is no script, as it is for npm. The
// error is for a value whose shape hides what would run.
func readHooks(raw jsontext.Value) (map[string]string, error) {
	hooks := map[string]string{}
	if !present(raw) {
		return hooks, nil
	}
	var all map[string]jsontext.Value
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, errors.New("\"scripts\" is not an object")
	}
	for _, hook := range installHooks {
		value, ok := all[hook]
		if !ok || string(value) == "null" {
			continue
		}
		var script string
		if err := json.Unmarshal(value, &script); err != nil {
			return nil, fmt.Errorf("the %s script is not a string", hook)
		}
		if script != "" {
			hooks[hook] = script
		}
	}
	return hooks, nil
}

// showHooks renders install scripts for a Value.
func showHooks(hooks map[string]string) string {
	if len(hooks) == 0 {
		return "none"
	}
	var parts []string
	for _, hook := range slices.Sorted(maps.Keys(hooks)) {
		parts = append(parts, hook+": "+quote(hooks[hook]))
	}
	return strings.Join(parts, ", ")
}

// installRecord is what the registry and the lock say about one version's
// install step.
type installRecord struct {
	// hooks are the install scripts in the registry's metadata.
	hooks map[string]string
	// registryFlag: the registry's metadata marks the version as building
	// on install ("gypfile" or "hasInstallScript").
	registryFlag bool
	// lockFlag: a lock entry for the version has "hasInstallScript".
	lockFlag bool
}

func (r installRecord) any() bool { return len(r.hooks) > 0 || r.registryFlag || r.lockFlag }

// recordOf builds a version's installRecord.
func recordOf(doc versionDoc, copies []node) (installRecord, error) {
	hooks, err := readHooks(doc.Scripts)
	return installRecord{
		hooks:        hooks,
		registryFlag: present(doc.Gypfile) || present(doc.HasInstallScript),
		lockFlag:     slices.ContainsFunc(copies, func(c node) bool { return c.HasInstallScript }),
	}, err
}

// noRegressFact is NoRegress as far as the registry and the lock can show
// it: the update has no install script the old version did not have word
// for word, and was built by the same provenance identity. The tarball's
// own files are the third source for install scripts (InspectTarballs),
// so this is never an update's NoRegress by itself: it is handed to the
// fetch command beside the update (facts.Result.NoRegressSoFar).
//
// A script here is the command package.json gives a hook ("node
// install.js"), and that is all that is compared. The file the command
// runs is code of the package like any other, and it is the model that
// reads it: the Value says "hook commands" so that a reader of the
// comment does not take an unchanged command for an unchanged install.js.
//
// scriptsOff says that the repository turns npm's install scripts off
// and that the fact covers this lock (facts.Result.ScriptsOff). The
// scripts and the two flags are then not compared: npm runs none of them
// for a dependency, whatever they are. Everything else is as it is
// without the fact: a version the registry does not have, scripts whose
// shape cannot be read, and the provenance.
func noRegressFact(ctx context.Context, reg *registry, u update, a packumentAnswer, source string, scriptsOff bool) (allow.Fact, error) {
	source += " and package-lock.json"
	to, missing, ok := a.version(u.To, source)
	if !ok {
		return missing, nil
	}
	toRecord, err := recordOf(to, u.New)
	if err != nil {
		return allow.No(show(u.To)+": "+err.Error(), source), nil
	}
	var from versionDoc
	var fromRecord installRecord
	if u.From != "" {
		if from, missing, ok = a.version(u.From, source); !ok {
			return missing, nil
		}
		if fromRecord, err = recordOf(from, u.Old); err != nil {
			return allow.No(show(u.From)+": "+err.Error(), source), nil
		}
	}

	scripts := "no install script"
	if scriptsOff {
		// Said first: the comment shows a value's first 200 characters,
		// and a provenance identity fills most of them.
		scripts = "install scripts not compared: the repository turns them off"
	} else if toRecord.any() {
		switch {
		case u.From == "":
			return allow.No("a new dependency with an install script ("+showHooks(toRecord.hooks)+")", source), nil
		case !maps.Equal(fromRecord.hooks, toRecord.hooks):
			return allow.No(fmt.Sprintf("install scripts change from %s to %s", showHooks(fromRecord.hooks), showHooks(toRecord.hooks)), source), nil
		case toRecord.lockFlag && !fromRecord.lockFlag:
			return allow.No("the lock marks "+show(u.To)+" as having an install script, and did not mark "+show(u.From), source), nil
		case toRecord.registryFlag && !fromRecord.registryFlag:
			return allow.No("the registry marks "+show(u.To)+" as building on install, and did not mark "+show(u.From), source), nil
		}
		scripts = "install hook commands unchanged (" + showHooks(toRecord.hooks) + ")"
	}

	provenance, err := provenanceFact(ctx, reg, u, from, to, source)
	if err != nil || !provenance.Holds() {
		return provenance, err
	}
	// The Value says whose word this is, so a reader of the comment does
	// not take the registry's for the tarball's.
	return allow.Yes(scripts+"; "+provenance.Value+", by the registry's metadata and the lock", source), nil
}

// identity is who built a version, according to its SLSA provenance. The
// git ref and commit are left out on purpose: they differ for every
// release.
type identity struct {
	// BuildType is the kind of build (GitHub Actions workflow).
	BuildType string
	// Builder is the runner that built it.
	Builder string
	// Repository is the source repository's URL, and Workflow the path of
	// the workflow file in it.
	Repository string
	Workflow   string
	// RepositoryID and OwnerID are GitHub's numeric IDs, which survive a
	// rename and do not survive a name being taken over.
	RepositoryID string
	OwnerID      string
}

func (id identity) String() string {
	return fmt.Sprintf("%s, workflow %s, builder %s", quote(id.Repository), quote(id.Workflow), quote(id.Builder))
}

// hasProvenance reports whether the registry's document for a version
// says it has a provenance attestation.
func hasProvenance(doc versionDoc) bool {
	if !present(doc.Dist.Attestations) {
		return false
	}
	var att struct {
		Provenance jsontext.Value `json:"provenance"`
	}
	if err := json.Unmarshal(doc.Dist.Attestations, &att); err != nil {
		// Something is there, in a shape the gate does not know. Say
		// yes, so that it has to be read, and reading it fails.
		return true
	}
	return present(att.Provenance)
}

// provenanceFact compares who built From and who built To. It holds when
// From has no provenance (there is nothing to lose), or when both have it
// and name the same identity. The error is the context's.
//
// The registry checked the attestation's signature when the version was
// published. The gate does not check it again (that needs a Sigstore
// verifier, which is not in the standard library): it reads the signed
// statement and trusts the registry for it being genuine, as it trusts
// the registry for dist.integrity.
func provenanceFact(ctx context.Context, reg *registry, u update, from, to versionDoc, source string) (allow.Fact, error) {
	if u.From == "" || !hasProvenance(from) {
		return allow.Yes("the old version has no provenance to lose", source), nil
	}
	if !hasProvenance(to) {
		return allow.No(show(u.From)+" was published with provenance, "+show(u.To)+" was not", source), nil
	}
	oldHash, oldOK := oneIntegrity(u.Old)
	newHash, newOK := oneIntegrity(u.New)
	if !oldOK || !newOK {
		return allow.No("the lock does not have a single sha512 for each version to match its provenance against", source), nil
	}
	var ids [2]identity
	for i, side := range []struct{ version, hash string }{{u.From, oldHash}, {u.To, newHash}} {
		id, missing, ok := reg.provenance(ctx, u.Name, side.version, side.hash, source)
		if ctx.Err() != nil {
			return allow.Fact{}, ctx.Err()
		}
		if !ok {
			return missing, nil
		}
		ids[i] = id
	}
	if ids[0] != ids[1] {
		return allow.No(fmt.Sprintf("provenance identity changes: %s was built from %s, %s from %s", show(u.From), ids[0], show(u.To), ids[1]), source), nil
	}
	return allow.Yes("same provenance identity ("+ids[1].String()+")", source), nil
}

const (
	slsaPredicate   = "https://slsa.dev/provenance/v1"
	intotoStatement = "https://in-toto.io/Statement/v1"
	intotoPayload   = "application/vnd.in-toto+json"
)

// provenance reads the identity in name@version's SLSA provenance
// statement. integrity is the lock's hash for that version: the statement
// must be about those bytes. When it reads none it reports false, and the
// fact says why: unavailable when the registry did not answer, never
// gathered when its answer could not be used, and a "no" for an answer
// that has no identity the gate reads.
func (r *registry) provenance(ctx context.Context, name, version, integrity, source string) (identity, allow.Fact, bool) {
	about := "provenance of " + show(version) + ": "
	no := func(problem string) (identity, allow.Fact, bool) {
		return identity{}, allow.No(about+problem, source), false
	}
	body, err := r.get(ctx, attestationURL(name, version), maxAttestation)
	switch {
	case errors.Is(err, errGone):
		return no("the registry has no attestations for it")
	case errors.Is(err, errUnreachable):
		return identity{}, allow.Unavailable(about+why(err), source), false
	case err != nil:
		return identity{}, allow.Fact{Value: about + why(err)}, false
	}
	var doc struct {
		Attestations []struct {
			PredicateType string `json:"predicateType"`
			Bundle        struct {
				Envelope struct {
					Payload     string `json:"payload"`
					PayloadType string `json:"payloadType"`
				} `json:"dsseEnvelope"`
			} `json:"bundle"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return no("the attestations could not be read: " + quote(err.Error()))
	}
	var payloads []string
	for _, a := range doc.Attestations {
		if a.PredicateType == slsaPredicate {
			if a.Bundle.Envelope.PayloadType != intotoPayload {
				return no("the provenance is not an in-toto statement")
			}
			payloads = append(payloads, a.Bundle.Envelope.Payload)
		}
	}
	if len(payloads) != 1 {
		return no(fmt.Sprintf("%d SLSA v1 provenance statements, where the gate reads exactly one", len(payloads)))
	}
	raw, err := base64.StdEncoding.DecodeString(payloads[0])
	if err != nil {
		return no("the provenance statement is not base64")
	}
	var st struct {
		Type    string `json:"_type"`
		Subject []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		PredicateType string `json:"predicateType"`
		Predicate     struct {
			BuildDefinition struct {
				BuildType          string `json:"buildType"`
				ExternalParameters struct {
					Workflow struct {
						Repository string `json:"repository"`
						Path       string `json:"path"`
					} `json:"workflow"`
				} `json:"externalParameters"`
				InternalParameters struct {
					GitHub struct {
						RepositoryID string `json:"repository_id"`
						OwnerID      string `json:"repository_owner_id"`
					} `json:"github"`
				} `json:"internalParameters"`
			} `json:"buildDefinition"`
			RunDetails struct {
				Builder struct {
					ID string `json:"id"`
				} `json:"builder"`
			} `json:"runDetails"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return no("the provenance statement could not be read: " + quote(err.Error()))
	}
	if st.Type != intotoStatement || st.PredicateType != slsaPredicate {
		return no("the provenance statement is not SLSA v1")
	}
	// The statement must be about this package's tarball, or it says
	// nothing about what the lock pins.
	sum, _ := artifact.NPMIntegrity(integrity)
	if len(st.Subject) != 1 || st.Subject[0].Name != purl(name, version) || st.Subject[0].Digest["sha512"] != hex.EncodeToString(sum) {
		return no("the provenance statement is not about the tarball the lock pins")
	}
	def := st.Predicate.BuildDefinition
	id := identity{
		BuildType:    def.BuildType,
		Builder:      st.Predicate.RunDetails.Builder.ID,
		Repository:   def.ExternalParameters.Workflow.Repository,
		Workflow:     def.ExternalParameters.Workflow.Path,
		RepositoryID: def.InternalParameters.GitHub.RepositoryID,
		OwnerID:      def.InternalParameters.GitHub.OwnerID,
	}
	if id.BuildType == "" || id.Builder == "" || id.Repository == "" || id.Workflow == "" {
		return no("the provenance statement names no source repository, workflow and builder in the shape the gate reads")
	}
	return id, allow.Fact{}, true
}

// purl is the package URL npm puts in a provenance statement's subject.
func purl(name, version string) string {
	return "pkg:npm/" + strings.Replace(name, "@", "%40", 1) + "@" + version
}

// maxPackageJSON bounds one package.json, binding.gyp or .gypi file of a
// tarball.
const maxPackageJSON = 8 << 20

// tarballSource is the Source of InspectTarballs' fact.
const tarballSource = "every package.json, binding.gyp and .gypi file in the verified tarballs"

// gypFile reports whether a file of this name is one a package is built
// from when it is installed: a binding.gyp, or a .gypi file. gyp reads a
// .gypi exactly as it reads a binding.gyp (a command in it runs while the
// file is loaded), a binding.gyp includes one by path, and node-gyp
// includes a config.gypi and a common.gypi beside a binding.gyp without
// being told to (node-gyp 12.4.0, lib/configure.js).
//
// The name is compared without regard to case: on a file system that
// ignores it (macOS, Windows) npm and node-gyp open a Binding.gyp or a
// common.GYPI as the file they look for (spec section 11, amendment 69).
func gypFile(name string) bool {
	return foldName(name) == "binding.gyp" || gypiFile(name)
}

// foldName is a file name as a file system that ignores case compares
// it, as far as the gate goes: without the dots and blanks at its end,
// which Windows drops, then in upper case, then in lower. Upper first
// takes a letter whose capital is an ASCII letter (the dotless i, the
// long s) to that letter, as such file systems do. The extraction folds
// paths the same way, and refuses an archive in which two files or two
// directories differ only so (spec section 11, amendment 72), so a
// package.json and the binding.gyp beside it are in one directory here
// exactly when they are in one there.
func foldName(name string) string {
	return strings.ToLower(strings.ToUpper(strings.TrimRight(name, ". ")))
}

// gypiFile reports whether a file of this name is a .gypi file, in any
// case.
func gypiFile(name string) bool {
	return strings.HasSuffix(foldName(name), ".gypi")
}

// gypBeside is the path of a file named binding.gyp in any case in the
// directory dir of tree, or "" when there is none. A nil tree has none.
func gypBeside(tree fs.FS, dir string) (string, error) {
	if tree == nil {
		return "", nil
	}
	entries, err := fs.ReadDir(tree, dir)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	for _, e := range entries {
		if !e.IsDir() && foldName(e.Name()) == "binding.gyp" {
			return path.Join(dir, e.Name()), nil
		}
	}
	return "", err
}

// gypWhy ends the problem a gyp file is.
const gypWhy = "it is a file a package is built from when it is installed"

// InspectTarballs is the tarballs' own word on the install step, and the
// one a publisher cannot keep out of sight: npm runs what the files say.
//
// It asks for equality, and has no model of when npm runs or builds
// what. Three things in a directory decide its install step: the install
// scripts of its package.json, that file's "gypfile" member, and a
// binding.gyp beside it, which npm builds by itself for some values of
// the other two. For every package.json in the new tarball the three
// must be what the old tarball has at the same path, a binding.gyp byte
// for byte. At a path the old tarball does not have, and for a new name,
// all three must be absent. A binding.gyp with no package.json beside it
// must be the old tarball's too. A script or a binding.gyp that is gone
// is a change like any other: dropping an install script, or a
// "gypfile": false, beside a binding.gyp is how a build starts that no
// script was added for.
//
// A .gypi file is held to the same equality as a binding.gyp, wherever it
// is (spec section 11, amendment 58): one in the new tarball must be the
// old tarball's, byte for byte, and one the old tarball has must still be
// there. It belongs to no package.json. Which binding.gyp includes it is
// written in that binding.gyp, which the gate does not parse, so one that
// is gone counts wherever it was; a binding.gyp that is gone together
// with its package.json, or that had none beside it, leaves nothing to
// build in that directory, and does not.
//
// What is compared is what package.json, binding.gyp and the .gypi files
// say, and nothing else they point at: not the file a script's command
// runs, not a file one of a binding.gyp's actions runs, and not a file it
// includes under any other name. Those are in the diff the model reads,
// like every other file that changed, and a rule that refused them would
// refuse every update of a package that has an install step. The Value
// says so.
//
// Every package.json, binding.gyp and .gypi file is looked at, wherever
// it is. That covers bundled dependencies, which are installed from
// inside this tarball and appear in no other source (spec section 11,
// amendment 5), and it is deliberately more than npm runs: a package.json
// in a test fixture counts too. Nothing here decides which directories
// npm treats as packages.
//
// It is an artifact.Inspect. oldPkg and newPkg are the extracted
// packages, each the directory that holds the package's own package.json;
// oldPkg is nil for a new name.
func InspectTarballs(oldPkg, newPkg fs.FS) allow.Fact {
	if newPkg == nil {
		return allow.Fact{Value: "the new tarball was not given"}
	}
	if _, err := fs.Stat(newPkg, "package.json"); err != nil {
		return allow.No("the new tarball has no package.json at its root", tarballSource)
	}
	manifests, gyps := 0, 0
	var problem string
	err := fs.WalkDir(newPkg, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		switch name := d.Name(); {
		case foldName(name) == "package.json":
			// In any case, as npm on such a file system reads it. The
			// root's is looked for by its exact name above.
			manifests++
			problem, err = manifestProblem(oldPkg, newPkg, p)
		case gypFile(name):
			gyps++
			problem, err = gypProblem(oldPkg, newPkg, p)
		}
		if err == nil && problem != "" {
			return fs.SkipAll
		}
		return err
	})
	if err == nil && problem == "" && oldPkg != nil {
		problem, err = gypiGone(oldPkg, newPkg)
	}
	switch {
	case err != nil:
		// The trees are the gate's own extraction of verified bytes. One
		// it cannot read back establishes nothing.
		return allow.Fact{Value: "the tarballs could not be read: " + quote(err.Error())}
	case problem != "":
		return allow.No(problem, tarballSource)
	}
	return allow.Yes(fmt.Sprintf("no install hook command, gypfile, binding.gyp or .gypi file is new, changed or gone in %d package.json (%d binding.gyp and .gypi files present); the other files these run were not compared", manifests, gyps), tarballSource)
}

// gypiGone names a .gypi file the old tarball has and the new one does
// not, and is empty when there is none. The walk over the new tarball
// does not meet a file that is gone.
func gypiGone(oldPkg, newPkg fs.FS) (string, error) {
	var problem string
	err := fs.WalkDir(oldPkg, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !gypiFile(d.Name()) {
			return err
		}
		if _, has, err := readSmall(newPkg, p); err != nil || has {
			return err
		}
		problem = show(p) + " is gone: " + gypWhy
		return fs.SkipAll
	})
	return problem, err
}

// gypProblem says how the binding.gyp or .gypi file at p is not the old
// tarball's, and is empty when it is.
func gypProblem(oldPkg, newPkg fs.FS, p string) (string, error) {
	is, _, err := readSmall(newPkg, p)
	if err != nil {
		return "", err
	}
	was, had, err := readSmall(oldPkg, p)
	switch {
	case err != nil:
		return "", err
	case !had:
		return show(p) + " is new: " + gypWhy, nil
	case !bytes.Equal(was, is):
		return show(p) + " changes: " + gypWhy, nil
	}
	return "", nil
}

// manifestProblem says how the install step of the directory of the
// package.json at p is not the old tarball's, and is empty when it is. A
// binding.gyp that is there is gypProblem's; this looks at its being
// there.
func manifestProblem(oldPkg, newPkg fs.FS, p string) (string, error) {
	is, _, err := readSmall(newPkg, p)
	if err != nil {
		return "", err
	}
	was, had, err := readSmall(oldPkg, p)
	if err != nil {
		return "", err
	}
	newGyp, err := gypBeside(newPkg, path.Dir(p))
	if err != nil {
		return "", err
	}
	oldGyp, err := gypBeside(oldPkg, path.Dir(p))
	if err != nil {
		return "", err
	}
	switch {
	case !had && newGyp != "":
		return show(p) + " is new beside a binding.gyp", nil
	case had && oldGyp != "" && newGyp == "":
		return show(oldGyp) + " is gone, and " + show(p) + " beside it stays", nil
	case had && bytes.Equal(was, is):
		// The same bytes say the same, whatever they say: that is what
		// keeps a fixture nobody can parse from stopping an update that
		// left it alone.
		return "", nil
	}

	hooks, gypfile, err := installInputs(is)
	if err != nil {
		return fmt.Sprintf("%s in the new tarball: %v", show(p), err), nil
	}
	if !had {
		switch {
		case len(hooks) > 0:
			return fmt.Sprintf("%s is new and has an install script (%s)", show(p), showHooks(hooks)), nil
		case gypfile != "":
			return fmt.Sprintf("%s is new and sets gypfile (%s)", show(p), quote(gypfile)), nil
		}
		return "", nil
	}
	oldHooks, oldGypfile, err := installInputs(was)
	switch {
	case err != nil:
		return fmt.Sprintf("%s in the old tarball: %v", show(p), err), nil
	case !maps.Equal(oldHooks, hooks):
		return fmt.Sprintf("the install scripts of %s change from %s to %s", show(p), showHooks(oldHooks), showHooks(hooks)), nil
	case oldGypfile != gypfile:
		return fmt.Sprintf("gypfile of %s changes from %s to %s", show(p), quote(oldGypfile), quote(gypfile)), nil
	}
	return "", nil
}

// installInputs reads what one package.json says of its install step:
// its install scripts, and its "gypfile" member as it is written, which
// is empty when it has none.
func installInputs(data []byte) (hooks map[string]string, gypfile string, err error) {
	var manifest struct {
		Scripts jsontext.Value `json:"scripts"`
		Gypfile jsontext.Value `json:"gypfile"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, "", errors.New("not JSON the gate can read")
	}
	hooks, err = readHooks(manifest.Scripts)
	return hooks, string(manifest.Gypfile), err
}

// readSmall reads one file of an extracted tarball and reports whether it
// is there. A nil tree has nothing. A file too large to be a package.json,
// a binding.gyp or a .gypi file anyone wrote is an error.
func readSmall(tree fs.FS, name string) ([]byte, bool, error) {
	if tree == nil {
		return nil, false, nil
	}
	f, err := tree.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxPackageJSON+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > maxPackageJSON {
		return nil, false, fmt.Errorf("%s is larger than %d MB", show(name), maxPackageJSON>>20)
	}
	return data, true, nil
}

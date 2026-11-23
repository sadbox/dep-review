package npm

import (
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
	"strings"

	"github.com/sadbox/dep-review/internal/allow"
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
	for _, hook := range sortedKeys(hooks) {
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
	if err != nil {
		return installRecord{}, err
	}
	r := installRecord{hooks: hooks, registryFlag: present(doc.Gypfile) || present(doc.HasInstallScript)}
	for _, c := range copies {
		if c.HasInstallScript {
			r.lockFlag = true
		}
	}
	return r, nil
}

// noRegressFact is the NoRegress fact as far as the registry and the lock
// can show it: the update bundles nothing, has no install script the old
// version did not have word for word, and was built by the same
// provenance identity. The tarball's own package.json is the third source
// for install scripts; TarballNoRegress adds it once the artifact reader
// has the verified tarballs.
func noRegressFact(ctx context.Context, reg *registry, u update, a packumentAnswer, source string) (allow.Fact, error) {
	source += " and package-lock.json"
	// Bundled dependencies are installed from inside this package's
	// tarball. The registry and the lock say nothing of their install
	// scripts, and their names never pass Known.
	if len(u.Bundled) > 0 {
		return allow.No("bundles dependencies inside its own tarball ("+list(u.Bundled, 8)+"), which the gate has no rule for", source), nil
	}
	switch {
	case a.failed != "":
		return allow.Fact{Value: a.failed}, nil
	case a.gone:
		return allow.No("the registry has no package of this name", source), nil
	}

	to, published, problem := a.doc.version(u.To)
	switch {
	case !published:
		return allow.No(show(u.To)+" is not on the registry (unpublished)", source), nil
	case problem != "":
		return allow.Fact{Value: problem}, nil
	}
	if declaresBundle(to.BundleDependencies) || declaresBundle(to.BundledDependencies) {
		return allow.No("the registry says it bundles dependencies inside its own tarball, which the gate has no rule for", source), nil
	}
	toRecord, err := recordOf(to, u.New)
	if err != nil {
		return allow.No(show(u.To)+": "+err.Error(), source), nil
	}

	var from versionDoc
	var fromRecord installRecord
	if u.From != "" {
		from, published, problem = a.doc.version(u.From)
		switch {
		case !published:
			return allow.No(show(u.From)+" is no longer on the registry, so its install scripts and provenance cannot be compared", source), nil
		case problem != "":
			return allow.Fact{Value: problem}, nil
		}
		fromRecord, err = recordOf(from, u.Old)
		if err != nil {
			return allow.No(show(u.From)+": "+err.Error(), source), nil
		}
	}

	scripts := "no install script"
	if toRecord.any() {
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
		scripts = "install scripts unchanged (" + showHooks(toRecord.hooks) + ")"
	}

	provenance, v, err := compareProvenance(ctx, reg, u, from, to)
	if err != nil {
		return allow.Fact{}, err
	}
	switch v {
	case fails:
		return allow.No(provenance, source), nil
	case unknown:
		return allow.Fact{Value: provenance}, nil
	}
	// The Value says what has not been looked at yet, so a reader of the
	// comment does not take the registry's word for the tarball's.
	return allow.Yes(scripts+"; "+provenance+notYetTarball, source), nil
}

// notYetTarball ends the Value of a NoRegress fact that holds on the
// registry's and the lock's word alone. TarballNoRegress replaces it with
// what the tarball showed.
const notYetTarball = "; from the registry's metadata and the lock, not yet from the tarball itself"

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

// verdict is how one comparison came out.
type verdict int

const (
	holds verdict = iota
	fails
	// unknown: nothing was learned (the registry did not answer). The
	// fact is then left ungathered, which is not the same as a no.
	unknown
)

// compareProvenance compares who built From and who built To. It holds
// when From has no provenance (there is nothing to lose), or when both
// have it and name the same identity. The string is for the fact's Value.
// The error is the context's.
//
// The registry checked the attestation's signature when the version was
// published. The gate does not check it again (that needs a Sigstore
// verifier, which is not in the standard library): it reads the signed
// statement and trusts the registry for it being genuine, as it trusts
// the registry for dist.integrity.
func compareProvenance(ctx context.Context, reg *registry, u update, from, to versionDoc) (string, verdict, error) {
	if u.From == "" || !hasProvenance(from) {
		return "the old version has no provenance to lose", holds, nil
	}
	if !hasProvenance(to) {
		return show(u.From) + " was published with provenance, " + show(u.To) + " was not", fails, nil
	}
	oldHash, ok := oneIntegrity(u.Old)
	if !ok {
		return "the base lock has no single sha512 for " + show(u.From) + " to match its provenance against", fails, nil
	}
	newHash, ok := oneIntegrity(u.New)
	if !ok {
		return "the head lock has no single sha512 for " + show(u.To) + " to match its provenance against", fails, nil
	}
	var ids [2]identity
	for i, side := range []struct{ version, hash string }{{u.From, oldHash}, {u.To, newHash}} {
		id, problem, answered, err := reg.provenance(ctx, u.Name, side.version, side.hash)
		switch {
		case err != nil:
			return "", unknown, err
		case !answered:
			return "provenance of " + show(side.version) + ": " + problem, unknown, nil
		case problem != "":
			return "provenance of " + show(side.version) + ": " + problem, fails, nil
		}
		ids[i] = id
	}
	if ids[0] != ids[1] {
		return fmt.Sprintf("provenance identity changes: %s was built from %s, %s from %s", show(u.From), ids[0], show(u.To), ids[1]), fails, nil
	}
	return "same provenance identity (" + ids[1].String() + ")", holds, nil
}

const (
	slsaPredicate   = "https://slsa.dev/provenance/v1"
	intotoStatement = "https://in-toto.io/Statement/v1"
	intotoPayload   = "application/vnd.in-toto+json"
)

// provenance reads the identity in name@version's SLSA provenance
// statement. integrity is the lock's hash for that version: the statement
// must be about those bytes. The string says why no identity could be
// read. answered is false when the registry gave no answer at all, so
// nothing was learned. The error is the context's.
func (r *registry) provenance(ctx context.Context, name, version, integrity string) (id identity, problem string, answered bool, err error) {
	id, problem, answered = r.readProvenance(ctx, name, version, integrity)
	if ctx.Err() != nil {
		return identity{}, "", false, ctx.Err()
	}
	return id, problem, answered, nil
}

func (r *registry) readProvenance(ctx context.Context, name, version, integrity string) (identity, string, bool) {
	body, err := r.get(ctx, attestationURL(name, version), maxAttestation)
	if errors.Is(err, errGone) {
		return identity{}, "the registry has no attestations for it", true
	}
	if err != nil {
		return identity{}, "the registry did not answer: " + quote(err.Error()), false
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
		return identity{}, "the attestations could not be read: " + quote(err.Error()), true
	}
	var payloads []string
	for _, a := range doc.Attestations {
		if a.PredicateType == slsaPredicate {
			if a.Bundle.Envelope.PayloadType != intotoPayload {
				return identity{}, "the provenance is not an in-toto statement", true
			}
			payloads = append(payloads, a.Bundle.Envelope.Payload)
		}
	}
	if len(payloads) != 1 {
		return identity{}, fmt.Sprintf("%d SLSA v1 provenance statements, where the gate reads exactly one", len(payloads)), true
	}
	raw, err := base64.StdEncoding.DecodeString(payloads[0])
	if err != nil {
		return identity{}, "the provenance statement is not base64", true
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
		return identity{}, "the provenance statement could not be read: " + quote(err.Error()), true
	}
	if st.Type != intotoStatement || st.PredicateType != slsaPredicate {
		return identity{}, "the provenance statement is not SLSA v1", true
	}
	// The statement must be about this package's tarball, or it says
	// nothing about what the lock pins.
	sum, _ := sha512Of(integrity)
	if len(st.Subject) != 1 || st.Subject[0].Name != purl(name, version) || st.Subject[0].Digest["sha512"] != hex.EncodeToString(sum) {
		return identity{}, "the provenance statement is not about the tarball the lock pins", true
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
		return identity{}, "the provenance statement names no source repository, workflow and builder in the shape the gate reads", true
	}
	return id, "", true
}

// purl is the package URL npm puts in a provenance statement's subject.
func purl(name, version string) string {
	return "pkg:npm/" + strings.Replace(name, "@", "%40", 1) + "@" + version
}

// maxPackageJSON bounds a tarball's package.json.
const maxPackageJSON = 8 << 20

// tarballRecord is what a package's own files say about its install step.
type tarballRecord struct {
	hooks map[string]string
	// gyp: the package has a binding.gyp. npm builds such a package on
	// install when it has no install or preinstall script, whatever the
	// registry and the lock say.
	gyp bool
	// bundles: package.json declares bundled dependencies, or the
	// tarball has a node_modules directory.
	bundles bool
}

// readTarball reads the install step out of one extracted package.
func readTarball(pkgRoot fs.FS) (tarballRecord, error) {
	f, err := pkgRoot.Open("package.json")
	if err != nil {
		return tarballRecord{}, errors.New("no package.json at the tarball's root")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxPackageJSON+1))
	if err != nil || len(data) > maxPackageJSON {
		return tarballRecord{}, errors.New("package.json could not be read in full")
	}
	var manifest struct {
		Scripts             jsontext.Value `json:"scripts"`
		BundleDependencies  jsontext.Value `json:"bundleDependencies"`
		BundledDependencies jsontext.Value `json:"bundledDependencies"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return tarballRecord{}, errors.New("package.json is not JSON the gate can read")
	}
	hooks, err := readHooks(manifest.Scripts)
	if err != nil {
		return tarballRecord{}, err
	}
	r := tarballRecord{hooks: hooks}
	if _, err := fs.Stat(pkgRoot, "binding.gyp"); err == nil {
		r.gyp = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		return tarballRecord{}, errors.New("binding.gyp could not be looked for")
	}
	r.bundles = declaresBundle(manifest.BundleDependencies) || declaresBundle(manifest.BundledDependencies)
	if _, err := fs.Stat(pkgRoot, "node_modules"); err == nil {
		r.bundles = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		return tarballRecord{}, errors.New("node_modules could not be looked for")
	}
	return r, nil
}

// TarballNoRegress finishes an update's NoRegress fact with the third
// source for install scripts, the one a publisher cannot keep out of the
// registry's metadata: the verified tarball's own package.json, and
// whether it has a binding.gyp. It is to be called once the artifact
// reader has extracted both tarballs, and its answer replaces the
// update's NoRegress.
//
// internal/artifact cannot import this package (internal/facts imports
// internal/artifact), which is why the signature needs nothing but allow
// and io/fs: whoever wires the reader and the gatherer together can hand
// the function over as a value.
//
// gathered is the update's NoRegress fact as Gather returned it. oldPkg
// and newPkg are the extracted packages: each is the directory that holds
// the package's own package.json (the tarball with its first path element
// dropped, as npm unpacks it). oldPkg is nil for a new name.
//
// The result can only be stricter than gathered: a fact that does not
// hold is returned as it is, and one that holds stays so only when the
// new tarball bundles nothing and has no install script and no
// binding.gyp that the old tarball did not have, word for word.
func TarballNoRegress(gathered allow.Fact, oldPkg, newPkg fs.FS) allow.Fact {
	if !gathered.Holds() {
		return gathered
	}
	source := gathered.Source + " and the tarballs' package.json"
	if newPkg == nil {
		return allow.No("the new tarball was not given", source)
	}
	is, err := readTarball(newPkg)
	if err != nil {
		return allow.No("the new tarball: "+err.Error(), source)
	}
	if is.bundles {
		return allow.No("the new tarball bundles dependencies (bundleDependencies or a node_modules directory), which the gate has no rule for", source)
	}
	said := strings.TrimSuffix(gathered.Value, notYetTarball)
	if len(is.hooks) == 0 && !is.gyp {
		return allow.Yes(said+"; the tarball's package.json has no install script and there is no binding.gyp", source)
	}
	if oldPkg == nil {
		return allow.No("a new dependency whose tarball has an install script or a binding.gyp ("+showHooks(is.hooks)+")", source)
	}
	was, err := readTarball(oldPkg)
	if err != nil {
		return allow.No("the old tarball: "+err.Error(), source)
	}
	if !maps.Equal(was.hooks, is.hooks) {
		return allow.No(fmt.Sprintf("the tarball's install scripts change from %s to %s", showHooks(was.hooks), showHooks(is.hooks)), source)
	}
	if is.gyp && !was.gyp {
		return allow.No("the new tarball has a binding.gyp, which npm builds on install, and the old one had none", source)
	}
	return allow.Yes(said+"; the tarball's install scripts are unchanged ("+showHooks(is.hooks)+gypNote(is.gyp)+")", source)
}

func gypNote(gyp bool) string {
	if gyp {
		return ", binding.gyp as before"
	}
	return ""
}

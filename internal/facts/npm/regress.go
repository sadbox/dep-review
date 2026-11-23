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
// can show it: the update has no install script the old version did not
// have word for word, and was built by the same provenance identity. The
// tarball's own files are the third source for install scripts, and the
// only one for the packages it bundles; InspectTarballs reads them once
// the artifact reader has the verified tarballs.
func noRegressFact(ctx context.Context, reg *registry, u update, a packumentAnswer, source string) (allow.Fact, error) {
	source += " and package-lock.json"
	switch {
	case a.failed != "":
		return a.unanswered(source), nil
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
	case unreachable:
		return allow.Unavailable(provenance, source), nil
	}
	// The Value says whose word this is, so a reader of the comment does
	// not take the registry's for the tarball's.
	value := scripts + "; " + provenance + ", by the registry's metadata and the lock"
	if len(u.Bundled) > 0 {
		value += "; bundles " + list(u.Bundled, 8) + ", which are read and inspected with its tarball"
	}
	return allow.Yes(value, source), nil
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

// verdict is how one comparison came out.
type verdict int

const (
	holds verdict = iota
	fails
	// unknown: nothing was learned from an answer that arrived. The fact
	// is then left ungathered, which is not the same as a no.
	unknown
	// unreachable: the registry was asked and did not answer. The fact is
	// then unavailable, which is a wait.
	unreachable
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
		id, problem, state, err := reg.provenance(ctx, u.Name, side.version, side.hash)
		switch {
		case err != nil:
			return "", unknown, err
		case state != holds:
			return "provenance of " + show(side.version) + ": " + problem, state, nil
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
// read. The verdict is holds when the registry answered (the identity is
// then read, or the string says what is wrong with the answer),
// unreachable when it did not answer, and unknown when its answer could
// not be used; in the last two nothing was learned. The error is the
// context's.
func (r *registry) provenance(ctx context.Context, name, version, integrity string) (id identity, problem string, state verdict, err error) {
	id, problem, state = r.readProvenance(ctx, name, version, integrity)
	if ctx.Err() != nil {
		return identity{}, "", unknown, ctx.Err()
	}
	return id, problem, state, nil
}

func (r *registry) readProvenance(ctx context.Context, name, version, integrity string) (identity, string, verdict) {
	body, err := r.get(ctx, attestationURL(name, version), maxAttestation)
	switch {
	case errors.Is(err, errGone):
		return identity{}, "the registry has no attestations for it", holds
	case errors.Is(err, errUnreachable):
		return identity{}, why(err), unreachable
	case err != nil:
		return identity{}, why(err), unknown
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
		return identity{}, "the attestations could not be read: " + quote(err.Error()), holds
	}
	var payloads []string
	for _, a := range doc.Attestations {
		if a.PredicateType == slsaPredicate {
			if a.Bundle.Envelope.PayloadType != intotoPayload {
				return identity{}, "the provenance is not an in-toto statement", holds
			}
			payloads = append(payloads, a.Bundle.Envelope.Payload)
		}
	}
	if len(payloads) != 1 {
		return identity{}, fmt.Sprintf("%d SLSA v1 provenance statements, where the gate reads exactly one", len(payloads)), holds
	}
	raw, err := base64.StdEncoding.DecodeString(payloads[0])
	if err != nil {
		return identity{}, "the provenance statement is not base64", holds
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
		return identity{}, "the provenance statement could not be read: " + quote(err.Error()), holds
	}
	if st.Type != intotoStatement || st.PredicateType != slsaPredicate {
		return identity{}, "the provenance statement is not SLSA v1", holds
	}
	// The statement must be about this package's tarball, or it says
	// nothing about what the lock pins.
	sum, _ := sha512Of(integrity)
	if len(st.Subject) != 1 || st.Subject[0].Name != purl(name, version) || st.Subject[0].Digest["sha512"] != hex.EncodeToString(sum) {
		return identity{}, "the provenance statement is not about the tarball the lock pins", holds
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
		return identity{}, "the provenance statement names no source repository, workflow and builder in the shape the gate reads", holds
	}
	return id, "", holds
}

// purl is the package URL npm puts in a provenance statement's subject.
func purl(name, version string) string {
	return "pkg:npm/" + strings.Replace(name, "@", "%40", 1) + "@" + version
}

// maxPackageJSON bounds one package.json or binding.gyp of a tarball.
const maxPackageJSON = 8 << 20

// tarballSource is the Source of InspectTarballs' fact.
const tarballSource = "every package.json and binding.gyp in the verified tarballs"

// InspectTarballs is the tarballs' own word on the install step: the
// third source for install scripts, and the one a publisher cannot keep
// out of sight, because npm runs what the files say whatever the
// registry's metadata and the lock say. It holds when no package.json in
// the new tarball has an install script, and no binding.gyp is there,
// that the old tarball did not have at the same path, word for word.
//
// Every package.json and binding.gyp is looked at, wherever it is. That
// covers bundled dependencies, which are installed from inside this
// tarball and appear in no other source (spec section 11, amendment 5),
// and it is deliberately more than npm runs: a package.json in a test
// fixture counts too. Nothing here decides which directories npm treats
// as packages.
//
// It has the signature of artifact.Inspect, so the fetch command can hand
// it to the artifact reader for artifact.NPMTarball; internal/artifact
// cannot import this package. oldPkg and newPkg are the extracted
// packages: each is the directory that holds the package's own
// package.json (the tarball with its first path element dropped, as npm
// unpacks it). oldPkg is nil for a new name. The fetch command ANDs the
// answer into the update's NoRegress, so an update whose tarballs were
// never inspected does not keep a NoRegress that holds.
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
		if err != nil {
			return err
		}
		if d.IsDir() || (d.Name() != "package.json" && d.Name() != "binding.gyp") {
			return nil
		}
		is, err := readSmall(newPkg, p)
		if err != nil {
			return err
		}
		// Whether the old tarball has the file, and with the same bytes.
		// A file that did not change brings nothing new, whatever it says:
		// that is what keeps a fixture nobody can parse from stopping an
		// update that left it alone.
		var was []byte
		had := false
		if oldPkg != nil {
			if was, err = readSmall(oldPkg, p); err == nil {
				had = true
			} else if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}

		if d.Name() == "binding.gyp" {
			gyps++
			if !had {
				problem = fmt.Sprintf("%s is new: npm builds a package that has a binding.gyp when it is installed", show(p))
				return fs.SkipAll
			}
			return nil
		}

		manifests++
		if had && bytes.Equal(was, is) {
			return nil
		}
		hooks, err := manifestHooks(is)
		if err != nil {
			problem = fmt.Sprintf("%s in the new tarball: %v", show(p), err)
			return fs.SkipAll
		}
		if len(hooks) == 0 {
			return nil
		}
		if !had {
			problem = fmt.Sprintf("%s is new and has an install script (%s)", show(p), showHooks(hooks))
			return fs.SkipAll
		}
		before, err := manifestHooks(was)
		if err != nil {
			problem = fmt.Sprintf("%s in the old tarball: %v", show(p), err)
			return fs.SkipAll
		}
		if !maps.Equal(before, hooks) {
			problem = fmt.Sprintf("the install scripts of %s change from %s to %s", show(p), showHooks(before), showHooks(hooks))
			return fs.SkipAll
		}
		return nil
	})
	switch {
	case err != nil:
		// The trees are the gate's own extraction of verified bytes. One
		// it cannot read back establishes nothing.
		return allow.Fact{Value: "the tarballs could not be read: " + quote(err.Error())}
	case problem != "":
		return allow.No(problem, tarballSource)
	}
	return allow.Yes(fmt.Sprintf("no new or changed install script in %d package.json, and no new binding.gyp (%d present)", manifests, gyps), tarballSource)
}

// readSmall reads one file of an extracted tarball, refusing one too
// large to be a package.json or a binding.gyp anyone wrote.
func readSmall(tree fs.FS, name string) ([]byte, error) {
	f, err := tree.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxPackageJSON+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPackageJSON {
		return nil, fmt.Errorf("%s is larger than %d MB", show(name), maxPackageJSON>>20)
	}
	return data, nil
}

// manifestHooks reads the install scripts out of one package.json.
func manifestHooks(data []byte) (map[string]string, error) {
	var manifest struct {
		Scripts jsontext.Value `json:"scripts"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, errors.New("not JSON the gate can read")
	}
	return readHooks(manifest.Scripts)
}

package npm

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/advisory"
	"github.com/sadbox/dep-review/internal/allow"
)

const (
	// registryURL is the only registry the gate knows. A lock that
	// resolves anywhere else is not Bound.
	registryURL = "https://registry.npmjs.org"

	// maxPackument bounds one package's document. It has every version
	// the package ever published (tailwindcss: 2720 versions, 11 MB), and
	// only the full document has the publication times.
	maxPackument = 256 << 20
	// maxAttestation bounds one version's attestations (about 15 KB).
	maxAttestation = 4 << 20
)

// packument is the registry's document for one package name, as far as
// the gatherer reads it.
type packument struct {
	Name string `json:"name"`
	// Time has "created", "modified" and one entry per version ever
	// published. An entry outlives its version being unpublished.
	Time map[string]jsontext.Value `json:"time"`
	// Versions has one document per version that is still published.
	Versions map[string]jsontext.Value `json:"versions"`
}

// versionDoc is the registry's document for one version. Most of it is
// the package.json its publisher uploaded, so every field but dist is the
// publisher's word, and is kept raw until its shape has been checked.
type versionDoc struct {
	Name                string         `json:"name"`
	Version             string         `json:"version"`
	Scripts             jsontext.Value `json:"scripts"`
	Deprecated          jsontext.Value `json:"deprecated"`
	Gypfile             jsontext.Value `json:"gypfile"`
	HasInstallScript    jsontext.Value `json:"hasInstallScript"`
	BundleDependencies  jsontext.Value `json:"bundleDependencies"`
	BundledDependencies jsontext.Value `json:"bundledDependencies"`
	Dist                struct {
		Tarball      string         `json:"tarball"`
		Integrity    string         `json:"integrity"`
		Attestations jsontext.Value `json:"attestations"`
	} `json:"dist"`
}

// packumentAnswer is what asking the registry for one name came to.
// Exactly one of doc, gone and failed is set.
type packumentAnswer struct {
	doc *packument
	// gone: the registry says there is no such package (404).
	gone bool
	// failed says why there is no answer at all.
	failed string
}

// registry asks registry.npmjs.org, once per name.
type registry struct {
	client     *http.Client
	packuments map[string]packumentAnswer
}

// packumentURL is where the registry serves name's document. The caller
// has checked name with validName.
func packumentURL(name string) string {
	return registryURL + "/" + strings.Replace(name, "/", "%2f", 1)
}

// attestationURL is where the registry serves the attestations of
// name@version. The gate builds it; the URL in the version document is
// not used.
func attestationURL(name, version string) string {
	return registryURL + "/-/npm/v1/attestations/" + strings.Replace(name, "/", "%2f", 1) + "@" + version
}

// tarballURL is where the registry serves name@version's tarball, and so
// the only "resolved" a lock entry for it may have.
func tarballURL(name, version string) string {
	base := name[strings.LastIndex(name, "/")+1:]
	return registryURL + "/" + name + "/-/" + base + "-" + version + ".tgz"
}

// errGone is the registry's 404.
var errGone = errors.New("the registry has no such document (404)")

// get fetches one document of at most max bytes.
func (r *registry) get(ctx context.Context, url string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// No User-Agent of the gate's own: the registry needs none, and a
	// request to an outside service does not have to say who is asking.
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// The registry answers these URLs itself. An answer that came from
	// somewhere else after a redirect is not the registry's.
	if resp.Request != nil && resp.Request.URL.String() != url {
		return nil, fmt.Errorf("redirected to %s", quote(resp.Request.URL.String()))
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, errGone
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("more than %d MB", max>>20)
	}
	return body, nil
}

// packument fetches name's document, or returns the answer it already
// has. The error is the context's; a registry that does not answer is an
// answer with failed set.
func (r *registry) packument(ctx context.Context, name string) (packumentAnswer, error) {
	if a, ok := r.packuments[name]; ok {
		return a, nil
	}
	a := r.fetchPackument(ctx, name)
	if ctx.Err() != nil {
		return packumentAnswer{}, ctx.Err()
	}
	r.packuments[name] = a
	return a, nil
}

func (r *registry) fetchPackument(ctx context.Context, name string) packumentAnswer {
	body, err := r.get(ctx, packumentURL(name), maxPackument)
	if errors.Is(err, errGone) {
		return packumentAnswer{gone: true}
	}
	if err != nil {
		return packumentAnswer{failed: "the registry did not answer: " + quote(err.Error())}
	}
	var doc packument
	if err := json.Unmarshal(body, &doc); err != nil {
		return packumentAnswer{failed: "the registry's document could not be read: " + quote(err.Error())}
	}
	if doc.Name != name {
		return packumentAnswer{failed: "the registry answered for " + show(doc.Name)}
	}
	return packumentAnswer{doc: &doc}
}

// version returns the registry's document for one version, and whether
// the version is published. The string says why a published version's
// document could not be used.
func (p *packument) version(version string) (doc versionDoc, published bool, problem string) {
	raw, ok := p.Versions[version]
	if !ok {
		return versionDoc{}, false, ""
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return versionDoc{}, true, "the registry's document for " + show(version) + " could not be read: " + quote(err.Error())
	}
	if doc.Name != p.Name || doc.Version != version {
		return versionDoc{}, true, "the registry's document for " + show(version) + " names " + show(doc.Name) + "@" + show(doc.Version)
	}
	return doc, true, ""
}

// when reads one entry of the packument's "time".
func (p *packument) when(key string) (time.Time, bool) {
	raw, ok := p.Time[key]
	if !ok {
		return time.Time{}, false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.IsZero() {
		return time.Time{}, false
	}
	return t, true
}

// sriRE is an integrity that is exactly one sha512 hash. npm accepts a
// download that matches any hash of a multi-hash string, so a second
// token would let through bytes other than the ones the gate checked.
var sriRE = regexp.MustCompile(`^sha512-[A-Za-z0-9+/]{86}==$`)

// sha512Of returns the digest of an integrity string that is exactly one
// sha512 hash.
func sha512Of(integrity string) ([]byte, bool) {
	if !sriRE.MatchString(integrity) {
		return nil, false
	}
	sum, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(integrity, "sha512-"))
	if err != nil || len(sum) != sha512.Size {
		return nil, false
	}
	return sum, true
}

// boundFact is the Bound fact: every head lock entry for the update is
// the registry's own tarball for that name and version, pinned by one
// sha512, and that hash is the one the registry reports now.
func boundFact(u update, a packumentAnswer, source string) allow.Fact {
	// What the lock says, first: this needs no registry.
	const lockSource = "package-lock.json at head"
	if !validName(u.Name) || !validVersion(u.To) {
		return allow.No("the name or version is not a shape the registry serves", lockSource)
	}
	want := tarballURL(u.Name, u.To)
	integrity := u.New[0].Integrity
	for _, c := range u.New {
		switch {
		case installedName(c.Path) != u.Name:
			return allow.No(fmt.Sprintf("%s holds %s: an alias, or a path outside node_modules, which the gate has no rule for", show(c.Path), show(u.Name)), lockSource)
		case c.Resolved != want:
			return allow.No(fmt.Sprintf("%s resolves to %s, not the registry's %s", show(c.Path), quote(c.Resolved), want), lockSource)
		case c.Integrity != integrity:
			return allow.No(fmt.Sprintf("the lock has two different hashes for %s@%s", show(u.Name), show(u.To)), lockSource)
		}
	}
	pinned, ok := sha512Of(integrity)
	if !ok {
		return allow.No("the lock's integrity is not exactly one sha512 hash: "+quote(integrity), lockSource)
	}

	switch {
	case a.failed != "":
		return allow.Fact{Value: a.failed}
	case a.gone:
		return allow.No("the registry has no package of this name", source)
	}
	doc, published, problem := a.doc.version(u.To)
	switch {
	case !published:
		return allow.No(show(u.To)+" is not on the registry (unpublished)", source)
	case problem != "":
		return allow.Fact{Value: problem}
	}
	reported, ok := sha512Of(doc.Dist.Integrity)
	if !ok {
		return allow.No("the registry's dist.integrity is not one sha512 hash: "+quote(doc.Dist.Integrity), source)
	}
	if !bytes.Equal(reported, pinned) {
		return allow.No(fmt.Sprintf("the lock pins %s, the registry reports %s", integrity, doc.Dist.Integrity), source)
	}
	if doc.Dist.Tarball != want {
		return allow.No("the registry serves this version from "+quote(doc.Dist.Tarball), source)
	}
	return allow.Yes(integrity+" is the registry's dist.integrity, and the lock resolves to the registry's tarball", source)
}

// timeFacts are FirstSeen (the registry's own clock for when the version
// was published) and NameCreated (when the name was first published).
func timeFacts(u update, a packumentAnswer, source string) (firstSeen, nameCreated allow.TimeFact) {
	switch {
	case a.failed != "":
		return allow.TimeFact{Value: a.failed}, allow.TimeFact{Value: a.failed}
	case a.gone:
		const gone = "the registry has no package of this name"
		return allow.TimeFact{Value: gone}, allow.TimeFact{Value: gone}
	}
	firstSeen = allow.TimeFact{Value: "the registry has no publication time for " + show(u.To)}
	if t, ok := a.doc.when(u.To); ok {
		firstSeen = allow.At(t, source+" time["+show(u.To)+"]")
	}
	nameCreated = allow.TimeFact{Value: "the registry has no creation time for the name"}
	if t, ok := a.doc.when("created"); ok {
		nameCreated = allow.At(t, source+" time.created")
	}
	return firstSeen, nameCreated
}

// cleanFact is the Clean fact. The registry knows whether the version is
// still published and whether it is deprecated; the advisory database
// knows the rest. A "no" from either is a gathered no; when either could
// not be asked and nothing said no, the fact is left ungathered.
func cleanFact(u update, a packumentAnswer, source string, adv advisory.Result, advFailed string) allow.Fact {
	registrySays := ""
	switch {
	case a.failed != "":
		// Not asked: decided below, after the advisories had their say.
	case a.gone:
		return allow.No("the registry has no package of this name", source)
	default:
		doc, published, problem := a.doc.version(u.To)
		switch {
		case !published:
			return allow.No(show(u.To)+" is not on the registry (unpublished)", source)
		case problem != "":
			return allow.Fact{Value: problem}
		}
		// The registry sets "deprecated" to the publisher's message. An
		// empty message is how a deprecation is withdrawn.
		if present(doc.Deprecated) && string(doc.Deprecated) != `""` {
			return allow.No("deprecated on the registry: "+quote(string(doc.Deprecated)), source)
		}
		registrySays = "published and not deprecated"
	}

	if advFailed == "" {
		for _, f := range []allow.Fact{adv.NoMalware, adv.NoNewAdvisory} {
			if f.Gathered() && !f.OK {
				return allow.No(f.Value, f.Source)
			}
		}
	}
	switch {
	case a.failed != "":
		return allow.Fact{Value: a.failed}
	case advFailed != "":
		return allow.Fact{Value: registrySays + "; " + advFailed}
	case !adv.NoMalware.Gathered() || !adv.NoNewAdvisory.Gathered():
		return allow.Fact{Value: registrySays + "; the advisory database gave no answer about malware or new advisories"}
	}
	return allow.Yes(
		registrySays+"; "+adv.NoMalware.Value+"; "+adv.NoNewAdvisory.Value,
		source+"; "+adv.NoMalware.Source+"; "+adv.NoNewAdvisory.Source)
}

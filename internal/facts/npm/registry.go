package npm

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/advisory"
	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/facts"
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
	Name             string         `json:"name"`
	Version          string         `json:"version"`
	Scripts          jsontext.Value `json:"scripts"`
	Deprecated       jsontext.Value `json:"deprecated"`
	Gypfile          jsontext.Value `json:"gypfile"`
	HasInstallScript jsontext.Value `json:"hasInstallScript"`
	Dist             struct {
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
	// failed says why there is no usable answer.
	failed string
	// unreachable goes with failed: the registry was asked and did not
	// answer (no response, a 429 or a 5xx), so asking again may. Without
	// it the answer arrived and cannot be used, or the question was never
	// put, and asking again would change nothing.
	unreachable bool
}

// noDoc is the fact for a question an answer without a document leaves
// open: a "no" when the registry has no such package, unavailable, which
// is a wait, when it did not answer, and otherwise never gathered, which
// is person.
func (a packumentAnswer) noDoc(source string) allow.Fact {
	switch {
	case a.gone:
		return allow.No("the registry has no package of this name", source)
	case a.unreachable:
		return allow.Unavailable(a.failed, source)
	}
	return allow.Fact{Value: a.failed}
}

// version returns the registry's document for one version. When there is
// none to use it reports false, and the fact says why: noDoc's, a "no"
// for a version that is not published, or never gathered for a document
// that cannot be read or names something else.
func (a packumentAnswer) version(version, source string) (versionDoc, allow.Fact, bool) {
	if a.doc == nil {
		return versionDoc{}, a.noDoc(source), false
	}
	raw, ok := a.doc.Versions[version]
	if !ok {
		return versionDoc{}, allow.No(show(version)+" is not on the registry (unpublished)", source), false
	}
	var doc versionDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return versionDoc{}, allow.Fact{Value: "the registry's document for " + show(version) + " could not be read: " + quote(err.Error())}, false
	}
	if doc.Name != a.doc.Name || doc.Version != version {
		return versionDoc{}, allow.Fact{Value: "the registry's document for " + show(version) + " names " + show(doc.Name) + "@" + show(doc.Version)}, false
	}
	return doc, allow.Fact{}, true
}

// registry asks registry.npmjs.org, once per name.
type registry struct {
	client     *http.Client
	packuments map[string]packumentAnswer
}

// packumentURL is where the registry serves name's document. The caller
// has checked name with artifact.ValidNPMName.
func packumentURL(name string) string {
	return registryURL + "/" + strings.Replace(name, "/", "%2f", 1)
}

// attestationURL is where the registry serves the attestations of
// name@version. The gate builds it; the URL in the version document is
// not used.
func attestationURL(name, version string) string {
	return registryURL + "/-/npm/v1/attestations/" + strings.Replace(name, "/", "%2f", 1) + "@" + version
}

// errGone is the registry's 404.
var errGone = errors.New("the registry has no such document (404)")

// errUnreachable is the error of a request the registry did not answer:
// no response, a 429 or a 5xx. It says nothing about the package. Every
// other error of get is an answer that arrived.
var errUnreachable = errors.New("the registry did not answer")

// why renders an error of get for a fact's Value: whether the registry
// did not answer or answered something that cannot be used, and then the
// error's own text, quoted, because it can carry what the other end sent.
func why(err error) string {
	if errors.Is(err, errUnreachable) {
		return "the registry did not answer: " + quote(strings.TrimPrefix(err.Error(), errUnreachable.Error()+": "))
	}
	return "the registry's answer could not be used: " + quote(err.Error())
}

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
		return nil, fmt.Errorf("%w: %v", errUnreachable, err)
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
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, fmt.Errorf("%w: HTTP status %d", errUnreachable, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errUnreachable, err)
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
	var a packumentAnswer
	var doc packument
	body, err := r.get(ctx, packumentURL(name), maxPackument)
	switch {
	case ctx.Err() != nil:
		return packumentAnswer{}, ctx.Err()
	case errors.Is(err, errGone):
		a.gone = true
	case err != nil:
		a.failed, a.unreachable = why(err), errors.Is(err, errUnreachable)
	default:
		if err := json.Unmarshal(body, &doc); err != nil {
			a.failed = "the registry's document could not be read: " + quote(err.Error())
		} else if doc.Name != name {
			a.failed = "the registry answered for " + show(doc.Name)
		} else {
			a.doc = &doc
		}
	}
	r.packuments[name] = a
	return a, nil
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

// boundFact is the Bound fact: every head lock entry for the update is
// the registry's own tarball for that name and version, pinned by one
// sha512, and that hash is the one the registry reports now.
func boundFact(u update, a packumentAnswer, source string) allow.Fact {
	// What the lock says, first: this needs no registry.
	const lockSource = "package-lock.json at head"
	if !artifact.ValidNPMName(u.Name) || !artifact.ValidNPMVersion(u.To) {
		return allow.No("the name or version is not a shape the registry serves", lockSource)
	}
	want := artifact.NPMTarballURL(u.Name, u.To)
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
	pinned, ok := artifact.NPMIntegrity(integrity)
	if !ok {
		return allow.No("the lock's integrity is not exactly one sha512 hash: "+quote(integrity), lockSource)
	}

	doc, missing, ok := a.version(u.To, source)
	if !ok {
		return missing
	}
	reported, ok := artifact.NPMIntegrity(doc.Dist.Integrity)
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
	if a.doc == nil {
		// A package the registry does not have has no time: nothing was
		// established, as when its answer cannot be used.
		none := allow.TimeFact{Value: a.noDoc(source).Value}
		if a.unreachable {
			none = allow.UnavailableTime(a.failed, source)
		}
		return none, none
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

// cleanFact is the Clean fact: the registry's part, and the advisory
// database's two.
func cleanFact(u update, a packumentAnswer, source string, adv advisory.Result) allow.Fact {
	return publishedFact(u, a, source).And(facts.AdvisoryClean(adv))
}

// publishedFact is the registry's part of Clean: the version is still
// published and not deprecated.
func publishedFact(u update, a packumentAnswer, source string) allow.Fact {
	doc, missing, ok := a.version(u.To, source)
	if !ok {
		return missing
	}
	// The registry sets "deprecated" to the publisher's message. An
	// empty message is how a deprecation is withdrawn.
	if present(doc.Deprecated) && string(doc.Deprecated) != `""` {
		return allow.No("deprecated on the registry: "+quote(string(doc.Deprecated)), source)
	}
	return allow.Yes("published and not deprecated", source)
}

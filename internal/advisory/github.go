package advisory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/gh"
)

// How this file talks to GitHub, and what was checked against the real
// API (2026-11-22; the recorded answers are in testdata):
//
//	GET /advisories?type=T&ecosystem=E&affects=NAME@VERSION&per_page=100
//
// GitHub evaluates the version ranges. Nothing here reads
// vulnerable_version_range.
//
// The one answer that grants anything is an empty list, so every way the
// API was seen to answer an empty list for a question it did not
// understand is closed before the request is made:
//
//   - A version it cannot read ("notaversion", "", " 1.2.3") is 200 with
//     an empty list, not an error. Only X.Y.Z is ever sent.
//   - NAME@VERSION matches the name byte for byte
//     ("azure/setup-kubectl@2.0.0" finds nothing, "Azure/setup-kubectl@2.0.0"
//     finds GHSA-p756-rfxh-x63h), while GitHub itself resolves an action's
//     owner/repo in any case. NAME alone matches in any case. For Actions
//     the database's own spelling is looked up first.
//   - Withdrawn advisories are in the answer unless filtered here.
//   - A comma in affects starts a second package.
//
// A leading "v" on the version makes no difference to the API for Go or
// Actions, and a Go "+incompatible" suffix is accepted. A malware
// advisory against a whole package (range "> 0") is in the answer for
// any version of it.

// The two advisory types the gate asks for. Every advisory has exactly
// one type, and the API answers for one type per request.
const (
	typeReviewed = "reviewed"
	typeMalware  = "malware"
)

// The database's ecosystem names for the ecosystems it shares with the
// gate. It has none for container images.
const (
	ecoGo      = "go"
	ecoNPM     = "npm"
	ecoActions = "actions"
)

// Pager is the one call the checker makes on a GitHub REST client: GET
// path and every following page, handing each page's body to fn.
// *gh.Client implements it, with the retries, the rate-limit waits and
// the check that a next-page link stays on the API host.
type Pager interface {
	Pages(ctx context.Context, path string, fn func(body []byte) error) error
}

// GitHub is the Checker that asks GitHub's global security advisories
// API. The endpoint is public: it needs no token permission and works
// without a token, at the unauthenticated rate limit.
type GitHub struct {
	api Pager
	// perPage is the page size asked for. Tests lower it to get a real
	// answer that spans pages.
	perPage int
}

// New returns a Checker that asks through api, which must not be nil.
func New(api Pager) *GitHub {
	return &GitHub{api: api, perPage: 100}
}

// Check implements Checker.
//
// It makes three requests for Go and npm (reviewed advisories on From,
// reviewed on To, malware on To), two for a new name, and none for
// Docker. Actions costs two more (four for an action in a directory), to
// find how the database spells the action's name, and makes no request
// about a version when the database has no advisory under the name at
// all.
//
// A request that fails, after the client's own retries, settles all
// three facts at once, since nothing can be said from half the answers.
// When GitHub did not answer (no response, a server error, a rate limit)
// they are unavailable, which is a wait. When it answered with an error
// that asking again would not change, they are left ungathered. An answer
// that arrived but is not what the API documents, or a name or version
// the API cannot be asked about, leaves the facts that depend on it
// ungathered too: their Source is empty and their Value says why. The
// error return is the context's.
func (g *GitHub) Check(ctx context.Context, q Query) (Result, error) {
	eco, covered := databaseEcosystem(q.Ecosystem)
	if !covered {
		return notCovered(q.Ecosystem), nil
	}
	if why := unaskable(eco, q); why != "" {
		return Result{SecurityFix: unknown(why), NoMalware: unknown(why), NoNewAdvisory: unknown(why)}, nil
	}
	res, err := g.ask(ctx, eco, q)
	switch {
	case err == nil:
		return res, nil
	case ctx.Err() != nil:
		return Result{}, fmt.Errorf("advisory: %w", ctx.Err())
	}
	// The status and nothing else of the error: its text can carry
	// GitHub's own message, and a fact's Value ends up in a comment.
	const source = "GET api.github.com/advisories"
	var f allow.Fact
	switch status := gh.StatusCode(err); {
	case gh.Unavailable(err) && status != 0:
		f = allow.Unavailable(fmt.Sprintf("GitHub's Advisory Database did not answer (HTTP %d, after retries)", status), source)
	case gh.Unavailable(err):
		f = allow.Unavailable("GitHub's Advisory Database did not answer (no response, after retries)", source)
	case status != 0:
		f = unknown(fmt.Sprintf("GitHub's Advisory Database answered with an error (HTTP %d); asking again would get the same", status))
	default:
		f = unknown("GitHub's Advisory Database gave an answer that could not be used; asking again would get the same")
	}
	return Result{SecurityFix: f, NoMalware: f, NoNewAdvisory: f}, nil
}

// ask makes the requests for one update. The error is the first request
// that failed.
func (g *GitHub) ask(ctx context.Context, eco string, q Query) (Result, error) {
	from, to := bare(eco, q.From), bare(eco, q.To)

	reviewedNames, err := g.spellings(ctx, eco, typeReviewed, q.Name)
	if err != nil {
		return Result{}, err
	}
	malwareNames, err := g.spellings(ctx, eco, typeMalware, q.Name)
	if err != nil {
		return Result{}, err
	}

	var onFrom asked
	if q.From != "" {
		if onFrom, err = g.affecting(ctx, eco, typeReviewed, reviewedNames, from); err != nil {
			return Result{}, err
		}
	}
	onTo, err := g.affecting(ctx, eco, typeReviewed, reviewedNames, to)
	if err != nil {
		return Result{}, err
	}
	malware, err := g.affecting(ctx, eco, typeMalware, malwareNames, to)
	if err != nil {
		return Result{}, err
	}

	return Result{
		SecurityFix:   securityFix(q, eco, onFrom, onTo),
		NoMalware:     noMalware(q, eco, malware),
		NoNewAdvisory: noNewAdvisory(q, eco, onFrom, onTo),
	}, nil
}

// databaseEcosystem maps one of allow's ecosystem constants to the
// database's name for it.
func databaseEcosystem(ecosystem string) (string, bool) {
	switch ecosystem {
	case allow.GoModules:
		return ecoGo, true
	case allow.NPM:
		return ecoNPM, true
	case allow.GitHubActions:
		return ecoActions, true
	}
	return "", false
}

// notCovered is the answer for an ecosystem the database is never asked
// about.
func notCovered(ecosystem string) Result {
	if ecosystem == allow.Docker {
		// The database has no container ecosystem, so there is nothing it
		// could say against an image, and that is known without asking.
		// The two Clean inputs are gathered as holding and say so: left
		// ungathered, a Docker update could never be Clean and the Docker
		// row of the decision table could never be reached.
		const value = "GitHub's Advisory Database has no container image ecosystem; nothing was asked"
		const source = "GitHub Advisory Database: its list of ecosystems"
		return Result{
			SecurityFix:   allow.No(value, source),
			NoMalware:     allow.Yes(value, source),
			NoNewAdvisory: allow.Yes(value, source),
		}
	}
	// Not one of allow's ecosystems. The database may well cover it, but
	// the gate has no rule for it and this package no name for it, so
	// nothing vouches for the new version.
	const why = "this ecosystem has no advisory lookup; nothing was asked"
	return Result{
		SecurityFix:   allow.No(why, "internal/advisory: ecosystems with a lookup"),
		NoMalware:     unknown(why),
		NoNewAdvisory: unknown(why),
	}
}

// unknown is a fact that could not be established, for a reason that
// asking again does not change. Its Source is empty, so allow reads it as
// never gathered whatever else it holds; Value only carries the reason to
// the pull request comment. (A database that did not answer is not this:
// see Check.)
func unknown(why string) allow.Fact { return allow.Fact{Value: why} }

var (
	// An npm name, with or without a scope. Wider than what the registry
	// accepts for a new package (old names have capitals); its job is to
	// keep "@" and "," out of the places where affects gives them meaning.
	npmNameRe = regexp.MustCompile(`^(@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+$`)
	// owner/repo, or owner/repo/path for an action in a directory.
	actionNameRe = regexp.MustCompile(`^[A-Za-z0-9-]+/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)
	// GitHub's advisory ID, from its own documented alphabet.
	ghsaRe = regexp.MustCompile(`^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)
)

// unaskable says why q cannot be put to the API, or "" when it can. It
// never quotes the name or version it refuses: they may be anything.
func unaskable(eco string, q Query) string {
	nameOK := false
	switch eco {
	case ecoGo:
		nameOK = module.CheckPath(q.Name) == nil
	case ecoNPM:
		nameOK = npmNameRe.MatchString(q.Name)
	case ecoActions:
		nameOK = actionNameRe.MatchString(q.Name)
		for _, part := range strings.Split(q.Name, "/") {
			if part == "." || part == ".." {
				nameOK = false
			}
		}
	}
	if !nameOK || len(q.Name) > 256 {
		return "the package name is not one the advisory query can carry; nothing was asked"
	}
	if !plainRelease(eco, q.To) {
		return "the new version is not a plain X.Y.Z release; the database answers \"no advisories\" for a version it cannot read, so nothing was asked"
	}
	if q.From != "" && !plainRelease(eco, q.From) {
		return "the old version is not a plain X.Y.Z release; the database answers \"no advisories\" for a version it cannot read, so nothing was asked"
	}
	return ""
}

// plainRelease reports whether v is three numbers and nothing else: the
// one version shape the API was checked to read. Go and Actions versions
// may carry their leading "v", and a Go version "+incompatible".
// x/mod/semver does the reading.
func plainRelease(eco, v string) bool {
	if eco != ecoNPM {
		v = strings.TrimPrefix(v, "v")
	}
	v = "v" + v
	if !semver.IsValid(v) || semver.Prerelease(v) != "" {
		return false
	}
	if eco == ecoGo {
		return module.CanonicalVersion(v) == v
	}
	return semver.Canonical(v) == v
}

// bare drops the leading "v" that Go module versions and action tags
// carry and the database's versions do not, so that "v1.2.3" and "1.2.3"
// are one version (spec section 11, amendment 8). It is the only change
// ever made to a version: the comparison with first_patched_version is
// otherwise byte for byte.
func bare(eco, v string) string {
	if eco == ecoGo || eco == ecoActions {
		return strings.TrimPrefix(v, "v")
	}
	return v
}

// names is how the database spells one package, for one advisory type.
type names struct {
	// spelled is every spelling the database uses. For Go and npm that is
	// the name as given. For Actions it may be empty: the database has no
	// advisory of this type under the name in any case.
	spelled []string
	// affects is what was asked to find out; empty for Go and npm.
	affects []string
	// problem is set when the answer could not be read.
	problem string
}

// spellings finds how the database spells name. Go and npm names are
// case-sensitive everywhere, so the name stands as given and nothing is
// asked. An action is the same action in any case to GitHub but not to
// NAME@VERSION, so the name is first asked for alone, which matches in
// any case, and the spellings in the answer are the ones to ask with.
//
// An action in a directory (owner/repo/path) is released with its
// repository, under the repository's tags, so an advisory against
// owner/repo is against it too: both names are asked for.
func (g *GitHub) spellings(ctx context.Context, eco, typ, name string) (names, error) {
	if eco != ecoActions {
		return names{spelled: []string{name}}, nil
	}
	ask := []string{name}
	if parts := strings.Split(name, "/"); len(parts) > 2 {
		ask = []string{parts[0] + "/" + parts[1], name}
	}
	var n names
	for _, alone := range ask {
		n.affects = append(n.affects, alone)
		recs, problem, err := g.list(ctx, eco, typ, alone)
		if err != nil {
			return names{}, err
		}
		if problem != "" {
			n.problem = problem
			return n, nil
		}
		for _, r := range recs {
			found := false
			for _, v := range r.Vulnerabilities {
				if v.Package.Ecosystem == eco && strings.EqualFold(v.Package.Name, alone) {
					found = true
					if !slices.Contains(n.spelled, v.Package.Name) {
						n.spelled = append(n.spelled, v.Package.Name)
					}
				}
			}
			if !found {
				n.problem = notAbout(eco, typ, alone, r.GHSAID)
				return n, nil
			}
		}
	}
	slices.Sort(n.spelled)
	return n, nil
}

// asked is one question put to the database (which advisories of one
// type affect one version of one package) and what came back.
type asked struct {
	// affects is every affects value that was sent, for a fact's Source.
	affects []string
	// live maps the ID of every advisory in the answer that is not
	// withdrawn to the first patched versions it lists for the package.
	live map[string][]string
	// problem is set when the answer could not be read. live then means
	// nothing.
	problem string
}

// affecting asks which advisories of typ affect version of the package,
// under every spelling the database has for it.
func (g *GitHub) affecting(ctx context.Context, eco, typ string, n names, version string) (asked, error) {
	a := asked{affects: slices.Clone(n.affects), live: map[string][]string{}, problem: n.problem}
	if a.problem != "" {
		return a, nil
	}
	for _, name := range n.spelled {
		affects := name + "@" + version
		a.affects = append(a.affects, affects)
		recs, problem, err := g.list(ctx, eco, typ, affects)
		if err != nil {
			return asked{}, err
		}
		if problem != "" {
			a.problem = problem
			return a, nil
		}
		for _, r := range recs {
			// An advisory in the answer that does not name the package
			// means the filter did not do what this code believes it
			// does, and then an empty answer would mean nothing either.
			named := false
			var patched []string
			for _, v := range r.Vulnerabilities {
				if v.Package.Ecosystem != eco || v.Package.Name != name {
					continue
				}
				named = true
				if v.FirstPatchedVersion != nil {
					patched = append(patched, *v.FirstPatchedVersion)
				}
			}
			if !named {
				a.problem = notAbout(eco, typ, affects, r.GHSAID)
				return a, nil
			}
			if r.withdrawn {
				continue
			}
			a.live[r.GHSAID] = append(a.live[r.GHSAID], patched...)
		}
	}
	return a, nil
}

// record is one advisory as the API returns it, cut down to what the
// gate reads. Summary, description and references are text a stranger
// wrote; none of it is decoded.
type record struct {
	GHSAID          string          `json:"ghsa_id"`
	Type            string          `json:"type"`
	WithdrawnAt     json.RawMessage `json:"withdrawn_at"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		FirstPatchedVersion *string `json:"first_patched_version"`
	} `json:"vulnerabilities"`

	// withdrawn is WithdrawnAt, once read.
	withdrawn bool
}

// errStop ends paging once a page could not be read.
var errStop = errors.New("advisory: unreadable page")

// list fetches every page of one advisories query. problem is set, with
// a nil error, when the API answered and the answer is not the list of
// advisories it documents.
func (g *GitHub) list(ctx context.Context, eco, typ, affects string) (recs []record, problem string, err error) {
	query := url.Values{
		"type":      {typ},
		"ecosystem": {eco},
		"affects":   {affects},
		"per_page":  {strconv.Itoa(g.perPage)},
	}
	err = g.api.Pages(ctx, "advisories?"+query.Encode(), func(body []byte) error {
		page, why := decodePage(body, typ)
		if why != "" {
			problem = describe(eco, typ, affects) + ": " + why
			return errStop
		}
		recs = append(recs, page...)
		return nil
	})
	if problem != "" {
		return nil, problem, nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("advisory: %s: %w", describe(eco, typ, affects), err)
	}
	return recs, "", nil
}

// decodePage reads one page of advisories of type typ. The second result
// says what is wrong with a page that is not what the API documents; it
// never quotes the page.
func decodePage(body []byte, typ string) ([]record, string) {
	// encoding/json decodes null into a nil slice without complaint, and
	// a nil slice would read as "no advisories".
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '[' {
		return nil, "the answer is not a list"
	}
	var page []record
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, "the answer is not a list of advisories in the documented shape"
	}
	for i := range page {
		r := &page[i]
		if !ghsaRe.MatchString(r.GHSAID) {
			return nil, fmt.Sprintf("entry %d has no GHSA ID", i+1)
		}
		if r.Type != typ {
			return nil, fmt.Sprintf("%s is not of the type asked for", r.GHSAID)
		}
		// withdrawn_at must be there to be believed: read as absent, a
		// renamed field would make every withdrawn advisory live, and a
		// withdrawn advisory must not grant the fast path.
		switch {
		case len(r.WithdrawnAt) == 0:
			return nil, fmt.Sprintf("%s does not say whether it was withdrawn", r.GHSAID)
		case string(r.WithdrawnAt) == "null":
		default:
			var at string
			if err := json.Unmarshal(r.WithdrawnAt, &at); err != nil {
				return nil, fmt.Sprintf("%s has an unreadable withdrawal time", r.GHSAID)
			}
			if _, err := time.Parse(time.RFC3339, at); err != nil {
				return nil, fmt.Sprintf("%s has an unreadable withdrawal time", r.GHSAID)
			}
			r.withdrawn = true
		}
	}
	return page, ""
}

// describe names one request in a fact's Value or in an error.
func describe(eco, typ, affects string) string {
	return "advisories?type=" + typ + "&ecosystem=" + eco + "&affects=" + affects
}

// notAbout is the problem of an answer that holds an advisory which does
// not name the package asked about.
func notAbout(eco, typ, affects, id string) string {
	return describe(eco, typ, affects) + ": the answer holds " + id + ", which does not name this package"
}

// source is a fact's Source: the requests its answer came from.
func source(eco, typ string, questions ...asked) string {
	var affects []string
	for _, a := range questions {
		for _, s := range a.affects {
			if !slices.Contains(affects, s) {
				affects = append(affects, s)
			}
		}
	}
	return "GET api.github.com/advisories?type=" + typ + "&ecosystem=" + eco + ", affects=" + strings.Join(affects, " and ")
}

// ids is the sorted, comma-separated list of the IDs in set.
func ids(set []string) string {
	slices.Sort(set)
	return strings.Join(set, ", ")
}

// securityFix builds the SecurityFix fact from the reviewed advisories
// on the old version and on the new one.
func securityFix(q Query, eco string, onFrom, onTo asked) allow.Fact {
	if q.From == "" {
		return allow.No("new name: there is no old version for an advisory to affect", "the update: it has no old version")
	}
	if onFrom.problem != "" {
		return unknown(onFrom.problem)
	}
	if onTo.problem != "" {
		return unknown(onTo.problem)
	}
	src := source(eco, typeReviewed, onFrom, onTo)

	// fixed: affects From and not To. named: of those, the ones that
	// list To as a first patched version. An advisory with several
	// ranges lists several, and which range From fell in is GitHub's
	// knowledge, not the gate's: any of them counts.
	var fixed, named []string
	to := bare(eco, q.To)
	for id, patched := range onFrom.live {
		if _, still := onTo.live[id]; still {
			continue
		}
		fixed = append(fixed, id)
		for _, p := range patched {
			if bare(eco, p) == to {
				named = append(named, id)
				break
			}
		}
	}
	switch {
	case len(named) > 0:
		return allow.Yes(fmt.Sprintf("%s: affects %s, not %s, first patched version %s", ids(named), q.From, q.To, q.To), src)
	case len(fixed) > 0:
		return allow.No(fmt.Sprintf("%s: affects %s, not %s, but first patched version is not %s", ids(fixed), q.From, q.To, q.To), src)
	}
	return allow.No(fmt.Sprintf("no reviewed advisory affects %s and not %s", q.From, q.To), src)
}

// noMalware builds the NoMalware fact from the malware advisories on the
// new version.
func noMalware(q Query, eco string, malware asked) allow.Fact {
	if malware.problem != "" {
		return unknown(malware.problem)
	}
	src := source(eco, typeMalware, malware)
	if len(malware.live) > 0 {
		return allow.No(fmt.Sprintf("%s: malware advisory affects %s", ids(slices.Collect(maps.Keys(malware.live))), q.To), src)
	}
	return allow.Yes("no malware advisory affects "+q.To, src)
}

// noNewAdvisory builds the NoNewAdvisory fact from the reviewed
// advisories on the old version and on the new one. For a new name
// onFrom is empty, so every advisory on the new version is new.
func noNewAdvisory(q Query, eco string, onFrom, onTo asked) allow.Fact {
	if onFrom.problem != "" {
		return unknown(onFrom.problem)
	}
	if onTo.problem != "" {
		return unknown(onTo.problem)
	}
	var fresh, both []string
	for id := range onTo.live {
		if _, had := onFrom.live[id]; had {
			both = append(both, id)
		} else {
			fresh = append(fresh, id)
		}
	}
	if q.From == "" {
		src := source(eco, typeReviewed, onTo)
		if len(fresh) > 0 {
			return allow.No(fmt.Sprintf("%s: affects %s (new name: there is no old version to compare)", ids(fresh), q.To), src)
		}
		return allow.Yes("no reviewed advisory affects "+q.To, src)
	}
	src := source(eco, typeReviewed, onFrom, onTo)
	if len(fresh) > 0 {
		return allow.No(fmt.Sprintf("%s: affects %s, not %s", ids(fresh), q.To, q.From), src)
	}
	value := fmt.Sprintf("no reviewed advisory affects %s and not %s", q.To, q.From)
	if len(both) > 0 {
		value += "; on both: " + ids(both)
	}
	return allow.Yes(value, src)
}

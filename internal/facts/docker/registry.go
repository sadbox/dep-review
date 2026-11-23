package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/facts"
)

// What the gatherer asks a registry: which digest a tag resolves to (a
// HEAD, which Docker Hub does not count as a pull), when that became
// public, and on GCR whether the manifest is marked deprecated. It never
// downloads a manifest body, a config, a layer or any other blob.
//
// Every URL is one of a fixed few, built here from parts that passed
// fromLineRe. Nothing a registry answers chooses where the next request
// goes: redirects are not followed, and the token endpoint is Docker
// Hub's own, not whatever a WWW-Authenticate header names.

const (
	// userAgent says what the client does and nothing about whose it is:
	// a registry has no need to know which project asks.
	userAgent = "oci-head/1"

	// acceptManifests lists both index and both manifest types. A
	// registry asked without the index types answers with a converted
	// manifest, whose digest is not the one a Dockerfile pins.
	acceptManifests = "application/vnd.oci.image.index.v1+json, " +
		"application/vnd.docker.distribution.manifest.list.v2+json, " +
		"application/vnd.oci.image.manifest.v1+json, " +
		"application/vnd.docker.distribution.manifest.v2+json"

	maxTokenBytes  = 64 << 10
	maxHubTagBytes = 1 << 20
	// maxGCRListBytes bounds GCR's tag list, which has one entry per
	// manifest ever uploaded: 5.6 MB for distroless/static-debian12 when
	// this was written, and growing.
	maxGCRListBytes = 64 << 20

	requestTimeout = time.Minute
	// maxTries is how often one request is made before the registry
	// counts as one that could not be asked.
	maxTries = 3
)

// earliestClock is before either registry existed. A time before it is a
// placeholder, not a clock reading: GCR's list carries "0" and year 1 in
// the fields next to the one read here, and a FirstSeen of 1970 would
// satisfy every age.
var earliestClock = time.Date(2014, 1, 1, 0, 0, 0, 0, time.UTC)

var (
	digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// tokenRe is the characters of a bearer token (RFC 6750). Anything
	// else must not reach a request header.
	tokenRe = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)
)

// asker makes the registry requests of one Gather call.
type asker struct {
	client *http.Client
	sleep  func(ctx context.Context, d time.Duration) error
	// hubTokens caches Docker Hub's anonymous pull token per repository.
	hubTokens map[string]string
	// gcrLists caches GCR's tag list per repository: it is megabytes, and
	// one Dockerfile often pins several tags of one repository.
	gcrLists map[string]gcrList
}

// answer is the part of a response the gatherer looks at.
type answer struct {
	status int
	// digest is the Docker-Content-Digest header, as sent.
	digest string
	// body is the body of a 200 answer to a GET. The body of any other
	// answer is never read: it is text for a person, written by the
	// registry or by whoever controls the repository.
	body []byte
	// tooLarge: the body was longer than the caller's limit, and dropped.
	tooLarge bool
	// failed: the registry could not be asked. Every try ended without a
	// connection, in a rate limit or in a server error. status is then
	// the last try's, or 0 when it had none. That says nothing about the
	// image, so what depended on the answer is unavailable, and it is
	// kept apart from every answer that did arrive: a 404 is a "no", and
	// an answer the gatherer cannot read (another status, a body in
	// another shape) establishes nothing however often it is asked for.
	failed bool
}

// unreachable describes a failed ask for a fact's value. It gives the
// status and never the transport's error text, which can carry whatever
// the other end sent.
func (ans answer) unreachable(who string) string {
	if ans.status != 0 {
		return fmt.Sprintf("%s could not be asked (HTTP %d, %d tries)", who, ans.status, maxTries)
	}
	return fmt.Sprintf("%s could not be reached (%d tries)", who, maxTries)
}

// transient reports whether a status says "ask again" and nothing about
// the image.
func transient(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// do makes one request, up to maxTries times. Every answer that says
// something about the image, 404 and 401 included, is returned as it is.
// A registry that could not be asked on any try is an answer too, in the
// failed state: what depended on it is unavailable. The error is non-nil
// only when the context is done: then the run itself is over and there is
// no result.
func (a *asker) do(ctx context.Context, method, rawURL, accept, bearer string, maxBody int64) (answer, error) {
	for try := 1; ; try++ {
		ans, err := a.once(ctx, method, rawURL, accept, bearer, maxBody)
		if err == nil && !transient(ans.status) {
			return ans, nil
		}
		if ctx.Err() != nil {
			return answer{}, ctx.Err()
		}
		if try == maxTries {
			// After a transport error ans is empty, so status is 0.
			return answer{status: ans.status, failed: true}, nil
		}
		if err := a.sleep(ctx, time.Duration(try)*time.Second); err != nil {
			return answer{}, err
		}
	}
}

// once makes one request.
func (a *asker) once(ctx context.Context, method, rawURL, accept, bearer string, maxBody int64) (answer, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return answer{}, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", accept)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return answer{}, err
	}
	defer resp.Body.Close()
	ans := answer{status: resp.StatusCode, digest: resp.Header.Get("Docker-Content-Digest")}
	if resp.StatusCode != http.StatusOK || method == http.MethodHead {
		return ans, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return answer{}, err
	}
	if int64(len(body)) > maxBody {
		ans.tooLarge = true
		return ans, nil
	}
	ans.body = body
	return ans, nil
}

// sleepCtx waits for d or for the context to end.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// registryFacts is what the registry is the source of, for the head side
// of one change.
type registryFacts struct {
	bound, clean, superseded allow.Fact
	firstSeen                allow.TimeFact
}

// unknownTime is a FirstSeen the registry was asked for and has no usable
// clock reading for, with why.
func unknownTime(why, source string) allow.TimeFact {
	return allow.TimeFact{Value: why, Source: source}
}

// unanswered is the same outcome for Bound, Clean and FirstSeen when the
// tag's digest could not be had (facts.Unanswered).
func unanswered(why, source string, unreachable bool) registryFacts {
	f := facts.Unanswered(why, source, unreachable)
	seen := facts.NotEstablishedTime(why)
	if unreachable {
		seen = allow.UnavailableTime(why, source)
	}
	return registryFacts{bound: f, clean: f, firstSeen: seen}
}

// ask establishes the facts a registry is the source of, for the head
// side of one change: Bound, Clean, FirstSeen, and whether the pin has
// been superseded. An error means the context ended.
func (a *asker) ask(ctx context.Context, c change) (registryFacts, error) {
	if c.toTag == "" {
		// Docker pulls such a line by digest alone. Guessing "latest"
		// would be asking about a tag the Dockerfile never named.
		return unanswered("the image is pinned without a tag, so there is no tag to ask the registry about", "", false), nil
	}

	var manifestURL, bearer string
	switch c.image.registry {
	case "docker.io":
		token, why, unreachable, err := a.hubToken(ctx, c.image.repo)
		if err != nil {
			return registryFacts{}, err
		}
		if why != "" {
			return unanswered(why, "GET https://auth.docker.io/token", unreachable), nil
		}
		bearer = token
		manifestURL = "https://registry-1.docker.io/v2/" + c.image.repo + "/manifests/" + c.toTag
	case "gcr.io":
		// Public GCR repositories answer without a token.
		manifestURL = "https://gcr.io/v2/" + c.image.repo + "/manifests/" + c.toTag
	default:
		return unanswered(c.image.registry+" is not a registry the gate knows how to ask", "", false), nil
	}

	source := "HEAD " + manifestURL
	ans, err := a.do(ctx, http.MethodHead, manifestURL, acceptManifests, bearer, 0)
	if err != nil {
		return registryFacts{}, err
	}
	switch {
	case ans.failed:
		return unanswered(ans.unreachable("the registry"), source, true), nil
	case ans.status == http.StatusNotFound:
		// An answer, and it is no: the tag the pull request pins is gone.
		why := fmt.Sprintf("the registry has no tag %s", c.toTag)
		return registryFacts{bound: allow.No(why, source), clean: allow.No(why, source), firstSeen: unknownTime("not asked: "+why, source)}, nil
	case ans.status != http.StatusOK:
		return unanswered(fmt.Sprintf("the registry answered HTTP %d for tag %s", ans.status, c.toTag), "", false), nil
	case !digestRe.MatchString(ans.digest):
		return unanswered(fmt.Sprintf("the registry reported no sha256 digest for tag %s", c.toTag), "", false), nil
	case ans.digest != c.toDigest:
		// The tag has moved on since Dependabot wrote the pin: an official
		// tag is rebuilt often, and Dependabot refreshes the digest on its
		// next run. So this is not a person's yet (spec section 11,
		// amendment 2). What the registry says about the old pin is still
		// reported as it is; allow.Decide sets it aside while Superseded
		// holds. Nothing more is asked: Docker Hub dates a tag, not a
		// digest, and the date it has now is the new image's.
		why := fmt.Sprintf("tag %s resolves to %s now, not to the pinned %s", c.toTag, ans.digest, c.toDigest)
		return registryFacts{
			bound:      allow.No(why, source),
			clean:      allow.No("the registry no longer serves the pinned digest under the tag: "+why, source),
			superseded: allow.Yes(why, source),
			firstSeen:  unknownTime("not asked: "+why, source),
		}, nil
	}
	f := registryFacts{
		bound:      allow.Yes(fmt.Sprintf("tag %s resolves to the pinned %s now", c.toTag, c.toDigest), source),
		superseded: allow.No(fmt.Sprintf("tag %s still resolves to the pinned digest", c.toTag), source),
	}

	// "Still published" is the answer just received. Beyond that there is
	// little to ask: an image has no retraction, GitHub's Advisory
	// Database has no container image ecosystem, and only GCR carries a
	// deprecation mark.
	served := fmt.Sprintf("the registry serves the pinned digest as tag %s now", c.toTag)
	if c.image.registry == "docker.io" {
		f.clean = allow.Yes(served+"; Docker Hub has no deprecation mark to read, and no advisory source covers container images", source)
		f.firstSeen, err = a.hubFirstSeen(ctx, c.image.repo, c.toTag, c.toDigest)
		return f, err
	}
	f.clean, f.firstSeen, err = a.gcrCleanAndFirstSeen(ctx, c.image.repo, c.toDigest, served)
	return f, err
}

// hubToken gets Docker Hub's anonymous pull token for one repository. No
// credentials are sent. why is set, and the token empty, when there is no
// token; unreachable then says the token service was asked and did not
// answer, as opposed to answering without one.
func (a *asker) hubToken(ctx context.Context, repo string) (token, why string, unreachable bool, err error) {
	if token, ok := a.hubTokens[repo]; ok {
		return token, "", false, nil
	}
	query := url.Values{
		"service": {"registry.docker.io"},
		"scope":   {"repository:" + repo + ":pull"},
	}
	ans, err := a.do(ctx, http.MethodGet, "https://auth.docker.io/token?"+query.Encode(), "application/json", "", maxTokenBytes)
	if err != nil {
		return "", "", false, err
	}
	if ans.failed {
		return "", ans.unreachable("Docker Hub's token service"), true, nil
	}
	if ans.status != http.StatusOK {
		return "", fmt.Sprintf("Docker Hub's token service answered HTTP %d", ans.status), false, nil
	}
	var doc struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if ans.tooLarge || json.Unmarshal(ans.body, &doc) != nil {
		return "", "Docker Hub's token service did not answer with a token", false, nil
	}
	token = doc.Token
	if token == "" {
		token = doc.AccessToken
	}
	if !tokenRe.MatchString(token) {
		return "", "Docker Hub's token service did not answer with a token", false, nil
	}
	a.hubTokens[repo] = token
	return token, "", false, nil
}

// hubFirstSeen reads when Docker Hub last saw the tag pushed. The time
// is Hub's own clock. It counts only when Hub reports the tag at the
// pinned digest: Hub keeps one time per tag, so for any other digest it
// is the time of a different image.
func (a *asker) hubFirstSeen(ctx context.Context, repo, tag, digest string) (allow.TimeFact, error) {
	tagURL := "https://hub.docker.com/v2/repositories/" + repo + "/tags/" + tag
	source := "GET " + tagURL + " (tag_last_pushed)"
	ans, err := a.do(ctx, http.MethodGet, tagURL, "application/json", "", maxHubTagBytes)
	if err != nil {
		return allow.TimeFact{}, err
	}
	if ans.failed {
		return allow.UnavailableTime(ans.unreachable("Docker Hub"), source), nil
	}
	if ans.status != http.StatusOK {
		return unknownTime(fmt.Sprintf("Docker Hub answered HTTP %d for tag %s", ans.status, tag), source), nil
	}
	var doc struct {
		Name          string `json:"name"`
		Digest        string `json:"digest"`
		TagLastPushed string `json:"tag_last_pushed"`
	}
	if ans.tooLarge || json.Unmarshal(ans.body, &doc) != nil {
		return unknownTime("Docker Hub's answer for the tag could not be read", source), nil
	}
	if doc.Name != tag {
		return unknownTime(fmt.Sprintf("Docker Hub answered for another tag than %s", tag), source), nil
	}
	if !digestRe.MatchString(doc.Digest) {
		return unknownTime(fmt.Sprintf("Docker Hub reports no sha256 digest for tag %s", tag), source), nil
	}
	if doc.Digest != digest {
		return unknownTime(fmt.Sprintf("Docker Hub reports tag %s at %s, not at the pinned digest, so its push time is another image's", tag, doc.Digest), source), nil
	}
	pushed, err := time.Parse(time.RFC3339, doc.TagLastPushed)
	if err != nil || pushed.Before(earliestClock) {
		return unknownTime(fmt.Sprintf("Docker Hub reports no usable tag_last_pushed for tag %s", tag), source), nil
	}
	return allow.At(pushed, source), nil
}

// gcrDeprecatedTag is a tag GCR's public repositories carry on a manifest
// that is deprecated: this prefix and the manifest's own digest in hex.
// The convention is observed, not documented. In November 2026 every
// manifest of the last build of gcr.io/distroless/static-debian12 (August
// 2026, none since) carried one, and no manifest of static-debian13 did.
// So it is read in one direction only: a manifest that carries the tag is
// not Clean, and its absence proves nothing.
const gcrDeprecatedTag = "deprecated-public-image-"

// gcrManifest is what is read of one manifest's entry in a tag list.
type gcrManifest struct {
	// uploadedMs is timeUploadedMs, as sent.
	uploadedMs string
	// deprecated: the manifest carries gcrDeprecatedTag for its digest.
	deprecated bool
}

// gcrList is one repository's tag list, reduced to what is read from it.
type gcrList struct {
	manifests map[string]gcrManifest
	// why is set when the list could not be read; unreachable then says
	// the registry was asked for it and did not answer.
	why         string
	unreachable bool
}

// gcrCleanAndFirstSeen reads GCR's tag list for the two things it knows
// about the manifest with the pinned digest: whether it is marked
// deprecated, and when GCR received it. The time is GCR's own clock. It
// is the upload of the manifest, not the moment a tag was pointed at it;
// that the tag points at it now is the Bound fact. served is what Bound
// established, for Clean's value.
func (a *asker) gcrCleanAndFirstSeen(ctx context.Context, repo, digest, served string) (allow.Fact, allow.TimeFact, error) {
	listURL := "https://gcr.io/v2/" + repo + "/tags/list"
	source := "GET " + listURL
	seenSource := source + " (timeUploadedMs)"
	list, ok := a.gcrLists[repo]
	if !ok {
		ans, err := a.do(ctx, http.MethodGet, listURL, "application/json", "", maxGCRListBytes)
		if err != nil {
			return allow.Fact{}, allow.TimeFact{}, err
		}
		list = readGCRList(ans)
		a.gcrLists[repo] = list
	}
	switch {
	case list.unreachable:
		return allow.Unavailable(list.why, source), allow.UnavailableTime(list.why, seenSource), nil
	case list.why != "":
		// An answer that cannot be read establishes nothing, and asking
		// again would get the same one.
		return facts.NotEstablished(list.why), unknownTime(list.why, seenSource), nil
	}
	m, ok := list.manifests[digest]
	if !ok {
		const why = "the registry's tag list has no manifest with the pinned digest"
		return facts.NotEstablished(why), unknownTime(why, seenSource), nil
	}

	clean := allow.Yes(served+" and does not mark it deprecated; no advisory source covers container images", source)
	if m.deprecated {
		clean = allow.No(fmt.Sprintf("the registry marks the pinned digest deprecated (it carries the tag %s<digest>)", gcrDeprecatedTag), source)
	}

	ms, err := strconv.ParseInt(m.uploadedMs, 10, 64)
	if err != nil || ms <= 0 || time.UnixMilli(ms).Before(earliestClock) {
		return clean, unknownTime("the registry's tag list has no usable timeUploadedMs for the pinned digest", seenSource), nil
	}
	return clean, allow.At(time.UnixMilli(ms).UTC(), seenSource), nil
}

// readGCRList decodes a tags/list answer.
func readGCRList(ans answer) gcrList {
	if ans.failed {
		return gcrList{why: ans.unreachable("the registry's tag list"), unreachable: true}
	}
	if ans.status != http.StatusOK {
		return gcrList{why: fmt.Sprintf("the registry answered HTTP %d for its tag list", ans.status)}
	}
	if ans.tooLarge {
		return gcrList{why: fmt.Sprintf("the registry's tag list is larger than %d MB", maxGCRListBytes>>20)}
	}
	var doc struct {
		Manifest map[string]struct {
			TimeUploadedMs string   `json:"timeUploadedMs"`
			Tag            []string `json:"tag"`
		} `json:"manifest"`
	}
	if err := json.Unmarshal(ans.body, &doc); err != nil {
		return gcrList{why: "the registry's tag list could not be read"}
	}
	list := gcrList{manifests: make(map[string]gcrManifest, len(doc.Manifest))}
	for digest, m := range doc.Manifest {
		list.manifests[digest] = gcrManifest{
			uploadedMs: m.TimeUploadedMs,
			deprecated: slices.Contains(m.Tag, gcrDeprecatedTag+strings.TrimPrefix(digest, "sha256:")),
		}
	}
	return list
}

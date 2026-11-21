package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sadbox/dep-review/internal/gh"
)

// A minimal, read-only OCI distribution client: anonymous bearer tokens,
// manifests by tag or digest, blobs by digest. Every byte it returns has
// been checked against the digest it was requested by; nothing is cached
// on disk.

const (
	userAgent        = "oci-fetch/1"
	maxManifestBytes = 4 << 20
	maxConfigBytes   = 16 << 20
	maxTokenBytes    = 64 << 10
	manifestTimeout  = time.Minute
)

const (
	mtOCIIndex      = "application/vnd.oci.image.index.v1+json"
	mtDockerList    = "application/vnd.docker.distribution.manifest.list.v2+json"
	mtOCIManifest   = "application/vnd.oci.image.manifest.v1+json"
	mtDockerV2      = "application/vnd.docker.distribution.manifest.v2+json"
	acceptManifests = mtOCIIndex + ", " + mtDockerList + ", " + mtOCIManifest + ", " + mtDockerV2
)

type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    *ociPlatform      `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type ociPlatform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
	OSVersion    string `json:"os.version,omitempty"`
}

func (p ociPlatform) String() string {
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

// manifestDoc is the union of an image index and an image manifest; which
// one it is follows from Manifests vs Layers (and the media type).
type manifestDoc struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Manifests     []descriptor      `json:"manifests,omitempty"`
	Config        *descriptor       `json:"config,omitempty"`
	Layers        []descriptor      `json:"layers,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

func (m *manifestDoc) isIndex() bool {
	return m.MediaType == mtOCIIndex || m.MediaType == mtDockerList || (m.MediaType == "" && m.Manifests != nil && m.Config == nil)
}

type statusError struct {
	Code int
	What string
}

func (e *statusError) Error() string { return fmt.Sprintf("%s: HTTP %d", e.What, e.Code) }

// Is makes errors.Is(err, gh.ErrNotFound) true for a 404.
func (e *statusError) Is(target error) bool {
	return target == gh.ErrNotFound && e.Code == http.StatusNotFound
}

// errDigestMismatch means the registry served bytes that do not hash to
// the digest they were requested by. It is a finding, not a retryable error.
var errDigestMismatch = errors.New("content does not match its digest")

// errTooLarge means a size limit was hit.
var errTooLarge = errors.New("size limit exceeded")

// errRateLimited means the registry still answered 429 or 503 after
// maxTries. It is an infrastructure error, never a finding: the fetch job
// fails, the PR stays pending and a later run (or sweep's stuck report)
// picks it up.
var errRateLimited = errors.New("registry rate limit or unavailable")

const (
	maxTries      = 3                // per request, for 429 and 503
	maxRetryAfter = 60 * time.Second // cap on a registry's Retry-After
)

type rateLimitError struct{ statusError }

func (e *rateLimitError) Is(target error) bool { return target == errRateLimited }

type registry struct {
	client   *http.Client
	endpoint func(host string) string // base URL for a registry host
	realmOK  func(u *url.URL) bool    // which token endpoints may be contacted

	maxTotal   int64 // bytes across every blob this client downloads
	downloaded atomic.Int64

	// sleep waits between retries (replaced in tests).
	sleep func(ctx context.Context, d time.Duration) error

	mu     sync.Mutex
	tokens map[string]string // host + "/" + repo -> bearer token
	// manifests caches verified manifests and indexes by digest for the
	// life of the client (one fetch run), so each is downloaded once.
	manifests map[string]cachedManifest // host + "/" + repo + "@" + digest
}

type cachedManifest struct {
	body []byte
	doc  manifestDoc
}

var defaultRealmHosts = map[string]bool{"auth.docker.io": true, "ghcr.io": true, "gcr.io": true}

func newRegistry(c *http.Client, maxTotal int64) *registry {
	if c == nil {
		c = &http.Client{}
	}
	cc := *c
	// Layers are large: a whole-request client timeout would cut them off.
	// Deadlines come from contexts instead (see manifestTimeout, blob).
	cc.Timeout = 0
	cc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" {
			return fmt.Errorf("refusing redirect to %s", req.URL.Scheme)
		}
		return nil
	}
	return &registry{
		client:   &cc,
		endpoint: defaultEndpoint,
		realmOK: func(u *url.URL) bool {
			return u.Scheme == "https" && defaultRealmHosts[u.Hostname()]
		},
		maxTotal:  maxTotal,
		tokens:    map[string]string{},
		manifests: map[string]cachedManifest{},
		sleep:     sleepCtx,
	}
}

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

// retryDelay is how long to wait before try number try (1-based) after a
// 429 or 503: the registry's Retry-After (seconds or an HTTP date) capped
// at maxRetryAfter, else 2s, 4s, ...
func retryDelay(h http.Header, try int) time.Duration {
	d := time.Duration(1<<try) * time.Second
	if v := strings.TrimSpace(h.Get("Retry-After")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			d = time.Duration(n) * time.Second
		} else if t, err := http.ParseTime(v); err == nil {
			d = time.Until(t)
		}
	}
	return min(max(d, 0), maxRetryAfter)
}

func defaultEndpoint(host string) string {
	if host == "docker.io" {
		host = "registry-1.docker.io"
	}
	return "https://" + host
}

func (rg *registry) tokenKey(r imageRef) string { return r.Registry + "/" + r.Repo }

func (rg *registry) do(ctx context.Context, r imageRef, method, path, accept string) (*http.Response, error) {
	u := rg.endpoint(r.Registry) + "/v2/" + r.Repo + "/" + path
	authed, tries := false, 0
	for {
		req, err := http.NewRequestWithContext(ctx, method, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		rg.mu.Lock()
		tok := rg.tokens[rg.tokenKey(r)]
		rg.mu.Unlock()
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := rg.client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusOK {
			return resp, nil
		}
		challenge := resp.Header.Get("WWW-Authenticate")
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized && !authed && challenge != "" {
			authed = true
			if err := rg.fetchToken(ctx, r, challenge); err != nil {
				return nil, err
			}
			continue
		}
		se := statusError{Code: resp.StatusCode, What: method + " " + r.Name() + " " + path}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			tries++
			if tries >= maxTries {
				return nil, &rateLimitError{se}
			}
			if err := rg.sleep(ctx, retryDelay(resp.Header, tries)); err != nil {
				return nil, err
			}
			continue
		}
		return nil, &se
	}
}

var challengeParam = regexp.MustCompile(`(\w+)="([^"]*)"`)

// fetchToken runs the anonymous bearer flow: no credentials are sent, only
// the scope the challenge asked for (pull on this repository).
func (rg *registry) fetchToken(ctx context.Context, r imageRef, challenge string) error {
	scheme, params, _ := strings.Cut(challenge, " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return fmt.Errorf("%s: unsupported auth scheme %q", r.Name(), scheme)
	}
	kv := map[string]string{}
	for _, m := range challengeParam.FindAllStringSubmatch(params, -1) {
		kv[strings.ToLower(m[1])] = m[2]
	}
	realm, err := url.Parse(kv["realm"])
	if err != nil || !rg.realmOK(realm) {
		return fmt.Errorf("%s: token realm %q not allowed", r.Name(), kv["realm"])
	}
	q := realm.Query()
	if s := kv["service"]; s != "" {
		q.Set("service", s)
	}
	q.Set("scope", "repository:"+r.Repo+":pull")
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := rg.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &statusError{Code: resp.StatusCode, What: "token for " + r.Name()}
	}
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenBytes)).Decode(&t); err != nil {
		return fmt.Errorf("token for %s: %w", r.Name(), err)
	}
	tok := t.Token
	if tok == "" {
		tok = t.AccessToken
	}
	if tok == "" {
		return fmt.Errorf("token for %s: empty", r.Name())
	}
	rg.mu.Lock()
	rg.tokens[rg.tokenKey(r)] = tok
	rg.mu.Unlock()
	return nil
}

func sha256Digest(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// manifest fetches a manifest or index by tag or digest. When reference is
// a digest the body must hash to it. The returned digest is always the
// hash of the returned bytes.
func (rg *registry) manifest(ctx context.Context, r imageRef, reference string) ([]byte, *manifestDoc, string, error) {
	key := rg.tokenKey(r) + "@" + reference
	if digestRe.MatchString(reference) {
		rg.mu.Lock()
		c, ok := rg.manifests[key]
		rg.mu.Unlock()
		if ok {
			doc := c.doc
			return c.body, &doc, reference, nil
		}
	}
	ctx, cancel := context.WithTimeout(ctx, manifestTimeout)
	defer cancel()
	resp, err := rg.do(ctx, r, http.MethodGet, "manifests/"+reference, acceptManifests)
	if err != nil {
		return nil, nil, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
	if err != nil {
		return nil, nil, "", err
	}
	if len(body) > maxManifestBytes {
		return nil, nil, "", fmt.Errorf("manifest %s@%s: %w", r.Name(), reference, errTooLarge)
	}
	dg := sha256Digest(body)
	if digestRe.MatchString(reference) && dg != reference {
		return nil, nil, "", fmt.Errorf("manifest %s@%s hashes to %s: %w", r.Name(), reference, dg, errDigestMismatch)
	}
	var m manifestDoc
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, nil, "", fmt.Errorf("manifest %s@%s: %w", r.Name(), reference, err)
	}
	if m.MediaType == "" {
		m.MediaType = resp.Header.Get("Content-Type")
	}
	rg.mu.Lock()
	rg.manifests[rg.tokenKey(r)+"@"+dg] = cachedManifest{body: body, doc: m}
	rg.mu.Unlock()
	doc := m
	return body, &doc, dg, nil
}

// tagDigest returns the digest a tag currently resolves to. HEAD is used
// first because it does not count against Docker Hub's pull limit.
func (rg *registry) tagDigest(ctx context.Context, r imageRef, tag string) (string, error) {
	hctx, cancel := context.WithTimeout(ctx, manifestTimeout)
	defer cancel()
	resp, err := rg.do(hctx, r, http.MethodHead, "manifests/"+tag, acceptManifests)
	if err == nil {
		resp.Body.Close()
		if d := resp.Header.Get("Docker-Content-Digest"); digestRe.MatchString(d) {
			return d, nil
		}
	}
	_, _, dg, err := rg.manifest(ctx, r, tag)
	return dg, err
}

// blob opens a blob for streaming. The reader enforces the descriptor's
// size and returns errDigestMismatch at EOF if the bytes do not hash to the
// digest; callers must read it to EOF before trusting anything they
// derived from it.
func (rg *registry) blob(ctx context.Context, r imageRef, d descriptor, max int64) (io.ReadCloser, error) {
	if !digestRe.MatchString(d.Digest) {
		return nil, fmt.Errorf("blob digest %q not sha256", d.Digest)
	}
	if d.Size < 0 || d.Size > max {
		return nil, fmt.Errorf("blob %s is %d bytes (limit %d): %w", d.Digest, d.Size, max, errTooLarge)
	}
	if rg.maxTotal > 0 && rg.downloaded.Add(d.Size) > rg.maxTotal {
		return nil, fmt.Errorf("download budget of %d bytes: %w", rg.maxTotal, errTooLarge)
	}
	// At least 256 KiB/s, plus two minutes of slack.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute+time.Duration(d.Size/(256<<10))*time.Second)
	resp, err := rg.do(ctx, r, http.MethodGet, "blobs/"+d.Digest, "")
	if err != nil {
		cancel()
		return nil, err
	}
	return &verifyingReader{rc: resp.Body, h: sha256.New(), want: d.Digest, size: d.Size, cancel: cancel}, nil
}

// readBlob reads a small blob (a config) fully.
func (rg *registry) readBlob(ctx context.Context, r imageRef, d descriptor, max int64) ([]byte, error) {
	rc, err := rg.blob(ctx, r, d, max)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

type verifyingReader struct {
	rc   io.ReadCloser
	h    hash.Hash
	want string
	size int64
	n    int64

	cancel context.CancelFunc
}

func (v *verifyingReader) Read(p []byte) (int, error) {
	n, err := v.rc.Read(p)
	v.n += int64(n)
	v.h.Write(p[:n])
	if v.n > v.size {
		return n, fmt.Errorf("blob %s longer than its descriptor: %w", v.want, errDigestMismatch)
	}
	if err == io.EOF {
		if v.n != v.size || "sha256:"+hex.EncodeToString(v.h.Sum(nil)) != v.want {
			return n, fmt.Errorf("blob %s: %w", v.want, errDigestMismatch)
		}
	}
	return n, err
}

func (v *verifyingReader) Close() error {
	err := v.rc.Close()
	if v.cancel != nil {
		v.cancel()
	}
	return err
}

// selectPlatform picks the image manifest for one platform from an index,
// skipping attestation manifests. "linux/arm64" matches variant "" and "v8".
func selectPlatform(idx *manifestDoc, want string) (descriptor, bool) {
	wos, warch, wvar := splitPlatform(want)
	for _, d := range idx.Manifests {
		if d.Platform == nil || d.Annotations["vnd.docker.reference.type"] != "" {
			continue
		}
		p := d.Platform
		if p.OS != wos || p.Architecture != warch {
			continue
		}
		v := p.Variant
		if warch == "arm64" && v == "v8" {
			v = ""
		}
		if v != wvar {
			continue
		}
		return d, true
	}
	return descriptor{}, false
}

func splitPlatform(p string) (os, arch, variant string) {
	parts := strings.SplitN(p, "/", 3)
	switch len(parts) {
	case 1:
		return "linux", parts[0], ""
	case 2:
		os, arch = parts[0], parts[1]
	default:
		os, arch, variant = parts[0], parts[1], parts[2]
	}
	if arch == "arm64" && variant == "v8" {
		variant = ""
	}
	return
}

// normPlatform canonicalises "linux/arm64/v8" to "linux/arm64".
func normPlatform(p string) string {
	os, arch, v := splitPlatform(strings.ToLower(strings.TrimSpace(p)))
	if v != "" {
		return os + "/" + arch + "/" + v
	}
	return os + "/" + arch
}

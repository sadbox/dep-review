// Package gh is a minimal GitHub REST client: JSON in and out, Link-header
// pagination, retries with backoff on server errors and rate limits, a
// per-request timeout and typed errors. No GraphQL, no third-party code.
//
// Paths are relative to the API root ("repos/o/r/pulls/1"). Callers build
// them from validated values only (see ValidRepo, ValidSHA); nothing taken
// from an event or an API response goes into a path unchecked.
package gh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultBaseURL = "https://api.github.com/"
	apiVersion     = "2022-11-28"
	maxBody        = 32 << 20 // per response
	maxPages       = 100      // 100 pages * 100 items is far beyond anything the gate lists
)

// Client is safe for concurrent use once configured.
type Client struct {
	BaseURL    string // with trailing slash
	Token      string
	HTTP       *http.Client
	UserAgent  string
	Timeout    time.Duration // per attempt
	MaxRetries int           // attempts after the first
	MinBackoff time.Duration
	MaxBackoff time.Duration // also caps Retry-After and rate-limit resets

	// Sleep waits d or until ctx is done; replaceable in tests.
	Sleep func(ctx context.Context, d time.Duration) error
}

// New returns a client for api.github.com with the given token.
func New(token string) *Client {
	return &Client{
		BaseURL:    DefaultBaseURL,
		Token:      token,
		HTTP:       &http.Client{},
		UserAgent:  "dep-review",
		Timeout:    30 * time.Second,
		MaxRetries: 5,
		MinBackoff: time.Second,
		MaxBackoff: 60 * time.Second,
		Sleep:      sleepCtx,
	}
}

// NewFromEnv reads the token from GH_TOKEN, and GITHUB_API_URL if set.
func NewFromEnv() (*Client, error) {
	tok := os.Getenv("GH_TOKEN")
	if tok == "" {
		return nil, errors.New("GH_TOKEN is not set")
	}
	c := New(tok)
	if u := os.Getenv("GITHUB_API_URL"); u != "" {
		if !strings.HasPrefix(u, "https://") {
			return nil, fmt.Errorf("GITHUB_API_URL must be https")
		}
		c.BaseURL = strings.TrimSuffix(u, "/") + "/"
	}
	return c, nil
}

// Error is a non-2xx response.
type Error struct {
	Method     string
	Path       string
	StatusCode int
	Message    string // GitHub's "message" field, if any
	// RateLimited: GitHub refused the request for a rate limit: a 429, or
	// a 403 that carries one of its rate-limit signals (see retryable).
	// The client has retried it already.
	RateLimited bool
}

func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("github: %s %s: %d %s", e.Method, e.Path, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("github: %s %s: %d", e.Method, e.Path, e.StatusCode)
}

// ErrNotFound is the gate's one "does not exist" sentinel, checked with
// errors.Is. A *Error matches it for a 404. The fetchers' other HTTP
// clients (registries, package indexes, the OCI client) wrap it for their
// own not-found statuses, so a fetcher never inspects status codes or
// error text to tell "missing" from "failed".
var ErrNotFound = errors.New("not found")

// Is makes errors.Is(err, ErrNotFound) true for a 404.
func (e *Error) Is(target error) bool {
	return target == ErrNotFound && e.StatusCode == http.StatusNotFound
}

// Unavailable reports whether err, from a call on a Client, means GitHub
// was asked and did not answer: no response at all (a network error or a
// timeout), a server error, or a rate limit, each after the client's own
// retries. Such a failure says nothing about what was asked for, and the
// v0.2 gate waits and asks again (docs/v0.2-spec.md, section 11,
// amendment 1). Every other error is an answer: a 404, a 403 that is not
// a rate limit, a body that could not be decoded.
//
// A caller whose own context has ended must look at that first: a
// deadline that ran out is a timeout here too.
func Unavailable(err error) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.RateLimited || e.StatusCode >= 500
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}

// StatusCode returns the HTTP status of a *Error anywhere in err's chain,
// or 0.
func StatusCode(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.StatusCode
	}
	return 0
}

var (
	repoRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$`)
	shaRe  = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
)

// ValidRepo reports whether s is a well-formed owner/name.
func ValidRepo(s string) bool {
	return repoRe.MatchString(s) && !strings.Contains(s, "..") && !strings.HasSuffix(s, "/.")
}

// ValidSHA reports whether s is a full lowercase hex commit ID.
func ValidSHA(s string) bool { return shaRe.MatchString(s) }

func (c *Client) Get(ctx context.Context, path string, v any) error {
	_, err := c.do(ctx, http.MethodGet, path, nil, v)
	return err
}

func (c *Client) Post(ctx context.Context, path string, body, v any) error {
	_, err := c.do(ctx, http.MethodPost, path, body, v)
	return err
}

func (c *Client) Put(ctx context.Context, path string, body, v any) error {
	_, err := c.do(ctx, http.MethodPut, path, body, v)
	return err
}

func (c *Client) Patch(ctx context.Context, path string, body, v any) error {
	_, err := c.do(ctx, http.MethodPatch, path, body, v)
	return err
}

// Pages GETs path and every following page (Link rel="next"), calling fn
// with each page's raw body. per_page=100 is added unless path sets it.
func (c *Client) Pages(ctx context.Context, path string, fn func(body []byte) error) error {
	next := withPerPage(path)
	for i := 0; next != ""; i++ {
		if i == maxPages {
			return fmt.Errorf("github: GET %s: more than %d pages", path, maxPages)
		}
		var raw json.RawMessage
		h, err := c.do(ctx, http.MethodGet, next, nil, &raw)
		if err != nil {
			return err
		}
		if err := fn(raw); err != nil {
			return err
		}
		next, err = c.nextPath(h.Get("Link"))
		if err != nil {
			return err
		}
	}
	return nil
}

// List collects every element of a paginated JSON-array endpoint.
func List[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var all []T
	err := c.Pages(ctx, path, func(body []byte) error {
		var page []T
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("github: GET %s: %w", path, err)
		}
		all = append(all, page...)
		return nil
	})
	return all, err
}

func withPerPage(path string) string {
	if strings.Contains(path, "per_page=") {
		return path
	}
	if strings.Contains(path, "?") {
		return path + "&per_page=100"
	}
	return path + "?per_page=100"
}

var linkNextRe = regexp.MustCompile(`<([^>]+)>\s*;\s*rel="?next"?`)

// nextPath extracts rel="next" and turns it back into a path, refusing any
// URL outside BaseURL so the token is never sent elsewhere.
func (c *Client) nextPath(link string) (string, error) {
	if link == "" {
		return "", nil
	}
	for _, part := range strings.Split(link, ",") {
		m := linkNextRe.FindStringSubmatch(part)
		if m == nil {
			continue
		}
		if !strings.HasPrefix(m[1], c.BaseURL) {
			return "", fmt.Errorf("github: next page %q is outside %s", m[1], c.BaseURL)
		}
		return strings.TrimPrefix(m[1], c.BaseURL), nil
	}
	return "", nil
}

// retryable reports whether a response may be retried and how long to
// wait at least. Rate-limit responses are retried for every method (GitHub
// did not act on the request); server errors only for GET, since a POST or
// PUT that timed out on GitHub's side may have taken effect.
func (c *Client) retryable(method string, resp *http.Response, body []byte) (bool, time.Duration) {
	wait := retryAfter(resp.Header)
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return true, wait
	case resp.StatusCode == http.StatusForbidden:
		if wait > 0 || bytes.Contains(bytes.ToLower(body), []byte("secondary rate limit")) {
			return true, wait
		}
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			if reset, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
				return true, time.Until(time.Unix(reset, 0)) + time.Second
			}
			return true, 0
		}
		return false, 0
	case resp.StatusCode >= 500:
		return method == http.MethodGet, wait
	}
	return false, 0
}

func retryAfter(h http.Header) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(v); err == nil && s >= 0 {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return time.Until(t)
	}
	return 0
}

func (c *Client) backoff(attempt int, atLeast time.Duration) time.Duration {
	d := c.MinBackoff << attempt
	if d <= 0 || d > c.MaxBackoff {
		d = c.MaxBackoff
	}
	if c.MinBackoff > 0 {
		d += time.Duration(rand.Int64N(int64(c.MinBackoff)))
	}
	if atLeast > d {
		d = atLeast
	}
	if d > c.MaxBackoff {
		d = c.MaxBackoff
	}
	return d
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) (http.Header, error) {
	path = strings.TrimPrefix(path, "/")
	u, err := url.Parse(c.BaseURL + path)
	if err != nil || !strings.HasPrefix(u.String(), c.BaseURL) {
		return nil, fmt.Errorf("github: bad path %q", path)
	}
	var payload []byte
	if in != nil {
		if payload, err = json.Marshal(in); err != nil {
			return nil, err
		}
	}
	for attempt := 0; ; attempt++ {
		h, body, status, err := c.once(ctx, method, u.String(), payload)
		if err == nil && status/100 == 2 {
			if out != nil && len(bytes.TrimSpace(body)) > 0 {
				if err := json.Unmarshal(body, out); err != nil {
					return h, fmt.Errorf("github: %s %s: decoding: %w", method, path, err)
				}
			}
			return h, nil
		}
		var wait time.Duration
		retry := false
		if err != nil {
			// Transport error or timeout: GitHub may have acted on a write.
			retry = method == http.MethodGet && ctx.Err() == nil
		} else {
			retry, wait = c.retryable(method, &http.Response{StatusCode: status, Header: h}, body)
			// retryable says yes to a 403 only for a rate limit.
			limited := status == http.StatusTooManyRequests || (status == http.StatusForbidden && retry)
			err = &Error{Method: method, Path: path, StatusCode: status, Message: apiMessage(body), RateLimited: limited}
		}
		if !retry || attempt >= c.MaxRetries {
			return h, err
		}
		if serr := c.Sleep(ctx, c.backoff(attempt, wait)); serr != nil {
			return h, err
		}
	}
}

func (c *Client) once(ctx context.Context, method, u string, payload []byte) (http.Header, []byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, nil, 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	req.Header.Set("User-Agent", c.UserAgent)
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return resp.Header, nil, 0, err
	}
	if len(body) > maxBody {
		return resp.Header, nil, 0, fmt.Errorf("github: %s: response larger than %d bytes", u, maxBody)
	}
	return resp.Header, body, resp.StatusCode, nil
}

func apiMessage(body []byte) string {
	var m struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &m) != nil {
		return ""
	}
	if len(m.Message) > 200 {
		return m.Message[:200]
	}
	return m.Message
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

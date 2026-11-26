package veto

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/config"
)

const (
	messagesPath = "/v1/messages"
	// apiVersion is the anthropic-version this client was written for.
	apiVersion = "2026-10-21"
	userAgent  = "dep-review-veto"

	// maxResponseBytes bounds a response body. An answer is a few
	// kilobytes; the rest is room for thinking blocks' signatures.
	maxResponseBytes = 8 << 20
	// retryBase is the wait before the first retry; it doubles after.
	retryBase = 2 * time.Second
	// maxRetryAfter is the longest retry-after the client sits out. A
	// longer one is not waited for: the update simply has no verdict
	// this time, and the gate asks again at its next evaluation.
	maxRetryAfter = time.Minute
)

// Client is the Reviewer that asks the model over the Messages API: one
// request per chunk, not streamed, with no tools.
type Client struct {
	conf  config.Config
	base  string
	creds Credentials
	http  *http.Client
	// timeout bounds one attempt at one chunk, from sending the request
	// to reading the whole response.
	timeout time.Duration

	// Logf, when set, receives one line per request with its size, token
	// usage and outcome, and one per retry. Chunk text, the model's text
	// and credentials are never passed to it.
	Logf func(format string, args ...any)

	sleep func(context.Context, time.Duration) error // the wait between attempts
}

var _ Reviewer = (*Client)(nil)

// New returns a Client. hc is the HTTP client to use, or nil for one that
// ignores proxy settings in the environment; either way redirects are
// never followed, so a credential only goes to cfg.BaseURL.
func New(cfg Config, creds Credentials, hc *http.Client) (*Client, error) {
	if creds == nil {
		return nil, errors.New("veto: no credentials")
	}
	base, err := apiOrigin(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("veto: base_url: %w", err)
	}
	return &Client{
		conf:    cfg.conf,
		base:    base,
		creds:   creds,
		http:    noRedirects(hc),
		timeout: time.Duration(cfg.conf.RequestTimeoutSeconds) * time.Second,
		sleep:   sleepContext,
	}, nil
}

// noRedirects returns hc, or a default client when hc is nil, set never
// to follow a redirect: every request this package makes carries a
// credential, and none of the three services it talks to redirects.
func noRedirects(hc *http.Client) *http.Client {
	var c http.Client
	if hc != nil {
		c = *hc
	} else {
		c.Transport = &http.Transport{
			// The environment's proxy variables are not consulted.
			Proxy:               nil,
			DialContext:         (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: 10 * time.Second,
			IdleConnTimeout:     90 * time.Second,
			// No ResponseHeaderTimeout: the request is not streamed, so
			// the headers arrive only when the model is done. Each
			// attempt is bounded by its context instead.
		}
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *Client) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// Review implements Reviewer.
//
// Chunks are asked in order, one request each. The first veto or refusal
// ends the review: no later answer could change it, and a later failure
// must not lose it.
//
// A read with no chunks is ErrUnusable: no request is made, and a verdict
// is the model's answer or nothing. The fetch job does not hand such a
// read on (spec section 11, amendment 53).
//
// ctx bounds the whole review. Without a deadline the worst case is
// max_chunks times attempts times the request timeout, so the caller
// should set one.
func (c *Client) Review(ctx context.Context, req Request) (Verdict, error) {
	p := req.Read
	if err := checkRead(c.conf, p); err != nil {
		// %q: the name has not passed the check that makes it printable.
		return Verdict{}, fmt.Errorf("%w: %q: not sent: %w", ErrUnusable, clip(p.Pair.Name, 80), err)
	}
	total := len(p.Chunks)
	var notes []string
	for i := range p.Chunks {
		// rand.Text is at least 128 random bits, new for every request.
		body, err := requestBody(c.conf, userMessage(p, i, rand.Text()))
		if err != nil {
			return Verdict{}, fmt.Errorf("veto: %w", err)
		}
		a, err := c.ask(ctx, body, i, total)
		if err != nil {
			return Verdict{}, fmt.Errorf("veto: %s: part %d of %d: %w", p.Pair.Name, i+1, total, err)
		}
		if a.category != "" {
			read := allow.ReadPartial
			if i == total-1 && a.category != Refused {
				read = p.State
			}
			return Verdict{Answer: Vetoed, Category: a.category, Quotes: a.quotes, Notes: a.notes, Read: read, Key: p.Key}, nil
		}
		if a.notes != "" {
			if total > 1 {
				a.notes = fmt.Sprintf("part %d: %s", i+1, a.notes)
			}
			notes = append(notes, a.notes)
		}
	}
	return Verdict{
		Answer: NoVeto,
		Quotes: []string{},
		Notes:  clip(strings.Join(notes, "\n"), maxNotesBytes),
		Read:   p.State,
		Key:    p.Key,
	}, nil
}

// ask sends one chunk's request and reads the answer.
func (c *Client) ask(ctx context.Context, body []byte, chunk, total int) (chunkAnswer, error) {
	raw, requestID, err := c.send(ctx, messagesPath, body)
	if err != nil {
		return chunkAnswer{}, err
	}
	var resp messagesResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return chunkAnswer{}, noVerdict("response is not JSON (request-id %s)", requestID)
	}
	a, err := interpret(resp)
	outcome := "no_veto"
	switch {
	case err != nil:
		outcome = "no verdict"
	case a.category != "":
		outcome = string(a.category)
	}
	// Request bytes next to input tokens is the measurement the chunk
	// budget's token-per-byte assumption can be checked against.
	c.logf("veto: part %d of %d: %d request bytes, %d input tokens, %d output tokens, stop_reason %s, request-id %s: %s",
		chunk+1, total, len(body), resp.Usage.InputTokens, resp.Usage.OutputTokens, safeToken(resp.StopReason), requestID, outcome)
	if err != nil {
		return chunkAnswer{}, fmt.Errorf("%w (request-id %s)", err, requestID)
	}
	return a, nil
}

// APIError is a response from the API that is not a 200.
type APIError struct {
	// Status is the HTTP status.
	Status int
	// Type is the API's error type, such as "overloaded_error".
	Type string
	// Message is the API's message, cut short and with control
	// characters removed.
	Message string
	// RequestID is the request-id header, for a report to Anthropic.
	RequestID string

	retry bool
}

// Error implements error: the status, then the API's type and message.
func (e *APIError) Error() string {
	s := fmt.Sprintf("HTTP %d", e.Status)
	if e.Type != "" {
		s += " " + e.Type
	}
	if e.Message != "" {
		s += ": " + e.Message
	}
	if e.RequestID != "" {
		s += " (request-id " + e.RequestID + ")"
	}
	return s
}

// send posts body to path until it gets a 200 or runs out of attempts,
// and returns the response body and its request-id. It is the only place
// that talks HTTP to the API, so a streamed exchange would replace it and
// nothing else.
//
// What is retried follows the API's documentation: 408, 409, 429 and
// every 5xx (500 api_error, 529 overloaded_error), and a failure before
// any response; an x-should-retry header overrides the status. A 401 is
// retried once, when the credentials can be renewed. Every other status
// is final.
func (c *Client) send(ctx context.Context, path string, body []byte) (raw []byte, requestID string, err error) {
	renewed := false
	for attempt := 1; ; attempt++ {
		var retryAfter time.Duration
		raw, requestID, retryAfter, err = c.post(ctx, path, body)
		if err == nil {
			return raw, requestID, nil
		}
		if ctx.Err() != nil {
			return nil, "", fmt.Errorf("%w (%v)", ctx.Err(), err) //nolint:errorlint // the class is the context's error; the attempt's error is text
		}

		// How long to wait before the next attempt; negative for none.
		wait := time.Duration(-1)
		var apiErr *APIError
		var credErr *credentialsError
		switch {
		case errors.As(err, &apiErr):
			switch {
			case apiErr.Status == http.StatusUnauthorized && !renewed && c.creds.Rejected():
				renewed, wait = true, 0
			case apiErr.retry && retryAfter > 0:
				wait = retryAfter
			case apiErr.retry:
				wait = retryBase << (attempt - 1)
			}
		case errors.As(err, &credErr), errors.Is(err, ErrNoVerdict):
			// The credential source has done its own retries, and an
			// unusable response is not a transient fault.
		default:
			// No response: a network failure, or the attempt ran into
			// its timeout.
			wait = retryBase << (attempt - 1)
		}
		if wait < 0 || attempt >= c.conf.Attempts {
			return nil, "", err
		}
		if wait > maxRetryAfter {
			return nil, "", fmt.Errorf("%w; the API asks to wait %s, longer than this client waits", err, wait)
		}
		c.logf("veto: attempt %d of %d failed, next in %s: %v", attempt, c.conf.Attempts, wait, err)
		if err := c.sleep(ctx, wait); err != nil {
			return nil, "", err
		}
	}
}

// credentialsError is a failure to get a credential, as opposed to a
// failure of the request that was to carry it.
type credentialsError struct{ err error }

func (e *credentialsError) Error() string { return "credentials: " + e.err.Error() }
func (e *credentialsError) Unwrap() error { return e.err }

// post is one attempt. wait is the API's retry-after, when it sent one.
func (c *Client) post(ctx context.Context, path string, body []byte) (raw []byte, requestID string, wait time.Duration, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Anthropic-Version", apiVersion)
	req.Header.Set("User-Agent", userAgent)
	if err := c.creds.Authorize(ctx, req.Header); err != nil {
		return nil, "", 0, &credentialsError{err}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", 0, fmt.Errorf("request failed: %w", scrub(err))
	}
	defer resp.Body.Close()
	requestID = safeToken(resp.Header.Get("Request-Id"))
	raw, err = io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, requestID, 0, fmt.Errorf("reading the response: %w", scrub(err))
	}
	if resp.StatusCode != http.StatusOK {
		apiErr := &APIError{Status: resp.StatusCode, RequestID: requestID}
		apiErr.Type, apiErr.Message = errorSummary(raw)
		s := resp.StatusCode
		apiErr.retry = s == http.StatusRequestTimeout || s == http.StatusConflict || s == http.StatusTooManyRequests || s >= 500
		switch resp.Header.Get("X-Should-Retry") {
		case "true":
			apiErr.retry = true
		case "false":
			apiErr.retry = false
		}
		if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs > 0 {
			wait = time.Duration(secs) * time.Second
		}
		return nil, requestID, wait, apiErr
	}
	if len(raw) > maxResponseBytes {
		return nil, requestID, 0, noVerdict("response is larger than %d bytes", maxResponseBytes)
	}
	return raw, requestID, 0, nil
}

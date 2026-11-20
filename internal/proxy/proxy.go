// Package proxy is the reviewer sandbox's only way out: a reverse proxy
// that holds the Claude credential, forwards POST /v1/messages to the
// Claude API and nothing else. It runs outside the sandbox (its own
// container, on the internal network and a normal bridge) and is the only
// process that sees the job's OIDC request token.
//
// Per request it: allows only POST /v1/messages (optionally ?beta=true,
// which the Claude Code CLI appends); rejects any model but the gate's and
// any body feature that would make Anthropic reach the network for the
// caller (see checkBody); drops every client header except a short
// allowlist, so whatever auth the client sends never leaves; injects its
// own bearer token; counts requests against a per-run cap; and logs the
// path, status and token usage, never headers or bodies.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

const (
	DefaultUpstream    = "https://api.anthropic.com"
	DefaultMaxRequests = 200
	DefaultMaxBody     = 32 << 20
	messagesPath       = "/v1/messages"
)

// Config is the proxy's fixed configuration.
type Config struct {
	Upstream    *url.URL // https://api.anthropic.com outside tests
	Model       string
	MaxRequests int64
	MaxBody     int64
	Tokens      *TokenSource
	Transport   http.RoundTripper // nil: a default transport
	Logf        func(string, ...any)
}

// Proxy is an http.Handler.
type Proxy struct {
	cfg  Config
	rp   *httputil.ReverseProxy
	n    atomic.Int64 // requests forwarded or refused for the cap
	logf func(string, ...any)
}

func New(cfg Config) (*Proxy, error) {
	switch {
	case cfg.Upstream == nil || cfg.Upstream.Host == "":
		return nil, errors.New("proxy: no upstream")
	case cfg.Model == "":
		return nil, errors.New("proxy: no model")
	case cfg.Tokens == nil:
		return nil, errors.New("proxy: no token source")
	}
	if cfg.MaxRequests <= 0 {
		cfg.MaxRequests = DefaultMaxRequests
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = DefaultMaxBody
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	base := cfg.Transport
	if base == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.Proxy = nil // never an HTTP(S)_PROXY from the environment
		t.ResponseHeaderTimeout = 10 * time.Minute
		base = t
	}
	p := &Proxy{cfg: cfg, logf: cfg.Logf}
	p.rp = &httputil.ReverseProxy{
		Rewrite:        p.rewrite,
		Transport:      &authTransport{base: base, tokens: cfg.Tokens, logf: cfg.Logf},
		FlushInterval:  -1, // stream SSE through as it arrives
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.errorHandler,
	}
	return p, nil
}

type ctxKey struct{}

type reqInfo struct {
	n     int64
	start time.Time
	sse   bool
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != messagesPath || (r.URL.RawQuery != "" && r.URL.RawQuery != "beta=true") {
		p.refuse(w, http.StatusForbidden, "permission_error", fmt.Sprintf("%s %q", safeToken(r.Method), safeToken(r.URL.RequestURI())), "only POST /v1/messages is allowed")
		return
	}
	if r.ContentLength > p.cfg.MaxBody {
		p.refuse(w, http.StatusRequestEntityTooLarge, "request_too_large", "POST /v1/messages", "body over the proxy's limit")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, p.cfg.MaxBody))
	if err != nil {
		p.refuse(w, http.StatusRequestEntityTooLarge, "request_too_large", "POST /v1/messages", "body over the proxy's limit or unreadable")
		return
	}
	if err := checkBody(body, p.cfg.Model); err != nil {
		p.refuse(w, http.StatusForbidden, "permission_error", "POST /v1/messages", err.Error())
		return
	}
	n := p.n.Add(1)
	if n > p.cfg.MaxRequests {
		p.refuse(w, http.StatusForbidden, "permission_error", "POST /v1/messages", fmt.Sprintf("request cap of %d reached", p.cfg.MaxRequests))
		return
	}
	var stream struct {
		Stream bool `json:"stream"`
	}
	_ = json.Unmarshal(body, &stream)
	info := &reqInfo{n: n, start: time.Now(), sse: stream.Stream}
	r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, info))
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	p.rp.ServeHTTP(w, r)
}

// Request headers that may pass through. Everything else, including any
// Authorization, X-Api-Key, Cookie or proxy header the client sends, is
// dropped; Accept-Encoding too, so the transport negotiates gzip itself
// and the usage reader sees plain text.
var passHeaders = []string{"Accept", "Anthropic-Beta", "Anthropic-Version", "Content-Type", "User-Agent", "X-App", "X-Claude-Code-Session-Id"}

func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	in := pr.In.Header
	out := http.Header{}
	for _, h := range passHeaders {
		if v := in.Values(h); len(v) > 0 {
			out[h] = append([]string(nil), v...)
		}
	}
	for k, v := range in {
		if strings.HasPrefix(k, "X-Stainless-") {
			out[k] = append([]string(nil), v...)
		}
	}
	pr.Out.Header = out
	pr.SetURL(p.cfg.Upstream)
	pr.Out.Host = p.cfg.Upstream.Host
	// The request path is exactly /v1/messages, the query empty or
	// beta=true (ServeHTTP checked both); SetURL joined them onto the
	// upstream's path.
	pr.Out.GetBody = pr.In.GetBody
}

// authTransport adds the bearer token, and on a 401 re-exchanges and
// retries the request once (the body is buffered).
type authTransport struct {
	base   http.RoundTripper
	tokens *TokenSource
	logf   func(string, ...any)
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, tok, err := t.try(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized || req.GetBody == nil {
		return resp, err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	t.logf("upstream 401: re-exchanging the token and retrying once")
	t.tokens.Invalidate(tok)
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	retry := req.Clone(req.Context())
	retry.Body = body
	resp, _, err = t.try(retry)
	return resp, err
}

func (t *authTransport) try(req *http.Request) (*http.Response, string, error) {
	tok, err := t.tokens.Token(req.Context())
	if err != nil {
		return nil, "", fmt.Errorf("credential: %w", err)
	}
	out := req.Clone(req.Context())
	out.Header.Set("Authorization", "Bearer "+tok)
	out.Header.Del("X-Api-Key")
	addBeta(out.Header, oauthBeta)
	resp, err := t.base.RoundTrip(out)
	return resp, tok, err
}

func addBeta(h http.Header, beta string) {
	var all []string
	for _, v := range h.Values("Anthropic-Beta") {
		for _, b := range strings.Split(v, ",") {
			if b = strings.TrimSpace(b); b != "" {
				if b == beta {
					return
				}
				all = append(all, b)
			}
		}
	}
	h.Set("Anthropic-Beta", strings.Join(append(all, beta), ","))
}

func (p *Proxy) modifyResponse(resp *http.Response) error {
	info, _ := resp.Request.Context().Value(ctxKey{}).(*reqInfo)
	if info == nil {
		return errors.New("no request info")
	}
	resp.Header.Del("Set-Cookie")
	sse := strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream")
	status := resp.StatusCode
	resp.Body = newUsageReader(resp.Body, sse, func(u Usage) {
		p.logf("#%d POST /v1/messages %d in=%d out=%d cache_read=%d cache_write=%d %.1fs",
			info.n, status, u.InputTokens, u.OutputTokens, u.CacheReadInputTokens, u.CacheCreationInputTokens,
			time.Since(info.start).Seconds())
	})
	return nil
}

func (p *Proxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	n := int64(0)
	if info, _ := r.Context().Value(ctxKey{}).(*reqInfo); info != nil {
		n = info.n
	}
	// err may wrap a token-exchange error; those carry no secrets (see
	// errorSummary), but keep the log line short anyway.
	p.logf("#%d POST /v1/messages upstream error: %s", n, safeText(err.Error()))
	writeError(w, http.StatusBadGateway, "api_error", "dep-review proxy: upstream unavailable")
}

func (p *Proxy) refuse(w http.ResponseWriter, status int, typ, what, why string) {
	p.logf("refused %s: %s", what, safeText(why))
	writeError(w, status, typ, "dep-review proxy: "+why)
}

// writeError answers in the Messages API's error shape, with
// x-should-retry: false so the client gives up rather than retrying.
func writeError(w http.ResponseWriter, status int, typ, msg string) {
	b, _ := json.Marshal(map[string]any{"type": "error", "error": map[string]string{"type": typ, "message": msg}})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Should-Retry", "false")
	w.WriteHeader(status)
	w.Write(b)
}

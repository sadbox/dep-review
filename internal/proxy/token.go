package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// The exchange follows the Anthropic TypeScript SDK's oidcFederationProvider
// (src/lib/credentials/oidc-federation.ts and types.ts) and Anthropic's
// docs ("Workload Identity Federation", "WIF reference", "Use WIF with
// GitHub Actions"):
//
//   - GitHub OIDC (GitHubOIDC, on the host): GET
//     $ACTIONS_ID_TOKEN_REQUEST_URL&audience=<aud> with "Authorization:
//     Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN"; the JWT is the "value" field. claude-code-action asks for the audience
//     https://api.anthropic.com.
//   - Exchange: POST <base>/v1/oauth/token, JSON body {grant_type:
//     urn:ietf:params:oauth:grant-type:jwt-bearer, assertion,
//     federation_rule_id, organization_id, service_account_id?,
//     workspace_id?}, headers content-type: application/json and
//     anthropic-beta: oauth-2025-04-20,oidc-federation-2026-04-01, no
//     redirects followed.
//   - Response: {access_token, token_type: "Bearer", expires_in, scope}.
//     The token is sent as "Authorization: Bearer <token>", with
//     oauth-2025-04-20 added to anthropic-beta.
//   - A JWT with a jti can be exchanged once, so every exchange (retries
//     included) fetches a fresh one. The minted token lives at most
//     min(rule lifetime, 2 x the JWT's remaining life): about ten minutes
//     for GitHub's five-minute JWTs.
const (
	DefaultAudience  = "https://api.anthropic.com"
	tokenPath        = "/v1/oauth/token"
	grantJWTBearer   = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	oauthBeta        = "oauth-2025-04-20"
	federationBeta   = "oidc-federation-2026-04-01"
	maxTokenResponse = 1 << 20
	maxAssertion     = 16 << 10

	// The SDK's refresh schedule (types.ts): try to refresh two minutes
	// before expiry, keep serving the old token on failure until 30 s
	// before.
	advisoryRefresh  = 120 * time.Second
	mandatoryRefresh = 30 * time.Second
	exchangeAttempts = 3
)

// Federation is what the exchange needs. The IDs are not secrets.
// IdentityToken returns a fresh GitHub OIDC JWT for DefaultAudience on
// every call: in the proxy, SocketIdentity (the host helper; see
// identity.go).
type Federation struct {
	IdentityToken    func(context.Context) (string, error)
	RuleID           string // fdrl_...
	OrganizationID   string // UUID
	WorkspaceID      string // wrkspc_..., optional
	ServiceAccountID string // svac_..., optional
}

func (f Federation) validate() error {
	switch {
	case f.IdentityToken == nil:
		return errors.New("no identity token source")
	case f.RuleID == "" || f.OrganizationID == "":
		return errors.New("federation rule ID and organization ID are required")
	}
	return nil
}

// TokenSource mints and caches the Claude access token. Token is safe for
// concurrent use; callers that arrive during an exchange wait for it.
type TokenSource struct {
	fed      Federation
	exchange string // <upstream>/v1/oauth/token
	client   *http.Client
	now      func() time.Time
	logf     func(string, ...any)
	backoff  time.Duration

	mu  sync.Mutex
	tok string
	exp time.Time
}

func NewTokenSource(fed Federation, upstream *url.URL, client *http.Client, logf func(string, ...any)) (*TokenSource, error) {
	if err := fed.validate(); err != nil {
		return nil, err
	}
	// Never follow a redirect with an assertion or a request token.
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &TokenSource{
		fed:      fed,
		exchange: strings.TrimSuffix(upstream.String(), "/") + tokenPath,
		client:   &c,
		now:      time.Now,
		logf:     logf,
		backoff:  time.Second,
	}, nil
}

// Token returns a token with more than advisoryRefresh left, exchanging a
// fresh OIDC JWT when needed. If that exchange fails it keeps serving the
// current token until mandatoryRefresh before expiry.
func (s *TokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	left := s.exp.Sub(s.now())
	if s.tok != "" && left > advisoryRefresh {
		return s.tok, nil
	}
	tok, ttl, err := s.mint(ctx)
	if err != nil {
		if s.tok != "" && left > mandatoryRefresh {
			s.logf("token refresh failed, keeping the current token (%ds left): %v", int(left.Seconds()), err)
			return s.tok, nil
		}
		return "", err
	}
	s.tok, s.exp = tok, s.now().Add(ttl)
	s.logf("token minted, expires in %ds", int(ttl.Seconds()))
	return s.tok, nil
}

// Invalidate forces the next Token call to exchange again, if tok is still
// the current token (an upstream 401 on it).
func (s *TokenSource) Invalidate(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tok == s.tok {
		s.exp = time.Time{}
	}
}

func (s *TokenSource) mint(ctx context.Context) (string, time.Duration, error) {
	var last error
	for i := range exchangeAttempts {
		if i > 0 {
			select {
			case <-ctx.Done():
				return "", 0, ctx.Err()
			case <-time.After(s.backoff << (i - 1)):
			}
		}
		jwt, err := s.fed.IdentityToken(ctx)
		if err != nil {
			last = err
			if retryable(err) {
				continue
			}
			return "", 0, err
		}
		tok, ttl, err := s.exchangeJWT(ctx, jwt)
		if err == nil {
			return tok, ttl, nil
		}
		last = err
		if !retryable(err) {
			return "", 0, err
		}
	}
	return "", 0, last
}

// httpError carries a status so retries can tell 5xx from 4xx.
type httpError struct {
	what   string
	status int
	detail string
}

func (e *httpError) Error() string {
	if e.detail == "" {
		return fmt.Sprintf("%s: HTTP %d", e.what, e.status)
	}
	return fmt.Sprintf("%s: HTTP %d: %s", e.what, e.status, e.detail)
}

func retryable(err error) bool {
	var he *httpError
	if errors.As(err, &he) {
		return he.status >= 500 || he.status == http.StatusTooManyRequests
	}
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

func (s *TokenSource) exchangeJWT(ctx context.Context, jwt string) (string, time.Duration, error) {
	body := map[string]string{
		"grant_type":         grantJWTBearer,
		"assertion":          jwt,
		"federation_rule_id": s.fed.RuleID,
		"organization_id":    s.fed.OrganizationID,
	}
	if s.fed.ServiceAccountID != "" {
		body["service_account_id"] = s.fed.ServiceAccountID
	}
	if s.fed.WorkspaceID != "" {
		body["workspace_id"] = s.fed.WorkspaceID
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.exchange, bytes.NewReader(raw))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Anthropic-Beta", oauthBeta+","+federationBeta)
	req.Header.Set("User-Agent", "dep-review-proxy")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("token exchange: %w", scrub(err))
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse))
	if err != nil {
		return "", 0, fmt.Errorf("token exchange response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		detail := errorSummary(rb)
		if id := resp.Header.Get("Request-Id"); id != "" {
			detail = strings.TrimSpace(detail + " (request-id " + safeToken(id) + ")")
		}
		return "", 0, &httpError{what: "token exchange", status: resp.StatusCode, detail: detail}
	}
	var tr struct {
		AccessToken string   `json:"access_token"`
		TokenType   string   `json:"token_type"`
		ExpiresIn   *float64 `json:"expires_in"`
	}
	if err := json.Unmarshal(rb, &tr); err != nil {
		return "", 0, errors.New("token exchange response is not JSON")
	}
	switch {
	case tr.AccessToken == "":
		return "", 0, errors.New("token exchange response has no access_token")
	case tr.TokenType != "" && !strings.EqualFold(tr.TokenType, "bearer"):
		return "", 0, fmt.Errorf("token exchange returned token_type %q, want Bearer", safeToken(tr.TokenType))
	case tr.ExpiresIn == nil || *tr.ExpiresIn <= 0:
		return "", 0, errors.New("token exchange response has no positive expires_in")
	case strings.ContainsAny(tr.AccessToken, "\r\n\x00 "):
		return "", 0, errors.New("token exchange returned a malformed access_token")
	}
	return tr.AccessToken, time.Duration(*tr.ExpiresIn * float64(time.Second)), nil
}

// errorSummary keeps only the error type and message of an Anthropic or
// RFC 6749 error body: anything else could echo the assertion.
func errorSummary(b []byte) string {
	var e struct {
		Error any `json:"error"`
	}
	if json.Unmarshal(b, &e) != nil {
		return ""
	}
	switch v := e.Error.(type) {
	case string:
		return safeToken(v)
	case map[string]any:
		t, _ := v["type"].(string)
		m, _ := v["message"].(string)
		return strings.TrimSpace(safeToken(t) + " " + safeText(m))
	}
	return ""
}

// scrub drops the URL from a transport error: the OIDC request URL is
// not secret, but there is no reason to log it either.
func scrub(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func safeToken(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return '?'
		}
		return r
	}, s)
}

func safeText(s string) string {
	if len(s) > 300 {
		s = s[:300]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

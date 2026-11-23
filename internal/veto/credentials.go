package veto

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Credentials is what lets a request through the API's door. The gate
// uses a Federated token; an APIKey is for evaluating the client on a
// workstation.
type Credentials interface {
	// Authorize adds the credential to the headers of one request.
	Authorize(ctx context.Context, h http.Header) error
	// Rejected is called when the API answered 401 to a request these
	// credentials authorized. It reports whether asking again can help:
	// a federated token is dropped and exchanged anew, an API key is
	// what it is.
	Rejected() bool
}

// APIKey is a Claude API key. It is for local evaluation only: the gate
// stores no key anywhere and its jobs use NewFederated.
type APIKey string

// APIKeyEnv is the environment variable APIKeyFromEnv reads.
const APIKeyEnv = "ANTHROPIC_API_KEY"

// APIKeyFromEnv returns the key in the environment variable APIKeyEnv.
func APIKeyFromEnv() (APIKey, error) {
	k := APIKey(os.Getenv(APIKeyEnv))
	if err := k.check(); err != nil {
		return "", err
	}
	return k, nil
}

func (k APIKey) check() error {
	if k == "" {
		return errors.New(APIKeyEnv + " is not set")
	}
	if !headerSafe(string(k)) {
		return errors.New(APIKeyEnv + " is not an API key")
	}
	return nil
}

// Authorize implements Credentials: an API key goes in x-api-key.
func (k APIKey) Authorize(_ context.Context, h http.Header) error {
	if err := k.check(); err != nil {
		return err
	}
	h.Set("X-Api-Key", string(k))
	return nil
}

// Rejected implements Credentials. A refused key stays refused.
func (APIKey) Rejected() bool { return false }

// String keeps the key out of anything that formats the value.
func (APIKey) String() string { return "APIKey(redacted)" }

// Workload identity federation: the job proves who it is with a GitHub
// OIDC token and exchanges that for a short-lived Claude access token. No
// key is stored. The exchange is v0.1.9's (internal/proxy/token.go and
// identity.go), which followed the Anthropic TypeScript SDK's
// oidcFederationProvider and the WIF documentation:
//
//   - GitHub OIDC: GET $ACTIONS_ID_TOKEN_REQUEST_URL&audience=<audience>
//     with "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN"; the
//     JWT is the "value" field.
//   - Exchange: POST <base>/v1/oauth/token, JSON body {grant_type:
//     urn:ietf:params:oauth:grant-type:jwt-bearer, assertion,
//     federation_rule_id, organization_id, service_account_id?,
//     workspace_id?}, anthropic-beta: oauth-2025-04-20 and
//     oidc-federation-2026-04-01, no redirect followed.
//   - Response: {access_token, token_type: "Bearer", expires_in}. The
//     token is sent as "Authorization: Bearer <token>" with
//     oauth-2025-04-20 in anthropic-beta.
//   - A JWT with a jti can be exchanged once, so every exchange, a retry
//     included, fetches a fresh one. The token lives about ten minutes
//     for GitHub's five-minute JWTs.
const (
	// FederationAudience is the audience the GitHub OIDC token is asked
	// for. A token for it is good for the Claude token exchange only.
	FederationAudience = "https://api.anthropic.com"

	tokenPath        = "/v1/oauth/token"
	grantJWTBearer   = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	oauthBeta        = "oauth-2025-04-20"
	federationBeta   = "oidc-federation-2026-04-01"
	maxTokenResponse = 1 << 20
	maxAssertion     = 16 << 10

	// The SDK's schedule: exchange again two minutes before expiry, and
	// if that fails keep using the current token until 30 s before.
	advisoryRefresh  = 120 * time.Second
	mandatoryRefresh = 30 * time.Second
	exchangeAttempts = 3
	// exchangeTimeout bounds one OIDC request or one exchange.
	exchangeTimeout = 30 * time.Second
)

// Federation is what the token exchange needs. The IDs are not secrets.
type Federation struct {
	// IdentityToken returns a fresh OIDC JWT for FederationAudience on
	// every call. In a GitHub Actions job it is GitHubOIDC.Token.
	IdentityToken func(context.Context) (string, error)
	// RuleID is the federation rule (fdrl_...).
	RuleID string
	// OrganizationID is the Anthropic organization's UUID.
	OrganizationID string
	// WorkspaceID (wrkspc_...) is needed when the rule covers more than
	// one workspace; otherwise optional.
	WorkspaceID string
	// ServiceAccountID (svac_...) is optional: the rule decides.
	ServiceAccountID string
}

// Federated is the Credentials of a job with workload identity: it
// exchanges, caches and renews the Claude access token. It is safe for
// concurrent use; callers that arrive during an exchange wait for it.
type Federated struct {
	fed      Federation
	exchange string // <base>/v1/oauth/token
	client   *http.Client
	now      func() time.Time
	sleep    func(context.Context, time.Duration) error

	// Logf, when set, is told when a token is minted and when a renewal
	// failed. It never receives a token or an assertion.
	Logf func(format string, args ...any)

	mu  sync.Mutex
	tok string
	exp time.Time
}

// NewFederated returns the credentials for fed against the API at
// baseURL, which must be the Config.BaseURL the Client uses. hc is as in
// New: nil for the default, and redirects are never followed.
func NewFederated(fed Federation, baseURL string, hc *http.Client) (*Federated, error) {
	switch {
	case fed.IdentityToken == nil:
		return nil, errors.New("veto: federation: no identity token source")
	case !headerSafe(fed.RuleID) || !headerSafe(fed.OrganizationID):
		return nil, errors.New("veto: federation: the rule ID and the organization ID are required")
	case fed.WorkspaceID != "" && !headerSafe(fed.WorkspaceID), fed.ServiceAccountID != "" && !headerSafe(fed.ServiceAccountID):
		return nil, errors.New("veto: federation: the workspace or service account ID is not an ID")
	}
	base, err := apiOrigin(baseURL)
	if err != nil {
		return nil, fmt.Errorf("veto: federation: base URL: %w", err)
	}
	return &Federated{
		fed:      fed,
		exchange: base + tokenPath,
		client:   noRedirects(hc),
		now:      time.Now,
		sleep:    sleepContext,
	}, nil
}

func (s *Federated) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// Authorize implements Credentials: the access token goes in
// Authorization, and the OAuth beta the API wants with it is added to
// whatever anthropic-beta the request already has.
func (s *Federated) Authorize(ctx context.Context, h http.Header) error {
	tok, err := s.token(ctx)
	if err != nil {
		return err
	}
	h.Set("Authorization", "Bearer "+tok)
	beta := oauthBeta
	if have := h.Get("Anthropic-Beta"); have != "" {
		beta = have + "," + oauthBeta
	}
	h.Set("Anthropic-Beta", beta)
	return nil
}

// Rejected implements Credentials: the token the API refused is dropped,
// so the next Authorize exchanges a fresh JWT for a new one.
func (s *Federated) Rejected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tok, s.exp = "", time.Time{}
	return true
}

// token returns a token with more than advisoryRefresh left, exchanging
// a fresh OIDC JWT when needed. If that exchange fails it keeps serving
// the current token until mandatoryRefresh before its expiry.
func (s *Federated) token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	left := s.exp.Sub(s.now())
	if s.tok != "" && left > advisoryRefresh {
		return s.tok, nil
	}
	tok, ttl, err := s.mint(ctx)
	if err != nil {
		if s.tok != "" && left > mandatoryRefresh {
			s.logf("veto: token renewal failed, keeping the current token (%ds left): %v", int(left.Seconds()), err)
			return s.tok, nil
		}
		return "", err
	}
	s.tok, s.exp = tok, s.now().Add(ttl)
	s.logf("veto: token minted, expires in %ds", int(ttl.Seconds()))
	return s.tok, nil
}

func (s *Federated) mint(ctx context.Context) (string, time.Duration, error) {
	var last error
	for i := range exchangeAttempts {
		if i > 0 {
			if err := s.sleep(ctx, time.Second<<(i-1)); err != nil {
				return "", 0, err
			}
		}
		tok, ttl, err := s.mintOnce(ctx)
		if err == nil {
			return tok, ttl, nil
		}
		last = err
		// A caller that gave up is not retried; a single exchange that
		// ran into its own timeout is.
		if ctx.Err() != nil || !retryable(err) {
			return "", 0, err
		}
	}
	return "", 0, last
}

// mintOnce fetches a fresh JWT and exchanges it.
func (s *Federated) mintOnce(ctx context.Context) (string, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*exchangeTimeout)
	defer cancel()
	jwt, err := s.fed.IdentityToken(ctx)
	if err != nil {
		return "", 0, err
	}
	return s.exchangeJWT(ctx, jwt)
}

// statusError carries a status so retries can tell 5xx from 4xx.
type statusError struct {
	what   string
	status int
	detail string
}

func (e *statusError) Error() string {
	if e.detail == "" {
		return fmt.Sprintf("%s: HTTP %d", e.what, e.status)
	}
	return fmt.Sprintf("%s: HTTP %d: %s", e.what, e.status, e.detail)
}

// retryable reports whether another exchange can help: after a 5xx, a
// 429 or a failure that produced no status at all.
func retryable(err error) bool {
	var se *statusError
	if errors.As(err, &se) {
		return se.status >= 500 || se.status == http.StatusTooManyRequests
	}
	return true
}

func (s *Federated) exchangeJWT(ctx context.Context, jwt string) (string, time.Duration, error) {
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
	req.Header.Set("User-Agent", userAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("token exchange: %w", scrub(err))
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse))
	if err != nil {
		return "", 0, fmt.Errorf("token exchange response: %w", scrub(err))
	}
	if resp.StatusCode != http.StatusOK {
		errType, message := errorSummary(rb)
		detail := strings.TrimSpace(errType + " " + message)
		if id := resp.Header.Get("Request-Id"); id != "" {
			detail = strings.TrimSpace(detail + " (request-id " + safeToken(id) + ")")
		}
		return "", 0, &statusError{what: "token exchange", status: resp.StatusCode, detail: detail}
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
	case len(tr.AccessToken) > maxAssertion || strings.ContainsFunc(tr.AccessToken, func(r rune) bool { return r < 0x21 || r > 0x7e }):
		// It goes into a header as it is.
		return "", 0, errors.New("token exchange returned a malformed access_token")
	}
	return tr.AccessToken, time.Duration(*tr.ExpiresIn * float64(time.Second)), nil
}

// GitHubOIDC fetches GitHub Actions OIDC tokens for FederationAudience
// and for nothing else: the audience is not a parameter.
//
// RequestToken is the job's ACTIONS_ID_TOKEN_REQUEST_TOKEN. In
// actions/runner that is also the job's runtime token, which can replace
// the run's artifacts and write caches, so it is sent to RequestURL only
// and that URL must be https.
type GitHubOIDC struct {
	// RequestURL is ACTIONS_ID_TOKEN_REQUEST_URL.
	RequestURL string
	// RequestToken is ACTIONS_ID_TOKEN_REQUEST_TOKEN.
	RequestToken string
	// Client is as in New: nil for the default, redirects never followed.
	Client *http.Client
}

// GitHubOIDCFromEnv reads the two variables GitHub sets in a job that
// has "id-token: write".
func GitHubOIDCFromEnv() GitHubOIDC {
	return GitHubOIDC{
		RequestURL:   os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"),
		RequestToken: os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
	}
}

// Token is one GET of RequestURL with audience=FederationAudience and
// the request token as a bearer credential; the JWT is the "value" field
// of the response. Its signature fits Federation.IdentityToken.
func (g GitHubOIDC) Token(ctx context.Context) (string, error) {
	if g.RequestURL == "" || g.RequestToken == "" {
		return "", errors.New("no GitHub OIDC request URL or token (does the job have id-token: write?)")
	}
	u, err := url.Parse(g.RequestURL)
	if err != nil {
		return "", errors.New("ACTIONS_ID_TOKEN_REQUEST_URL is not a URL")
	}
	if _, err := apiOrigin(u.Scheme + "://" + u.Host); err != nil {
		return "", fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_URL: %w", err)
	}
	q := u.Query()
	q.Set("audience", FederationAudience)
	u.RawQuery = q.Encode()
	ctx, cancel := context.WithTimeout(ctx, exchangeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+g.RequestToken)
	req.Header.Set("Accept", "application/json")
	resp, err := noRedirects(g.Client).Do(req)
	if err != nil {
		return "", fmt.Errorf("GitHub OIDC token request: %w", scrub(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", &statusError{what: "GitHub OIDC token request", status: resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse))
	if err != nil {
		return "", fmt.Errorf("identity token response: %w", scrub(err))
	}
	var v struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &v); err != nil || v.Value == "" {
		return "", errors.New("identity token response has no value")
	}
	if len(v.Value) > maxAssertion {
		return "", fmt.Errorf("identity token is %d bytes, over the 16 KiB assertion limit", len(v.Value))
	}
	return v.Value, nil
}

// errorSummary keeps only the error type and message of an Anthropic or
// RFC 6749 error body, cut short: anything else could echo what was
// sent, an assertion included.
func errorSummary(b []byte) (errType, message string) {
	var e struct {
		Error any `json:"error"`
	}
	if json.Unmarshal(b, &e) != nil {
		return "", ""
	}
	switch v := e.Error.(type) {
	case string:
		return safeToken(v), ""
	case map[string]any:
		t, _ := v["type"].(string)
		m, _ := v["message"].(string)
		return safeToken(t), safeText(m)
	}
	return "", ""
}

// scrub drops the URL from a transport error. The OIDC request URL is
// not secret, but there is no reason to log it either.
func scrub(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// safeToken makes a short identifier from the API fit for a log line.
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

// safeText makes a message from the API fit for a log line.
func safeText(s string) string {
	s = clip(strings.ToValidUTF8(s, "?"), 300)
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

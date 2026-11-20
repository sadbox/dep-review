package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
)

// The proxy never holds the job's ACTIONS_ID_TOKEN_REQUEST_TOKEN. In
// actions/runner that variable is the job's runtime token (the same value
// as ACTIONS_RUNTIME_TOKEN), which can replace the run's artifacts and
// write caches. It stays on the host, in `dep-review review`, which serves
// the proxy one thing over a unix socket: a fresh GitHub OIDC JWT for the
// audience https://api.anthropic.com, which is only good for the Claude
// token exchange.

// GitHubOIDC fetches GitHub Actions OIDC tokens for DefaultAudience only.
type GitHubOIDC struct {
	RequestURL   string // ACTIONS_ID_TOKEN_REQUEST_URL
	RequestToken string // ACTIONS_ID_TOKEN_REQUEST_TOKEN
	Client       *http.Client
}

// Token is one GET $ACTIONS_ID_TOKEN_REQUEST_URL&audience=... with the
// request token as a bearer credential; the JWT is the "value" field.
func (g GitHubOIDC) Token(ctx context.Context) (string, error) {
	if g.RequestURL == "" || g.RequestToken == "" {
		return "", errors.New("no GitHub OIDC request URL/token (does the job have id-token: write?)")
	}
	u, err := url.Parse(g.RequestURL)
	if err != nil {
		return "", errors.New("ACTIONS_ID_TOKEN_REQUEST_URL is not a URL")
	}
	q := u.Query()
	q.Set("audience", DefaultAudience)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+g.RequestToken)
	req.Header.Set("Accept", "application/json")
	c := *g.Client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("GitHub OIDC token request: %w", scrub(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", &httpError{what: "GitHub OIDC token request", status: resp.StatusCode}
	}
	return readJWT(resp.Body)
}

func readJWT(r io.Reader) (string, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxTokenResponse))
	if err != nil {
		return "", fmt.Errorf("identity token response: %w", err)
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

// IdentityHandler serves GET /token: a fresh JWT from src, at most max per
// run. Nothing else, and no parameters: the audience is fixed in
// GitHubOIDC.
func IdentityHandler(src func(context.Context) (string, error), max int64, logf func(string, ...any)) http.Handler {
	var n atomic.Int64
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/token" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if n.Add(1) > max {
			logf("identity: refused, %d tokens already issued", max)
			http.Error(w, "identity token cap reached", http.StatusTooManyRequests)
			return
		}
		jwt, err := src(r.Context())
		if err != nil {
			logf("identity: %v", err)
			status := http.StatusBadGateway
			var he *httpError
			if errors.As(err, &he) && he.status < 500 && he.status != http.StatusTooManyRequests {
				status = http.StatusForbidden // not retryable
			}
			http.Error(w, "identity token unavailable", status)
			return
		}
		logf("identity: issued token %d", n.Load())
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"value": jwt})
	})
}

// SocketIdentity is the proxy's side: it asks the host helper on the unix
// socket at path for a JWT.
func SocketIdentity(path string) func(context.Context) (string, error) {
	client := &http.Client{Transport: &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}}
	return func(ctx context.Context) (string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://identity/token", nil)
		if err != nil {
			return "", err
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("identity socket: %w", scrub(err))
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", &httpError{what: "identity socket", status: resp.StatusCode}
		}
		return readJWT(resp.Body)
	}
}

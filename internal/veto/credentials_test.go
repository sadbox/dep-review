package veto

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// federated returns credentials that get their JWTs from the fake's OIDC
// endpoint and exchange them at the fake's token endpoint, with a clock
// the test moves and no real waiting between attempts.
func federated(t *testing.T, f *fakeAPI) (*Federated, *time.Time) {
	t.Helper()
	oidc := GitHubOIDC{RequestURL: f.srv.URL + "/oidc?api-version=2.0", RequestToken: f.oidcToken}
	creds, err := NewFederated(Federation{
		IdentityToken:  oidc.Token,
		RuleID:         "fdrl_test",
		OrganizationID: "org-uuid",
		WorkspaceID:    "wrkspc_test",
	}, f.srv.URL, nil)
	if err != nil {
		t.Fatalf("NewFederated: %v", err)
	}
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	creds.now = func() time.Time { return now }
	creds.sleep = func(context.Context, time.Duration) error { return nil }
	return creds, &now
}

func (f *fakeAPI) counts() (jwts, exchanges int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.jwts, f.exchanges
}

func TestAPIKey(t *testing.T) {
	h := http.Header{}
	if err := APIKey("sk-ant-x").Authorize(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if h.Get("X-Api-Key") != "sk-ant-x" || h.Get("Authorization") != "" || len(h) != 1 {
		t.Errorf("headers = %v", h)
	}
	if APIKey("sk-ant-x").Rejected() {
		t.Error("an API key claims a retry can help after a 401")
	}
	if s := fmt.Sprintf("%v %s %+v", APIKey("sk-ant-x"), APIKey("sk-ant-x"), struct{ K APIKey }{"sk-ant-x"}); strings.Contains(s, "sk-ant-x") {
		t.Errorf("formatting an APIKey prints it: %s", s)
	}
	for _, bad := range []APIKey{"", "two words", "line\nbreak"} {
		if err := bad.Authorize(context.Background(), http.Header{}); err == nil {
			t.Errorf("APIKey(%q) was put in a header", string(bad))
		}
	}

	t.Setenv(APIKeyEnv, "sk-ant-from-env")
	if k, err := APIKeyFromEnv(); err != nil || string(k) != "sk-ant-from-env" {
		t.Errorf("APIKeyFromEnv = %q, %v", string(k), err)
	}
	t.Setenv(APIKeyEnv, "")
	if _, err := APIKeyFromEnv(); err == nil {
		t.Error("APIKeyFromEnv succeeded with no key set")
	}
}

// The whole path a gate job takes: a JWT from GitHub, exchanged once,
// and the token reused for every chunk.
func TestFederatedReview(t *testing.T) {
	f := newFakeAPI(t)
	creds, _ := federated(t, f)
	c, _ := testClient(t, f, creds)
	v, err := c.Review(context.Background(), Request{Read: prepared("a\n", "b\n", "c\n")})
	if err != nil || v.Answer != NoVeto {
		t.Fatalf("Review = %+v, %v", v, err)
	}
	reqs := f.recordedRequests()
	if len(reqs) != 3 {
		t.Fatalf("%d requests, want 3", len(reqs))
	}
	for i, r := range reqs {
		if r.header.Get("Authorization") != "Bearer tok-1" || r.header.Get("Anthropic-Beta") != "oauth-2025-04-20" || r.header.Get("X-Api-Key") != "" {
			t.Errorf("request %d: credential headers %v", i, r.header)
		}
	}
	if jwts, exchanges := f.counts(); jwts != 1 || exchanges != 1 {
		t.Errorf("%d JWTs and %d exchanges, want 1 and 1", jwts, exchanges)
	}
}

func TestFederatedRenewal(t *testing.T) {
	f := newFakeAPI(t)
	creds, now := federated(t, f)
	token := func() string {
		t.Helper()
		h := http.Header{}
		if err := creds.Authorize(context.Background(), h); err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		return strings.TrimPrefix(h.Get("Authorization"), "Bearer ")
	}

	if got := token(); got != "tok-1" {
		t.Fatalf("first token %q", got)
	}
	// 600 s of life; still more than two minutes left after 470 s.
	*now = now.Add(470 * time.Second)
	if got := token(); got != "tok-1" {
		t.Errorf("token with 130 s left was replaced by %q", got)
	}
	// Under two minutes left: a fresh JWT, a new token.
	*now = now.Add(20 * time.Second)
	if got := token(); got != "tok-2" {
		t.Errorf("token with 110 s left was kept: %q", got)
	}
	if jwts, exchanges := f.counts(); jwts != 2 || exchanges != 2 {
		t.Errorf("%d JWTs and %d exchanges, want 2 and 2", jwts, exchanges)
	}

	// A renewal that fails keeps the current token while it has more
	// than 30 s left, and fails once it has not.
	f.exchangeStatus = func(int) int { return http.StatusBadRequest }
	*now = now.Add(500 * time.Second) // 100 s left on tok-2
	if got := token(); got != "tok-2" {
		t.Errorf("renewal failed with 100 s left and the token was not kept: %q", got)
	}
	*now = now.Add(80 * time.Second) // 20 s left
	if err := creds.Authorize(context.Background(), http.Header{}); err == nil {
		t.Error("a token with 20 s left was served after a failed renewal")
	}
}

func TestFederatedExchangeFailures(t *testing.T) {
	tests := []struct {
		name          string
		status        func(n int) int
		wantErr       string
		wantExchanges int
	}{
		{"a 500 is retried with a fresh JWT each time", func(n int) int {
			if n < 2 {
				return 500
			}
			return 0
		}, "", 3},
		{"a 429 is retried", func(n int) int {
			if n < 1 {
				return 429
			}
			return 0
		}, "", 2},
		{"a 500 three times is an error", func(int) int { return 500 }, "token exchange: HTTP 500", 3},
		{"a 400 is final", func(int) int { return 400 }, "token exchange: HTTP 400", 1},
		{"a 403 is final", func(int) int { return 403 }, "token exchange: HTTP 403", 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t)
			f.exchangeStatus = tc.status
			creds, _ := federated(t, f)
			c, _ := testClient(t, f, creds)
			v, err := c.Review(context.Background(), Request{Read: prepared("a\n")})
			if tc.wantErr == "" {
				if err != nil || v.Answer != NoVeto {
					t.Fatalf("Review = %+v, %v", v, err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Review error = %v, want one containing %q", err, tc.wantErr)
				}
				// The fake's error body echoes the assertion; only the
				// error's type, message and request-id may be repeated.
				if strings.Contains(err.Error(), "jwt-") || !strings.Contains(err.Error(), "api_error exchange failed (request-id req_fake_exchange)") {
					t.Errorf("the error is not the API's type and message alone: %v", err)
				}
				if n := len(f.recordedRequests()); n != 0 {
					t.Errorf("%d Messages requests without a token", n)
				}
			}
			jwts, exchanges := f.counts()
			if exchanges != tc.wantExchanges || jwts != exchanges {
				t.Errorf("%d JWTs and %d exchanges, want %d of each: a JWT is good for one exchange", jwts, exchanges, tc.wantExchanges)
			}
		})
	}
}

// A 401 on a federated token drops it: the request is sent once more
// with a newly exchanged token, and a second 401 is final.
func TestFederatedTokenRejected(t *testing.T) {
	t.Run("once", func(t *testing.T) {
		f := newFakeAPI(t)
		f.reject401 = 1
		creds, _ := federated(t, f)
		c, waits := testClient(t, f, creds)
		v, err := c.Review(context.Background(), Request{Read: prepared("a\n")})
		if err != nil || v.Answer != NoVeto {
			t.Fatalf("Review = %+v, %v", v, err)
		}
		reqs := f.recordedRequests()
		if len(reqs) != 1 || reqs[0].header.Get("Authorization") != "Bearer tok-2" {
			t.Errorf("the answered request did not carry the new token")
		}
		if _, exchanges := f.counts(); exchanges != 2 {
			t.Errorf("%d exchanges, want 2", exchanges)
		}
		if len(*waits) != 1 || (*waits)[0] != 0 {
			t.Errorf("waits = %v, want one of zero: a renewed token is tried at once", *waits)
		}
	})
	t.Run("twice", func(t *testing.T) {
		f := newFakeAPI(t)
		f.reject401 = 5
		creds, _ := federated(t, f)
		c, _ := testClient(t, f, creds)
		_, err := c.Review(context.Background(), Request{Read: prepared("a\n")})
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
			t.Fatalf("Review error = %v, want a 401", err)
		}
		if _, exchanges := f.counts(); exchanges != 2 {
			t.Errorf("%d exchanges, want 2: one renewal, not one per attempt", exchanges)
		}
	})
}

func TestFederatedConcurrentUse(t *testing.T) {
	f := newFakeAPI(t)
	creds, _ := federated(t, f)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := creds.Authorize(context.Background(), http.Header{}); err != nil {
				t.Errorf("Authorize: %v", err)
			}
		}()
	}
	wg.Wait()
	if _, exchanges := f.counts(); exchanges != 1 {
		t.Errorf("%d exchanges for 8 concurrent callers, want 1", exchanges)
	}
}

func TestFederatedAddsToExistingBeta(t *testing.T) {
	f := newFakeAPI(t)
	creds, _ := federated(t, f)
	h := http.Header{}
	h.Set("Anthropic-Beta", "some-beta-2026-01-01")
	if err := creds.Authorize(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if got := h.Get("Anthropic-Beta"); got != "some-beta-2026-01-01,oauth-2025-04-20" {
		t.Errorf("anthropic-beta = %q", got)
	}
}

func TestNewFederated(t *testing.T) {
	src := func(context.Context) (string, error) { return "jwt", nil }
	tests := []struct {
		name string
		fed  Federation
		base string
		ok   bool
	}{
		{"rule and organization", Federation{IdentityToken: src, RuleID: "fdrl_1", OrganizationID: "org"}, DefaultBaseURL, true},
		{"with the optional IDs", Federation{IdentityToken: src, RuleID: "fdrl_1", OrganizationID: "org", WorkspaceID: "wrkspc_1", ServiceAccountID: "svac_1"}, DefaultBaseURL, true},
		{"no identity source", Federation{RuleID: "fdrl_1", OrganizationID: "org"}, DefaultBaseURL, false},
		{"no rule", Federation{IdentityToken: src, OrganizationID: "org"}, DefaultBaseURL, false},
		{"no organization", Federation{IdentityToken: src, RuleID: "fdrl_1"}, DefaultBaseURL, false},
		{"a workspace with a space", Federation{IdentityToken: src, RuleID: "fdrl_1", OrganizationID: "org", WorkspaceID: "a b"}, DefaultBaseURL, false},
		{"plain http", Federation{IdentityToken: src, RuleID: "fdrl_1", OrganizationID: "org"}, "http://api.anthropic.com", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewFederated(tc.fed, tc.base, nil)
			if (err == nil) != tc.ok {
				t.Errorf("NewFederated error = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

// What the exchange answers decides whether there is a token; anything
// short of a usable bearer token is an error.
func TestExchangeResponses(t *testing.T) {
	tests := []struct {
		name string
		body string
		ok   bool
	}{
		{"a bearer token", `{"access_token":"tok","token_type":"Bearer","expires_in":600}`, true},
		{"token_type in lower case", `{"access_token":"tok","token_type":"bearer","expires_in":600.5}`, true},
		{"no token_type", `{"access_token":"tok","expires_in":600}`, true},
		{"another token_type", `{"access_token":"tok","token_type":"mac","expires_in":600}`, false},
		{"no access_token", `{"token_type":"Bearer","expires_in":600}`, false},
		{"no expires_in", `{"access_token":"tok","token_type":"Bearer"}`, false},
		{"expires_in zero", `{"access_token":"tok","token_type":"Bearer","expires_in":0}`, false},
		{"a token with a newline", `{"access_token":"tok\r\nX-Injected: 1","token_type":"Bearer","expires_in":600}`, false},
		{"a token with a space", `{"access_token":"to k","token_type":"Bearer","expires_in":600}`, false},
		{"not JSON", `<html>`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			creds, err := NewFederated(Federation{
				IdentityToken: func(context.Context) (string, error) { return "jwt", nil },
				RuleID:        "fdrl_1", OrganizationID: "org",
			}, srv.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			creds.sleep = func(context.Context, time.Duration) error { return nil }
			h := http.Header{}
			err = creds.Authorize(context.Background(), h)
			if (err == nil) != tc.ok {
				t.Fatalf("Authorize error = %v, want ok=%v", err, tc.ok)
			}
			if !tc.ok && h.Get("Authorization") != "" {
				t.Errorf("a header was set from a refused response: %v", h)
			}
		})
	}
}

func TestGitHubOIDC(t *testing.T) {
	f := newFakeAPI(t)
	good := GitHubOIDC{RequestURL: f.srv.URL + "/oidc?api-version=2.0", RequestToken: f.oidcToken}
	if jwt, err := good.Token(context.Background()); err != nil || jwt != "jwt-1" {
		t.Errorf("Token = %q, %v", jwt, err)
	}

	tests := []struct {
		name    string
		oidc    GitHubOIDC
		wantErr string
	}{
		{"no URL", GitHubOIDC{RequestToken: "x"}, "id-token: write"},
		{"no token", GitHubOIDC{RequestURL: f.srv.URL + "/oidc"}, "id-token: write"},
		{"a wrong request token", GitHubOIDC{RequestURL: good.RequestURL, RequestToken: "wrong"}, "HTTP 401"},
		{"plain http to a host: the runtime token is not sent", GitHubOIDC{RequestURL: "http://example.com/oidc", RequestToken: "x"}, "loopback"},
		{"not a URL", GitHubOIDC{RequestURL: "://", RequestToken: "x"}, "not a URL"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.oidc.Token(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Token error = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}

	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.invalid/token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runtime-token")
	if g := GitHubOIDCFromEnv(); g.RequestURL != "https://example.invalid/token" || g.RequestToken != "runtime-token" {
		t.Errorf("GitHubOIDCFromEnv = %+v", g)
	}
}

func TestGitHubOIDCResponses(t *testing.T) {
	tests := []struct {
		name   string
		status int
		header map[string]string
		body   string
		ok     bool
	}{
		{"a value", 200, nil, `{"value":"jwt"}`, true},
		{"no value", 200, nil, `{"count":1}`, false},
		{"not JSON", 200, nil, `jwt`, false},
		{"an assertion over 16 KiB", 200, nil, `{"value":"` + strings.Repeat("a", 16<<10+1) + `"}`, false},
		{"a server error", 500, nil, `{"value":"jwt"}`, false},
		{"a redirect is not followed", 302, map[string]string{"Location": "/elsewhere"}, ``, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			elsewhere := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/elsewhere" {
					elsewhere = true
					w.Write([]byte(`{"value":"jwt-from-elsewhere"}`))
					return
				}
				for k, v := range tc.header {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			jwt, err := GitHubOIDC{RequestURL: srv.URL + "/token", RequestToken: "x"}.Token(context.Background())
			if (err == nil) != tc.ok {
				t.Errorf("Token = %q, %v; want ok=%v", jwt, err, tc.ok)
			}
			if elsewhere {
				t.Error("the request token followed a redirect")
			}
		})
	}
}

func TestErrorSummary(t *testing.T) {
	tests := []struct {
		body        string
		wantType    string
		wantMessage string
	}{
		{`{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`, "overloaded_error", "Overloaded"},
		{`{"error":"invalid_grant","error_description":"assertion: eyJhbGciOi"}`, "invalid_grant", ""},
		{`{"error":{"type":"bad\ntype","message":"line one\nline two\u0007"}}`, "bad?type", "line one line two "},
		{`{"error":{"message":"` + strings.Repeat("m", 400) + `"}}`, "", strings.Repeat("m", 297) + "..."},
		{`not json`, "", ""},
		{`{"error":7}`, "", ""},
	}
	for _, tc := range tests {
		gotType, gotMessage := errorSummary([]byte(tc.body))
		if gotType != tc.wantType || gotMessage != tc.wantMessage {
			t.Errorf("errorSummary(%.40s) = %q, %q; want %q, %q", tc.body, gotType, gotMessage, tc.wantType, tc.wantMessage)
		}
	}
}

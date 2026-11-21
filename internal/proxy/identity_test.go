package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The proxy's JWTs come over a unix socket from the host helper, which
// alone holds the OIDC request token and asks only for the Claude
// audience.
func TestIdentitySocket(t *testing.T) {
	var mu sync.Mutex
	var auds []string
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer runtime-token" {
			http.Error(w, "no", 401)
			return
		}
		mu.Lock()
		auds = append(auds, r.URL.Query()["audience"]...)
		n := len(auds)
		mu.Unlock()
		fmt.Fprintf(w, `{"value":"jwt-%d"}`, n)
	}))
	defer gh.Close()

	dir, err := os.MkdirTemp("", "id")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	src := GitHubOIDC{RequestURL: gh.URL + "/?api-version=2.0&audience=evil", RequestToken: "runtime-token", Client: http.DefaultClient}.Token
	srv := &http.Server{Handler: IdentityHandler(src, 2, t.Logf)}
	go srv.Serve(ln)
	defer srv.Close()

	get := SocketIdentity(sock)
	for i := 1; i <= 2; i++ {
		jwt, err := get(context.Background())
		if err != nil || jwt != fmt.Sprintf("jwt-%d", i) {
			t.Fatalf("token %d: %q %v", i, jwt, err)
		}
	}
	// The cap, and a non-retryable error for it.
	_, err = get(context.Background())
	var he *httpError
	if !errors.As(err, &he) || he.status != http.StatusTooManyRequests {
		t.Errorf("over the cap: %v", err)
	}
	mu.Lock()
	if strings.Join(auds, ",") != DefaultAudience+","+DefaultAudience {
		t.Errorf("audiences requested: %v", auds)
	}
	mu.Unlock()

	// Only GET /token.
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	for _, r := range []struct{ m, p string }{{"POST", "/token"}, {"GET", "/token/x"}, {"GET", "/"}} {
		req, _ := http.NewRequest(r.m, "http://identity"+r.p, nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s = %d", r.m, r.p, resp.StatusCode)
		}
	}
}

func TestGitHubOIDCErrors(t *testing.T) {
	if _, err := (GitHubOIDC{Client: http.DefaultClient}).Token(context.Background()); err == nil {
		t.Error("no request URL accepted")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.invalid/steal", http.StatusFound)
	}))
	defer srv.Close()
	_, err := GitHubOIDC{RequestURL: srv.URL, RequestToken: "t", Client: http.DefaultClient}.Token(context.Background())
	var he *httpError
	if !errors.As(err, &he) || he.status != http.StatusFound {
		t.Errorf("redirect followed or misreported: %v", err)
	}
}

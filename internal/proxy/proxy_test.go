package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/fakeanthropic"
)

const model = "claude-opus-5-5"

// upstream is a fake Claude API: an OIDC endpoint, the token exchange and
// /v1/messages, recording what reached it.
type upstream struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	jwts      int
	exchanged []map[string]string
	exchHdr   []http.Header
	msgs      []*http.Request
	bodies    [][]byte
	ttl       int
	fail401   int // answer this many Messages requests with 401
	exchFail  int // fail this many exchanges with 503
}

func newUpstream(t *testing.T) *upstream {
	u := &upstream{t: t, ttl: 600}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oidc", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer req-token" || r.URL.Query().Get("audience") != DefaultAudience || r.URL.Query().Get("api-version") != "2.0" {
			http.Error(w, "bad oidc request", 401)
			return
		}
		u.mu.Lock()
		u.jwts++
		n := u.jwts
		u.mu.Unlock()
		fmt.Fprintf(w, `{"value":"jwt-%d"}`, n)
	})
	mux.HandleFunc("POST /v1/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		var b map[string]string
		json.NewDecoder(r.Body).Decode(&b)
		u.mu.Lock()
		defer u.mu.Unlock()
		u.exchanged = append(u.exchanged, b)
		u.exchHdr = append(u.exchHdr, r.Header.Clone())
		if u.exchFail > 0 {
			u.exchFail--
			http.Error(w, `{"type":"error","error":{"type":"overloaded_error","message":"busy"}}`, 503)
			return
		}
		fmt.Fprintf(w, `{"access_token":"sk-ant-oat01-%d","token_type":"Bearer","expires_in":%d,"scope":"workspace:inference"}`, len(u.exchanged), u.ttl)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.msgs = append(u.msgs, r)
		u.bodies = append(u.bodies, body)
		f := u.fail401 > 0
		if f {
			u.fail401--
		}
		u.mu.Unlock()
		if f {
			http.Error(w, `{"type":"error","error":{"type":"authentication_error","message":"expired"}}`, 401)
			return
		}
		if bytes.Contains(body, []byte(`"stream":true`)) {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":11,\"cache_read_input_tokens\":7,\"output_tokens\":1}}}\n\n")
			w.(http.Flusher).Flush()
			fmt.Fprint(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":42}}\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"type":"message","usage":{"input_tokens":5,"output_tokens":6}}`)
	})
	u.srv = httptest.NewServer(mux)
	t.Cleanup(u.srv.Close)
	return u
}

type logbuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logbuf) logf(f string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.b, f+"\n", a...)
}

func (l *logbuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func newProxy(t *testing.T, u *upstream, maxReq int64) (*Proxy, *TokenSource, *logbuf, *httptest.Server) {
	t.Helper()
	base, _ := url.Parse(u.srv.URL)
	lb := &logbuf{}
	ts, err := NewTokenSource(Federation{
		OIDCRequestURL:   u.srv.URL + "/oidc?api-version=2.0",
		OIDCRequestToken: "req-token",
		RuleID:           "fdrl_1",
		OrganizationID:   "org-1",
		WorkspaceID:      "wrkspc_1",
	}, base, http.DefaultClient, lb.logf)
	if err != nil {
		t.Fatal(err)
	}
	ts.backoff = time.Millisecond
	p, err := New(Config{Upstream: base, Model: model, MaxRequests: maxReq, Tokens: ts, Logf: lb.logf})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(p)
	t.Cleanup(front.Close)
	return p, ts, lb, front
}

func msgBody(extra string) string {
	return `{"model":"` + model + `","max_tokens":1,"stream":true,"messages":[{"role":"user","content":"hi"}]` + extra + `}`
}

func do(t *testing.T, method, url, body string, hdr map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestPathAllowlist(t *testing.T) {
	u := newUpstream(t)
	_, _, lb, front := newProxy(t, u, 0)
	for _, c := range []struct{ method, path string }{
		{"GET", "/v1/messages"},
		{"GET", "/v1/models"},
		{"POST", "/v1/messages/count_tokens"},
		{"POST", "/v1/messages/batches"},
		{"POST", "/v1/files"},
		{"POST", "/v1/oauth/token"},
		{"POST", "/v1/complete"},
		{"POST", "/v1/messages/"},
		{"POST", "/v1/messages?beta=false"},
		{"POST", "/v1/messages?beta=true&x=1"},
		{"POST", "/v1//messages"},
		{"POST", "/v1/messages/../models"},
		{"PUT", "/v1/messages"},
		{"DELETE", "/v1/messages"},
	} {
		st, body := do(t, c.method, front.URL+c.path, msgBody(""), nil)
		if st != http.StatusForbidden || !strings.Contains(body, "permission_error") {
			t.Errorf("%s %s = %d %s", c.method, c.path, st, body)
		}
	}
	for _, p := range []string{"/v1/messages", "/v1/messages?beta=true"} {
		if st, body := do(t, "POST", front.URL+p, msgBody(""), nil); st != 200 {
			t.Errorf("POST %s = %d %s", p, st, body)
		}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.msgs) != 2 {
		t.Fatalf("upstream saw %d requests, want 2", len(u.msgs))
	}
	if u.msgs[0].URL.RequestURI() != "/v1/messages" || u.msgs[1].URL.RequestURI() != "/v1/messages?beta=true" {
		t.Errorf("upstream paths %s %s", u.msgs[0].URL.RequestURI(), u.msgs[1].URL.RequestURI())
	}
	if !strings.Contains(lb.String(), "refused GET \"/v1/models\"") {
		t.Errorf("refusals not logged:\n%s", lb)
	}
}

func TestAbsoluteFormAndConnect(t *testing.T) {
	u := newUpstream(t)
	_, _, _, front := newProxy(t, u, 0)
	// A proxy-style absolute-form request: the authority is ignored, the
	// request goes to the configured upstream or nowhere.
	req, _ := http.NewRequest("POST", "http://example.invalid/v1/messages", strings.NewReader(msgBody("")))
	tr := &http.Transport{Proxy: func(*http.Request) (*url.URL, error) { return url.Parse(front.URL) }}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("absolute-form = %d", resp.StatusCode)
	}
	u.mu.Lock()
	if len(u.msgs) != 1 {
		t.Errorf("absolute-form request did not reach the upstream")
	}
	u.mu.Unlock()
	if st, _ := do(t, "CONNECT", front.URL, "", nil); st != http.StatusForbidden {
		t.Errorf("CONNECT = %d", st)
	}
}

func TestHeaders(t *testing.T) {
	u := newUpstream(t)
	_, _, lb, front := newProxy(t, u, 0)
	st, _ := do(t, "POST", front.URL+"/v1/messages?beta=true", msgBody(""), map[string]string{
		"Authorization":       "Bearer client-secret",
		"X-Api-Key":           "client-key",
		"Cookie":              "c=1",
		"Proxy-Authorization": "Basic x",
		"Anthropic-Beta":      "claude-code-20250219,context-management-2025-06-27",
		"Anthropic-Version":   "2023-06-01",
		"Anthropic-Dangerous-Direct-Browser-Access": "true",
		"Anthropic-Workspace-Id":                    "wrkspc_other",
		"X-Stainless-Retry-Count":                   "0",
		"X-Forwarded-For":                           "1.2.3.4",
		"X-Custom":                                  "x",
		"User-Agent":                                "claude-cli/2.1.329",
	})
	if st != 200 {
		t.Fatalf("status %d", st)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	h := u.msgs[0].Header
	if got := h.Get("Authorization"); got != "Bearer sk-ant-oat01-1" {
		t.Errorf("Authorization = %q", got)
	}
	if got := h.Get("Anthropic-Beta"); got != "claude-code-20250219,context-management-2025-06-27,"+oauthBeta {
		t.Errorf("Anthropic-Beta = %q", got)
	}
	for _, k := range []string{"X-Api-Key", "Cookie", "Proxy-Authorization", "Anthropic-Dangerous-Direct-Browser-Access", "Anthropic-Workspace-Id", "X-Forwarded-For", "X-Custom"} {
		if v := h.Values(k); len(v) > 0 {
			t.Errorf("%s reached the upstream: %q", k, v)
		}
	}
	for k, want := range map[string]string{"Anthropic-Version": "2023-06-01", "X-Stainless-Retry-Count": "0", "User-Agent": "claude-cli/2.1.329"} {
		if h.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, h.Get(k), want)
		}
	}
	if u.msgs[0].Host != strings.TrimPrefix(u.srv.URL, "http://") {
		t.Errorf("Host = %q", u.msgs[0].Host)
	}
	// The log has the path, status and usage; never a header or a token.
	log := lb.String()
	if !strings.Contains(log, "#1 POST /v1/messages 200 in=11 out=42 cache_read=7 cache_write=0") {
		t.Errorf("usage not logged:\n%s", log)
	}
	for _, secret := range []string{"client-secret", "client-key", "sk-ant-oat01", "req-token", "jwt-1", "hi"} {
		if strings.Contains(log, secret) {
			t.Errorf("log contains %q:\n%s", secret, log)
		}
	}
	// The exchange: the documented body and headers.
	ex := u.exchanged[0]
	want := map[string]string{"grant_type": grantJWTBearer, "assertion": "jwt-1", "federation_rule_id": "fdrl_1", "organization_id": "org-1", "workspace_id": "wrkspc_1"}
	if fmt.Sprint(ex) != fmt.Sprint(want) {
		t.Errorf("exchange body %v, want %v", ex, want)
	}
	if got := u.exchHdr[0].Get("Anthropic-Beta"); got != oauthBeta+","+federationBeta {
		t.Errorf("exchange beta %q", got)
	}
}

func TestBodyChecks(t *testing.T) {
	u := newUpstream(t)
	_, _, _, front := newProxy(t, u, 0)
	bad := map[string]string{
		"other model":     strings.Replace(msgBody(""), model, "claude-haiku-4-5", 1),
		"no model":        `{"max_tokens":1,"messages":[]}`,
		"not json":        `{"model":`,
		"server tool":     msgBody(`,"tools":[{"type":"web_fetch_20250910","name":"web_fetch"}]`),
		"search tool":     msgBody(`,"tools":[{"type":"web_search_20250305","name":"web_search"}]`),
		"mcp connector":   msgBody(`,"mcp_servers":[{"type":"url","url":"https://x.example/mcp","name":"x"}]`),
		"container":       msgBody(`,"container":"cntr_1"`),
		"url image":       `{"model":"` + model + `","messages":[{"role":"user","content":[{"type":"image","source":{"type":"url","url":"https://x.example/a.png"}}]}]}`,
		"file document":   `{"model":"` + model + `","messages":[{"role":"user","content":[{"type":"document","source":{"type":"file","file_id":"file_1"}}]}]}`,
		"nested url":      `{"model":"` + model + `","messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":[{"type":"image","source":{"type":"url","url":"https://x.example"}}]}]}]}`,
		"system url":      `{"model":"` + model + `","system":[{"type":"document","source":{"type":"url","url":"https://x.example"}}],"messages":[]}`,
		"container files": `{"model":"` + model + `","messages":[{"role":"user","content":[{"type":"container_upload","file_id":"f"}]}]}`,
	}
	for name, body := range bad {
		if st, resp := do(t, "POST", front.URL+"/v1/messages", body, nil); st != http.StatusForbidden {
			t.Errorf("%s: %d %s", name, st, resp)
		}
	}
	good := map[string]string{
		"custom tools":  msgBody(`,"tools":[{"name":"Read","input_schema":{"type":"object"}},{"name":"X","type":"custom","input_schema":{}},{"name":"D","defer_loading":true,"input_schema":{}}]`),
		"inline image":  `{"model":"` + model + `","messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AA=="}}]}]}`,
		"search result": `{"model":"` + model + `","messages":[{"role":"user","content":[{"type":"search_result","source":"https://x.example","title":"t","content":[]}]}]}`,
	}
	for name, body := range good {
		if st, resp := do(t, "POST", front.URL+"/v1/messages", body, nil); st != 200 {
			t.Errorf("%s: %d %s", name, st, resp)
		}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.msgs) != len(good) {
		t.Errorf("upstream saw %d requests, want %d", len(u.msgs), len(good))
	}
}

func TestBodyLimit(t *testing.T) {
	u := newUpstream(t)
	p, _, _, front := newProxy(t, u, 0)
	p.cfg.MaxBody = 1024
	if st, _ := do(t, "POST", front.URL+"/v1/messages", msgBody(`,"x":"`+strings.Repeat("a", 2048)+`"`), nil); st != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body = %d", st)
	}
}

func TestRequestCap(t *testing.T) {
	u := newUpstream(t)
	_, _, lb, front := newProxy(t, u, 3)
	// Refused requests do not use up the cap.
	do(t, "GET", front.URL+"/v1/models", "", nil)
	do(t, "POST", front.URL+"/v1/messages", strings.Replace(msgBody(""), model, "m", 1), nil)
	for i := 1; i <= 5; i++ {
		st, _ := do(t, "POST", front.URL+"/v1/messages", msgBody(""), nil)
		if want := map[bool]int{true: 200, false: 403}[i <= 3]; st != want {
			t.Errorf("request %d = %d, want %d", i, st, want)
		}
	}
	u.mu.Lock()
	n := len(u.msgs)
	u.mu.Unlock()
	if n != 3 {
		t.Errorf("upstream saw %d, want 3", n)
	}
	if !strings.Contains(lb.String(), "request cap of 3 reached") {
		t.Errorf("cap not logged:\n%s", lb)
	}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestRefreshBeforeExpiry(t *testing.T) {
	u := newUpstream(t)
	_, ts, _, front := newProxy(t, u, 0)
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	ts.now = clk.now

	auth := func() string {
		t.Helper()
		if st, _ := do(t, "POST", front.URL+"/v1/messages", msgBody(""), nil); st != 200 {
			t.Fatalf("status %d", st)
		}
		u.mu.Lock()
		defer u.mu.Unlock()
		return u.msgs[len(u.msgs)-1].Header.Get("Authorization")
	}
	if a := auth(); a != "Bearer sk-ant-oat01-1" {
		t.Fatalf("first: %s", a)
	}
	clk.add(400 * time.Second) // 200 s left: reuse
	if a := auth(); a != "Bearer sk-ant-oat01-1" {
		t.Errorf("at 200s left: %s", a)
	}
	clk.add(90 * time.Second) // 110 s left: inside the advisory window
	if a := auth(); a != "Bearer sk-ant-oat01-2" {
		t.Errorf("at 110s left: %s", a)
	}
	u.mu.Lock()
	jwts, ex := u.jwts, u.exchanged
	u.mu.Unlock()
	if jwts != 2 || ex[0]["assertion"] == ex[1]["assertion"] {
		t.Errorf("each exchange must use a fresh JWT: %d JWTs, %v", jwts, ex)
	}

	// A failing refresh keeps the current token while more than 30 s
	// remain, then fails.
	clk.add(500 * time.Second) // token 2 has 100 s left
	u.mu.Lock()
	u.exchFail = 100
	u.mu.Unlock()
	if a := auth(); a != "Bearer sk-ant-oat01-2" {
		t.Errorf("advisory failure should keep the token: %s", a)
	}
	clk.add(80 * time.Second) // 20 s left
	if st, body := do(t, "POST", front.URL+"/v1/messages", msgBody(""), nil); st != http.StatusBadGateway {
		t.Errorf("mandatory failure = %d %s", st, body)
	}
	u.mu.Lock()
	u.exchFail = 0
	u.mu.Unlock()
	if a := auth(); !strings.HasPrefix(a, "Bearer sk-ant-oat01-") || a == "Bearer sk-ant-oat01-2" {
		t.Errorf("recovered: %s", a)
	}
}

func TestExchangeRetriesWithFreshJWT(t *testing.T) {
	u := newUpstream(t)
	_, ts, _, _ := newProxy(t, u, 0)
	u.exchFail = 2
	tok, err := ts.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if tok != "sk-ant-oat01-3" || len(u.exchanged) != 3 {
		t.Fatalf("tok %s after %d exchanges", tok, len(u.exchanged))
	}
	seen := map[string]bool{}
	for _, e := range u.exchanged {
		if seen[e["assertion"]] {
			t.Errorf("assertion %s reused", e["assertion"])
		}
		seen[e["assertion"]] = true
	}
}

func TestRetryOn401(t *testing.T) {
	u := newUpstream(t)
	_, _, _, front := newProxy(t, u, 0)
	if st, _ := do(t, "POST", front.URL+"/v1/messages", msgBody(""), nil); st != 200 {
		t.Fatal(st)
	}
	u.mu.Lock()
	u.fail401 = 1
	u.mu.Unlock()
	if st, _ := do(t, "POST", front.URL+"/v1/messages", msgBody(""), nil); st != 200 {
		t.Fatalf("after one 401: %d", st)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	last := u.msgs[len(u.msgs)-1]
	if len(u.msgs) != 3 || last.Header.Get("Authorization") != "Bearer sk-ant-oat01-2" || !bytes.Equal(u.bodies[2], u.bodies[1]) {
		t.Errorf("retry: %d requests, auth %s", len(u.msgs), last.Header.Get("Authorization"))
	}
}

func TestTokenSourceConfig(t *testing.T) {
	base, _ := url.Parse("https://api.anthropic.com")
	for _, f := range []Federation{
		{OIDCRequestToken: "t", RuleID: "r", OrganizationID: "o"},
		{OIDCRequestURL: "u", RuleID: "r", OrganizationID: "o"},
		{OIDCRequestURL: "u", OIDCRequestToken: "t", OrganizationID: "o"},
		{OIDCRequestURL: "u", OIDCRequestToken: "t", RuleID: "r"},
	} {
		if _, err := NewTokenSource(f, base, http.DefaultClient, t.Logf); err == nil {
			t.Errorf("accepted %+v", f)
		}
	}
}

func TestExchangeErrorsRedacted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc" {
			fmt.Fprint(w, `{"value":"secret-jwt"}`)
			return
		}
		w.Header().Set("Request-Id", "req_1")
		w.WriteHeader(401)
		fmt.Fprint(w, `{"type":"error","error":{"type":"authentication_error","message":"Authentication failed"},"assertion":"secret-jwt"}`)
	}))
	defer srv.Close()
	base, _ := url.Parse(srv.URL)
	ts, _ := NewTokenSource(Federation{OIDCRequestURL: srv.URL + "/oidc", OIDCRequestToken: "t", RuleID: "r", OrganizationID: "o"}, base, http.DefaultClient, t.Logf)
	_, err := ts.Token(context.Background())
	if err == nil || strings.Contains(err.Error(), "secret-jwt") || !strings.Contains(err.Error(), "Authentication failed") || !strings.Contains(err.Error(), "req_1") {
		t.Errorf("err = %v", err)
	}
}

// The proxy in front of the strict fake used by the CI end-to-end test.
func TestAgainstFake(t *testing.T) {
	fake := &fakeanthropic.Server{Model: model, RuleID: "fdrl_1", OrganizationID: "org-1", Verdict: json.RawMessage(`{"verdict":"pass","flags":[],"summary":"s"}`), Logf: t.Logf}
	srv := httptest.NewServer(fake.Handler())
	defer srv.Close()
	base, _ := url.Parse(srv.URL)
	ts, err := NewTokenSource(Federation{OIDCRequestURL: srv.URL + "/oidc/token?api-version=2.0", OIDCRequestToken: fakeanthropic.OIDCRequestToken, RuleID: "fdrl_1", OrganizationID: "org-1"}, base, http.DefaultClient, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := New(Config{Upstream: base, Model: model, Tokens: ts, Logf: t.Logf})
	front := httptest.NewServer(p)
	defer front.Close()
	st, body := do(t, "POST", front.URL+"/v1/messages?beta=true", msgBody(""), map[string]string{"X-Api-Key": "placeholder"})
	if st != 200 || !strings.Contains(body, `"name":"Read"`) {
		t.Fatalf("%d %s (fake failures: %v)", st, body, fake.Failures)
	}
}

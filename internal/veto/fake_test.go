package veto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/config"
)

// fakeAPI stands in for the three services the package talks to: the
// Messages API, the Claude token exchange and GitHub's OIDC endpoint. It
// is strict about what it is sent, like the real ones: a request that is
// not exactly the shape this package is meant to send is answered with an
// error and fails the test.
type fakeAPI struct {
	t   *testing.T
	srv *httptest.Server
	// cfg is the embedded settings against the fake's own address.
	cfg Config
	// timeout is the request timeout testClient gives its client: the
	// settings count in whole seconds, and a test cannot wait that long.
	timeout time.Duration

	// reply scripts the Messages API: n counts requests from 0.
	reply func(n int, r recorded) reply
	// apiKey is the key the fake accepts in x-api-key.
	apiKey string
	// oidcToken is the request token the OIDC endpoint accepts.
	oidcToken string
	// tokenTTL is the expires_in of minted tokens, in seconds.
	tokenTTL float64
	// exchangeStatus, when it returns non-zero, fails exchange n (from 0).
	exchangeStatus func(n int) int
	// reject401 makes the Messages API refuse the first n valid requests
	// with a 401, as it would a token that had just been revoked.
	reject401 int

	mu        sync.Mutex
	requests  []recorded
	problems  []string
	jwts      int
	usedJWT   map[string]bool
	tokens    map[string]bool
	exchanges int
}

// recorded is one Messages request that passed the fake's checks.
type recorded struct {
	raw    []byte
	header http.Header
	system string
	user   string
}

// reply is what the fake answers one Messages request with.
type reply struct {
	status int
	header map[string]string
	body   string
	// hang makes the fake wait for the client to give up.
	hang bool
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{
		t:         t,
		apiKey:    "sk-ant-test-key",
		oidcToken: "oidc-request-token",
		tokenTTL:  600,
		usedJWT:   map[string]bool{},
		tokens:    map[string]bool{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/messages", f.messages)
	mux.HandleFunc("/v1/oauth/token", f.exchange)
	mux.HandleFunc("/oidc", f.oidc)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f.problem("request to unknown path %s", r.URL.Path)
		http.NotFound(w, r)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	t.Cleanup(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, p := range f.problems {
			t.Errorf("fake API: %s", p)
		}
	})
	f.cfg = FromConfig(embedded(t))
	f.cfg.BaseURL = f.srv.URL
	f.timeout = 5 * time.Second
	return f
}

// embedded is the gate's built-in settings, which is what the review job
// builds its client from.
func embedded(t *testing.T) config.Config {
	t.Helper()
	c, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fakeAPI) problem(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.problems = append(f.problems, fmt.Sprintf(format, args...))
}

func (f *fakeAPI) recordedRequests() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.requests...)
}

func apiError(w http.ResponseWriter, status int, errType, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Request-Id", "req_fake_error")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{ // a failed write is the client's to report
		"type":       "error",
		"error":      map[string]string{"type": errType, "message": message},
		"request_id": "req_fake_error",
	})
}

// authorized checks the credential of a Messages request: the API key in
// x-api-key, or a token this fake minted as a bearer credential together
// with the OAuth beta. Never both.
func (f *fakeAPI) authorized(r *http.Request) bool {
	key, bearer := r.Header.Get("X-Api-Key"), r.Header.Get("Authorization")
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case key != "" && bearer != "":
		return false
	case key != "":
		return key == f.apiKey
	case strings.HasPrefix(bearer, "Bearer "):
		return f.tokens[strings.TrimPrefix(bearer, "Bearer ")] && r.Header.Get("Anthropic-Beta") == "oauth-2025-04-20"
	}
	return false
}

// checkCommon checks what every API request must carry.
func (f *fakeAPI) checkCommon(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.Method != http.MethodPost:
		f.problem("%s: method %s", r.URL.Path, r.Method)
	case r.Header.Get("Anthropic-Version") != "2026-10-21":
		f.problem("%s: anthropic-version %q", r.URL.Path, r.Header.Get("Anthropic-Version"))
	case r.Header.Get("Content-Type") != "application/json":
		f.problem("%s: content-type %q", r.URL.Path, r.Header.Get("Content-Type"))
	case !f.authorized(r):
		// Not a problem by itself: some tests send a bad credential.
		apiError(w, http.StatusUnauthorized, "authentication_error", "invalid credential")
		return nil, false
	default:
		return body, true
	}
	apiError(w, http.StatusBadRequest, "invalid_request_error", "fake: malformed request")
	return nil, false
}

// wireRequest is the Messages request as the fake reads it, written out
// here and not shared with the package, so a field the package adds by
// mistake (tools, temperature, stream) is an unknown field.
type wireRequest struct {
	Model     string `json:"model"`
	MaxTokens int    `json:"max_tokens"`
	System    string `json:"system"`
	Thinking  struct {
		Type string `json:"type"`
	} `json:"thinking"`
	OutputConfig struct {
		Effort string `json:"effort"`
		Format struct {
			Type   string          `json:"type"`
			Schema json.RawMessage `json:"schema"`
		} `json:"format"`
	} `json:"output_config"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
}

func (f *fakeAPI) messages(w http.ResponseWriter, r *http.Request) {
	body, ok := f.checkCommon(w, r)
	if !ok {
		return
	}
	var keys map[string]json.RawMessage
	_ = json.Unmarshal(body, &keys) // a body that is not JSON is reported by the strict decode below
	var names []string
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	var req wireRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	err := dec.Decode(&req)
	bad := ""
	switch {
	case err != nil:
		bad = "body: " + err.Error()
	case strings.Join(names, ",") != "max_tokens,messages,model,output_config,system,thinking":
		bad = "top-level keys are " + strings.Join(names, ",")
	case req.Model != f.cfg.conf.Model:
		bad = "model " + req.Model
	case req.MaxTokens != f.cfg.conf.MaxOutputTokens:
		bad = fmt.Sprintf("max_tokens %d", req.MaxTokens)
	case req.Thinking.Type != "adaptive":
		bad = "thinking " + req.Thinking.Type
	case req.OutputConfig.Effort != f.cfg.conf.Effort:
		bad = "effort " + req.OutputConfig.Effort
	case req.OutputConfig.Format.Type != "json_schema" || len(req.OutputConfig.Format.Schema) == 0:
		bad = "output_config.format is not a json_schema"
	case len(req.Messages) != 1 || req.Messages[0].Role != "user" || req.Messages[0].Content == "":
		bad = "messages is not one user turn"
	case req.System == "":
		bad = "no system prompt"
	}
	if bad != "" {
		f.problem("messages: %s", bad)
		apiError(w, http.StatusBadRequest, "invalid_request_error", "fake: "+bad)
		return
	}

	f.mu.Lock()
	if f.reject401 > 0 {
		f.reject401--
		f.mu.Unlock()
		apiError(w, http.StatusUnauthorized, "authentication_error", "token revoked")
		return
	}
	n := len(f.requests)
	rec := recorded{raw: body, header: r.Header.Clone(), system: req.System, user: req.Messages[0].Content}
	f.requests = append(f.requests, rec)
	f.mu.Unlock()

	rep := reply{status: http.StatusOK, body: okMessage(answerJSON("no_veto", nil, ""))}
	if f.reply != nil {
		rep = f.reply(n, rec)
	}
	if rep.hang {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
			f.problem("messages: the client never gave up on a hanging request")
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Request-Id", fmt.Sprintf("req_fake_%d", n))
	for k, v := range rep.header {
		w.Header().Set(k, v)
	}
	if rep.status == 0 {
		rep.status = http.StatusOK
	}
	w.WriteHeader(rep.status)
	_, _ = io.WriteString(w, rep.body) // a failed write is the client's to report
}

// oidc is GitHub's token endpoint: a fresh JWT per call, for the one
// audience, to whoever holds the request token.
func (f *fakeAPI) oidc(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method != http.MethodGet:
		f.problem("oidc: method %s", r.Method)
	case r.Header.Get("Authorization") != "Bearer "+f.oidcToken:
		http.Error(w, "bad request token", http.StatusUnauthorized)
		return
	case r.URL.Query().Get("audience") != "https://api.anthropic.com":
		f.problem("oidc: audience %q", r.URL.Query().Get("audience"))
	case r.URL.Query().Get("api-version") != "2.0":
		f.problem("oidc: the request URL's own query was lost: %q", r.URL.RawQuery)
	default:
		f.mu.Lock()
		f.jwts++
		jwt := fmt.Sprintf("jwt-%d", f.jwts)
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"value": jwt}) // a failed write is the client's to report
		return
	}
	http.Error(w, "bad request", http.StatusBadRequest)
}

// exchange is the Claude token exchange. Like the real one it accepts an
// assertion once.
func (f *fakeAPI) exchange(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]string
	bad := ""
	switch {
	case r.Method != http.MethodPost:
		bad = "method " + r.Method
	case r.Header.Get("Content-Type") != "application/json":
		bad = "content-type " + r.Header.Get("Content-Type")
	case r.Header.Get("Anthropic-Beta") != "oauth-2025-04-20,oidc-federation-2026-04-01":
		bad = "anthropic-beta " + r.Header.Get("Anthropic-Beta")
	case r.Header.Get("Authorization") != "" || r.Header.Get("X-Api-Key") != "":
		bad = "the exchange carried a credential"
	case json.Unmarshal(raw, &body) != nil:
		bad = "body is not a JSON object of strings"
	case body["grant_type"] != "urn:ietf:params:oauth:grant-type:jwt-bearer":
		bad = "grant_type " + body["grant_type"]
	case body["federation_rule_id"] != "fdrl_test" || body["organization_id"] != "org-uuid":
		bad = "rule or organization"
	case body["workspace_id"] != "wrkspc_test":
		bad = "workspace_id " + body["workspace_id"]
	case len(body) != 5:
		bad = fmt.Sprintf("%d members in the body", len(body))
	}
	if bad != "" {
		f.problem("exchange: %s", bad)
		apiError(w, http.StatusBadRequest, "invalid_request_error", "fake: "+bad)
		return
	}
	f.mu.Lock()
	n := f.exchanges
	f.exchanges++
	reused := f.usedJWT[body["assertion"]]
	f.usedJWT[body["assertion"]] = true
	f.mu.Unlock()
	if f.exchangeStatus != nil {
		if status := f.exchangeStatus(n); status != 0 {
			// The body echoes the assertion outside the error's type and
			// message, as a careless server might.
			w.Header().Set("Request-Id", "req_fake_exchange")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{ // a failed write is the client's to report
				"type":    "error",
				"error":   map[string]string{"type": "api_error", "message": "exchange failed", "assertion": body["assertion"]},
				"request": body,
			})
			return
		}
	}
	if reused {
		f.problem("exchange: assertion %s was used twice", body["assertion"])
		apiError(w, http.StatusBadRequest, "invalid_grant", "assertion already used")
		return
	}
	f.mu.Lock()
	tok := fmt.Sprintf("tok-%d", len(f.tokens)+1)
	f.tokens[tok] = true
	f.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": f.tokenTTL}) // a failed write is the client's to report
}

// block is one content block of a response.
type block map[string]any

func textBlock(s string) block { return block{"type": "text", "text": s} }

// thinkingBlock is what a real response starts with: thinking is always
// on for the default model, and its text is empty by default.
func thinkingBlock() block {
	return block{"type": "thinking", "thinking": "", "signature": "c2lnbmF0dXJl"}
}

// messageJSON is a Messages response.
func messageJSON(stop string, details any, blocks ...block) string {
	if blocks == nil {
		blocks = []block{}
	}
	b, err := json.Marshal(map[string]any{
		"id":            "msg_fake",
		"type":          "message",
		"role":          "assistant",
		"model":         "claude-opus-5-5",
		"content":       blocks,
		"stop_reason":   stop,
		"stop_sequence": nil,
		"stop_details":  details,
		"usage":         map[string]int{"input_tokens": 1234, "output_tokens": 56},
	})
	if err != nil {
		panic(err)
	}
	return string(b)
}

// okMessage is a normal response whose text block is text: a thinking
// block first, as the API sends it.
func okMessage(text string) string {
	return messageJSON("end_turn", nil, thinkingBlock(), textBlock(text))
}

// answerJSON is the answer object the schema describes.
func answerJSON(verdict string, quotes []string, notes string) string {
	if quotes == nil {
		quotes = []string{}
	}
	b, err := json.Marshal(map[string]any{"verdict": verdict, "quotes": quotes, "notes": notes})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func ok(text string) reply { return reply{status: http.StatusOK, body: okMessage(text)} }

func httpError(status int, errType string) reply {
	b, _ := json.Marshal(map[string]any{"type": "error", "error": map[string]string{"type": errType, "message": "fake " + errType}})
	return reply{status: status, body: string(b)}
}

// testClient returns a Client against the fake that never really sleeps
// between attempts, and the waits it was asked for.
func testClient(t *testing.T, f *fakeAPI, creds Credentials) (*Client, *[]time.Duration) {
	t.Helper()
	c, err := New(f.cfg, creds, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.timeout = f.timeout
	var waits []time.Duration
	c.sleep = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	return c, &waits
}

// prepared is a read of the given chunks, full unless unread files are
// added by the caller.
func prepared(chunks ...string) artifact.Prepared {
	p := artifact.Prepared{
		Pair:  artifact.Pair{Ecosystem: allow.GoModules, Name: "example.com/mod", From: "v1.0.0", To: "v1.0.1"},
		State: allow.ReadFull,
	}
	h := sha256.New()
	for i, c := range chunks {
		p.Chunks = append(p.Chunks, artifact.Chunk{Index: i, Text: c})
		h.Write([]byte(c))
		h.Write([]byte{0})
	}
	p.Key = hex.EncodeToString(h.Sum(nil))
	return p
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

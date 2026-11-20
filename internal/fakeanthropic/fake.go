// Package fakeanthropic is a stand-in for the three services the review
// sandbox talks to, for tests only: GitHub's OIDC token endpoint, the
// Claude token exchange and enough of the streaming Messages API for the
// Claude Code CLI to run a short scripted review.
//
// It is strict on purpose: it answers 401 to any Messages request that
// does not carry a token it minted (an API key, a reused token, the
// client's own Authorization), refuses a reused OIDC assertion like the
// real exchange does, and fails the scripted conversation unless the
// reviewer really read the evidence and grepped the repository. A test
// that gets the canned verdict back has therefore also shown that the
// proxy injected the credential and the sandbox's file tools worked.
package fakeanthropic

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// OIDCRequestToken is what the fake OIDC endpoint expects as
// ACTIONS_ID_TOKEN_REQUEST_TOKEN.
const OIDCRequestToken = "fake-oidc-request-token"

// Marker must appear in the evidence file and in a file of the repository
// for the scripted review to reach its verdict.
const Marker = "dep-review-e2e-marker"

type Server struct {
	Model          string
	RuleID         string
	OrganizationID string
	Verdict        json.RawMessage // StructuredOutput input the script returns
	TokenTTL       time.Duration   // default 10 minutes
	Logf           func(string, ...any)
	RecordDir      string // if set, every Messages request body is written here

	mu       sync.Mutex
	jwts     int
	used     map[string]bool // exchanged assertions
	tokens   map[string]time.Time
	minted   int
	toolN    int
	Stats    Stats
	Failures []string
}

type Stats struct {
	OIDC      int `json:"oidc"`
	Exchanges int `json:"exchanges"`
	Messages  int `json:"messages"`
	Rejected  int `json:"rejected"`
}

func (s *Server) logf(format string, a ...any) {
	if s.Logf != nil {
		s.Logf(format, a...)
	} else {
		log.Printf(format, a...)
	}
}

func (s *Server) fail(w http.ResponseWriter, status int, why string) {
	s.mu.Lock()
	s.Stats.Rejected++
	s.Failures = append(s.Failures, why)
	s.mu.Unlock()
	s.logf("fake: REJECT %d: %s", status, why)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Should-Retry", "false")
	w.WriteHeader(status)
	b, _ := json.Marshal(map[string]any{"type": "error", "error": map[string]string{"type": "invalid_request_error", "message": "fake: " + why}})
	w.Write(b)
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oidc/token", s.oidc)
	mux.HandleFunc("POST /v1/oauth/token", s.exchange)
	mux.HandleFunc("POST /v1/messages", s.messages)
	mux.HandleFunc("GET /_stats", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"stats": s.Stats, "failures": s.Failures})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.fail(w, http.StatusNotFound, fmt.Sprintf("unexpected %s %s", r.Method, r.URL.Path))
	})
	return mux
}

func (s *Server) oidc(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+OIDCRequestToken {
		s.fail(w, http.StatusUnauthorized, "oidc: bad request token")
		return
	}
	if r.URL.Query().Get("audience") != "https://api.anthropic.com" {
		s.fail(w, http.StatusBadRequest, "oidc: audience "+r.URL.Query().Get("audience"))
		return
	}
	s.mu.Lock()
	s.jwts++
	s.Stats.OIDC++
	jwt := fmt.Sprintf("fake-jwt-%d", s.jwts)
	s.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]string{"value": jwt})
}

func (s *Server) exchange(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(r.Header.Get("Anthropic-Beta"), "oidc-federation-2026-04-01") {
		s.fail(w, http.StatusBadRequest, "exchange: no federation beta header")
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		s.fail(w, http.StatusBadRequest, "exchange: not JSON")
		return
	}
	var b map[string]string
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&b); err != nil {
		s.fail(w, http.StatusBadRequest, "exchange: body")
		return
	}
	switch {
	case b["grant_type"] != "urn:ietf:params:oauth:grant-type:jwt-bearer":
		s.fail(w, http.StatusBadRequest, "exchange: grant_type")
		return
	case b["federation_rule_id"] != s.RuleID || b["organization_id"] != s.OrganizationID:
		s.fail(w, http.StatusUnauthorized, "exchange: rule or organization")
		return
	case !strings.HasPrefix(b["assertion"], "fake-jwt-"):
		s.fail(w, http.StatusUnauthorized, "exchange: assertion")
		return
	}
	ttl := s.TokenTTL
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	s.mu.Lock()
	if s.used == nil {
		s.used, s.tokens = map[string]bool{}, map[string]time.Time{}
	}
	if s.used[b["assertion"]] {
		s.mu.Unlock()
		s.fail(w, http.StatusUnauthorized, "exchange: jti_reused")
		return
	}
	s.used[b["assertion"]] = true
	s.minted++
	s.Stats.Exchanges++
	tok := fmt.Sprintf("sk-ant-oat01-fake-%d", s.minted)
	s.tokens[tok] = time.Now().Add(ttl)
	s.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": int(ttl.Seconds()), "scope": "workspace:inference"})
}

type block struct {
	Type      string          `json:"type"`
	Name      string          `json:"name"`
	Content   json.RawMessage `json:"content"`
	IsError   bool            `json:"is_error"`
	ToolUseID string          `json:"tool_use_id"`
}

type message struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

func (s *Server) messages(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(auth, "Bearer ")
	s.mu.Lock()
	exp, known := s.tokens[tok]
	s.mu.Unlock()
	switch {
	case r.Header.Get("X-Api-Key") != "":
		s.fail(w, http.StatusUnauthorized, "messages: client x-api-key reached upstream")
		return
	case !ok || !known:
		s.fail(w, http.StatusUnauthorized, "messages: token not minted by the exchange")
		return
	case time.Now().After(exp):
		s.fail(w, http.StatusUnauthorized, "messages: token expired")
		return
	case !strings.Contains(r.Header.Get("Anthropic-Beta"), "oauth-2025-04-20"):
		s.fail(w, http.StatusBadRequest, "messages: no oauth beta header")
		return
	}
	var req struct {
		Model    string    `json:"model"`
		Stream   bool      `json:"stream"`
		Messages []message `json:"messages"`
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil || json.Unmarshal(raw, &req) != nil {
		s.fail(w, http.StatusBadRequest, "messages: body")
		return
	}
	if s.RecordDir != "" {
		s.mu.Lock()
		n := s.Stats.Messages + 1
		s.mu.Unlock()
		os.WriteFile(filepath.Join(s.RecordDir, fmt.Sprintf("messages-%03d.json", n)), raw, 0o644)
		h, _ := json.Marshal(map[string][]string{"Anthropic-Beta": r.Header.Values("Anthropic-Beta"), "Anthropic-Version": r.Header.Values("Anthropic-Version"), "Accept": r.Header.Values("Accept"), "Content-Type": r.Header.Values("Content-Type")})
		os.WriteFile(filepath.Join(s.RecordDir, fmt.Sprintf("messages-%03d.headers.json", n)), h, 0o644)
	}
	if req.Model != s.Model {
		s.fail(w, http.StatusBadRequest, "messages: model "+req.Model)
		return
	}
	s.mu.Lock()
	s.Stats.Messages++
	s.mu.Unlock()

	// Where are we in the script? Every step is one tool call; the CLI
	// sends the whole conversation each time, so the number of tool_use
	// blocks so far is the step, and the result of the previous call is
	// checked before the next one is made.
	var uses []string // tool_use IDs in order
	results := map[string]block{}
	for _, m := range req.Messages {
		for _, raw := range rawBlocks(m.Content) {
			var b struct {
				Type      string          `json:"type"`
				ID        string          `json:"id"`
				ToolUseID string          `json:"tool_use_id"`
				IsError   bool            `json:"is_error"`
				Content   json.RawMessage `json:"content"`
			}
			if json.Unmarshal(raw, &b) != nil {
				continue
			}
			switch b.Type {
			case "tool_use":
				uses = append(uses, b.ID)
			case "tool_result":
				results[b.ToolUseID] = block{Type: b.Type, ToolUseID: b.ToolUseID, IsError: b.IsError, Content: b.Content}
			}
		}
	}
	step := len(uses)
	if step > 0 && step <= len(script) {
		prev := script[step-1]
		res, ok := results[uses[step-1]]
		if !ok {
			s.fail(w, http.StatusBadRequest, fmt.Sprintf("script: no result for step %d (%s)", step, prev.tool))
			return
		}
		if err := prev.expect(res); err != nil {
			s.fail(w, http.StatusBadRequest, fmt.Sprintf("script: step %d (%s): %v: %.300s", step, prev.tool, err, res.Content))
			return
		}
	}
	if step < len(script) {
		st := script[step]
		input := st.input
		if st.tool == "StructuredOutput" {
			var v map[string]any
			json.Unmarshal(s.Verdict, &v)
			input = v
		}
		s.toolUse(w, req.Model, st.tool, input)
		return
	}
	s.text(w, req.Model, "Review complete.")
}

type scriptStep struct {
	tool   string
	input  map[string]any
	expect func(block) error
}

func hasMarker(b block) error {
	if b.IsError || !strings.Contains(string(b.Content), Marker) {
		return fmt.Errorf("want the marker, got is_error=%v", b.IsError)
	}
	return nil
}

func denied(b block) error {
	if !b.IsError {
		return errors.New("want a permission denial, the read succeeded")
	}
	// The e2e puts the marker in .git/config; /proc/self/environ would show
	// the ANTHROPIC_ variables.
	if strings.Contains(string(b.Content), Marker) || strings.Contains(string(b.Content), "ANTHROPIC_BASE_URL=") {
		return errors.New("the denial leaked file content")
	}
	return nil
}

// The scripted review: read the evidence, search the repository, try two
// reads the settings deny (the process environment, and .git inside the
// working directory), then answer.
var script = []scriptStep{
	{"Read", map[string]any{"file_path": "/work/evidence/evidence.json"}, hasMarker},
	{"Grep", map[string]any{"pattern": Marker, "path": "/work/repo", "output_mode": "content"}, hasMarker},
	{"Read", map[string]any{"file_path": "/proc/self/environ"}, denied},
	// Inside the working directory, so only the settings' deny rule
	// (Read(./repo/.git/**)) refuses it: proof the settings are in force.
	{"Read", map[string]any{"file_path": "/work/repo/.git/config"}, denied},
	{"StructuredOutput", nil, func(b block) error {
		if b.IsError {
			return errors.New("the CLI rejected the structured output")
		}
		return nil
	}},
}

func rawBlocks(raw json.RawMessage) []json.RawMessage {
	var bs []json.RawMessage
	if json.Unmarshal(raw, &bs) != nil {
		return nil
	}
	return bs
}

func (s *Server) stream(w http.ResponseWriter, model, stop string, start map[string]any, delta map[string]any) {
	s.logf("fake: messages -> %s %v", stop, start["name"])
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Request-Id", "req_fake")
	msg := map[string]any{"id": "msg_fake", "type": "message", "role": "assistant", "model": model, "content": []any{},
		"stop_reason": nil, "stop_sequence": nil, "usage": map[string]any{"input_tokens": 100, "output_tokens": 1}}
	// Like a real turn with adaptive thinking (display omitted): a thinking
	// block with only a signature, a short text, then the answer block, so
	// the CLI replays all three kinds in its next request.
	events := []map[string]any{
		{"type": "message_start", "message": msg},
		{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "thinking", "thinking": "", "signature": ""}},
		{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "signature_delta", "signature": "ZmFrZS1zaWduYXR1cmU="}},
		{"type": "content_block_stop", "index": 0},
		{"type": "content_block_start", "index": 1, "content_block": map[string]any{"type": "text", "text": ""}},
		{"type": "content_block_delta", "index": 1, "delta": map[string]any{"type": "text_delta", "text": "Checking."}},
		{"type": "content_block_stop", "index": 1},
		{"type": "content_block_start", "index": 2, "content_block": start},
		{"type": "content_block_delta", "index": 2, "delta": delta},
		{"type": "content_block_stop", "index": 2},
		{"type": "message_delta", "delta": map[string]any{"stop_reason": stop, "stop_sequence": nil}, "usage": map[string]any{"output_tokens": 20}},
		{"type": "message_stop"},
	}
	fl, _ := w.(http.Flusher)
	for _, e := range events {
		b, _ := json.Marshal(e)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e["type"], b)
		if fl != nil {
			fl.Flush()
		}
	}
}

func (s *Server) toolUse(w http.ResponseWriter, model, name string, input any) {
	in, _ := json.Marshal(input)
	s.mu.Lock()
	s.toolN++
	id := fmt.Sprintf("toolu_fake%04d", s.toolN)
	s.mu.Unlock()
	s.stream(w, model, "tool_use",
		map[string]any{"type": "tool_use", "id": id, "name": name, "input": map[string]any{}},
		map[string]any{"type": "input_json_delta", "partial_json": string(in)})
}

func (s *Server) text(w http.ResponseWriter, model, text string) {
	s.stream(w, model, "end_turn",
		map[string]any{"type": "text", "text": ""},
		map[string]any{"type": "text_delta", "text": text})
}

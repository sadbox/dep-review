package proxy

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

// A real request from Claude Code 2.1.329 (recorded by the CI end-to-end
// run's fake upstream: --tools Read,Grep,Glob, --json-schema, after four
// tool calls) passes as is.
func TestRecordedRequestPasses(t *testing.T) {
	raw, err := os.ReadFile("testdata/claude-code-request.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := checkBody(raw, model); err != nil {
		t.Fatalf("recorded CLI request refused: %v", err)
	}
	u := newUpstream(t)
	_, _, lb, front := newProxy(t, u, 0)
	st, body := do(t, "POST", front.URL+"/v1/messages?beta=true", string(raw), map[string]string{
		"Anthropic-Beta": "claude-code-20250219,interleaved-thinking-2025-05-14,context-management-2025-06-27,per-turn-control-2026-07-01,mid-conversation-tool-changes-2026-07-01,thinking-token-count-2026-05-13,effort-2025-11-24",
	})
	if st != 200 {
		t.Fatalf("%d %s", st, body)
	}
	if strings.Contains(lb.String(), "dropped") || strings.Contains(lb.String(), "refused") {
		t.Errorf("the CLI's own betas were dropped:\n%s", lb)
	}
}

// mutate applies f to the recorded request and returns the new body.
func mutate(t *testing.T, f func(m map[string]any)) string {
	t.Helper()
	raw, err := os.ReadFile("testdata/claude-code-request.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	b, _ := json.Marshal(m)
	return string(b)
}

func lastUser(m map[string]any) map[string]any {
	msgs := m["messages"].([]any)
	return msgs[len(msgs)-1].(map[string]any)
}

func TestBodyAllowlist(t *testing.T) {
	addTool := func(tool map[string]any) func(map[string]any) {
		return func(m map[string]any) { m["tools"] = append(m["tools"].([]any), tool) }
	}
	addBlock := func(b map[string]any) func(map[string]any) {
		return func(m map[string]any) {
			u := lastUser(m)
			u["content"] = append(u["content"].([]any), b)
		}
	}
	cases := map[string]func(map[string]any){
		"web_fetch tool":      addTool(map[string]any{"type": "web_fetch_20250910", "name": "web_fetch"}),
		"web_search tool":     addTool(map[string]any{"type": "web_search_20250305", "name": "web_search"}),
		"code execution":      addTool(map[string]any{"type": "code_execution_20250825", "name": "code_execution"}),
		"bash tool":           addTool(map[string]any{"type": "bash_20250124", "name": "bash"}),
		"text editor":         addTool(map[string]any{"type": "text_editor_20250728", "name": "str_replace_based_edit_tool"}),
		"computer":            addTool(map[string]any{"type": "computer_20250124", "name": "computer", "display_width_px": 1}),
		"memory":              addTool(map[string]any{"type": "memory_20250818", "name": "memory"}),
		"tool search":         addTool(map[string]any{"type": "tool_search_tool_regex_20251119", "name": "tool_search"}),
		"mcp toolset":         addTool(map[string]any{"type": "mcp_toolset", "mcp_server_name": "x"}),
		"unknown tool type":   addTool(map[string]any{"type": "frobnicate", "name": "f", "input_schema": map[string]any{}}),
		"custom with extras":  addTool(map[string]any{"name": "f", "input_schema": map[string]any{}, "allowed_callers": []any{"code_execution_20250825"}}),
		"tool without schema": addTool(map[string]any{"name": "f"}),
		"mcp_servers": func(m map[string]any) {
			m["mcp_servers"] = []any{map[string]any{"type": "url", "url": "https://x.example/mcp", "name": "x"}}
		},
		"container":            func(m map[string]any) { m["container"] = "cntr_1" },
		"unknown top level":    func(m map[string]any) { m["frobnicate"] = true },
		"temperature":          func(m map[string]any) { m["temperature"] = 0 },
		"other model":          func(m map[string]any) { m["model"] = "claude-haiku-4-5" },
		"tool_choice unknown":  func(m map[string]any) { m["tool_choice"] = map[string]any{"type": "tool", "name": "web_fetch"} },
		"tool_choice bad type": func(m map[string]any) { m["tool_choice"] = map[string]any{"type": "server"} },
		"output_config format": func(m map[string]any) { m["output_config"].(map[string]any)["format"] = map[string]any{} },
		"metadata extra":       func(m map[string]any) { m["metadata"].(map[string]any)["x"] = 1 },
		"context edit": func(m map[string]any) {
			m["context_management"] = map[string]any{"edits": []any{map[string]any{"type": "fetch_url"}}}
		},
		"url image":           addBlock(map[string]any{"type": "image", "source": map[string]any{"type": "url", "url": "https://x.example/a.png"}}),
		"file document":       addBlock(map[string]any{"type": "document", "source": map[string]any{"type": "file", "file_id": "file_1"}}),
		"search_result":       addBlock(map[string]any{"type": "search_result", "source": "https://x.example", "title": "t", "content": []any{}}),
		"container_upload":    addBlock(map[string]any{"type": "container_upload", "file_id": "f"}),
		"server_tool_use":     addBlock(map[string]any{"type": "server_tool_use", "id": "s", "name": "web_fetch", "input": map[string]any{"url": "https://x.example"}}),
		"text with citations": addBlock(map[string]any{"type": "text", "text": "x", "citations": []any{}}),
		"unknown block in tool_result": addBlock(map[string]any{"type": "tool_result", "tool_use_id": "t",
			"content": []any{map[string]any{"type": "web_fetch_result", "url": "https://x.example"}}}),
		"url image in tool_result": addBlock(map[string]any{"type": "tool_result", "tool_use_id": "t",
			"content": []any{map[string]any{"type": "image", "source": map[string]any{"type": "url", "url": "https://x.example"}}}}),
		"tool_use in tool_result": addBlock(map[string]any{"type": "tool_result", "tool_use_id": "t",
			"content": []any{map[string]any{"type": "tool_use", "id": "x", "name": "Read", "input": map[string]any{}}}}),
		"system document": func(m map[string]any) {
			m["system"] = append(m["system"].([]any), map[string]any{"type": "document", "source": map[string]any{"type": "url", "url": "https://x.example"}})
		},
		"message extra field": func(m map[string]any) { lastUser(m)["cache"] = true },
		"developer role":      func(m map[string]any) { lastUser(m)["role"] = "developer" },
		"system msg tool_use": func(m map[string]any) {
			m["messages"] = append(m["messages"].([]any), map[string]any{"role": "system", "content": []any{map[string]any{"type": "tool_use", "id": "x", "name": "Read", "input": map[string]any{}}}})
		},
	}
	for name, f := range cases {
		if err := checkBody([]byte(mutate(t, f)), model); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := map[string]func(map[string]any){
		"tool_choice auto": func(m map[string]any) { m["tool_choice"] = map[string]any{"type": "auto"} },
		"tool_choice Read": func(m map[string]any) { m["tool_choice"] = map[string]any{"type": "tool", "name": "StructuredOutput"} },
		"inline image":     addBlock(map[string]any{"type": "image", "source": map[string]any{"type": "base64", "media_type": "image/png", "data": "AA=="}}),
		"thinking replay": func(m map[string]any) {
			m["messages"] = append(m["messages"].([]any), map[string]any{"role": "assistant", "content": []any{map[string]any{"type": "thinking", "thinking": "", "signature": "sig"}, map[string]any{"type": "redacted_thinking", "data": "x"}}})
		},
		"tool_result blocks": addBlock(map[string]any{"type": "tool_result", "tool_use_id": "t", "is_error": true, "content": []any{map[string]any{"type": "text", "text": "x"}}}),
	}
	for name, f := range ok {
		if err := checkBody([]byte(mutate(t, f)), model); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}

func TestStrictJSON(t *testing.T) {
	bad := map[string]string{
		"duplicate tools":       `{"model":"m","tools":[],"messages":[],"tools":[{"type":"web_fetch_20250910","name":"web_fetch"}]}`,
		"duplicate model":       `{"model":"x","model":"m","messages":[]}`,
		"duplicate deep":        `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"a","type":"image"}]}]}`,
		"duplicate in input":    `{"model":"m","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"Read","input":{"a":1,"a":2}}]}]}`,
		"trailing object":       `{"model":"m","messages":[]}{"model":"x"}`,
		"trailing garbage":      `{"model":"m","messages":[]} x`,
		"truncated":             `{"model":"m","messages":[`,
		"empty":                 ``,
		"not an object":         `["model"]`,
		"escaped duplicate key": `{"model":"m","messages":[],"tools":[],"tools":[{"type":"bash_20250124","name":"bash"}]}`,
	}
	for name, b := range bad {
		if err := checkBody([]byte(b), "m"); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if strings.Contains(name, "duplicate") {
			if err := strictJSON([]byte(b)); err == nil || !strings.Contains(err.Error(), "duplicate key") {
				t.Errorf("%s: strictJSON = %v", name, err)
			}
		}
	}
	for _, b := range []string{`{"model":"m","messages":[]}`, " {\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"{}\"}]}],\"metadata\":{}}\n"} {
		if err := checkBody([]byte(b), "m"); err != nil {
			t.Errorf("%q: %v", b, err)
		}
	}
	// Same key in sibling objects is fine.
	if err := strictJSON([]byte(`{"a":{"x":1},"b":{"x":2},"c":[{"x":1},{"x":2}]}`)); err != nil {
		t.Error(err)
	}
}

func TestHeaderAllowlist(t *testing.T) {
	u := newUpstream(t)
	_, _, lb, front := newProxy(t, u, 0)
	if st, _ := do(t, "POST", front.URL+"/v1/messages", msgBody(""), map[string]string{"Anthropic-Version": "2099-01-01"}); st != http.StatusForbidden {
		t.Errorf("other anthropic-version = %d", st)
	}
	st, _ := do(t, "POST", front.URL+"/v1/messages", msgBody(""), map[string]string{"Anthropic-Beta": "code-execution-2025-08-25,skills-2025-10-02"})
	if st != 200 {
		t.Fatalf("status %d", st)
	}
	u.mu.Lock()
	got := u.msgs[0].Header.Get("Anthropic-Beta")
	u.mu.Unlock()
	if got != oauthBeta {
		t.Errorf("non-allowlisted betas forwarded: %q", got)
	}
	if !strings.Contains(lb.String(), "dropped anthropic-beta code-execution-2025-08-25,skills-2025-10-02") {
		t.Errorf("drop not logged:\n%s", lb)
	}
}

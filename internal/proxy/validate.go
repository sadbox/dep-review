package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// checkBody allows a Messages request only if every part of it is on an
// allowlist taken from what the pinned Claude Code CLI (2.1.329, with
// --tools Read,Grep,Glob and --json-schema) actually sends; see
// testdata/claude-code-request.json, recorded from the CI end-to-end run.
//
// The Messages API can reach the network for the caller: server tools
// (web_fetch, web_search, code execution, bash, text editor, computer,
// memory, tool search), the MCP connector, containers and skills, URL and
// file content sources. With code execution in the sandbox an attacker
// writes the request, so each of these would be a way to exfiltrate the
// repository or make Anthropic fetch attacker URLs. Anything not known to
// be inert is refused, and a CLI upgrade that sends something new fails
// closed (no verdict, a human reviews) until the list is extended.
func checkBody(raw []byte, model string) error {
	if err := strictJSON(raw); err != nil {
		return err
	}
	var req map[string]json.RawMessage
	if err := json.Unmarshal(raw, &req); err != nil {
		return errors.New("body is not a JSON object")
	}
	for k := range req {
		if !topLevel[k] {
			return fmt.Errorf("field %q is not allowed", safeToken(k))
		}
	}
	var m string
	if err := json.Unmarshal(req["model"], &m); err != nil || m == "" {
		return errors.New("model missing")
	}
	if m != model {
		return fmt.Errorf("model %q is not the gate's model", safeToken(m))
	}
	tools, err := checkTools(req["tools"])
	if err != nil {
		return err
	}
	if err := checkToolChoice(req["tool_choice"], tools); err != nil {
		return err
	}
	if err := checkMessages(req["messages"]); err != nil {
		return err
	}
	if v, ok := req["system"]; ok {
		if err := checkContent(v, systemBlocks, "system"); err != nil {
			return err
		}
	}
	for k, allowed := range nestedKeys {
		if v, ok := req[k]; ok {
			if err := checkKeys(v, allowed, k); err != nil {
				return err
			}
		}
	}
	if v, ok := req["context_management"]; ok {
		var cm struct {
			Edits []map[string]json.RawMessage `json:"edits"`
		}
		if err := json.Unmarshal(v, &cm); err != nil {
			return errors.New("context_management is malformed")
		}
		for _, e := range cm.Edits {
			t, _ := optString(e["type"])
			if !strings.HasPrefix(t, "clear_") {
				return fmt.Errorf("context_management edit %q is not allowed", safeToken(t))
			}
		}
	}
	return nil
}

// The top-level fields the CLI sends, plus tool_choice (checked below).
var topLevel = set("model", "max_tokens", "messages", "system", "tools", "tool_choice", "stream",
	"metadata", "thinking", "output_config", "context_management")

// Keys allowed inside the small configuration objects.
var nestedKeys = map[string]map[string]bool{
	"metadata":           set("user_id"),
	"thinking":           set("type", "display", "budget_tokens"),
	"output_config":      set("effort"),
	"context_management": set("edits"),
}

// Client tools only: no type, or type "custom". Every server tool has a
// dated type (web_search_20250305, bash_20250124, …) or a known name
// (tool_search_*, mcp_toolset), and none of them is "custom".
var toolKeys = set("name", "description", "input_schema", "type", "defer_loading", "cache_control")

func checkTools(raw json.RawMessage) (map[string]bool, error) {
	names := map[string]bool{}
	if raw == nil {
		return names, nil
	}
	var tools []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &tools); err != nil {
		return nil, errors.New("tools is not an array of objects")
	}
	for _, tool := range tools {
		typ, err := optString(tool["type"])
		if err != nil {
			return nil, errors.New("tool type is not a string")
		}
		if _, has := tool["type"]; has && typ != "custom" {
			return nil, fmt.Errorf("tool type %q is not allowed (client tools only)", safeToken(typ))
		}
		for k := range tool {
			if !toolKeys[k] {
				return nil, fmt.Errorf("tool field %q is not allowed", safeToken(k))
			}
		}
		name, err := optString(tool["name"])
		if err != nil || name == "" {
			return nil, errors.New("tool without a name")
		}
		if _, ok := tool["input_schema"]; !ok {
			return nil, fmt.Errorf("tool %q has no input_schema", safeToken(name))
		}
		names[name] = true
	}
	return names, nil
}

func checkToolChoice(raw json.RawMessage, tools map[string]bool) error {
	if raw == nil || string(raw) == "null" {
		return nil
	}
	var tc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &tc); err != nil {
		return errors.New("tool_choice is not an object")
	}
	if err := checkKeys(raw, set("type", "name", "disable_parallel_tool_use"), "tool_choice"); err != nil {
		return err
	}
	t, _ := optString(tc["type"])
	switch t {
	case "auto", "any", "none":
		if _, ok := tc["name"]; ok {
			return errors.New("tool_choice name without type tool")
		}
		return nil
	case "tool":
		n, _ := optString(tc["name"])
		if !tools[n] {
			return fmt.Errorf("tool_choice names %q, which is not an allowed tool", safeToken(n))
		}
		return nil
	}
	return fmt.Errorf("tool_choice type %q is not allowed", safeToken(t))
}

// Content blocks, by where they may appear. tool_result content may hold
// only text and images; images only with an inline base64 source.
var (
	messageBlocks = set("text", "image", "tool_use", "tool_result", "thinking", "redacted_thinking")
	resultBlocks  = set("text", "image")
	systemBlocks  = set("text")
	blockKeys     = map[string]map[string]bool{
		"text":              set("type", "text", "cache_control"),
		"image":             set("type", "source", "cache_control"),
		"tool_use":          set("type", "id", "name", "input", "cache_control"),
		"tool_result":       set("type", "tool_use_id", "content", "is_error", "cache_control"),
		"thinking":          set("type", "thinking", "signature"),
		"redacted_thinking": set("type", "data"),
	}
)

func checkMessages(raw json.RawMessage) error {
	var msgs []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &msgs); err != nil {
		return errors.New("messages is not an array of objects")
	}
	for _, m := range msgs {
		for k := range m {
			if k != "role" && k != "content" && k != "output_config" {
				return fmt.Errorf("message field %q is not allowed", safeToken(k))
			}
		}
		// Per-turn effort (per-turn-control beta).
		if v, ok := m["output_config"]; ok {
			if err := checkKeys(v, nestedKeys["output_config"], "message output_config"); err != nil {
				return err
			}
		}
		role, _ := optString(m["role"])
		allowed := messageBlocks
		switch role {
		case "user", "assistant":
		case "system":
			// The CLI sends its environment notes as a mid-conversation
			// system message (mid-conversation-tool-changes beta).
			allowed = systemBlocks
		default:
			return fmt.Errorf("message role %q is not allowed", safeToken(role))
		}
		if err := checkContent(m["content"], allowed, role+" message"); err != nil {
			return err
		}
	}
	return nil
}

// checkContent accepts a string, or an array of blocks of the allowed
// types with only their known fields, recursing into tool_result content.
func checkContent(raw json.RawMessage, allowed map[string]bool, where string) error {
	if len(raw) == 0 {
		return fmt.Errorf("%s content missing", where)
	}
	if raw[0] == '"' {
		return nil
	}
	var blocks []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return fmt.Errorf("%s content is neither a string nor an array of blocks", where)
	}
	for _, b := range blocks {
		t, _ := optString(b["type"])
		if !allowed[t] {
			return fmt.Errorf("%s block type %q is not allowed", where, safeToken(t))
		}
		for k := range b {
			if !blockKeys[t][k] {
				return fmt.Errorf("%s block %s field %q is not allowed", where, t, safeToken(k))
			}
		}
		switch t {
		case "image":
			var src map[string]json.RawMessage
			if err := json.Unmarshal(b["source"], &src); err != nil {
				return errors.New("image source is not an object")
			}
			if st, _ := optString(src["type"]); st != "base64" {
				return fmt.Errorf("image source type %q is not allowed", safeToken(st))
			}
			if err := checkKeys(b["source"], set("type", "media_type", "data"), "image source"); err != nil {
				return err
			}
		case "tool_result":
			if c, ok := b["content"]; ok {
				if err := checkContent(c, resultBlocks, "tool_result"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func checkKeys(raw json.RawMessage, allowed map[string]bool, where string) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("%s is not an object", where)
	}
	for k := range m {
		if !allowed[k] {
			return fmt.Errorf("%s field %q is not allowed", where, safeToken(k))
		}
	}
	return nil
}

// strictJSON walks the body token by token and rejects a duplicate key in
// any object, at any depth, and anything after the top-level value.
// encoding/json keeps the last of two equal keys and other parsers may keep
// the first, so a duplicate could carry one value past these checks and
// another to the API.
func strictJSON(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	type frame struct {
		obj  bool
		keys map[string]bool
		key  bool // next token in an object is a key
	}
	var stack []*frame
	first := true
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if len(stack) != 0 || first {
				return errors.New("body is truncated")
			}
			return nil
		}
		if err != nil {
			return errors.New("body is not valid JSON")
		}
		if len(stack) == 0 && !first {
			return errors.New("trailing data after the JSON body")
		}
		first = false
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.obj && top.key {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				continue
			}
			k, _ := tok.(string)
			if top.keys[k] {
				return fmt.Errorf("duplicate key %q", safeToken(k))
			}
			top.keys[k] = true
			top.key = false
			continue
		}
		if top != nil && top.obj {
			top.key = true // this token is the value; a key comes next
		}
		switch tok {
		case json.Delim('{'):
			stack = append(stack, &frame{obj: true, keys: map[string]bool{}, key: true})
		case json.Delim('['):
			stack = append(stack, &frame{})
		case json.Delim(']'):
			stack = stack[:len(stack)-1]
		}
		if len(stack) > 128 {
			return errors.New("body nested too deeply")
		}
	}
}

func set(s ...string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, k := range s {
		m[k] = true
	}
	return m
}

func optString(raw json.RawMessage) (string, error) {
	if raw == nil || string(raw) == "null" {
		return "", nil
	}
	var s string
	err := json.Unmarshal(raw, &s)
	return s, err
}

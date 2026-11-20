package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
)

// checkBody enforces what a Messages request from the reviewer may ask
// for. The Messages API can itself reach the network on the caller's
// behalf: server tools (web_fetch, web_search, code execution, …), the MCP
// connector (mcp_servers), and URL or file content sources all make
// Anthropic fetch or touch something chosen by the request. With code
// execution in the sandbox an attacker writes the request, so any of these
// would be an exfiltration path for the repository checkout. Claude Code
// with --tools Read,Grep,Glob sends only custom tools and inline content,
// so the checks cost nothing legitimate. The model must be exactly the
// gate's model input.
func checkBody(raw []byte, model string) error {
	var req map[string]json.RawMessage
	if err := json.Unmarshal(raw, &req); err != nil {
		return errors.New("body is not a JSON object")
	}
	var m string
	if err := json.Unmarshal(req["model"], &m); err != nil || m == "" {
		return errors.New("model missing")
	}
	if m != model {
		return fmt.Errorf("model %q is not the gate's model", safeToken(m))
	}
	for _, k := range []string{"mcp_servers", "container"} {
		if v, ok := req[k]; ok && string(v) != "null" {
			return fmt.Errorf("%s is not allowed", k)
		}
	}
	if t, ok := req["tools"]; ok {
		var tools []map[string]json.RawMessage
		if err := json.Unmarshal(t, &tools); err != nil {
			return errors.New("tools is not an array of objects")
		}
		for _, tool := range tools {
			typ, err := optString(tool["type"])
			if err != nil {
				return errors.New("tool type is not a string")
			}
			if typ != "" && typ != "custom" {
				return fmt.Errorf("server tool %q is not allowed", safeToken(typ))
			}
		}
	}
	for _, k := range []string{"messages", "system"} {
		v, ok := req[k]
		if !ok {
			continue
		}
		var tree any
		if err := json.Unmarshal(v, &tree); err != nil {
			return fmt.Errorf("%s is not JSON", k)
		}
		if err := checkContent(tree, 0); err != nil {
			return err
		}
	}
	return nil
}

// Inline sources are the only ones that make Anthropic fetch nothing.
var inlineSource = map[string]bool{"base64": true, "text": true, "content": true}

// Blocks that point at stored files or server-side state.
var forbiddenBlock = map[string]bool{"container_upload": true, "mcp_tool_use": true, "mcp_tool_result": true}

func checkContent(v any, depth int) error {
	if depth > 64 {
		return errors.New("content nested too deeply")
	}
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			if err := checkContent(e, depth+1); err != nil {
				return err
			}
		}
	case map[string]any:
		if t, _ := x["type"].(string); forbiddenBlock[t] {
			return fmt.Errorf("content block %q is not allowed", t)
		}
		// search_result blocks carry "source" as a plain string (a
		// citation label); only object sources are fetched.
		if src, ok := x["source"].(map[string]any); ok {
			t, _ := src["type"].(string)
			if !inlineSource[t] {
				return fmt.Errorf("content source type %q is not allowed", safeToken(t))
			}
		}
		for _, e := range x {
			if err := checkContent(e, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func optString(raw json.RawMessage) (string, error) {
	if raw == nil || string(raw) == "null" {
		return "", nil
	}
	var s string
	err := json.Unmarshal(raw, &s)
	return s, err
}

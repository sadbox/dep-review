// Package reviewprep renders the reviewer's prompt, the Claude Code user
// settings and the compact verdict schema for the review sandbox
// (internal/sandbox): files that the sandbox hands to the CLI as its
// stdin, a read-only ~/.claude/settings.json and the --json-schema
// argument.
package reviewprep

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	notesPlaceholder = "{{NOTES}}"
	notesMax         = 20 << 10
	noNotes          = "(This repository has no review notes.)"
)

// Settings is the Claude Code settings for the review session, loaded as
// user settings (--setting-sources user). Paths are relative to the
// sandbox's working directory, /work, which holds exactly ./evidence and
// ./repo. Grep and Glob take no path rules of their own (Claude Code
// ignores Grep(path)/Glob(path)); Read rules govern what they search, and
// blockReadsOutsideWorkingDirectories keeps every file tool inside the
// working directory in every mode. The sandbox already confines what the
// CLI could reach; these rules are the second layer.
func Settings() map[string]any {
	deny := []string{
		"Read(./repo/.git/**)",
		"Read(./repo/.git)",
		"Read(//proc/**)",
		"Read(//sys/**)",
		"Read(//etc/**)",
		"Read(//tmp/**)",
		"Read(//root/**)",
		"Read(//dev/**)",
		"Read(//run/**)",
		"Read(//var/**)",
		"Read(//home/**)",
		"Read(~/.*)",
		"Read(~/.*/**)",
		"Edit",
		"Write",
		"NotebookEdit",
		"Bash",
		"WebFetch",
		"WebSearch",
		"mcp__*",
	}
	return map[string]any{
		"permissions": map[string]any{
			"allow":                               []string{"Read(./evidence/**)", "Read(./repo/**)", "Grep", "Glob"},
			"deny":                                deny,
			"defaultMode":                         "dontAsk",
			"blockReadsOutsideWorkingDirectories": true,
			"disableBypassPermissionsMode":        "disable",
		},
		"disableAllHooks":   true,
		"autoMemoryEnabled": false,
		"env": map[string]string{
			"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
			"DISABLE_TELEMETRY":                        "1",
			"DISABLE_ERROR_REPORTING":                  "1",
			"CLAUDE_CODE_DISABLE_CLAUDE_MDS":           "1",
			"CLAUDE_CODE_DISABLE_AUTO_MEMORY":          "1",
			"CLAUDE_CODE_DISABLE_WEB_FETCH":            "1",
		},
	}
}

// RenderPrompt substitutes the notes into the prompt template.
func RenderPrompt(tmpl, notes string) (string, error) {
	if strings.Count(tmpl, notesPlaceholder) != 1 {
		return "", fmt.Errorf("prompt must contain %s exactly once", notesPlaceholder)
	}
	notes = strings.TrimSpace(notes)
	if notes == "" {
		notes = noNotes
	}
	return strings.Replace(tmpl, notesPlaceholder, notes, 1), nil
}

// ReadNotes reads the notes file under the working directory: missing is
// fine, a symlink or anything escaping the directory is not. Capped at
// 20 KB on a UTF-8 boundary.
func ReadNotes(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	if filepath.IsAbs(path) {
		return "", errors.New("notes path must be relative to the working directory")
	}
	root, err := os.OpenRoot(".")
	if err != nil {
		return "", err
	}
	defer root.Close()
	fi, err := root.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("notes %s is not a regular file", path)
	}
	f, err := root.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, notesMax+1))
	if err != nil {
		return "", err
	}
	truncated := len(b) > notesMax
	if truncated {
		b = b[:notesMax]
		for len(b) > 0 && !utf8.Valid(b) {
			b = b[:len(b)-1]
		}
	}
	s := strings.ToValidUTF8(string(b), "\uFFFD")
	s = strings.ReplaceAll(s, "\x00", "")
	if truncated {
		s += "\n\n(Review notes truncated at 20 KB.)"
	}
	return s, nil
}

// CompactSchema validates the verdict schema and returns it on one line
// for --json-schema. (The sandbox passes it as one argv element; the
// single-quote rule dates from shell-quoted arguments and costs nothing.)
func CompactSchema(raw []byte) (string, error) {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return "", fmt.Errorf("schema: %w", err)
	}
	if obj["type"] != "object" {
		return "", errors.New("schema must be an object schema")
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return "", err
	}
	s := buf.String()
	if strings.ContainsAny(s, "'\n\r") {
		return "", errors.New("schema must not contain single quotes or newlines")
	}
	return s, nil
}

// Run does the whole review-prep step: outDir gets prompt.md,
// settings.json and schema.json.
func Run(promptPath, schemaPath, notesPath, outDir string) error {
	tmpl, err := os.ReadFile(promptPath)
	if err != nil {
		return err
	}
	notes, err := ReadNotes(notesPath)
	if err != nil {
		return err
	}
	prompt, err := RenderPrompt(string(tmpl), notes)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		return err
	}
	schema, err := CompactSchema(raw)
	if err != nil {
		return err
	}
	settings, err := json.Marshal(Settings())
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	for name, data := range map[string]string{"prompt.md": prompt, "settings.json": string(settings), "schema.json": schema} {
		// Readable by the sandbox's user, which is not the runner's.
		if err := os.WriteFile(filepath.Join(outDir, name), []byte(data), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// Package reviewprep renders the reviewer's prompt and the Claude Code
// settings for the review job, and writes them as step outputs for
// anthropics/claude-code-action.
//
// How the action takes them (verified against its source at
// c84e279f859e2591391e95bd309286eb111c345f):
//   - prompt: the `prompt` input, any text; the action writes it to a file.
//   - settings: the `settings` input, a JSON string (or a file path); the
//     action merges it into ~/.claude/settings.json, i.e. user settings.
//   - --json-schema: inside `claude_args`, which the action splits with
//     shell-quote and passes to the CLI; the CLI takes the schema inline
//     (not a path). So the schema must be one single-quoted token: we emit
//     it compacted on one line and refuse a schema containing a single
//     quote.
//   - structured_output: JSON.stringify of the validated object; the step
//     fails when the model returns none.
package reviewprep

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	notesPlaceholder = "{{NOTES}}"
	notesMax         = 20 << 10
	noNotes          = "(This repository has no review notes.)"
)

// Settings is the Claude Code settings for the review session. Paths are
// relative to the job's working directory, which holds ./evidence and
// ./repo. Grep and Glob take no path rules of their own (Claude Code
// ignores Grep(path)/Glob(path)); Read rules govern what they search, and
// blockReadsOutsideWorkingDirectories keeps every file tool inside the
// working directory in every mode.
func Settings(runnerTemp string) map[string]any {
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
		// The workspace is under $HOME (/home/runner/work/...), so //home/**
		// would deny the evidence too; deny the home directory's dotfiles
		// (credentials, Claude's own config) instead.
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
	if p, ok := safeAbs(runnerTemp); ok {
		// The runner's temp dir holds the OIDC identity token file.
		deny = append(deny, "Read(/"+p+"/**)")
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

var absRe = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

func safeAbs(p string) (string, bool) {
	p = filepath.Clean(p)
	if !absRe.MatchString(p) || strings.Contains(p, "..") || p == "/" {
		return "", false
	}
	return p, true
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

// CompactSchema validates the verdict schema and returns it on one line,
// fit for a single-quoted --json-schema argument.
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

// WriteOutputs appends name=value pairs to a GITHUB_OUTPUT file, using a
// random heredoc delimiter for every value.
func WriteOutputs(w io.Writer, kv [][2]string) error {
	var b strings.Builder
	for _, p := range kv {
		var rnd [16]byte
		if _, err := rand.Read(rnd[:]); err != nil {
			return err
		}
		delim := "DEP_REVIEW_" + hex.EncodeToString(rnd[:])
		if strings.Contains(p[1], delim) {
			return errors.New("value contains the delimiter")
		}
		fmt.Fprintf(&b, "%s<<%s\n%s\n%s\n", p[0], delim, p[1], delim)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// Run does the whole review-prep step.
func Run(promptPath, schemaPath, notesPath, outPath, runnerTemp string) error {
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
	settings, err := json.Marshal(Settings(runnerTemp))
	if err != nil {
		return err
	}
	f, err := os.OpenFile(outPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if err := WriteOutputs(f, [][2]string{
		{"prompt", prompt},
		{"settings", string(settings)},
		{"json_schema", schema},
	}); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

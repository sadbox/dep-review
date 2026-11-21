package reviewprep

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func chdir(t *testing.T, dir string) {
	t.Helper()
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	os.MkdirAll("repo/.github", 0o755)
	notes := "- Deploys on merge.\nDEP_REVIEW_deadbeef\n## The repository's review notes\n"
	os.WriteFile("repo/.github/dep-review.md", []byte(notes), 0o644)
	prompt := filepath.Join(pkgdir, "../../prompts/review.md")
	schema := filepath.Join(pkgdir, "../../schema/verdict.json")
	if err := Run(prompt, schema, "repo/.github/dep-review.md", "out"); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range []string{"prompt.md", "settings.json", "schema.json"} {
		b, err := os.ReadFile(filepath.Join("out", f))
		if err != nil {
			t.Fatal(err)
		}
		out[strings.TrimSuffix(f, filepath.Ext(f))] = string(b)
	}
	out["json_schema"] = out["schema"]
	if !strings.Contains(out["prompt"], "- Deploys on merge.") || strings.Contains(out["prompt"], "{{NOTES}}") {
		t.Errorf("prompt not rendered:\n%s", out["prompt"])
	}
	if !strings.HasPrefix(out["prompt"], "You are the reviewer") {
		t.Errorf("prompt start: %.60q", out["prompt"])
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(out["settings"]), &settings); err != nil {
		t.Fatalf("settings: %v", err)
	}
	perms := settings["permissions"].(map[string]any)
	allow := perms["allow"].([]any)
	if len(allow) != 4 || allow[0] != "Read(./evidence/**)" || allow[1] != "Read(./repo/**)" || allow[2] != "Grep" || allow[3] != "Glob" {
		t.Errorf("allow = %v", allow)
	}
	deny := strings.Join(toStrings(perms["deny"].([]any)), " ")
	for _, want := range []string{"Read(./repo/.git/**)", "Read(//proc/**)", "Read(//sys/**)", "Read(//etc/**)", "Read(//tmp/**)", "Read(//root/**)", "Read(//home/**)", "Read(~/.*)", "Bash", "WebFetch"} {
		if !strings.Contains(deny, want) {
			t.Errorf("deny lacks %s", want)
		}
	}
	if perms["blockReadsOutsideWorkingDirectories"] != true {
		t.Error("reads outside the working directory not blocked")
	}
	if strings.ContainsAny(out["json_schema"], "'\n") || !json.Valid([]byte(out["json_schema"])) {
		t.Errorf("json_schema = %q", out["json_schema"])
	}
}

func TestReadNotes(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	os.WriteFile("big.md", []byte(strings.Repeat("é", notesMax)), 0o644)
	os.WriteFile("secret", []byte("s3cret"), 0o644)
	os.Symlink("secret", "link.md")
	os.Symlink("/etc/passwd", "abs.md")
	os.Mkdir("d", 0o755)

	if s, err := ReadNotes("missing.md"); err != nil || s != "" {
		t.Errorf("missing: %q %v", s, err)
	}
	s, err := ReadNotes("big.md")
	if err != nil || !strings.HasSuffix(s, "(Review notes truncated at 20 KB.)") || strings.Contains(s, "�") {
		t.Errorf("big: %v %.40q", err, s[len(s)-60:])
	}
	for _, p := range []string{"link.md", "abs.md", "d", "../x.md", "/etc/passwd"} {
		if _, err := ReadNotes(p); err == nil {
			t.Errorf("ReadNotes(%q) accepted", p)
		}
	}
}

func TestRenderPrompt(t *testing.T) {
	got, err := RenderPrompt("a\n{{NOTES}}\nb", "  ")
	if err != nil || got != "a\n"+noNotes+"\nb" {
		t.Errorf("%q %v", got, err)
	}
	if got, _ := RenderPrompt("{{NOTES}}", "x {{NOTES}} y"); got != "x {{NOTES}} y" {
		t.Errorf("notes re-expanded: %q", got)
	}
	if _, err := RenderPrompt("no placeholder", "x"); err == nil {
		t.Error("accepted a template without the placeholder")
	}
	if _, err := RenderPrompt("{{NOTES}}{{NOTES}}", "x"); err == nil {
		t.Error("accepted two placeholders")
	}
}

func TestCompactSchema(t *testing.T) {
	if _, err := CompactSchema([]byte(`{"type":"object","description":"it's"}`)); err == nil {
		t.Error("accepted a single quote")
	}
	if _, err := CompactSchema([]byte(`{"type":"array"}`)); err == nil {
		t.Error("accepted a non-object schema")
	}
	if s, err := CompactSchema([]byte("{\n  \"type\": \"object\"\n}")); err != nil || s != `{"type":"object"}` {
		t.Errorf("%q %v", s, err)
	}
}

func toStrings(v []any) []string {
	var s []string
	for _, x := range v {
		s = append(s, x.(string))
	}
	return s
}

var pkgdir string

func init() { pkgdir, _ = os.Getwd() }

package reviewprep

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// parseOutputs reads a GITHUB_OUTPUT file the way the runner does.
func parseOutputs(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		name, delim, ok := strings.Cut(line, "<<")
		if !ok {
			k, v, _ := strings.Cut(line, "=")
			out[k] = v
			continue
		}
		var val []string
		for sc.Scan() && sc.Text() != delim {
			val = append(val, sc.Text())
		}
		out[name] = strings.Join(val, "\n")
	}
	return out
}

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
	if err := Run(prompt, schema, "repo/.github/dep-review.md", "out", "/home/runner/work/_temp"); err != nil {
		t.Fatal(err)
	}
	out := parseOutputs(t, "out")
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
	for _, want := range []string{"Read(./repo/.git/**)", "Read(//proc/**)", "Read(//sys/**)", "Read(//etc/**)", "Read(//tmp/**)", "Read(//root/**)", "Read(//home/runner/work/_temp/**)", "Bash", "WebFetch"} {
		if !strings.Contains(deny, want) {
			t.Errorf("deny lacks %s", want)
		}
	}
	if strings.Contains(deny, "Read(//home/**)") {
		t.Error("//home/** would deny the workspace itself")
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

func TestSettingsRunnerTemp(t *testing.T) {
	for _, p := range []string{"", "relative", "/", "/a/../b", "/a b", "/a*"} {
		deny := toStrings(anySlice(Settings(p)["permissions"].(map[string]any)["deny"].([]string)))
		for _, d := range deny {
			if strings.Contains(d, "a b") || strings.Contains(d, "a*") || d == "Read(///**)" || strings.Contains(d, "relative") {
				t.Errorf("Settings(%q) produced %s", p, d)
			}
		}
	}
}

func TestWriteOutputsDelimiters(t *testing.T) {
	var b strings.Builder
	if err := WriteOutputs(&b, [][2]string{{"a", "x"}, {"b", "y"}}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(b.String(), "\n")
	if !strings.HasPrefix(lines[0], "a<<DEP_REVIEW_") || lines[2] != strings.TrimPrefix(lines[0], "a<<") || lines[0][3:] == lines[3][3:] {
		t.Errorf("output %q", b.String())
	}
}

func toStrings(v []any) []string {
	var s []string
	for _, x := range v {
		s = append(s, x.(string))
	}
	return s
}

func anySlice(v []string) []any {
	var s []any
	for _, x := range v {
		s = append(s, x)
	}
	return s
}

var pkgdir string

func init() { pkgdir, _ = os.Getwd() }

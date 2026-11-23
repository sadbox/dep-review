package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// Errors can embed git's stderr or a registry's message; none of it may
// start a workflow command or a new line.
func TestLogLine(t *testing.T) {
	for in, want := range map[string]string{
		"plain error": "plain error",
		"git show: exit status 128: fatal: x\n::error::pwned\n##[group]x": `git show: exit status 128: fatal: x\n: :error: :pwned\n# #[group]x`,
		"a\r::add-mask::x":               "a\\r: :add-mask: :x",
		":::":                            ": : :",
		"###[x":                          "## #[x",
		"tab\there\x1b[31mred\x7f\u0085": "tab\\there\\x1b[31mred\\x7f\\x85",
		"bidi " + string(rune(0x202e)) + " and " + string(rune(0x2028)) + " line sep": "bidi \\" + "u202e and \\" + "u2028 line sep",
		"bad utf8 \xff": "bad utf8 \\" + "ufffd",
	} {
		if got := logLine(in); got != want {
			t.Errorf("logLine(%q) = %q, want %q", in, got, want)
		}
	}
	long := logLine(strings.Repeat("é", 5000))
	if n := utf8.RuneCountInString(long); n > maxLogLine+20 || !strings.HasSuffix(long, "[truncated]") {
		t.Errorf("long line: %d runes", n)
	}
}

func TestLineWriter(t *testing.T) {
	var buf bytes.Buffer
	l := log.New(lineWriter{&buf}, "", 0)
	l.Printf("merge refused: %v", "github: 422 nope\n::error file=x::injected")
	l.Printf("second")
	if got := buf.String(); got != "merge refused: github: 422 nope\\n: :error file=x: :injected\nsecond\n" {
		t.Errorf("%q", got)
	}
}

// Every subcommand refuses to start without its required flags, before it
// reads anything or calls an API, and takes no stray argument.
func TestRequiredFlags(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	complete := map[string][]string{
		"classify": {"--event", "e", "--trigger-path", "t", "--out", "o"},
		"fetch":    {"--classification", "c", "--repo-dir", "r", "--out", "o"},
		"review":   {"--facts", "f", "--out", "o"},
		"publish":  {"--in", "i"},
		"refresh":  {"--repo-dir", "r", "--out", "o", "--app-slug", "gate"},
	}
	for cmd, run := range commands {
		args, ok := complete[cmd]
		if !ok {
			t.Errorf("%s: no arguments in this test", cmd)
			continue
		}
		for i := 0; i < len(args); i += 2 {
			without := append(append([]string{}, args[:i]...), args[i+2:]...)
			if err := run(without); err == nil || !strings.Contains(err.Error(), "required") {
				t.Errorf("%s without %s: %v", cmd, args[i], err)
			}
			empty := append([]string{}, args...)
			empty[i+1] = ""
			if err := run(empty); err == nil || !strings.Contains(err.Error(), "required") {
				t.Errorf("%s with an empty %s: %v", cmd, args[i], err)
			}
		}
		if err := run(append(append([]string{}, args...), "stray")); err == nil || !strings.Contains(err.Error(), "required") {
			t.Errorf("%s with a stray argument: %v", cmd, err)
		}
	}
}

// An unknown ecosystem name fails classify, refresh and publish before
// they read anything or call the API.
func TestIgnoreEcosystemsUnknownFails(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	for cmd, args := range map[string][]string{
		"classify": {"--event", "/nonexistent", "--trigger-path", "t", "--out", "/nonexistent/c.json"},
		"refresh":  {"--repo-dir", "/nonexistent", "--out", "/nonexistent", "--app-slug", "gate"},
		"publish":  {"--in", "/nonexistent"},
	} {
		for _, bad := range []string{"gitsubmodule", "submodules,", "*"} {
			err := commands[cmd](append(args, "--ignore-ecosystems", bad))
			if err == nil || !strings.Contains(err.Error(), "--ignore-ecosystems: unknown ecosystem") {
				t.Errorf("%s --ignore-ecosystems %q: %v", cmd, bad, err)
			}
		}
	}
}

// replay is no job's subcommand, so the tests over commands do not see
// it. It refuses to start without its flags, or with a clock or a policy
// it cannot read, before it reads a record.
func TestReplayFlags(t *testing.T) {
	const records = "../../internal/replay/testdata/records"
	notPolicy := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(notPolicy, []byte(`{"min_age_hours": 1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no directory", []string{"--now", "2026-03-02T00:00:00Z"}, "required"},
		{"no clock", []string{"--dir", records}, "required"},
		{"a stray argument", []string{"--dir", records, "--now", "2026-03-02T00:00:00Z", "stray"}, "required"},
		{"a clock that is not a time", []string{"--dir", records, "--now", "yesterday"}, "--now"},
		{"a name time that is not a time", []string{"--dir", records, "--now", "2026-03-02T00:00:00Z", "--name-created", "2020"}, "--name-created"},
		{"a policy file that is not complete", []string{"--dir", records, "--now", "2026-03-02T00:00:00Z", "--policy", notPolicy}, "a key is missing"},
		{"a policy file that is not there", []string{"--dir", records, "--now", "2026-03-02T00:00:00Z", "--policy", notPolicy + ".none"}, "no such file"},
	} {
		if err := tools["replay"](tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error that says %q", tc.name, err, tc.want)
		}
	}
}

// The gate's jobs resolve their policy with config.Load, which holds a
// repository's file to the built-in floors. The one reader that holds a
// file to no floor is internal/replay's, for measuring a policy, and no
// job's path may reach it. Imports are per file, so that is: replay.go is
// the only file of the module that imports internal/replay, replay is no
// job's subcommand, and Load is the only function internal/config
// exports.
func TestOnlyReplayReadsAPolicyWithoutFloors(t *testing.T) {
	const root, replayPackage = "../..", "github.com/sadbox/dep-review/internal/replay"
	if _, ok := commands["replay"]; ok {
		t.Error("replay is a job's subcommand")
	}
	fset := token.NewFileSet()
	var importers, exported []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		rel := filepath.ToSlash(strings.TrimPrefix(path, root+"/"))
		switch {
		case err != nil:
			return err
		case d.IsDir() && (d.Name() == "testdata" || rel == "internal/replay"):
			return filepath.SkipDir
		case d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go"):
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			if imp.Path.Value == `"`+replayPackage+`"` {
				importers = append(importers, rel)
			}
		}
		if strings.HasPrefix(rel, "internal/config/") {
			for _, decl := range f.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.IsExported() {
					exported = append(exported, fn.Name.Name)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(importers, " "); got != "cmd/dep-review/replay.go" {
		t.Errorf("internal/replay is imported by %q, want cmd/dep-review/replay.go alone", got)
	}
	if got := strings.Join(exported, " "); got != "Load" {
		t.Errorf("internal/config exports the functions %q, want Load alone: any other way to a Config has no floors", got)
	}
}

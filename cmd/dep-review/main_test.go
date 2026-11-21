package main

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"unicode/utf8"
)

// Errors can embed git's stderr or a registry's message (see
// ecoutil.Git.run); none of it may start a workflow command or a new line.
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

// A missing trigger path would let the trigger's no-op run count as CI,
// so publish and sweep refuse to start without one.
func TestTriggerPathRequired(t *testing.T) {
	for name, run := range map[string]func() error{
		"publish":       func() error { return runPublish([]string{"--in", t.TempDir()}) },
		"publish empty": func() error { return runPublish([]string{"--in", t.TempDir(), "--trigger-path", ""}) },
		"sweep":         func() error { return runSweep([]string{"--repo", "o/r"}) },
		"sweep empty":   func() error { return runSweep([]string{"--repo", "o/r", "--trigger-path="}) },
	} {
		if err := run(); err == nil || !strings.Contains(err.Error(), "--trigger-path") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestFetchRejectsBadDockerPlatforms(t *testing.T) {
	err := runFetch([]string{"--classification", "x", "--repo-dir", "y", "--out", "z", "--docker-platforms", "linux/amd64;id"})
	if err == nil || !strings.Contains(err.Error(), "docker platform") {
		t.Errorf("err = %v", err)
	}
}

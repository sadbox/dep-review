package actions

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
)

// File kinds the github_actions ecosystem may change.
const (
	kindWorkflow = "workflow"
	kindAction   = "action"
)

// fileKind classifies a path in the caller repository: a workflow
// (.github/workflows/*.yml|yaml, top level only, as GitHub reads them) or an
// action metadata file (action.yml|yaml anywhere). Anything else is "".
func fileKind(p string) string {
	dir, base := path.Split(p)
	if dir == ".github/workflows/" && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")) {
		return kindWorkflow
	}
	if base == "action.yml" || base == "action.yaml" {
		return kindAction
	}
	return ""
}

// usesRef is one parsed `uses:` value.
type usesRef struct {
	prefix  string // everything before the action name: indentation, "- ", "uses:", quote
	action  string // owner/repo[/path], or a docker:// / ./ reference
	ref     string // after '@'
	comment string // text after '#', trimmed; "" when absent
}

var usesLineRx = regexp.MustCompile(`^(\s*(?:-\s+)?uses:\s*)(['"]?)([^@\s'"#]+)@([^\s'"#]+)(['"]?)\s*(?:#\s*(.*?))?\s*$`)

// parseUsesLine reads the value as raw text, so it refuses a backslash
// anywhere in it: inside double quotes GitHub decodes it as an escape
// ("acme/act/path@..." is acme/act/path) and no real action name,
// path or ref contains one.
func parseUsesLine(line string) (usesRef, bool) {
	m := usesLineRx.FindStringSubmatch(line)
	if m == nil || m[2] != m[5] || strings.ContainsRune(m[3]+m[4], '\\') {
		return usesRef{}, false
	}
	return usesRef{prefix: m[1] + m[2], action: m[3], ref: m[4], comment: m[6]}, true
}

var (
	ownerRx = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	repoRx  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	shaRx   = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// splitAction splits owner/repo[/path] and validates the owner and repo
// names. sub is "" for the repository root.
func splitAction(a string) (owner, repo, sub string, err error) {
	if strings.HasPrefix(a, "docker://") || strings.HasPrefix(a, "./") || strings.HasPrefix(a, "../") {
		return "", "", "", fmt.Errorf("not a repository action")
	}
	parts := strings.SplitN(a, "/", 3)
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("not owner/repo")
	}
	owner, repo = parts[0], parts[1]
	if !ownerRx.MatchString(owner) || !repoRx.MatchString(repo) || repo == "." || repo == ".." {
		return "", "", "", fmt.Errorf("invalid owner/repo")
	}
	if len(parts) == 3 {
		sub = path.Clean(parts[2])
		if sub == "." || strings.HasPrefix(sub, "..") || strings.HasPrefix(sub, "/") {
			return "", "", "", fmt.Errorf("invalid action path")
		}
	}
	return owner, repo, sub, nil
}

// lineIndent is the number of leading spaces; tabs are not valid YAML
// indentation and count as content.
func lineIndent(s string) int {
	n := 0
	for n < len(s) && s[n] == ' ' {
		n++
	}
	return n
}

// blankOrComment reports a line YAML ignores structurally.
func blankOrComment(s string) bool {
	t := strings.TrimSpace(s)
	return t == "" || strings.HasPrefix(t, "#")
}

// yamlKeyRx matches a block-mapping key at the start of (de-indented) text.
var yamlKeyRx = regexp.MustCompile(`^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s#'"\-?:,\[\]{}&*!|>%@` + "`" + `][^#:]*?|-[^\s#:][^#:]*?)\s*:(?:\s|$)`)

// lineTokens returns the structural tokens of one YAML line with their
// columns: "-" for each sequence-item dash and the key name for a mapping
// key. "- - key:" yields three tokens.
type token struct {
	col  int
	name string
}

func lineTokens(s string) ([]token, error) {
	var ts []token
	col := lineIndent(s)
	rest := s[col:]
	for {
		if rest == "-" || strings.HasPrefix(rest, "- ") {
			ts = append(ts, token{col, "-"})
			n := 1
			for n < len(rest) && rest[n] == ' ' {
				n++
			}
			col += n
			rest = rest[n:]
			continue
		}
		break
	}
	if m := yamlKeyRx.FindStringSubmatch(rest); m != nil {
		k, err := keyName(m)
		if err != nil {
			return nil, err
		}
		ts = append(ts, token{col, k})
	}
	return ts, nil
}

// keyName returns the key of a yamlKeyRx match (m from FindStringSubmatch).
// A quoted key is accepted only when its text is literal: no backslash
// (double-quoted escapes such as s or \x73), no doubled ” (single-
// quoted escape), and ':' straight after the closing quote. Anything else
// is an error rather than a guess, because GitHub decodes such a key
// (`"post":` is post) and a key the gate reads differently could hide
// a runs.post hook or a runs.using change.
func keyName(m []string) (string, error) {
	k := strings.TrimSpace(m[1])
	if k == "" || (k[0] != '"' && k[0] != '\'') {
		return k, nil
	}
	inner := k[1 : len(k)-1]
	if strings.ContainsRune(inner, '\\') || strings.Contains(inner, "''") {
		return "", errors.New("quoted mapping key with an escape sequence")
	}
	if !strings.HasPrefix(m[0][len(m[1]):], ":") {
		return "", errors.New("text between a quoted mapping key and its ':'")
	}
	return inner, nil
}

// keyOnly reports whether a line is exactly "key:" (optionally with a
// comment), i.e. a key whose value is the following block.
func keyOnly(s string) (bool, error) {
	ts, err := lineTokens(s)
	if err != nil || len(ts) != 1 || ts[0].name == "-" {
		return false, err
	}
	_, v, err := splitKeyValue(strings.TrimSpace(s))
	return v == "", err
}

// yamlPath returns the chain of mapping keys and sequence dashes leading
// to line i, from the document root, by indentation alone. It returns nil
// when line i is inside a block scalar or otherwise not a structural line,
// or when a line on the way up has a key keyName refuses.
func yamlPath(lines []string, i int) []string {
	own, err := lineTokens(lines[i])
	if err != nil || len(own) == 0 {
		return nil
	}
	var rev []string
	for k := len(own) - 1; k >= 0; k-- {
		rev = append(rev, own[k].name)
	}
	c := own[0].col
	dash := own[0].name == "-"
	for j := i - 1; j >= 0 && (c > 0 || dash); j-- {
		l := lines[j]
		if blankOrComment(l) {
			continue
		}
		ind := lineIndent(l)
		parent := ind < c
		if !parent && dash && ind == c {
			ko, err := keyOnly(l)
			if err != nil {
				return nil
			}
			parent = ko
		}
		if !parent {
			continue
		}
		ts, err := lineTokens(l)
		if err != nil || len(ts) == 0 {
			return nil // a refused key, or a scalar continuation or block scalar owns line i
		}
		// A parent key with an inline value (a block scalar header, or a
		// plain scalar being continued) owns line i as text.
		if last := ts[len(ts)-1]; last.name != "-" && last.col < c {
			if _, v, err := splitKeyValue(l[last.col:]); err != nil || v != "" {
				return nil
			}
		}
		var added []token
		for _, t := range ts {
			if t.col < c || (dash && t.col == c && t.name != "-") {
				added = append(added, t)
			}
		}
		if len(added) == 0 {
			continue
		}
		for k := len(added) - 1; k >= 0; k-- {
			rev = append(rev, added[k].name)
		}
		c = added[0].col
		dash = added[0].name == "-"
		if c == 0 && !dash {
			break
		}
	}
	out := make([]string, len(rev))
	for k := range rev {
		out[k] = rev[len(rev)-1-k]
	}
	return out
}

func isBlockScalarHeader(v string) bool {
	v = stripComment(v)
	if v == "" || (v[0] != '|' && v[0] != '>') {
		return false
	}
	for _, c := range v[1:] {
		if c != '-' && c != '+' && (c < '1' || c > '9') {
			return false
		}
	}
	return true
}

// usesContext reports whether a YAML path is a real action reference: a
// step's uses (jobs.<id>.steps[].uses in a workflow, runs.steps[].uses in
// an action) or a job-level reusable-workflow uses (jobs.<id>.uses).
func usesContext(kind string, p []string) bool {
	n := len(p)
	if n == 0 || p[n-1] != "uses" {
		return false
	}
	switch kind {
	case kindWorkflow:
		if n == 5 && p[0] == "jobs" && p[2] == "steps" && p[3] == "-" {
			return true
		}
		return n == 3 && p[0] == "jobs"
	case kindAction:
		return n == 4 && p[0] == "runs" && p[1] == "steps" && p[2] == "-"
	}
	return false
}

// usesChange is one `uses:` line Dependabot rewrote.
type usesChange struct {
	file     string
	kind     string
	line     int // 1-based, in the new file
	old, new usesRef
}

// fileDiffError is a reason a changed caller file is not a pure `uses:`
// rewrite.
type fileDiffError struct {
	file, reason string
}

// usesChanges diffs one workflow/action file and returns the rewritten
// `uses:` lines, or the reasons the change is something else.
func usesChanges(file, kind, oldText, newText string) ([]usesChange, []fileDiffError) {
	a, b := splitLines(oldText), splitLines(newText)
	var out []usesChange
	var errs []fileDiffError
	bad := func(format string, args ...any) {
		errs = append(errs, fileDiffError{file, fmt.Sprintf(format, args...)})
	}
	if strings.HasSuffix(oldText, "\n") != strings.HasSuffix(newText, "\n") {
		bad("trailing newline changed")
	}
	for _, h := range changeHunks(diffLines(a, b)) {
		if len(h.del) != len(h.ins) {
			bad("lines %d-%d: %d lines removed, %d added; only in-place uses: rewrites are allowed", lineNo(h.ins, h.del), lineNo(h.ins, h.del)+len(h.ins), len(h.del), len(h.ins))
			continue
		}
		for k := range h.del {
			ol, nl := a[h.del[k]], b[h.ins[k]]
			ln := h.ins[k] + 1
			o, ok1 := parseUsesLine(ol)
			n, ok2 := parseUsesLine(nl)
			if !ok1 || !ok2 {
				bad("line %d: changed line is not a uses: line", ln)
				continue
			}
			if o.prefix != n.prefix {
				bad("line %d: indentation or key changed", ln)
				continue
			}
			if o.action != n.action {
				bad("line %d: action name changed", ln)
				continue
			}
			pa, pb := yamlPath(a, h.del[k]), yamlPath(b, h.ins[k])
			if !usesContext(kind, pa) || !usesContext(kind, pb) || strings.Join(pa, ".") != strings.Join(pb, ".") {
				bad("line %d: uses: line is not a step or job reference (path %s)", ln, strings.Join(pb, "."))
				continue
			}
			out = append(out, usesChange{file: file, kind: kind, line: ln, old: o, new: n})
		}
	}
	return out, errs
}

func lineNo(ins, del []int) int {
	if len(ins) > 0 {
		return ins[0] + 1
	}
	if len(del) > 0 {
		return del[0] + 1
	}
	return 0
}

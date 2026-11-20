package classify

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Declared is one entry of the `updated-dependencies:` block Dependabot
// puts at the end of its commit message:
//
//	---
//	updated-dependencies:
//	- dependency-name: github.com/aws/aws-sdk-go-v2/credentials
//	  dependency-version: 1.21.0
//	  dependency-type: direct:production
//	  update-type: version-update:semver-minor
//	  dependency-group: aws
//	...
type Declared struct {
	Name       string
	Version    string // dependency-version: the new version
	DepType    string // direct:production, direct:development, indirect
	UpdateType string // version-update:semver-{patch,minor,major}
	Group      string
	From       string // from the "Updates `x` from A to B" / "Bumps x from A to B" prose, if found
	// FromRef/ToRef: when the prose names a pin instead of a version
	// (a backticked, usually abbreviated, hex digest or commit SHA:
	// "Updates `golang` from `01aa404` to `205c763`"), that pin. A Docker
	// digest bump declares its tag as Version and the digests only here.
	FromRef, ToRef string
}

var (
	errNoBlock = errors.New("no updated-dependencies block in the commit message")
	// Dependency names and versions end up in comments, paths and URLs
	// downstream; anything outside this set is not something Dependabot
	// writes, so the PR goes to a human instead.
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9@][A-Za-z0-9@/._+~:-]{0,213}$`)
	versionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~:^-]{0,127}$`)
	fieldRe   = regexp.MustCompile(`^[a-z-]{1,40}$`)
)

// ParseDeclared extracts the updated-dependencies block from a Dependabot
// commit message. It is a deliberately small parser for the fixed shape
// Dependabot writes (a YAML list of flat string maps between "---" and
// "..."), not a YAML parser: anything else is an error.
func ParseDeclared(msg string) ([]Declared, error) {
	msg = strings.ReplaceAll(msg, "\r\n", "\n")
	lines := strings.Split(msg, "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimRight(l, " ") == "updated-dependencies:" && i > 0 && strings.TrimRight(lines[i-1], " ") == "---" {
			start = i + 1
		}
	}
	if start < 0 {
		return nil, errNoBlock
	}
	var out []Declared
	var cur *Declared
	seen := map[string]bool{}
	ended := false
	for _, raw := range lines[start:] {
		l := strings.TrimRight(raw, " \t")
		if l == "..." || l == "---" {
			ended = true
			break
		}
		if strings.TrimSpace(l) == "" {
			continue
		}
		var kv string
		switch {
		case strings.HasPrefix(l, "- "):
			out = append(out, Declared{})
			cur = &out[len(out)-1]
			seen = map[string]bool{}
			kv = l[2:]
		case strings.HasPrefix(l, "  ") && cur != nil:
			kv = l[2:]
		default:
			return nil, fmt.Errorf("unexpected line in updated-dependencies: %.80q", l)
		}
		key, val, ok := strings.Cut(kv, ":")
		if !ok || !fieldRe.MatchString(key) {
			return nil, fmt.Errorf("unexpected line in updated-dependencies: %.80q", l)
		}
		if seen[key] {
			return nil, fmt.Errorf("duplicate %s in updated-dependencies", key)
		}
		seen[key] = true
		v, err := scalar(strings.TrimSpace(val))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		switch key {
		case "dependency-name":
			cur.Name = v
		case "dependency-version":
			cur.Version = v
		case "dependency-type":
			cur.DepType = v
		case "update-type":
			cur.UpdateType = v
		case "dependency-group":
			cur.Group = v
		default:
			// Unknown keys are tolerated (Dependabot adds fields over time)
			// but never used.
		}
	}
	if !ended {
		return nil, errors.New("updated-dependencies block is not terminated")
	}
	if len(out) == 0 {
		return nil, errors.New("updated-dependencies block is empty")
	}
	for _, d := range out {
		if !nameRe.MatchString(d.Name) || strings.Contains(d.Name, "..") {
			return nil, fmt.Errorf("dependency name %.80q has unexpected characters", d.Name)
		}
		if d.Version != "" && !versionRe.MatchString(d.Version) {
			return nil, fmt.Errorf("version %.80q of %s has unexpected characters", d.Version, d.Name)
		}
	}
	prose := parseProse(lines[:start])
	for i := range out {
		p, ok := prose[out[i].Name]
		if !ok {
			continue
		}
		if ref, ok := proseRef(p.from); ok {
			out[i].FromRef = ref
		} else if f := strings.Trim(p.from, "`"); versionRe.MatchString(f) {
			out[i].From = f
		}
		if ref, ok := proseRef(p.to); ok {
			out[i].ToRef = ref
		}
	}
	return out, nil
}

// scalar decodes the YAML scalars Dependabot writes: plain, 'single' (with
// doubled-quote escapes) or "double" (simple backslash escapes).
func scalar(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	switch s[0] {
	case '\'':
		if len(s) < 2 || s[len(s)-1] != '\'' {
			return "", errors.New("unterminated quoted value")
		}
		inner := s[1 : len(s)-1]
		if strings.Count(strings.ReplaceAll(inner, "''", ""), "'") != 0 {
			return "", errors.New("bad quoting")
		}
		return strings.ReplaceAll(inner, "''", "'"), nil
	case '"':
		if len(s) < 2 || s[len(s)-1] != '"' {
			return "", errors.New("unterminated quoted value")
		}
		inner := s[1 : len(s)-1]
		var b strings.Builder
		for i := 0; i < len(inner); i++ {
			c := inner[i]
			if c == '"' {
				return "", errors.New("bad quoting")
			}
			if c == '\\' {
				i++
				if i == len(inner) {
					return "", errors.New("bad escape")
				}
				switch inner[i] {
				case '\\', '"', '/':
					b.WriteByte(inner[i])
				default:
					return "", errors.New("unsupported escape")
				}
				continue
			}
			b.WriteByte(c)
		}
		return b.String(), nil
	}
	if strings.ContainsAny(s[:1], "&*!|>%@`{[") || strings.Contains(s, " #") {
		return "", errors.New("unsupported YAML scalar")
	}
	return s, nil
}

var (
	// Updates `golang` from `01aa404` to `205c763`
	// Updates `github.com/x/y` from 1.20.17 to 1.21.0
	updatesRe = regexp.MustCompile("^Updates `([^`]+)` from (`[^` ]+`|[^` ]+) to (`[^` ]+`|[^` ]+)")
	// Bumps [actions/setup-go](https://...) from 7.0.0 to 7.1.0.
	// Bumps golang from 1.27.3 to 1.27.4.
	bumpsRe = regexp.MustCompile("^Bumps \\[?([^\\] ]+)\\]?(?:\\([^)]*\\))? from (`[^` ]+?`|[^` ]+?) to (`[^` ]+?`|[^` ]+?)\\.?$")
	// A backticked abbreviated (or full) digest or commit SHA.
	proseRefRe = regexp.MustCompile("^`(?:sha256:)?([0-9a-f]{7,64})`$")
)

// proseSides is one dependency's "from A to B" in the prose, each side
// with its backticks (if any) kept.
type proseSides struct{ from, to string }

// parseProse finds each dependency's "from A to B" in the prose above the
// metadata block. Best effort: fetch recomputes the real change set.
func parseProse(lines []string) map[string]proseSides {
	m := map[string]proseSides{}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if s := updatesRe.FindStringSubmatch(l); s != nil {
			m[s[1]] = proseSides{s[2], s[3]}
		} else if s := bumpsRe.FindStringSubmatch(l); s != nil {
			if _, ok := m[s[1]]; !ok {
				m[s[1]] = proseSides{s[2], s[3]}
			}
		}
	}
	return m
}

// proseRef returns the hex of a backticked digest/SHA side. Dependabot
// backticks pins and never versions, so "from 20240101 to 20240102" stays
// a version.
func proseRef(side string) (string, bool) {
	m := proseRefRe.FindStringSubmatch(side)
	if m == nil {
		return "", false
	}
	return m[1], true
}

var dirRe = regexp.MustCompile(` in (/[A-Za-z0-9._/-]*)$`)

// subjectDirectory returns the manifest directory an ungrouped Dependabot
// subject names ("Bump x from 1 to 2 in /api"), or "".
func subjectDirectory(msg string) string {
	subject, _, _ := strings.Cut(msg, "\n")
	m := dirRe.FindStringSubmatch(strings.TrimSpace(subject))
	if m == nil || strings.Contains(m[1], "..") {
		return ""
	}
	return m[1]
}

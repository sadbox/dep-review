package gomod

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Finding Detail text is trusted: the reviewer and the PR comment read it
// as the gate's own words. Every dependency- or PR-chosen value that goes
// into one passes through a check below first, and anything that fails is
// replaced by a fixed placeholder with a hash prefix for correlation.

// maxDetailValue caps each value placed in a Detail.
const maxDetailValue = 200

func placeholder(kind, s string) string {
	sum := sha256.Sum256([]byte(s))
	return "<invalid-" + kind + ":" + hex.EncodeToString(sum[:4]) + ">"
}

// safeImport returns p if it is a valid import path by the rules of
// golang.org/x/mod/module.CheckImportPath (reimplemented here rather than
// adding the dependency) and at most maxDetailValue bytes.
func safeImport(p string) string {
	if len(p) > maxDetailValue || !validImportPath(p) {
		return placeholder("import-path", p)
	}
	return p
}

func validImportPath(p string) bool {
	if p == "" || !utf8.ValidString(p) || p[0] == '-' || strings.Contains(p, "//") || p[len(p)-1] == '/' {
		return false
	}
	for _, elem := range strings.Split(p, "/") {
		if !validPathElem(elem, true) {
			return false
		}
	}
	return true
}

var badWindowsNames = strings.Fields("CON PRN AUX NUL COM1 COM2 COM3 COM4 COM5 COM6 COM7 COM8 COM9 LPT1 LPT2 LPT3 LPT4 LPT5 LPT6 LPT7 LPT8 LPT9")

// validPathElem is x/mod's checkElem for import paths (plus=true allows
// '+') and for the stricter file-path subset used here.
func validPathElem(elem string, plus bool) bool {
	if elem == "" || strings.Count(elem, ".") == len(elem) || elem[len(elem)-1] == '.' {
		return false
	}
	for _, r := range elem {
		ok := r == '-' || r == '.' || r == '_' || r == '~' || (plus && r == '+') ||
			'0' <= r && r <= '9' || 'A' <= r && r <= 'Z' || 'a' <= r && r <= 'z'
		if !ok {
			return false
		}
	}
	short, _, _ := strings.Cut(elem, ".")
	for _, bad := range badWindowsNames {
		if strings.EqualFold(bad, short) {
			return false
		}
	}
	if t := strings.LastIndexByte(short, '~'); t >= 0 && t < len(short)-1 {
		if strings.Trim(short[t+1:], "0123456789") == "" {
			return false
		}
	}
	return true
}

// safeFile returns a slash path (relative to a module or repository root)
// whose elements pass validPathElem, or "." for the root.
func safeFile(p string) string {
	if p == "." {
		return p
	}
	if len(p) > maxDetailValue || !validImportPath(p) {
		return placeholder("path", p)
	}
	return p
}

// safeDir is safeFile for a repository directory written as "/" or "/a/b".
func safeDir(d string) string {
	if d == "/" {
		return d
	}
	if s := safeFile(strings.TrimPrefix(d, "/")); !strings.HasPrefix(s, "<") {
		return "/" + s
	}
	return placeholder("path", d)
}

var identRx = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// safeIdent returns s if it is a Go identifier made of ASCII letters,
// digits and '_' only.
func safeIdent(s string) string {
	if len(s) > maxDetailValue || !identRx.MatchString(s) {
		return placeholder("identifier", s)
	}
	return s
}

var (
	versionRx = regexp.MustCompile(`^v[0-9A-Za-z.+-]+$`)
	goVerRx   = regexp.MustCompile(`^(go)?[0-9]+(\.[0-9]+)*([a-z]+[0-9]*)?$`)
	hashRx    = regexp.MustCompile(`^h1:[A-Za-z0-9+/]{43}=$`)
)

// safeVersion returns a module version ("v1.2.3", pseudo-versions,
// "+incompatible") or a go/toolchain version ("1.27", "go1.27.4").
func safeVersion(v string) string {
	if len(v) > maxDetailValue || !(versionRx.MatchString(v) || goVerRx.MatchString(v)) {
		return placeholder("version", v)
	}
	return v
}

func safeHash(h string) string {
	if !hashRx.MatchString(h) {
		return placeholder("hash", h)
	}
	return h
}

// safeSumKey renders a go.sum key ("mod ver" or "mod ver/go.mod").
func safeSumKey(k string) string {
	mod, ver, _ := strings.Cut(k, " ")
	ver, gomod := strings.CutSuffix(ver, "/go.mod")
	s := safeImport(mod) + " " + safeVersion(ver)
	if gomod {
		s += "/go.mod"
	}
	return s
}

// safeDirective renders a go.mod directive token by token: keywords and
// "=>" as they are, then import paths, relative paths and versions;
// anything else (a godebug value, a quoted path) becomes a placeholder.
func safeDirective(d string) string {
	var out []string
	for _, t := range strings.Fields(d) {
		switch {
		case t == "=>" || t == "replace" || t == "exclude" || t == "godebug" || t == "tool" || t == "ignore" || t == "retract":
			out = append(out, t)
		case versionRx.MatchString(t) && len(t) <= maxDetailValue:
			out = append(out, t)
		case strings.HasPrefix(t, "./") || strings.HasPrefix(t, "../"):
			rest := strings.TrimLeft(t, "./")
			if rest == "" || !strings.HasPrefix(safeFile(rest), "<") {
				out = append(out, t)
			} else {
				out = append(out, placeholder("path", t))
			}
		default:
			out = append(out, safeImport(t))
		}
	}
	return strings.Join(out, " ")
}

// safeList applies f to each value.
func safeList(vs []string, f func(string) string) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = f(v)
	}
	return out
}

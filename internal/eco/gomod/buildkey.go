package gomod

import (
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"path"
	"slices"
	"strings"
)

// buildKey is what decides whether the go command compiles a .go file on
// some platform: its build-constraint lines (//go:build, // +build) and
// its _GOOS/_GOARCH file name suffix. A file whose key differs between the
// old and new tree is checked as a new file: dropping a //go:build ignore
// line brings old code into the build without changing its text.
func buildKey(rel string, src []byte) string {
	var lines []string
	for _, line := range strings.Split(string(src), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "package ") || t == "package" {
			break
		}
		if constraint.IsGoBuild(t) || constraint.IsPlusBuild(t) || strings.HasPrefix(t, "//go:build") || strings.HasPrefix(strings.TrimPrefix(t, "//"), "+build") {
			lines = append(lines, t)
		}
	}
	base := strings.TrimSuffix(strings.TrimSuffix(path.Base(rel), ".go"), "_test")
	suffix := ""
	if parts := strings.Split(base, "_"); len(parts) >= 2 {
		for _, p := range parts[max(1, len(parts)-2):] {
			if slices.Contains(knownOS, p) || slices.Contains(knownArch, p) {
				suffix += "_" + p
			}
		}
	}
	return strings.Join(lines, "\n") + "|" + suffix
}

// excluded: a build constraint names the tag "ignore", the convention
// for a file never compiled (over-matching is the safe side: such an old
// file's directives never count).
func excluded(src []byte) bool {
	for _, line := range strings.Split(buildKey("x.go", src), "\n") {
		e, err := constraint.Parse(strings.TrimSuffix(line, "|"))
		if err != nil {
			if strings.Contains(line, "ignore") {
				return true
			}
			continue
		}
		found := false
		e.Eval(func(tag string) bool {
			found = found || tag == "ignore"
			return true
		})
		if found {
			return true
		}
	}
	return false
}

// sameBuild: the old version of rel counts as the same compiled file as
// the new one (same constraints and suffix, and not excluded).
func sameBuild(rel string, oldSrc, newSrc []byte) bool {
	return buildKey(rel, oldSrc) == buildKey(rel, newSrc) && !excluded(oldSrc)
}

// oldEmbedPatterns are the //go:embed patterns of the old version of a
// file that cmd/go acted on, under-approximated: only line comments that
// are //go:embed directives (followed by a space or tab), in a file that
// imports "embed" and parses, built the same way as the new version.
func oldEmbedPatterns(rel string, oldSrc, newSrc []byte) []string {
	if !sameBuild(rel, oldSrc, newSrc) {
		return nil
	}
	file, err := parser.ParseFile(token.NewFileSet(), rel, oldSrc, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil || !importsEmbed(file) {
		return nil
	}
	var out []string
	for _, cg := range file.Comments {
		for _, c := range cg.List {
			if !strings.HasPrefix(c.Text, "//go:embed ") && !strings.HasPrefix(c.Text, "//go:embed\t") {
				continue
			}
			if pats, err := parseGoEmbed(strings.TrimPrefix(c.Text, "//go:embed")); err == nil {
				out = append(out, pats...)
			}
		}
	}
	return out
}

func importsEmbed(file *ast.File) bool {
	for _, imp := range file.Imports {
		if imp.Path.Value == `"embed"` {
			return true
		}
	}
	return false
}

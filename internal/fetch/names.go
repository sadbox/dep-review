package fetch

import (
	"regexp"
	"strings"

	"github.com/sadbox/dep-review/internal/model"
)

var pep503Sep = regexp.MustCompile(`[-_.]+`)

// NormalizeName is the one rule for when two dependency names in an
// ecosystem are the same dependency:
//
//   - github_actions, submodules: GitHub owner/repo names are
//     case-insensitive, so they compare lowercased.
//   - uv: PyPI project names per PEP 503 (lowercase, every run of -, _
//     and . is one -).
//   - go_modules, npm_and_yarn, docker and anything else: exact. Go module
//     paths and npm names are case-sensitive identifiers, and image
//     repositories are lowercase by spec.
func NormalizeName(eco model.Ecosystem, name string) string {
	switch eco {
	case model.GitHubActions, model.GitSubmodule:
		return strings.ToLower(name)
	case model.UV:
		return strings.ToLower(pep503Sep.ReplaceAllString(name, "-"))
	}
	return name
}

// SameName reports whether a and b name the same dependency in eco.
func SameName(eco model.Ecosystem, a, b string) bool {
	return NormalizeName(eco, a) == NormalizeName(eco, b)
}

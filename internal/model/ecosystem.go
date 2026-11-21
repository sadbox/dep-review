package model

import (
	"fmt"
	"sort"
	"strings"
)

// knownEcosystems are the ecosystems the gate handles, by branch name.
var knownEcosystems = map[Ecosystem]bool{
	GoModules: true, NPM: true, UV: true, GitHubActions: true, Docker: true, GitSubmodule: true,
}

// EcosystemFromBranch returns the ecosystem a Dependabot branch
// (dependabot/<ecosystem>/...) names, if the gate knows it.
func EcosystemFromBranch(ref string) (Ecosystem, bool) {
	rest, ok := strings.CutPrefix(ref, "dependabot/")
	if !ok {
		return "", false
	}
	name, _, ok := strings.Cut(rest, "/")
	if !ok || !knownEcosystems[Ecosystem(name)] {
		return "", false
	}
	return Ecosystem(name), true
}

// ParseEcosystems parses a comma-separated list of ecosystems in
// branch-name form (the ignore_ecosystems input). Empty means none. An
// unknown name or an empty element is an error, never "ignore nothing" or
// "ignore everything".
func ParseEcosystems(list string) (map[Ecosystem]bool, error) {
	if strings.TrimSpace(list) == "" {
		return nil, nil
	}
	out := map[Ecosystem]bool{}
	for _, el := range strings.Split(list, ",") {
		e := Ecosystem(strings.TrimSpace(el))
		if !knownEcosystems[e] {
			var valid []string
			for k := range knownEcosystems {
				valid = append(valid, string(k))
			}
			sort.Strings(valid)
			return nil, fmt.Errorf("unknown ecosystem %.40q in %.200q; valid names (as in Dependabot's branch names) are %s",
				e, list, strings.Join(valid, ", "))
		}
		out[e] = true
	}
	return out, nil
}

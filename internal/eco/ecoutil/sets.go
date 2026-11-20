package ecoutil

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// List joins up to n items, noting how many were left out.
func List(items []string, n int) string {
	if len(items) > n {
		return strings.Join(items[:n], ", ") + fmt.Sprintf(" and %d more", len(items)-n)
	}
	return strings.Join(items, ", ")
}

// OrNew shows an empty "from" version as "(new)".
func OrNew(v string) string {
	if v == "" {
		return "(new)"
	}
	return v
}

// Union merges two maps (b wins).
func Union[V any](a, b map[string]V) map[string]V {
	out := maps.Clone(a)
	if out == nil {
		out = map[string]V{}
	}
	maps.Copy(out, b)
	return out
}

// DiffSets returns the values only in base (removed) and only in head (added).
func DiffSets(base, head []string) (removed, added []string) {
	for _, v := range base {
		if !slices.Contains(head, v) {
			removed = append(removed, v)
		}
	}
	for _, v := range head {
		if !slices.Contains(base, v) {
			added = append(added, v)
		}
	}
	return removed, added
}

// Intersect returns the values in both a and b.
func Intersect(a, b []string) []string {
	var out []string
	for _, v := range a {
		if slices.Contains(b, v) {
			out = append(out, v)
		}
	}
	return out
}

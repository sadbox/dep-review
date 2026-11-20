package ecoutil

import (
	"cmp"
	"slices"
	"strconv"
	"strings"

	"github.com/sadbox/dep-review/internal/model"
)

// Version is a parsed release version: numeric release segments and an
// optional pre-release/local suffix (anything after the first segment that
// is not plain digits).
type Version struct {
	Release []int
	Suffix  string
	ok      bool
}

// ParseVersion parses semver ("v1.2.3", "1.2.3-rc.1+build", Go's
// "+incompatible") and plain PEP 440 releases ("2.21.6", "2024.1",
// "1.0.post1" keeps ".post1" as the suffix). It never fails; an
// unparseable version has ok=false.
func ParseVersion(s string) Version {
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimSuffix(s, "+incompatible")
	var v Version
	rest := s
	for {
		end := 0
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		if end == 0 {
			break
		}
		n, err := strconv.Atoi(rest[:end])
		if err != nil {
			return Version{}
		}
		v.Release = append(v.Release, n)
		rest = rest[end:]
		if len(rest) > 1 && rest[0] == '.' && rest[1] >= '0' && rest[1] <= '9' {
			rest = rest[1:]
			continue
		}
		break
	}
	if len(v.Release) == 0 {
		return Version{}
	}
	v.Suffix = rest
	v.ok = true
	return v
}

func (v Version) seg(i int) int {
	if i < len(v.Release) {
		return v.Release[i]
	}
	return 0
}

// Compare orders versions by release segments, then a version without a
// suffix after one with a suffix (1.0.0-rc1 < 1.0.0), then suffixes as
// strings. It is only used to pair versions, never to decide a route.
func Compare(a, b Version) int {
	for i := range max(len(a.Release), len(b.Release)) {
		if c := cmp.Compare(a.seg(i), b.seg(i)); c != 0 {
			return c
		}
	}
	switch {
	case a.Suffix == b.Suffix:
		return 0
	case a.Suffix == "":
		return 1
	case b.Suffix == "":
		return -1
	}
	return strings.Compare(a.Suffix, b.Suffix)
}

// TypeOf is the semver size of from -> to, computed by the gate:
//
//   - different first segment: major
//   - different second: minor; any later segment: patch
//   - a downgrade, an unparseable side, a new dependency (from ""), or a
//     change only in the pre-release/pseudo-version suffix: unknown, which
//     policy treats like a major.
func TypeOf(from, to string) model.UpdateType {
	a, b := ParseVersion(from), ParseVersion(to)
	if !a.ok || !b.ok || Compare(a, b) >= 0 {
		return model.Unknown
	}
	if a.Suffix != "" || b.Suffix != "" {
		// Pre-releases and Go pseudo-versions: no stability promise.
		return model.Unknown
	}
	switch {
	case a.seg(0) != b.seg(0):
		return model.Major
	case a.seg(1) != b.seg(1):
		return model.Minor
	}
	return model.Patch
}

// Pair matches the versions of one package that disappeared (removed) with
// those that appeared (added). Lockfiles can hold several copies of a
// package, so this is not always one-to-one: sorted removed and added
// versions pair in order; an extra added version pairs with the highest
// version the package still had (from), or "" if the package is new; extra
// removed versions are returned as gone.
func Pair(removed, added, kept []string) (pairs [][2]string, gone []string) {
	byVer := func(s []string) []string {
		s = slices.Clone(s)
		slices.SortFunc(s, func(x, y string) int { return Compare(ParseVersion(x), ParseVersion(y)) })
		return s
	}
	removed, added = byVer(removed), byVer(added)
	n := min(len(removed), len(added))
	for i := range n {
		pairs = append(pairs, [2]string{removed[i], added[i]})
	}
	gone = removed[n:]
	if len(added) > n {
		from := ""
		if all := byVer(append(slices.Clone(kept), removed...)); len(all) > 0 {
			from = all[len(all)-1]
		}
		for _, a := range added[n:] {
			pairs = append(pairs, [2]string{from, a})
		}
	}
	return pairs, gone
}

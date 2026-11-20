package actions

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/sadbox/dep-review/internal/model"
)

// semver is a plain X.Y.Z release version. Pre-release and build suffixes
// are deliberately unsupported: a tag carrying one is not a release tag.
type semver struct{ major, minor, patch int }

var semverTagRx = regexp.MustCompile(`^v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)

// parseTag parses a vX.Y.Z tag name.
func parseTag(tag string) (semver, bool) {
	m := semverTagRx.FindStringSubmatch(tag)
	if m == nil {
		return semver{}, false
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	c, _ := strconv.Atoi(m[3])
	return semver{a, b, c}, true
}

func (v semver) String() string {
	return strconv.Itoa(v.major) + "." + strconv.Itoa(v.minor) + "." + strconv.Itoa(v.patch)
}

func (v semver) cmp(w semver) int {
	switch {
	case v.major != w.major:
		return sign(v.major - w.major)
	case v.minor != w.minor:
		return sign(v.minor - w.minor)
	default:
		return sign(v.patch - w.patch)
	}
}

func sign(x int) int {
	switch {
	case x < 0:
		return -1
	case x > 0:
		return 1
	}
	return 0
}

func updateType(from, to semver) model.UpdateType {
	switch {
	case from.major != to.major:
		return model.Major
	case from.minor != to.minor:
		return model.Minor
	case from.patch != to.patch:
		return model.Patch
	}
	return model.Digest
}

// versionComment is a `# v4`, `# v4.6` or `# v4.6.0` comment, as numeric
// components. ok is false for anything else (no comment, free text).
func versionComment(c string) (parts []int, ok bool) {
	c = strings.TrimSpace(c)
	if !strings.HasPrefix(c, "v") {
		return nil, false
	}
	fs := strings.Split(c[1:], ".")
	if len(fs) == 0 || len(fs) > 3 {
		return nil, false
	}
	for _, f := range fs {
		n, err := strconv.Atoi(f)
		if err != nil || n < 0 || (len(f) > 1 && f[0] == '0') {
			return nil, false
		}
		parts = append(parts, n)
	}
	return parts, true
}

// commentMatches reports whether a version comment is consistent with v:
// its components are a prefix of v's (`# v4` and `# v4.6.0` both match
// 4.6.0).
func commentMatches(parts []int, v semver) bool {
	full := []int{v.major, v.minor, v.patch}
	for i, p := range parts {
		if full[i] != p {
			return false
		}
	}
	return true
}

// npmVersion is a loose semver parse for lockfile versions: X.Y.Z with an
// optional pre-release that sorts before the release.
type npmVersion struct {
	v   semver
	pre string
}

var npmVersionRx = regexp.MustCompile(`^v?(\d{1,9})\.(\d{1,9})\.(\d{1,9})(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$`)

func parseNPMVersion(s string) (npmVersion, bool) {
	m := npmVersionRx.FindStringSubmatch(s)
	if m == nil {
		return npmVersion{}, false
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	c, _ := strconv.Atoi(m[3])
	return npmVersion{semver{a, b, c}, m[4]}, true
}

func (x npmVersion) cmp(y npmVersion) int {
	if c := x.v.cmp(y.v); c != 0 {
		return c
	}
	switch {
	case x.pre == y.pre:
		return 0
	case x.pre == "":
		return 1
	case y.pre == "":
		return -1
	}
	return strings.Compare(x.pre, y.pre)
}

package npm

import (
	"regexp"
	"strconv"
	"unicode/utf8"

	"golang.org/x/mod/semver"

	"github.com/sadbox/dep-review/internal/allow"
)

var (
	// plainRE is a plain release: three numbers, nothing after them. A
	// pre-release or a build suffix is not one. On this shape
	// golang.org/x/mod/semver and npm's own semver order versions the
	// same way.
	plainRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

	// safeRE is text that can be shown as it is: no spaces, quotes,
	// control or bidi characters, nothing a comment would render.
	safeRE = regexp.MustCompile(`^[A-Za-z0-9@/._+-]{1,214}$`)
)

// increaseFact is the Increase fact: both versions are plain releases and
// To is the higher one. A new name has no From; To must be a plain
// release.
func increaseFact(from, to, source string) allow.Fact {
	value := orNew(from) + " -> " + show(to)
	if !plainRE.MatchString(to) || (from != "" && !plainRE.MatchString(from)) {
		return allow.No(value+": not plain x.y.z releases", source)
	}
	if from != "" && semver.Compare("v"+to, "v"+from) <= 0 {
		return allow.No(value+": not an increase", source)
	}
	return allow.Yes(value, source)
}

// majorFact is the Major fact: the leading version component changed. It
// is left ungathered when the versions are not plain releases, because
// then nobody knows; Increase already says no to those.
func majorFact(from, to, source string) allow.Fact {
	if from == "" {
		return allow.No("a new name has no earlier version", source)
	}
	if !plainRE.MatchString(from) || !plainRE.MatchString(to) {
		return allow.Fact{Value: "not compared: the versions are not plain x.y.z releases"}
	}
	a, b := semver.Major("v"+from), semver.Major("v"+to)
	if a != b {
		return allow.Yes("major "+a[1:]+" -> "+b[1:], source)
	}
	return allow.No("major "+a[1:]+" on both sides", source)
}

// show renders a string that came from the lock, the registry or npm for
// a fact's Value. A name or version of the usual shape is shown as it is;
// anything else is quoted, so that control and bidi characters arrive as
// visible escapes, and cut short.
func show(s string) string {
	if safeRE.MatchString(s) {
		return s
	}
	return quote(s)
}

// quote is show for text that is never a plain name: always quoted,
// escaped and cut to a length a comment can carry.
func quote(s string) string {
	const max = 160
	if len(s) > max {
		cut := max
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "..."
	}
	return strconv.QuoteToASCII(s)
}

package docker

import (
	"fmt"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/sadbox/dep-review/internal/allow"
)

// versionOf splits a tag into the version x/mod/semver compares and the
// suffix after it: one to three dotted numbers, then nothing or a dash
// and more ("1.27-bookworm", "24", "22.11.0-bookworm-slim"). semver takes
// no leading zero, so "24.04" is not silently read as 24.4. There is no
// registry-side notion of tag order to ask instead; a tag of another form
// is not compared. The tag is one fromLineRe matched, so the suffix needs
// no check of its own.
func versionOf(tag string) (version, suffix string, ok bool) {
	numbers, rest, dashed := strings.Cut(tag, "-")
	version = "v" + numbers
	// Build metadata is semver's, not a tag's.
	if !semver.IsValid(version) || semver.Build(version) != "" || (dashed && rest == "") {
		return "", "", false
	}
	// A number of ten digits or more is a date and time or a build ID,
	// not a version to put in order.
	for _, n := range strings.Split(numbers, ".") {
		if len(n) > 9 {
			return "", "", false
		}
	}
	return version, tag[len(numbers):], true
}

// compareTags establishes Increase and Major for a move from one tag to
// another. Both come from this one function so they cannot disagree:
// Major is a gathered "no" whenever Increase does not hold, and Increase
// not holding is already person.
//
// The same tag at base and head is a digest refresh: the publisher
// rebuilt the image under that tag. It is an increase with no change of
// version. Otherwise both tags must be versions with the same number of
// components and the identical suffix, and the head's must be greater.
//
// Major is about the tag, the only version an image shows. For a refresh
// it is "no" whatever the tag is, and that is a limit (spec section 11,
// amendment 50): a tag that is not a version (latest, lts, nonroot) can
// be moved from one major of the software to the next without changing,
// and nothing here could see it, because nothing of an image is read.
// Such a refresh waits min_age like any other and not major_age. The
// value says so, so the comment does not claim a comparison that was not
// made. Calling every such refresh a major was weighed and left to the
// owner: where the tag has no version because the repository's name
// carries it (gcr.io/distroless/static-debian12:nonroot), it would make
// every refresh wait 14 days for a major that cannot happen.
func compareTags(from, to string) (increase, major allow.Fact) {
	notComparable := func(why string) (allow.Fact, allow.Fact) {
		return allow.No(why, shapeSource),
			allow.No("not established: "+why, shapeSource)
	}
	if from == "" || to == "" {
		return notComparable("an image pinned without a tag has no version to compare")
	}
	if from == to {
		unchanged := "the tag did not change"
		if _, _, ok := versionOf(to); !ok {
			unchanged += fmt.Sprintf("; %s is not of the form N[.N[.N]][-suffix], so whether the image behind it moved to another major was not compared", to)
		}
		return allow.Yes(fmt.Sprintf("same tag %s, new digest", to), shapeSource),
			allow.No(unchanged, shapeSource)
	}
	old, oldSuffix, ok := versionOf(from)
	if !ok {
		return notComparable(fmt.Sprintf("tag %s is not of the form N[.N[.N]][-suffix]", from))
	}
	cur, curSuffix, ok := versionOf(to)
	if !ok {
		return notComparable(fmt.Sprintf("tag %s is not of the form N[.N[.N]][-suffix]", to))
	}
	if strings.Count(old, ".") != strings.Count(cur, ".") {
		return notComparable(fmt.Sprintf("tags %s and %s do not have the same number of version components", from, to))
	}
	if oldSuffix != curSuffix {
		return notComparable(fmt.Sprintf("tags %s and %s do not have the same suffix", from, to))
	}
	if semver.Compare(cur, old) <= 0 {
		return notComparable(fmt.Sprintf("tag %s is not a higher version than %s", to, from))
	}
	increase = allow.Yes(fmt.Sprintf("%s to %s", from, to), shapeSource)
	if semver.Major(cur) != semver.Major(old) {
		return increase, allow.Yes(fmt.Sprintf("leading version component %s to %s", semver.Major(old)[1:], semver.Major(cur)[1:]), shapeSource)
	}
	return increase, allow.No(fmt.Sprintf("leading version component stays %s", semver.Major(cur)[1:]), shapeSource)
}

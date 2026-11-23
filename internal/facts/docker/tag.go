package docker

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/sadbox/dep-review/internal/allow"
)

// versionTagRe is the one tag shape the comparator reads: one to three
// dotted numbers and an optional suffix that starts with a dash
// ("1.27-bookworm", "24", "22.11.0-bookworm-slim"). A number has no
// leading zero and at most nine digits, so it always fits an int and
// "24.04" is not silently read as 24.4. There is no registry-side notion
// of tag order to ask instead; a tag that does not match is not compared.
var versionTagRe = regexp.MustCompile(
	`^(0|[1-9][0-9]{0,8})(?:\.(0|[1-9][0-9]{0,8}))?(?:\.(0|[1-9][0-9]{0,8}))?(-[A-Za-z0-9_.-]+)?$`)

// versionTag is a tag that matched versionTagRe.
type versionTag struct {
	numbers []int  // one to three
	suffix  string // "" or "-bookworm"
}

// parseVersionTag reads a tag of the comparator's shape.
func parseVersionTag(tag string) (versionTag, bool) {
	m := versionTagRe.FindStringSubmatch(tag)
	if m == nil {
		return versionTag{}, false
	}
	v := versionTag{suffix: m[4]}
	for _, digits := range m[1:4] {
		if digits == "" {
			break
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			return versionTag{}, false
		}
		v.numbers = append(v.numbers, n)
	}
	return v, true
}

// compareTags establishes Increase and Major for a move from one tag to
// another. Both come from this one function so they cannot disagree:
// Major is a gathered "no" whenever Increase does not hold, and Increase
// not holding is already person.
//
// The same tag at base and head is a digest refresh: the publisher
// rebuilt the image under that tag. It is an increase with no change of
// version. Otherwise both tags must be of the comparator's shape, with
// the same number of components and the identical suffix, and the head's
// numbers greater.
func compareTags(from, to string) (increase, major allow.Fact) {
	notComparable := func(why string) (allow.Fact, allow.Fact) {
		return allow.No(why, shapeSource),
			allow.No("not established: "+why, shapeSource)
	}
	if from == "" || to == "" {
		return notComparable("an image pinned without a tag has no version to compare")
	}
	if from == to {
		return allow.Yes(fmt.Sprintf("same tag %s, new digest", to), shapeSource),
			allow.No("the tag did not change", shapeSource)
	}
	old, ok := parseVersionTag(from)
	if !ok {
		return notComparable(fmt.Sprintf("tag %s is not of the form N[.N[.N]][-suffix]", from))
	}
	cur, ok := parseVersionTag(to)
	if !ok {
		return notComparable(fmt.Sprintf("tag %s is not of the form N[.N[.N]][-suffix]", to))
	}
	if len(old.numbers) != len(cur.numbers) {
		return notComparable(fmt.Sprintf("tags %s and %s do not have the same number of version components", from, to))
	}
	if old.suffix != cur.suffix {
		return notComparable(fmt.Sprintf("tags %s and %s do not have the same suffix", from, to))
	}
	order := 0
	for i := range old.numbers {
		if cur.numbers[i] != old.numbers[i] {
			order = 1
			if cur.numbers[i] < old.numbers[i] {
				order = -1
			}
			break
		}
	}
	if order <= 0 {
		return notComparable(fmt.Sprintf("tag %s is not a higher version than %s", to, from))
	}
	increase = allow.Yes(fmt.Sprintf("%s to %s", from, to), shapeSource)
	if cur.numbers[0] != old.numbers[0] {
		return increase, allow.Yes(fmt.Sprintf("leading version component %d to %d", old.numbers[0], cur.numbers[0]), shapeSource)
	}
	return increase, allow.No(fmt.Sprintf("leading version component stays %d", cur.numbers[0]), shapeSource)
}

package docker

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/facts"
)

// One path component of an image name, as registries accept it: lower
// case letters and digits, separated by ".", "_", "__" or dashes.
const nameComponent = `[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*`

// The two ways of writing an image name that are read: a gcr.io image by
// its full name, and an official Docker Hub image by its bare name. Which
// registry and repository any other spelling means is for Docker's own
// defaulting rules to say, and they are not ported here: such a line does
// not match.
const imageName = `(?:gcr\.io/` + nameComponent + `(?:/` + nameComponent + `)*|` + nameComponent + `)`

// fromLineRe is the one line shape the gatherer reads:
//
//	FROM [--platform=<value>] name[:tag]@sha256:<64 hex> [AS stage]
//
// The groups are: 1 everything up to and including the name, 2 the name,
// 3 the tag, 4 the digest, 5 everything after the digest. Groups 1 and 5
// must be byte-identical at base and head, so however loosely they match
// (blanks, keyword case, the platform value, a trailing carriage return)
// nothing in them can change unseen. A build variable, a continuation, a
// second flag or a comment does not match, and that is the point: there
// is no Dockerfile parser here to understand them.
var fromLineRe = regexp.MustCompile(
	`^([ \t]*(?i:FROM)[ \t]+(?:--platform=[^ \t]+[ \t]+)?(` + imageName + `))` +
		`(?::([A-Za-z0-9_][A-Za-z0-9_.-]{0,127}))?` +
		`@(sha256:[0-9a-f]{64})` +
		`((?:[ \t]+(?i:AS)[ \t]+[A-Za-z0-9_][A-Za-z0-9_.-]*)?[ \t]*\r?)$`)

// shapeSource is the Source of the Shape fact and of the facts that come
// from the two Dockerfiles alone.
const shapeSource = "Dockerfile lines at the base and head commits"

// notFromLine is the refusal of a changed line that does not match. It
// names the images that are read, the part of the shape a person is
// least likely to guess.
const notFromLine = "it is not a FROM line pinned by digest in the accepted shape (an official Docker Hub image by its bare name, or a gcr.io image)"

// fromLine is one line that matched fromLineRe.
type fromLine struct {
	prefix string // up to and including the name
	name   string // as written
	tag    string // empty when the line pins a digest without a tag
	digest string // sha256:<64 hex>
	suffix string // after the digest
}

// parseFromLine matches one line against the shape.
func parseFromLine(line []byte) (fromLine, bool) {
	m := fromLineRe.FindSubmatch(line)
	if m == nil {
		return fromLine{}, false
	}
	return fromLine{
		prefix: string(m[1]),
		name:   string(m[2]),
		tag:    string(m[3]),
		digest: string(m[4]),
		suffix: string(m[5]),
	}, true
}

// image is an image name split the way a registry is asked for it.
type image struct {
	registry string // "docker.io" or "gcr.io"
	repo     string // "library/golang", "distroless/static-debian12"
}

// Name is registry/repository: what the policy list is matched against.
func (im image) Name() string { return im.registry + "/" + im.repo }

// newImage is the image a name that fromLineRe matched stands for: a
// bare name is an official image, under "library/" on Docker Hub.
func newImage(name string) image {
	if repo, ok := strings.CutPrefix(name, "gcr.io/"); ok {
		return image{registry: "gcr.io", repo: repo}
	}
	return image{registry: "docker.io", repo: "library/" + name}
}

// change is one image reference that differs between base and head.
type change struct {
	image      image
	fromTag    string
	fromDigest string
	toTag      string
	toDigest   string
}

// version is how an update's From and To are written: tag@digest, or the
// digest alone for a line with no tag. The digest is part of it because a
// same-tag refresh would otherwise have From equal to To.
func version(tag, digest string) string {
	if tag == "" {
		return digest
	}
	return tag + "@" + digest
}

// readShape establishes the Shape fact and the change set from the files
// the pull request changes: only files named Dockerfile*, each a regular
// file at both commits with the same number of lines, and every line
// that differs a FROM line of the one shape at both commits, equal in
// everything but tag and digest.
//
// When the fact does not hold the returned change set is nil.
func readShape(files []facts.File) ([]change, allow.Fact) {
	no := func(format string, args ...any) ([]change, allow.Fact) {
		return nil, allow.No(fmt.Sprintf(format, args...), shapeSource)
	}
	if len(files) == 0 {
		return no("the pull request changes no file")
	}

	var changes []change
	changedLines := 0
	for _, f := range files {
		if !strings.HasPrefix(path.Base(f.Path), "Dockerfile") {
			return no("%s changed, and it is not a file named Dockerfile*", facts.Show(f.Path))
		}
		if problem := facts.NotRegular(f); problem != "" {
			return no("%s", problem)
		}
		base := bytes.Split(f.Base, []byte("\n"))
		head := bytes.Split(f.Head, []byte("\n"))
		if len(base) != len(head) {
			return no("%s has %d lines at base and %d at head; only FROM lines may change, in place", facts.Show(f.Path), len(base), len(head))
		}
		changedHere := 0
		for i := range base {
			if bytes.Equal(base[i], head[i]) {
				continue
			}
			line := i + 1
			old, ok := parseFromLine(base[i])
			if !ok {
				return no("%s line %d changed, and at base %s", facts.Show(f.Path), line, notFromLine)
			}
			cur, ok := parseFromLine(head[i])
			if !ok {
				return no("%s line %d changed, and at head %s", facts.Show(f.Path), line, notFromLine)
			}
			if old.prefix != cur.prefix || old.suffix != cur.suffix {
				return no("%s line %d changed something other than the tag and the digest", facts.Show(f.Path), line)
			}
			changedHere++
			changes = append(changes, change{
				image:      newImage(cur.name),
				fromTag:    old.tag,
				fromDigest: old.digest,
				toTag:      cur.tag,
				toDigest:   cur.digest,
			})
		}
		if changedHere == 0 {
			return no("%s is listed as changed, and no line of it differs", facts.Show(f.Path))
		}
		changedLines += changedHere
	}
	return changes, allow.Yes(
		fmt.Sprintf("%d FROM line(s) changed in %d Dockerfile(s), in tag and digest only", changedLines, len(files)),
		shapeSource)
}

// distinct drops repeats of the same update (the same image moved the
// same way on several lines or in several Dockerfiles), keeping the order
// of first appearance.
func distinct(changes []change) []change {
	var out []change
	seen := map[change]bool{}
	for _, c := range changes {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

package gomod

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
	"github.com/sadbox/dep-review/internal/evidence"
)

// Reachability decides which binaries are flagged, never which are
// cleared: every flagged binary goes to a person. A binary outside
// testdata/ is flagged whenever it is added or changed. One under
// testdata/ keeps the go command's exemption (it is never built) unless
// something can reach it. And any binary, changed or not, that the new
// tree can reach but the old one could not is flagged as newly reachable:
// a new //go:embed or cgo line can pull an unchanged file into the build.

// maxReachScan bounds the .go bytes read for //go:embed lines; past it
// every binary counts as reachable.
const maxReachScan = 64 << 20

// reach is what can pull a file of one module tree into the build.
type reach struct {
	links  string                // moduleLinks: cgo, C or assembly sources, a .syso
	embeds map[string][]embedPat // non-test //go:embed patterns by folded package directory
	all    string                // when set, every file is reachable, for this reason
}

type embedPat struct {
	file string // sanitized
	line int
	pat  string
	any  bool // matches every file under its directory
}

// newReach indexes tree t; nil for no tree (a new module).
func newReach(t *ecoutil.Tree) *reach {
	if t == nil {
		return nil
	}
	x := &reach{links: moduleLinks(t), embeds: map[string][]embedPat{}}
	scanned := 0
	for _, f := range t.Files {
		if path.Ext(f) != ".go" || strings.HasSuffix(f, "_test.go") {
			continue
		}
		src := t.ReadFile(f)
		if scanned += len(src); scanned > maxReachScan {
			x.all = fmt.Sprintf("the module has more than %d bytes of Go source; the gate did not read all its //go:embed lines", maxReachScan)
			return x
		}
		// Read whatever the file looks like: the go command compiles it.
		for n, line := range strings.Split(string(src), "\n") {
			tl := strings.TrimSpace(line)
			if !strings.HasPrefix(tl, "//go:embed") {
				continue
			}
			pats, err := parseGoEmbed(strings.TrimPrefix(tl, "//go:embed"))
			d := fold(path.Dir(f))
			if err != nil {
				x.embeds[d] = append(x.embeds[d], embedPat{safeFile(f), n + 1, "(a list the gate could not split)", true})
				continue
			}
			for _, p := range pats {
				p = strings.TrimPrefix(p, "all:")
				// A character class or an escape is beyond what the gate
				// models (folding changes what [^A-Z] accepts), and so is a
				// non-ASCII byte (Unicode folding and normalization on
				// macOS): such a pattern can match anything under its
				// directory.
				anyFile := strings.ContainsAny(p, `[\`) || !ascii(p)
				x.embeds[d] = append(x.embeds[d], embedPat{safeFile(f), n + 1, p, anyFile})
			}
		}
	}
	return x
}

// reachable is why the build can reach the file at rel, or "".
func (x *reach) reachable(rel string) string {
	if x == nil {
		return ""
	}
	if x.all != "" {
		return x.all
	}
	ext := path.Ext(rel)
	if ext == ".syso" {
		return "a .syso is linked into its package"
	}
	if x.links != "" && (inTestdata(rel) || linkExts[ext]) {
		return "the module has " + x.links + ", which can link or include it without naming it"
	}
	for d := path.Dir(rel); ; d = path.Dir(d) {
		r := rel
		if d != "." {
			r = strings.TrimPrefix(rel, d+"/")
		}
		for _, e := range x.embeds[fold(d)] {
			if e.any || !ascii(rel) || embedReaches(e.pat, r) {
				return fmt.Sprintf("//go:embed %s at %s:%d can match it", clipText(e.pat), e.file, e.line)
			}
		}
		if d == "." {
			return ""
		}
	}
}

// embedReaches: pattern p (no class, escape or non-ASCII byte) matches
// rel or one of its parent directories. Segments with * or ? match as
// path.Match does, case-sensitively (the go command's directory scan);
// literal segments are compared case-folded (a stat on macOS or Windows
// finds payload.bin for PAYLOAD.BIN).
func embedReaches(p, rel string) bool {
	ps, rs := strings.Split(p, "/"), strings.Split(rel, "/")
	if len(ps) > len(rs) {
		return false
	}
	for i, seg := range ps {
		if strings.ContainsAny(seg, "*?") {
			if ok, err := path.Match(seg, rs[i]); err != nil || !ok {
				return err != nil // a malformed glob: assume it matches
			}
		} else if fold(seg) != fold(rs[i]) {
			return false
		}
	}
	return true
}

func inTestdata(rel string) bool {
	return slices.Contains(strings.Split(path.Dir(rel), "/"), "testdata")
}

// isBinaryFile is how CheckTrees decides a file is a binary to flag:
// a .syso or library/object file by name, a .go test file or any file the
// toolchain does not compile as source by its bytes.
func isBinaryFile(rel string, data []byte) bool {
	switch ext := path.Ext(rel); {
	case ext == ".syso" || linkExts[ext]:
		return true
	case ext == ".go":
		return strings.HasSuffix(rel, "_test.go") && evidence.IsBinary(data)
	case ext == ".s" || ext == ".S" || ext == ".sx" || cgoSourceExts[ext]:
		return false
	}
	return evidence.IsBinary(data)
}

// ascii reports a string of ASCII bytes only.
func ascii(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// fold is the case folding of a case-insensitive file system for literal
// names (macOS, Windows). Over-matching is the safe side.
func fold(s string) string { return strings.ToLower(s) }

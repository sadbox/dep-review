package gomod

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
	"github.com/sadbox/dep-review/internal/evidence"
)

// Exact //go:embed resolution. Every non-test //go:embed pattern is
// resolved in both trees as cmd/go does (load.resolveEmbed): segments
// matched with path.Match against the directory's entries, a matched
// directory embedded recursively without names starting with "." or "_"
// unless the pattern has "all:", VCS directories never embedded. The
// matched sets are compared per (embedding file, pattern): every file the
// new tree embeds that the old one did not is newly embedded, changed or
// not. Old reachability can never mask it: only the exact old set for the
// same file and pattern is subtracted.
//
// Literal segments are matched case-folded (ASCII): on macOS and Windows
// cmd/go's Lstat finds payload.bin for PAYLOAD.BIN. What the gate does
// not model exactly goes to a person: a pattern with "[", "\" or a
// non-ASCII byte, an embedding file in a directory with a non-ASCII name
// (Unicode folding and normalization), a pattern the gate cannot split or
// resolve, and resolution past its work budget.

// maxEmbedWork bounds directory entries examined resolving one tree's
// patterns.
const maxEmbedWork = 2_000_000

var errEmbedBudget = errors.New("the gate's work budget for resolving //go:embed patterns is spent")

// treeDirs lists, per directory of a tree, its entries.
type treeDirs struct {
	entries map[string][]dirEntry
	work    int // entries examined so far
}

type dirEntry struct {
	name  string
	isDir bool
}

func indexDirs(t *ecoutil.Tree) *treeDirs {
	td := &treeDirs{entries: map[string][]dirEntry{}}
	if t == nil {
		return td
	}
	seen := map[string]bool{}
	for _, f := range t.Files {
		td.add(path.Dir(f), path.Base(f), false, seen)
		for d := path.Dir(f); d != "."; d = path.Dir(d) {
			td.add(path.Dir(d), path.Base(d), true, seen)
		}
	}
	return td
}

func (td *treeDirs) add(dir, name string, isDir bool, seen map[string]bool) {
	k := dir + "\x00" + name
	if seen[k] {
		return
	}
	seen[k] = true
	td.entries[dir] = append(td.entries[dir], dirEntry{name, isDir})
}

func join(dir, name string) string {
	if dir == "." {
		return name
	}
	return dir + "/" + name
}

// modelled reports whether the gate resolves pattern p from a file in dir
// exactly; why it does not, otherwise.
func modelled(dir, p string) string {
	switch {
	case !ascii(dir):
		return "the embedding file's directory has a non-ASCII name, which file systems may fold or normalize into another"
	case strings.ContainsAny(p, `[\`):
		return "the pattern has a character class or an escape"
	case !ascii(p):
		return "the pattern has a non-ASCII character"
	}
	return ""
}

var badEmbedNames = map[string]bool{".bzr": true, ".hg": true, ".git": true, ".svn": true}

// resolve is the set of files pattern p, written in a file of package
// directory dir, embeds; an error where cmd/go fails or the gate cannot
// tell.
func (td *treeDirs) resolve(dir, p string) ([]string, error) {
	all := strings.HasPrefix(p, "all:")
	p = strings.TrimPrefix(p, "all:")
	if _, err := path.Match(p, ""); err != nil || p == "." || !fs.ValidPath(p) {
		return nil, fmt.Errorf("invalid pattern syntax")
	}
	cur := []string{dir}
	for _, seg := range strings.Split(p, "/") {
		var next []string
		for _, d := range cur {
			for _, e := range td.entries[d] {
				if td.work++; td.work > maxEmbedWork {
					return nil, errEmbedBudget
				}
				ok := false
				if strings.ContainsAny(seg, "*?") {
					ok, _ = path.Match(seg, e.name)
				} else {
					ok = fold(seg) == fold(e.name)
				}
				if ok {
					next = append(next, join(d, e.name))
				}
			}
		}
		cur = next
	}
	var files []string
	for _, m := range cur {
		for _, el := range strings.Split(strings.TrimPrefix(m, dir+"/"), "/") {
			if badEmbedNames[el] {
				return nil, fmt.Errorf("cannot embed %s: invalid name", el)
			}
		}
		if !td.isDir(m) {
			files = append(files, m)
			continue
		}
		if err := td.walk(m, all, &files); err != nil {
			return nil, err
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no matching files found")
	}
	slices.Sort(files)
	return slices.Compact(files), nil
}

func (td *treeDirs) isDir(p string) bool {
	d, name := path.Dir(p), path.Base(p)
	for _, e := range td.entries[d] {
		if e.name == name {
			return e.isDir
		}
	}
	return false
}

func (td *treeDirs) walk(d string, all bool, files *[]string) error {
	for _, e := range td.entries[d] {
		if td.work++; td.work > maxEmbedWork {
			return errEmbedBudget
		}
		if badEmbedNames[e.name] || (!all && (strings.HasPrefix(e.name, ".") || strings.HasPrefix(e.name, "_"))) {
			continue
		}
		p := join(d, e.name)
		if e.isDir {
			if err := td.walk(p, all, files); err != nil {
				return err
			}
			continue
		}
		*files = append(*files, p)
	}
	return nil
}

// nonASCIIPath: a path element of t is not ASCII.
func nonASCIIPath(t *ecoutil.Tree) bool {
	if t == nil {
		return false
	}
	return slices.ContainsFunc(t.Files, func(f string) bool { return !ascii(f) })
}

// embedLines are the //go:embed patterns of one non-test Go file, and
// lines the gate could not split.
type embedLine struct {
	line int
	pats []string
	err  error
}

// embedLinesOf finds a new file's //go:embed comments as go/build does
// (directives.go), in every file whatever its constraints or imports. A
// comment whose arguments do not parse, or a file the scanner rejects,
// is a line with an error: unresolved, for a person.
func embedLinesOf(src []byte) []embedLine {
	var out []embedLine
	dirs, scanErr := scanDirectives("x.go", src)
	if scanErr && bytes.Contains(src, []byte("//go:embed")) {
		out = append(out, embedLine{0, nil, errors.New("the Go scanner rejects the file")})
	}
	for _, d := range dirs {
		pats, ok, err := embedArgs(d.text)
		if ok {
			out = append(out, embedLine{d.line, pats, err})
		}
	}
	return out
}

// embedResult is what the embed analysis tells binaries: the files the
// new tree embeds, and the newly embedded ones with the reason.
type embedResult struct {
	embedded map[string]bool
	newly    map[string]string
	// unresolved are the patterns the gate could not resolve exactly:
	// every binary under scope counts as embedded by them (scope "." when
	// the embedding directory's name is not ASCII: it may alias any
	// directory), and as newly embedded when the pattern is new.
	unresolved []unresolvedEmbed
}

type unresolvedEmbed struct {
	scope, label string
	isNew        bool
}

// embeddedBy is why the new tree embeds rel, and whether that is new.
func (e embedResult) embeddedBy(rel string) (why string, isNew bool) {
	if w := e.newly[rel]; w != "" {
		return w, true
	}
	if e.embedded[rel] {
		return "embedded by a //go:embed of the new tree", false
	}
	for _, u := range e.unresolved {
		if u.scope == "." || strings.HasPrefix(rel, u.scope+"/") {
			return "possibly embedded by " + u.label + ", which the gate could not resolve exactly", u.isNew
		}
	}
	return "", false
}

// embeds resolves every non-test //go:embed in both trees. Each newly
// embedded text file is quoted in full under the embedding file's
// gomod.go-embed item; each newly embedded binary is returned for
// binaries to flag. A pattern the gate does not resolve exactly puts the
// embed item in front of a person.
func (r *report) embeds(old, cur *ecoutil.Tree) embedResult {
	res := embedResult{embedded: map[string]bool{}, newly: map[string]string{}}
	nd, od := indexDirs(cur), indexDirs(old)
	aliased := nonASCIIPath(cur) || nonASCIIPath(old)
	for _, f := range cur.Files {
		if path.Ext(f) != ".go" || strings.HasSuffix(f, "_test.go") {
			continue
		}
		lines := embedLinesOf(cur.ReadFile(f))
		if len(lines) == 0 {
			continue
		}
		var oldPats []string
		if old.Has(f) {
			oldPats = oldEmbedPatterns(f, old.ReadFile(f), cur.ReadFile(f))
		}
		dir, item := path.Dir(f), safeFile(f)
		for _, l := range lines {
			where := fmt.Sprintf("%s:%d", item, l.line)
			scope := dir
			if !ascii(dir) || aliased {
				scope = "."
			}
			if l.err != nil {
				r.add(codeEmbed, item, false, fmt.Sprintf("//go:embed at %s: the gate could not split it as the go command does; a person decides\n", where))
				res.unresolved = append(res.unresolved, unresolvedEmbed{scope, "the //go:embed at " + where, true})
				continue
			}
			for _, p := range l.pats {
				label := "//go:embed " + p + " at " + where
				isNew := !slices.Contains(oldPats, p)
				why := modelled(dir, p)
				if aliased {
					why = "the module has a path with a non-ASCII name, which a file system may fold or normalize into any directory"
				}
				if why != "" {
					r.add(codeEmbed, item, false, quote("not resolved exactly ("+why+"); a person decides", label))
					res.unresolved = append(res.unresolved, unresolvedEmbed{scope, label, isNew})
					continue
				}
				files, err := nd.resolve(dir, p)
				if err != nil {
					r.add(codeEmbed, item, false, quote("not resolved ("+err.Error()+"); a person decides", label))
					res.unresolved = append(res.unresolved, unresolvedEmbed{scope, label, isNew})
					continue
				}
				var before []string
				if !isNew {
					before, _ = od.resolve(dir, p)
				}
				for _, e := range files {
					res.embedded[e] = true
					if slices.Contains(before, e) {
						continue
					}
					data := cur.ReadFile(e)
					// Anything not binary is quoted (visible escapes ESC, C1
					// and invalid UTF-8); the rest is flagged in binaries.
					if !evidence.IsBinary(data) {
						r.add(codeEmbed, item, true, quote("newly embedded by", label)+"newly embedded: "+r.fileRef(e, data))
						continue
					}
					if _, done := res.newly[e]; !done {
						res.newly[e] = "newly embedded by " + label
					}
				}
			}
		}
	}
	return res
}

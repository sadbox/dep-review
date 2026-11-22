package gomod

import (
	"bytes"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
	"github.com/sadbox/dep-review/internal/evidence"
)

// //go:embed: what each package embeds is go list's EmbedFiles in both
// trees (golist.go), compared per package directory and configuration: a
// file the new tree embeds in some configuration in which the old one did
// not is newly embedded, changed or not (a dropped //go:build windows
// newly embeds on linux what the old tree embedded on windows only).
//
// An old answer is credited for a configuration only when every file the
// new package takes //go:embed patterns from there (go/build's
// EmbedPatternPos for that configuration) is byte-identical to its old
// version and built in the same configurations. Otherwise every file the
// package embeds there counts as newly embedded. go list reports patterns
// the compiler would reject (a trailing //go:embed, one not on a var);
// with this rule such an old pattern is never credited for a changed
// file, and the gate needs no rule about where a directive may stand. A text file newly embedded is quoted in full; anything else goes
// to binaries, for a person. The gate resolves no pattern itself.
//
// Unresolved, for a person (every binary under the package counts as
// possibly newly embedded):
//   - a package with a //go:embed comment go list gives no answer for
//     (an error on the package, a failed run, no go command);
//   - a .go file with a //go:embed comment that no default configuration
//     builds but some -tags set can (build.go), when it or anything under
//     its directory changed: go list never resolves its patterns, and
//     with nothing changed under the directory its patterns match what
//     they matched before (patterns cannot reach outside it). Running go
//     list once per tag set instead would need every tag set, not one;
//     a person is the simpler sound answer;
//   - every package with a //go:embed comment when a path in either tree
//     has a non-ASCII element: the gate runs on Linux, and a consumer's
//     file system may fold or normalize names (macOS, Windows) so one
//     pattern matches another file.

// embedResult is what the embed analysis tells binaries: the files the
// new tree embeds, and the newly embedded ones with the reason.
type embedResult struct {
	embedded   map[string]bool
	newly      map[string]string
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
			return "possibly embedded by " + u.label + ", which the gate could not resolve", u.isNew
		}
	}
	return "", false
}

// nonASCIIPath: a path element of t is not ASCII.
func nonASCIIPath(t *ecoutil.Tree) bool {
	if t == nil {
		return false
	}
	return slices.ContainsFunc(t.Files, func(f string) bool { return !ascii(f) })
}

// hasEmbedComment: src has a //go:embed comment token (go/scanner), or
// the scanner rejects it and "//go:embed" occurs in it.
func hasEmbedComment(rel string, src []byte) bool {
	dirs, scanErr := scanDirectives(rel, src)
	if scanErr && bytes.Contains(src, []byte("//go:embed")) {
		return true
	}
	return slices.ContainsFunc(dirs, func(d directive) bool { return strings.HasPrefix(d.text, "//go:embed") })
}

// embedFiles are the non-test .go files of t with a //go:embed comment.
func embedFiles(t *ecoutil.Tree) []string {
	if t == nil {
		return nil
	}
	var out []string
	for _, f := range t.Files {
		if path.Ext(f) == ".go" && !strings.HasSuffix(f, "_test.go") && hasEmbedComment(f, t.ReadFile(f)) {
			out = append(out, f)
		}
	}
	return out
}

func packageDirs(files []string) []string {
	set := map[string]bool{}
	for _, f := range files {
		set[path.Dir(f)] = true
	}
	return slices.Sorted(maps.Keys(set))
}

// embeds compares what the two trees embed.
func (r *report) embeds(old, cur *ecoutil.Tree, ob, nb *builtSet) embedResult {
	res := embedResult{embedded: map[string]bool{}, newly: map[string]string{}}
	curFiles := embedFiles(cur)
	if len(curFiles) == 0 {
		return res
	}
	dirs := packageDirs(curFiles)
	item := func(d string) string { return safeFile(d) }
	if nb.unresolved() || ob.unresolved() {
		for _, d := range dirs {
			r.add(codeEmbed, item(d), false, "not resolved: the gate's go/build budget for the module was spent; a person decides\n")
			res.unresolved = append(res.unresolved, unresolvedEmbed{".", "the //go:embed comments of package " + item(d), true})
		}
		return res
	}
	if nonASCIIPath(cur) || nonASCIIPath(old) {
		for _, d := range dirs {
			label := "the //go:embed comments of package " + item(d)
			r.add(codeEmbed, item(d), false, "not resolved: the module has a path with a non-ASCII element, which a consumer's file system may fold or normalize into another name; a person decides\n")
			res.unresolved = append(res.unresolved, unresolvedEmbed{".", label, true})
		}
		return res
	}
	// A file with //go:embed that only a -tags build builds.
	for _, f := range curFiles {
		if nb.anywhere(f) || !nb.possibly(f) || !subtreeChanged(old, cur, path.Dir(f)) {
			continue
		}
		d := path.Dir(f)
		r.add(codeEmbed, item(d), false, quote("not resolved: "+safeFile(f)+" has a //go:embed comment and only a -tags build builds it (go list resolves default builds only), and its directory changed; a person decides", excerptEmbed(cur.ReadFile(f))))
		res.unresolved = append(res.unresolved, unresolvedEmbed{d, "the //go:embed comments of " + safeFile(f), true})
	}
	now := r.lister.listEmbeds(cur, nb, dirs)
	before := r.lister.listEmbeds(old, ob, packageDirs(embedFiles(old)))
	r.listRuns += now.runs + before.runs
	r.listTook += now.took + before.took
	for _, d := range dirs {
		// A name the tree does not list: the file system go list ran on
		// folded or normalized it (macOS, Windows).
		for _, e := range now.embedded(d) {
			if !cur.Has(e) && now.failed[d] == "" {
				now.failed[d] = "go list names " + safeFile(e) + ", which the module's file list does not hold (a case-folding or normalizing file system)"
			}
		}
		if why := now.failed[d]; why != "" {
			r.add(codeEmbed, item(d), false, quote("not resolved (go list gave no answer for the package); a person decides", why))
			res.unresolved = append(res.unresolved, unresolvedEmbed{d, "the //go:embed comments of package " + item(d), true})
			continue
		}
		// Old embeds are credited only from go list's answer for the old
		// package, configuration by configuration.
		var was map[string][]bool
		if before.failed[d] == "" {
			was = before.files[d]
		}
		credit := creditable(old, cur, ob, nb, d)
		for _, e := range now.embedded(d) {
			res.embedded[e] = true
			if !newIn(now.files[d][e], creditedIn(was[e], credit)) {
				continue
			}
			label := "package " + item(d) + " (go list EmbedFiles)"
			data := cur.ReadFile(e)
			if !evidence.IsBinary(data) {
				r.add(codeEmbed, item(d), true, quote("newly embedded by", label)+"newly embedded: "+r.fileRef(e, data))
				continue
			}
			if _, done := res.newly[e]; !done {
				res.newly[e] = "newly embedded by " + label
			}
		}
	}
	return res
}

// subtreeChanged: a file under dir was added, removed or changed.
func subtreeChanged(old, cur *ecoutil.Tree, dir string) bool {
	under := func(f string) bool { return dir == "." || strings.HasPrefix(f, dir+"/") }
	if old == nil {
		return true
	}
	for _, f := range cur.Files {
		if under(f) && (!old.Has(f) || !bytes.Equal(old.ReadFile(f), cur.ReadFile(f))) {
			return true
		}
	}
	for _, f := range old.Files {
		if under(f) && !cur.Has(f) {
			return true
		}
	}
	return false
}

// creditable is, per configuration, whether the old tree's EmbedFiles for
// package dir may be credited: every file the new package takes patterns
// from in that configuration is byte-identical to its old version and
// built in the same configurations. A changed embedding file whose
// constraint consults a tag a consumer can set uncredits every
// configuration: a -tags build can take its patterns anywhere.
func creditable(old, cur *ecoutil.Tree, ob, nb *builtSet, dir string) []bool {
	ok := make([]bool, len(configs))
	for i := range ok {
		ok[i] = old != nil
	}
	for f, in := range nb.embedders[dir] {
		same := old.Has(f) && bytes.Equal(old.ReadFile(f), cur.ReadFile(f)) && ob != nil && slices.Equal(ob.in[f], nb.in[f])
		tagged := nb.userTags[f] || (ob != nil && ob.userTags[f])
		for i, b := range in {
			if !same && (b || tagged) {
				ok[i] = false
			}
		}
	}
	return ok
}

// creditedIn is was restricted to the creditable configurations.
func creditedIn(was, credit []bool) []bool {
	if was == nil {
		return nil
	}
	out := make([]bool, len(was))
	for i := range was {
		out[i] = was[i] && credit[i]
	}
	return out
}

// newIn: some configuration in cur is not in old (nil: none).
func newIn(cur, old []bool) bool {
	for i, b := range cur {
		if b && (old == nil || !old[i]) {
			return true
		}
	}
	return false
}

// excerptEmbed is the //go:embed lines of src.
func excerptEmbed(src []byte) string {
	var b strings.Builder
	for i, line := range strings.Split(string(src), "\n") {
		if strings.Contains(line, "//go:embed") {
			fmt.Fprintf(&b, "%d: %s\n", i+1, line)
		}
	}
	return b.String()
}

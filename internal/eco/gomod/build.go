package gomod

import (
	"bytes"
	_ "embed"
	"errors"
	"go/build"
	"io"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
)

// Which .go files the go command builds is go/build's answer, never the
// gate's (README "Design rules"): build.Context.ImportDir over the
// module tree, for every GOOS/GOARCH of `go tool dist list`, with cgo on
// and off, the gate toolchain's release and tool tags, and no other tags.
// What go/build cannot answer is over-approximated toward flagging more,
// which differs by side: in the new tree, a directory ImportDir fails on
// (two package clauses, an unreadable header) counts every non-test .go
// file in it as built, and so does a file go/build reports invalid; in
// the old tree they count as built nowhere, so none of their text is
// credited.
//
// Tags a consumer sets with -tags (purego, netgo, http2legacy, even
// ignore) are over-approximated: a file no default configuration builds
// counts as possibly built when go/build builds it, alone in its
// directory, with some set of the non-platform tags its constraint
// consults (go/build reports them in AllTags, also for a file it
// excludes), in some configuration. Past maxTagSearch such tags it counts
// as possibly built without searching. The gate never parses a
// constraint itself.

//go:embed distlist.txt
var distList string

// config is one build configuration.
type config struct {
	goos, goarch string
	cgo          bool
}

// configs is every dist-list platform with cgo off and on.
var configs = func() []config {
	var out []config
	for _, p := range strings.Fields(distList) {
		goos, goarch, _ := strings.Cut(p, "/")
		out = append(out, config{goos, goarch, false}, config{goos, goarch, true})
	}
	return out
}()

// maxTagSearch bounds the non-platform tags whose subsets are searched
// for one file; maxTagWork bounds the ImportDir calls of the search over
// one tree. Past either, a file counts as possibly built.
const (
	maxTagSearch = 10
	maxTagWork   = 200_000
)

// builtSet is, per non-test .go file, the configurations that build it
// with default tags, and whether some -tags set can build it.
type builtSet struct {
	in       map[string][]bool // rel -> per configs index
	possible map[string]bool   // rel -> built by no default configuration, but by some -tags set
	errs     map[string]string // package dir -> first ImportDir error over-approximated
	took     time.Duration
}

// possibly: some configuration builds rel with default tags or with some
// -tags set.
func (b *builtSet) possibly(rel string) bool {
	return b != nil && (b.anywhere(rel) || b.possible[rel])
}

// anywhere: some configuration builds rel.
func (b *builtSet) anywhere(rel string) bool {
	return b != nil && slices.Contains(b.in[rel], true)
}

// everywhere: every configuration builds rel.
func (b *builtSet) everywhere(rel string) bool {
	return b != nil && len(b.in[rel]) == len(configs) && !slices.Contains(b.in[rel], false)
}

// newlyBuilt: some default configuration builds rel in cur but did not
// in old (old nil or without rel: every configuration that builds it), or
// some -tags set can build it in cur and none could in old. Such a file
// enters that build with whatever text it has, so it is checked as new:
// none of its old text is credited. (Possibly built in both does not
// credit by itself: an old //go:build ignore file is possibly built, and
// its text newly enters the default build when the line goes.)
func newlyBuilt(old, cur *builtSet, rel string) bool {
	if cur.possibly(rel) && !old.possibly(rel) {
		return true
	}
	n := cur.in[rel]
	var o []bool
	if old != nil {
		o = old.in[rel]
	}
	for i, b := range n {
		if b && (o == nil || !o[i]) {
			return true
		}
	}
	return false
}

// treeFS serves an ecoutil.Tree to go/build: only the tree's listed
// files exist, read once.
type treeFS struct {
	t    *ecoutil.Tree
	dirs map[string][]fs.FileInfo
	data map[string][]byte
}

type fileInfo struct {
	name string
	dir  bool
	size int64
}

func (f fileInfo) Name() string { return f.name }
func (f fileInfo) Size() int64  { return f.size }
func (f fileInfo) Mode() fs.FileMode {
	if f.dir {
		return fs.ModeDir | 0o755
	}
	return 0o644
}
func (f fileInfo) ModTime() time.Time { return time.Time{} }
func (f fileInfo) IsDir() bool        { return f.dir }
func (f fileInfo) Sys() any           { return nil }

func newTreeFS(t *ecoutil.Tree) *treeFS {
	tf := &treeFS{t: t, dirs: map[string][]fs.FileInfo{".": nil}, data: map[string][]byte{}}
	seen := map[string]bool{}
	add := func(dir string, fi fileInfo) {
		if k := dir + "\x00" + fi.name; !seen[k] {
			seen[k] = true
			tf.dirs[dir] = append(tf.dirs[dir], fi)
		}
	}
	for _, f := range t.Files {
		add(path.Dir(f), fileInfo{name: path.Base(f)})
		for d := path.Dir(f); d != "."; d = path.Dir(d) {
			add(path.Dir(d), fileInfo{name: path.Base(d), dir: true})
			if tf.dirs[d] == nil {
				tf.dirs[d] = []fs.FileInfo{}
			}
		}
	}
	for _, fis := range tf.dirs {
		slices.SortFunc(fis, func(a, b fs.FileInfo) int { return strings.Compare(a.Name(), b.Name()) })
	}
	return tf
}

func (tf *treeFS) read(rel string) []byte {
	if b, ok := tf.data[rel]; ok {
		return b
	}
	b := tf.t.ReadFile(rel)
	tf.data[rel] = b
	return b
}

func (tf *treeFS) context(c config) *build.Context {
	ctxt := build.Default
	ctxt.GOOS, ctxt.GOARCH, ctxt.CgoEnabled = c.goos, c.goarch, c.cgo
	ctxt.GOROOT, ctxt.GOPATH, ctxt.Dir = "", "", ""
	ctxt.BuildTags = nil
	ctxt.ReleaseTags = slices.Clone(build.Default.ReleaseTags)
	ctxt.ToolTags = slices.Clone(build.Default.ToolTags)
	ctxt.UseAllFiles = false
	ctxt.JoinPath = func(elem ...string) string { return path.Join(elem...) }
	ctxt.SplitPathList = func(string) []string { return nil }
	ctxt.IsAbsPath = func(string) bool { return false }
	ctxt.IsDir = func(p string) bool { _, ok := tf.dirs[path.Clean(p)]; return ok }
	ctxt.HasSubdir = func(string, string) (string, bool) { return "", false }
	ctxt.ReadDir = func(dir string) ([]fs.FileInfo, error) {
		fis, ok := tf.dirs[path.Clean(dir)]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return fis, nil
	}
	ctxt.OpenFile = func(p string) (io.ReadCloser, error) {
		p = path.Clean(p)
		if !tf.t.Has(p) {
			return nil, fs.ErrNotExist
		}
		return io.NopCloser(bytes.NewReader(tf.read(p))), nil
	}
	return &ctxt
}

// analyzeBuild runs go/build over every package directory of t (a
// directory with a .go file) in every configuration. old selects the
// old tree's over-approximation (built nowhere) for what go/build cannot
// answer.
func analyzeBuild(t *ecoutil.Tree, old bool) *builtSet {
	if t == nil {
		return nil
	}
	start := time.Now()
	b := &builtSet{in: map[string][]bool{}, possible: map[string]bool{}, errs: map[string]string{}}
	tf := newTreeFS(t)
	goFiles := map[string][]string{} // dir -> its non-test .go files
	for _, f := range t.Files {
		if path.Ext(f) == ".go" && !strings.HasSuffix(f, "_test.go") {
			goFiles[path.Dir(f)] = append(goFiles[path.Dir(f)], f)
			b.in[f] = make([]bool, len(configs))
		}
	}
	for i, c := range configs {
		ctxt := tf.context(c)
		for dir, files := range goFiles {
			p, err := ctxt.ImportDir(dir, 0)
			var noGo *build.NoGoError
			switch {
			case err == nil:
			case errors.As(err, &noGo):
				continue
			default:
				// New tree: every non-test .go file is built. Old tree:
				// none is.
				if b.errs[dir] == "" {
					b.errs[dir] = err.Error()
				}
				for _, f := range files {
					b.in[f][i] = !old
				}
				continue
			}
			lists := [][]string{p.GoFiles, p.CgoFiles}
			if !old {
				lists = append(lists, p.InvalidGoFiles)
			}
			for _, names := range lists {
				for _, n := range names {
					if rel := path.Join(dir, n); b.in[rel] != nil {
						b.in[rel][i] = true
					}
				}
			}
		}
	}
	work := 0
	for dir, files := range goFiles {
		if old && b.errs[dir] != "" {
			continue // the old tree's failed directory: built nowhere
		}
		for _, f := range files {
			if !b.anywhere(f) && tf.possiblyBuilt(f, old, &work) {
				b.possible[f] = true
			}
		}
	}
	b.took = time.Since(start)
	return b
}

// platformTags are tags -tags cannot meaningfully set: the GOOS and GOARCH
// values (one configuration fixes them), unix and cgo (implied by it).
var platformTags = func() map[string]bool {
	m := map[string]bool{"unix": true, "cgo": true}
	for _, c := range configs {
		m[c.goos], m[c.goarch] = true, true
	}
	return m
}()

// possiblyBuilt: go/build builds rel, alone in its directory, in some
// configuration with some set of the non-platform tags it consults.
func (tf *treeFS) possiblyBuilt(rel string, old bool, work *int) bool {
	dir, name := path.Dir(rel), path.Base(rel)
	built := func(p *build.Package) bool {
		lists := [][]string{p.GoFiles, p.CgoFiles}
		if !old {
			lists = append(lists, p.InvalidGoFiles)
		}
		for _, l := range lists {
			if slices.Contains(l, name) {
				return true
			}
		}
		return false
	}
	tagSet := map[string]bool{}
	for _, c := range configs {
		p, _ := tf.alone(c, rel, nil).ImportDir(dir, 0)
		*work++
		if p == nil {
			continue
		}
		for _, tag := range p.AllTags {
			if !platformTags[tag] {
				tagSet[tag] = true
			}
		}
	}
	tags := slices.Sorted(maps.Keys(tagSet))
	if len(tags) > maxTagSearch {
		return true
	}
	for mask := 1; mask < 1<<len(tags); mask++ {
		var set []string
		for i, tag := range tags {
			if mask&(1<<i) != 0 {
				set = append(set, tag)
			}
		}
		for _, c := range configs {
			if *work++; *work > maxTagWork {
				return true
			}
			if p, _ := tf.alone(c, rel, set).ImportDir(dir, 0); p != nil && built(p) {
				return true
			}
		}
	}
	return false
}

// alone is the context for configuration c with -tags set, in which rel's
// directory holds only rel.
func (tf *treeFS) alone(c config, rel string, set []string) *build.Context {
	ctxt := tf.context(c)
	ctxt.BuildTags = set
	dir := path.Dir(rel)
	var only []fs.FileInfo
	for _, fi := range tf.dirs[dir] {
		if fi.Name() == path.Base(rel) {
			only = append(only, fi)
		}
	}
	read := ctxt.ReadDir
	ctxt.ReadDir = func(d string) ([]fs.FileInfo, error) {
		if path.Clean(d) == dir {
			return only, nil
		}
		return read(d)
	}
	return ctxt
}

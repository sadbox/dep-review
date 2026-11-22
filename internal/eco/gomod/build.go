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
	"sync"
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
// ignore) are over-approximated from go/build's AllTags for each file
// alone in its directory (reported also for a file it excludes): a
// changed file whose constraint consults such a tag in either tree is
// checked as new (newlyBuilt), and a file no default configuration builds
// counts as possibly built when go/build builds it with some subset of
// those tags in some configuration. The gate never parses a constraint.

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

// Bounds on the go/build work over one tree. Past maxBuildWork ImportDir
// calls or maxBuildTime, the tree is unresolved (builtSet.over): every
// file counts as newly built and every embed goes to a person. Within
// them, a file whose -tags search passes maxTagSearch tags or the tree's
// maxTagWork search calls counts as possibly built. Variables for tests.
var (
	maxTagSearch = 10
	maxTagWork   = 200_000
	maxBuildWork = 2_000_000
	maxBuildTime = 2 * time.Minute
)

// builtSet is, per non-test .go file, the configurations that build it
// with default tags, whether some -tags set can build it, and whether
// its constraint consults a tag a consumer can set.
type builtSet struct {
	in       map[string][]bool // rel -> per configs index
	possible map[string]bool   // rel -> built by no default configuration, but by some -tags set
	// userTags: go/build's AllTags for the file, alone in its directory,
	// hold a tag that is not a platform tag (platformTag).
	userTags map[string]bool
	// embedders are, per package directory, the files go/build reports
	// //go:embed patterns from (EmbedPatternPos), per configuration.
	embedders map[string]map[string][]bool
	errs      map[string]string // package dir -> first ImportDir error over-approximated
	over      bool              // the work or time budget was spent: nothing is resolved
	took      time.Duration
}

// unresolved: the budget was spent on this tree.
func (b *builtSet) unresolved() bool { return b != nil && b.over }

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

// newlyBuilt reports that none of rel's old text may be credited: it is
// checked as new. In order:
//   - either tree past its budget: nothing is credited, not even an
//     identical file;
//   - a byte-identical file (identical) keeps its credit;
//   - a file whose constraint, in either tree, consults a tag a consumer
//     can set (-tags purego, netgo, ignore...): which builds include it
//     can change with that tag in ways the default configurations do not
//     show (linux -> linux || purego newly builds on darwin with purego),
//     and per-tag-set state is not tracked;
//   - a file no default configuration builds in cur;
//   - otherwise, a file some default configuration builds in cur that did
//     not build it in old.
func newlyBuilt(old, cur *builtSet, rel string, identical bool) bool {
	if cur.unresolved() || old.unresolved() {
		return true
	}
	if identical {
		return false
	}
	if cur.userTags[rel] || (old != nil && old.userTags[rel]) {
		return true
	}
	if !cur.anywhere(rel) {
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
	info map[string]fs.FileInfo // rel -> its entry
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
	tf := &treeFS{t: t, dirs: map[string][]fs.FileInfo{".": nil}, info: map[string]fs.FileInfo{}, data: map[string][]byte{}}
	seen := map[string]bool{}
	add := func(dir string, fi fileInfo) {
		if k := dir + "\x00" + fi.name; !seen[k] {
			seen[k] = true
			tf.dirs[dir] = append(tf.dirs[dir], fi)
		}
	}
	for _, f := range t.Files {
		tf.info[f] = fileInfo{name: path.Base(f)}
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
// directory with a .go file) in every configuration, then over each
// non-test .go file alone for the tags its constraint consults. old
// selects the old tree's over-approximation (built nowhere) for what
// go/build cannot answer.
func analyzeBuild(t *ecoutil.Tree, old bool) *builtSet {
	if t == nil {
		return nil
	}
	start := time.Now()
	b := &builtSet{in: map[string][]bool{}, possible: map[string]bool{}, userTags: map[string]bool{},
		embedders: map[string]map[string][]bool{}, errs: map[string]string{}}
	defer func() { b.took = time.Since(start) }()
	tf := newTreeFS(t)
	w := &work{deadline: start.Add(maxBuildTime)}
	goFiles := map[string][]string{} // dir -> its non-test .go files
	for _, f := range t.Files {
		if path.Ext(f) == ".go" && !strings.HasSuffix(f, "_test.go") {
			goFiles[path.Dir(f)] = append(goFiles[path.Dir(f)], f)
			b.in[f] = make([]bool, len(configs))
		}
	}
	dirs := slices.Sorted(maps.Keys(goFiles))
	for i, c := range configs {
		ctxt := tf.context(c)
		for _, dir := range dirs {
			if w.spent() {
				b.over = true
				return b
			}
			files := goFiles[dir]
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
			for _, poss := range p.EmbedPatternPos {
				for _, pos := range poss {
					rel := path.Join(dir, path.Base(pos.Filename))
					if b.embedders[dir] == nil {
						b.embedders[dir] = map[string][]bool{}
					}
					if b.embedders[dir][rel] == nil {
						b.embedders[dir][rel] = make([]bool, len(configs))
					}
					b.embedders[dir][rel][i] = true
				}
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
	for _, dir := range dirs {
		for _, f := range goFiles[dir] {
			tags := tf.fileTags(f, w)
			if w.spent() {
				b.over = true
				return b
			}
			b.userTags[f] = slices.ContainsFunc(tags, func(tag string) bool { return !platformTag(tag) })
			if old && b.errs[dir] != "" {
				continue // the old tree's failed directory: built nowhere
			}
			if !b.anywhere(f) && tf.possiblyBuilt(f, tags, old, w) {
				b.possible[f] = true
			}
			if w.spent() {
				b.over = true
				return b
			}
		}
	}
	return b
}

// work counts go/build calls over one tree against the budgets.
type work struct {
	calls, tagCalls int
	deadline        time.Time
}

func (w *work) spent() bool {
	return w.calls > maxBuildWork || time.Now().After(w.deadline)
}

// platformTag: a tag one configuration fixes or the toolchain sets, which
// -tags does not meaningfully change: a GOOS or GOARCH value go/build
// knows (also one without a dist port, such as zos), go1.N, cgo, unix,
// gc, gccgo. Every other tag (purego, netgo, ignore, goexperiment.*,
// amd64.v3, ...) a consumer can set.
func platformTag(tag string) bool {
	if platformTags[tag] || knownGOOSOrGOARCH(tag) {
		return true
	}
	if v, ok := strings.CutPrefix(tag, "go1."); ok && v != "" && strings.Trim(v, "0123456789") == "" {
		return true
	}
	return false
}

var platformTags = func() map[string]bool {
	m := map[string]bool{"unix": true, "cgo": true, "gc": true, "gccgo": true}
	for k := range fixedTags {
		m[k] = true
	}
	return m
}()

// knownGOOSOrGOARCH asks go/build whether it knows tag as a GOOS or
// GOARCH value: it then treats a _tag.go file name suffix as a
// constraint, and excludes x_tag.go from a build for another platform.
func knownGOOSOrGOARCH(tag string) bool {
	knownMu.Lock()
	defer knownMu.Unlock()
	if v, ok := known[tag]; ok {
		return v
	}
	ctxt := build.Default
	ctxt.BuildTags, ctxt.CgoEnabled = nil, false
	ctxt.GOOS, ctxt.GOARCH = "linux", "amd64"
	if tag == "linux" || tag == "amd64" {
		ctxt.GOOS, ctxt.GOARCH = "windows", "arm64"
	}
	ctxt.OpenFile = func(string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("package p\n")), nil
	}
	ok, err := ctxt.MatchFile("d", "x_"+tag+".go")
	v := err == nil && !ok
	known[tag] = v
	return v
}

var (
	knownMu sync.Mutex
	known   = map[string]bool{}
)

// fixedTags are the tags a configuration fixes, which a tag search does
// not set: the GOOS and GOARCH values, unix and cgo.
var fixedTags = func() map[string]bool {
	m := map[string]bool{"unix": true, "cgo": true}
	for _, c := range configs {
		m[c.goos], m[c.goarch] = true, true
	}
	return m
}()

// fileTags are the tags go/build consults for rel alone in its
// directory, but for fixedTags (a search may set go1.99: a later
// toolchain does), over every GOOS/GOARCH (a file name suffix can stop
// go/build before it reads the constraint; cgo does not, and constraint
// evaluation observes every tag).
func (tf *treeFS) fileTags(rel string, w *work) []string {
	dir := path.Dir(rel)
	set := map[string]bool{}
	for _, c := range configs {
		if c.cgo {
			continue
		}
		if w.calls++; w.spent() {
			return nil
		}
		p, _ := tf.alone(c, rel, nil).ImportDir(dir, 0)
		if p == nil {
			continue
		}
		for _, tag := range p.AllTags {
			if !fixedTags[tag] {
				set[tag] = true
			}
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// possiblyBuilt: go/build builds rel, alone in its directory, in some
// configuration with some subset of tags (fileTags) set.
func (tf *treeFS) possiblyBuilt(rel string, tags []string, old bool, w *work) bool {
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
			w.calls++
			if w.tagCalls++; w.tagCalls > maxTagWork || w.spent() {
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
	only := []fs.FileInfo{tf.info[rel]}
	read := ctxt.ReadDir
	ctxt.ReadDir = func(d string) ([]fs.FileInfo, error) {
		if path.Clean(d) == dir {
			return only, nil
		}
		return read(d)
	}
	return ctxt
}

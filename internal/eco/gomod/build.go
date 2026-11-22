package gomod

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
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

// Which .go files the go command builds is the toolchain's answer, never
// the gate's (README "Design rules"): go list for every package directory
// with a //go:embed comment (golist.go), build.Context.ImportDir over the
// module tree for the others, for every GOOS/GOARCH of `go tool dist
// list`, with cgo on and off, the gate toolchain's release tags and each
// target's own tool tags (toolTags), and no other tags.
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
	tags         []string // -tags (a declared tag set; none by default)
}

// configs is every dist-list platform with cgo off and on.
var configs = func() []config {
	var out []config
	for _, p := range strings.Fields(distList) {
		goos, goarch, _ := strings.Cut(p, "/")
		out = append(out, config{goos: goos, goarch: goarch}, config{goos: goos, goarch: goarch, cgo: true})
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
// its constraint consults a tag a consumer can set. in also holds the
// assembly and .syso files of each package directory: built in a
// configuration when the toolchain lists them (SFiles, SysoFiles) and the
// package builds there (it has Go or cgo files to build); a package whose
// Go files a configuration excludes still lists its .s files.
type builtSet struct {
	// cfgs are the configurations evaluated (configs, or a repository's
	// declared ones, each with its tag set); declared: the repository
	// declared them, so -tags do not vary between consumers.
	cfgs     []config
	declared bool
	// cgoDirs: package directories some configuration builds cgo files of
	// (only true entries).
	cgoDirs map[string]bool
	in      map[string][]bool // rel -> per cfgs index
	// linkFiles are, per package directory, its .s, .S, .sx and .syso
	// files.
	linkFiles map[string][]string
	possible  map[string]bool // rel -> built by no default configuration, but by some -tags set
	// userTags: go/build's AllTags for the file, alone in its directory,
	// hold a tag that is not a platform tag (platformTag).
	userTags map[string]bool
	// embedders are, per package directory with a //go:embed comment, the
	// files go list builds there that hold one, per configuration.
	embedders map[string]map[string][]bool
	// embedFiles are go list's EmbedFiles per package directory, per
	// configuration; embedFailed the directories it gave no answer for.
	embedFiles  map[string]map[string][]bool
	embedFailed map[string]string
	errs        map[string]string // package dir -> first ImportDir error over-approximated
	over        bool              // a budget was spent or the toolchain gave no tool tags: nothing is resolved
	overWhy     string
	listRuns    int
	listTook    time.Duration
	took        time.Duration
	tf          *treeFS
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
	return b != nil && len(b.in[rel]) == len(b.cfgs) && !slices.Contains(b.in[rel], false)
}

// newlyBuilt reports that none of rel's old text may be credited: it is
// checked as new. In order:
//   - either tree unresolved: nothing is credited, not even an identical
//     file;
//   - some default configuration builds rel in cur that did not build it
//     in old (an old directory go/build or go list failed on built
//     nothing), or a -tags build can build it in exactly one tree: also
//     for a byte-identical file, which newly enters a build when a
//     sibling's package clause is fixed;
//   - a byte-identical file (identical) otherwise keeps its credit;
//   - a file whose constraint, in either tree, consults a tag that varies
//     between consumers (anything but a GOOS or GOARCH value, unix, cgo
//     and gc: -tags, go1.N for older and newer toolchains, gccgo, GOARCH
//     feature levels, GOEXPERIMENT): which builds include it can change in
//     ways the gate's configurations do not show;
//   - a file no default configuration builds in cur.
//
// Known limit (README "Design rules"): the -tags search looks at rel
// alone, so under a non-default tag an identical file that a sibling's fix
// makes buildable (the old package did not build with that tag) keeps its
// credit.
func newlyBuilt(old, cur *builtSet, rel string, identical bool) bool {
	if cur.unresolved() || old.unresolved() {
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
	if cur.possibly(rel) != old.possibly(rel) {
		return true
	}
	if identical {
		return false
	}
	if cur.userTags[rel] || (old != nil && old.userTags[rel]) {
		return true
	}
	return !cur.anywhere(rel)
}

// treeFS serves an ecoutil.Tree to go/build: only the tree's listed
// files exist, read once.
type treeFS struct {
	t    *ecoutil.Tree
	dirs map[string][]fs.FileInfo
	info map[string]fs.FileInfo // rel -> its entry
	data map[string][]byte
	tt   map[string][]string // GOOS/GOARCH -> the toolchain's tool tags
	mu   sync.Mutex
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
	tf.mu.Lock()
	defer tf.mu.Unlock()
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
	ctxt.BuildTags = slices.Clone(c.tags)
	ctxt.ReleaseTags = slices.Clone(build.Default.ReleaseTags)
	ctxt.ToolTags = slices.Clone(tf.tt[c.goos+"/"+c.goarch])
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
// directory with a .go file) in every configuration, go list over those
// with a //go:embed comment, then go/build over each non-test .go file
// alone for the tags its constraint consults. old selects the old tree's
// over-approximation (built nowhere) for what neither can answer.
func analyzeBuild(t *ecoutil.Tree, old bool, l goLister) *builtSet {
	if t == nil {
		return nil
	}
	start := time.Now()
	b := &builtSet{cfgs: l.configs(), cgoDirs: map[string]bool{}, in: map[string][]bool{}, possible: map[string]bool{}, userTags: map[string]bool{},
		embedders: map[string]map[string][]bool{}, embedFiles: map[string]map[string][]bool{}, embedFailed: map[string]string{},
		errs: map[string]string{}, linkFiles: map[string][]string{}}
	defer func() { b.took = time.Since(start) }()
	b.declared = l.plan != nil
	tf := newTreeFS(t)
	b.tf = tf
	tt, err := l.toolTags()
	if err != nil {
		b.over, b.overWhy = true, err.Error()
		return b
	}
	tf.tt = tt
	w := &work{deadline: start.Add(maxBuildTime)}
	goFiles := map[string][]string{} // dir -> its non-test .go files
	for _, f := range t.Files {
		if path.Ext(f) == ".go" && !strings.HasSuffix(f, "_test.go") {
			goFiles[path.Dir(f)] = append(goFiles[path.Dir(f)], f)
			b.in[f] = make([]bool, len(b.cfgs))
		}
	}
	for _, f := range t.Files {
		if _, ok := goFiles[path.Dir(f)]; ok && linkedExt(f) {
			b.linkFiles[path.Dir(f)] = append(b.linkFiles[path.Dir(f)], f)
			b.in[f] = make([]bool, len(b.cfgs))
		}
	}
	dirs := slices.Sorted(maps.Keys(goFiles))
	for i, c := range b.cfgs {
		ctxt := tf.context(c)
		for _, dir := range dirs {
			if w.spent() {
				b.over, b.overWhy = true, "the go/build work or time budget is spent"
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
				// New tree: every non-test .go, .s and .syso file is built.
				// Old tree: none is.
				if b.errs[dir] == "" {
					b.errs[dir] = err.Error()
				}
				for _, f := range append(slices.Clone(files), b.linkFiles[dir]...) {
					b.in[f][i] = !old
				}
				if !old {
					b.cgoDirs[dir] = true
				}
				continue
			}
			b.recordLinked(dir, i, len(p.GoFiles)+len(p.CgoFiles) > 0, p.SFiles, p.SysoFiles)
			// cgo files, or SWIG files (cmd/go then compiles the
			// package's C as for cgo).
			if len(p.CgoFiles)+len(p.SwigFiles)+len(p.SwigCXXFiles) > 0 {
				b.cgoDirs[dir] = true
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
	// Directories with a //go:embed comment: go list's answer replaces
	// go/build's.
	var embedDirs []string
	for _, dir := range dirs {
		if slices.ContainsFunc(goFiles[dir], func(f string) bool { return hasEmbedComment(f, tf.read(f)) }) {
			embedDirs = append(embedDirs, dir)
		}
	}
	if len(embedDirs) > 0 {
		l.listDirs(t, b, embedDirs, old, goFiles)
	}
	for _, dir := range dirs {
		for _, f := range goFiles[dir] {
			tags := tf.fileTags(f, w)
			if w.spent() {
				b.over, b.overWhy = true, "the go/build work or time budget is spent"
				return b
			}
			varies := func(tag string) bool { return !platformTag(tag) }
			if b.declared {
				// Declared builds fix -tags, not the toolchain: go1.N,
				// GOARCH feature levels, gccgo and GOEXPERIMENT still vary.
				varies = toolchainTag
			}
			b.userTags[f] = slices.ContainsFunc(tags, varies)
			if b.declared {
				continue
			}
			if old && b.errs[dir] != "" {
				continue // the old tree's failed directory: built nowhere
			}
			if !b.anywhere(f) && tf.possiblyBuilt(f, tags, old, w) {
				b.possible[f] = true
			}
			if w.spent() {
				b.over, b.overWhy = true, "the go/build work or time budget is spent"
				return b
			}
		}
	}
	return b
}

// linkDirsNewlyBuilt are the package directories whose assembly and
// .syso files count as newly built whatever their own analysis says: a Go
// file of the directory is newly built (newlyBuilt), or possibly built in
// one tree and not the other. A link file gets only the default-tag
// analysis, not the -tags search, so a package that builds only under a
// user tag (//go:build ignore turned //go:build purego) newly assembles
// it unseen otherwise. Fail closed.
func linkDirsNewlyBuilt(old, cur *ecoutil.Tree, ob, nb *builtSet) map[string]bool {
	out := map[string]bool{}
	if nb == nil {
		return out
	}
	for dir := range nb.linkFiles {
		for _, f := range cur.Files {
			if path.Dir(f) != dir || path.Ext(f) != ".go" || strings.HasSuffix(f, "_test.go") {
				continue
			}
			identical := old.Has(f) && bytes.Equal(old.ReadFile(f), cur.ReadFile(f))
			if newlyBuilt(ob, nb, f, identical) || nb.possibly(f) != ob.possibly(f) {
				out[dir] = true
				break
			}
		}
	}
	return out
}

// linkedExt: an assembly or .syso file, which the toolchain assembles or
// links into its package.
func linkedExt(f string) bool {
	switch path.Ext(f) {
	case ".s", ".S", ".sx", ".syso":
		return true
	}
	return false
}

// recordLinked sets, for configuration i, the assembly and .syso files of
// dir that are built: those listed, when the package builds.
func (b *builtSet) recordLinked(dir string, i int, builds bool, lists ...[]string) {
	listed := map[string]bool{}
	for _, l := range lists {
		for _, n := range l {
			listed[path.Join(dir, n)] = true
		}
	}
	for _, f := range b.linkFiles[dir] {
		b.in[f][i] = builds && listed[f]
	}
}

// work counts go/build calls over one tree against the budgets.
type work struct {
	calls, tagCalls int
	deadline        time.Time
}

func (w *work) spent() bool {
	return w.calls > maxBuildWork || time.Now().After(w.deadline)
}

// platformTag: a tag one configuration fixes, the same for every
// consumer building it: exactly a GOOS or GOARCH value go/build knows
// (also one without a dist port, such as zos; no "." or "_", which the
// file-name probe would cut at), unix, cgo, gc. Every other tag varies
// between consumers: -tags (purego, netgo, ignore, foo_windows,
// windows.x), go1.N (older and newer toolchains), gccgo, GOARCH feature
// levels (amd64.v3, arm.7, arm64.v9.0, ppc64le.power9, 386.sse2: GOAMD64,
// GOARM, ...), goexperiment.* (GOEXPERIMENT).
func platformTag(tag string) bool {
	return platformTags[tag] || (!strings.ContainsAny(tag, "._") && knownGOOSOrGOARCH(tag))
}

var platformTags = func() map[string]bool {
	m := map[string]bool{"unix": true, "cgo": true, "gc": true}
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
	// Every subset, the empty one included: with a set given, alone turns
	// off every consulted tag the subset does not turn on (go1.27, a
	// default GOEXPERIMENT, arm.7 included).
	for mask := 0; mask < 1<<len(tags); mask++ {
		set := []string{}
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

// alone is the context for configuration c, in which rel's directory
// holds only rel. With set nil, it has the configuration's default tags.
// With set given, the -tags search: exactly set is on beyond the fixed
// tags (GOOS, GOARCH, unix, cgo) and gc; release and tool tags a
// toolchain sets by default (go1.27, goexperiment.greenteagc, arm.7) are
// off unless set turns them on, as an older toolchain, GOEXPERIMENT or
// GOARM can make them.
func (tf *treeFS) alone(c config, rel string, set []string) *build.Context {
	ctxt := tf.context(c)
	ctxt.BuildTags = set
	if set != nil {
		strip := func(l []string) []string {
			return slices.DeleteFunc(slices.Clone(l), func(t string) bool { return !fixedTags[t] && t != "gc" })
		}
		ctxt.ReleaseTags, ctxt.ToolTags = strip(ctxt.ReleaseTags), strip(ctxt.ToolTags)
	}
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

// BuildPlan is a repository's declared builds (gate inputs go_platforms
// and go_tags): each platform, cgo off and on, with no tags and with each
// declared tag set.
type BuildPlan struct {
	cfgs []config
}

// Bounds on a declared plan.
const (
	maxPlanPlatforms = 20
	maxPlanTagSets   = 4
	maxPlanTags      = 10 // per set
)

// ParseBuildPlan validates the declared platforms (GOOS/GOARCH pairs of
// the gate toolchain's dist list, separated by commas or spaces) and tag
// sets (separated by spaces or ";", the tags of one set by commas; each
// tag letters, digits, "_" and "."). Every platform is evaluated with no
// tags as well. Both empty: no plan (nil).
func ParseBuildPlan(platforms, tagSets string) (*BuildPlan, error) {
	ps := strings.FieldsFunc(platforms, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' })
	sets := strings.FieldsFunc(tagSets, func(r rune) bool { return r == ';' || r == ' ' || r == '\n' || r == '\t' })
	if len(ps) == 0 {
		if len(sets) > 0 {
			return nil, errors.New("go_tags needs go_platforms")
		}
		return nil, nil
	}
	if len(ps) > maxPlanPlatforms || len(sets) > maxPlanTagSets {
		return nil, fmt.Errorf("at most %d platforms and %d tag sets", maxPlanPlatforms, maxPlanTagSets)
	}
	variants := [][]string{nil}
	for _, set := range sets {
		var tags []string
		for _, t := range strings.Split(set, ",") {
			if t == "" || strings.Trim(t, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.") != "" {
				return nil, fmt.Errorf("%q is not a build tag", t)
			}
			if !slices.Contains(tags, t) {
				tags = append(tags, t)
			}
		}
		if len(tags) > maxPlanTags {
			return nil, fmt.Errorf("at most %d tags in a set", maxPlanTags)
		}
		variants = append(variants, tags)
	}
	plan := &BuildPlan{}
	seen := map[string]bool{}
	for _, p := range ps {
		if seen[p] {
			continue
		}
		seen[p] = true
		var found bool
		for _, c := range configs {
			if c.goos+"/"+c.goarch != p {
				continue
			}
			found = true
			for _, tags := range variants {
				v := c
				v.tags = tags
				plan.cfgs = append(plan.cfgs, v)
			}
		}
		if !found {
			return nil, fmt.Errorf("%q is not a GOOS/GOARCH of the gate's toolchain", p)
		}
	}
	return plan, nil
}

// declaredUnbuilt is, under declared builds, every file of cur no
// declared configuration compiles, so the checks skip it:
//   - a non-test .go or a .syso file go/build or go list builds in none of
//     them: Go source and linker objects are never included by name;
//   - C, C++ and other cgo sources, when no package builds cgo or SWIG
//     files in any of them and the module has no assembly (which can
//     #include them).
//
// Assembly is never skipped: a built .s can include another under any
// spelling. Nor is a file whose constraint consults a tag the toolchain
// sets (userTags: another Go version or GOAMD64 builds it), C when such a
// file uses cgo, a .syso beside one, anything go
// list embeds in some configuration, or anything in a package whose
// embeds go list did not resolve. Nothing is skipped without a plan, or
// when the tree is unresolved.
func declaredUnbuilt(cur *ecoutil.Tree, nb *builtSet) map[string]bool {
	out := map[string]bool{}
	if nb == nil || !nb.declared || nb.unresolved() {
		return out
	}
	embedded := map[string]bool{}
	for _, files := range nb.embedFiles {
		for f := range files {
			embedded[f] = true
		}
	}
	unresolvedEmbed := func(rel string) bool {
		for d := range nb.embedFailed {
			if d == "." || rel == d || strings.HasPrefix(rel, d+"/") {
				return true
			}
		}
		return false
	}
	asm := slices.ContainsFunc(cur.Files, func(f string) bool {
		ext := path.Ext(f)
		return ext == ".s" || ext == ".S" || ext == ".sx"
	})
	// Whether a package builds cgo or links a .syso is go/build's answer
	// at the gate toolchain's defaults; a .go file another toolchain
	// builds (userTags) can change it: then its cgo counts, and no .syso
	// of its directory is skipped.
	varied := map[string]bool{} // directories with a userTags .go file
	cgo := len(nb.cgoDirs) > 0
	for _, rel := range cur.Files {
		if path.Ext(rel) == ".go" && nb.userTags[rel] {
			varied[path.Dir(rel)] = true
			text := cur.ReadFile(rel)
			cgo = cgo || bytes.Contains(text, []byte(`"C"`)) || bytes.Contains(text, []byte("#cgo"))
		}
	}
	cSkippable := !cgo && !asm
	for _, rel := range cur.Files {
		if embedded[rel] || unresolvedEmbed(rel) || nb.userTags[rel] {
			continue
		}
		ext := path.Ext(rel)
		switch {
		case nb.in[rel] != nil && ext == ".go":
			out[rel] = !nb.anywhere(rel)
		case nb.in[rel] != nil && ext == ".syso":
			out[rel] = !nb.anywhere(rel) && !varied[path.Dir(rel)]
		case cgoSourceExts[ext]:
			out[rel] = cSkippable
		}
	}
	return out
}

// toolchainTag: a build tag the toolchain, not -tags, sets: a release
// tag (go1.N), a GOARCH feature level (amd64.v3, arm.7), gccgo, a
// GOEXPERIMENT. These vary between consumers whatever they declare.
func toolchainTag(tag string) bool {
	if strings.HasPrefix(tag, "go1.") || strings.HasPrefix(tag, "goexperiment.") || tag == "gccgo" {
		return true
	}
	arch, _, ok := strings.Cut(tag, ".")
	return ok && knownGOOSOrGOARCH(arch)
}

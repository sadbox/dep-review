package gomod

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
)

// What a package embeds, and which of its files a configuration builds,
// is go list's answer (README "Design rules"). go list runs over a copy
// of the tree holding only the files the gate lists, with a go.mod the
// gate writes (module gate.invalid/m, the gate toolchain's go version, no
// requirements): embed resolution and file selection depend only on the
// package directory's files, and the module's own go.mod could name a
// newer toolchain or a replace directory outside the tree. Dependencies
// are missing (GOPROXY=off); go list -e still answers for every package.
//
// Plain go list (no -compiled, -export or -test) runs neither cgo nor any
// module code, also with CGO_ENABLED=1 (TestGoListRunsNoCompiler).
//
// go list runs in every dist-list configuration, cgo on and off, over
// every package directory with a //go:embed comment, several at a time
// (x/net v0.61.0 and v0.63.0: 188 runs, about 5 s sequential, TestMeasure).
// Each configuration uses its own tool tags (GOARCH feature levels,
// default GOEXPERIMENTs), read from the toolchain (toolTags); go/build,
// used for the other packages and the -tags search, is given the same.

const (
	// listTimeout bounds one go list run.
	listTimeout = 2 * time.Minute
	// listBudget bounds all go list runs over one tree; past it the tree
	// is unresolved, for a person.
	listBudget = 5 * time.Minute
)

// listParallel is how many go list runs go at once, each in its own
// memory-limited child.
var listParallel = min(8, max(1, runtime.NumCPU()))

// goLister runs go list. goBin "" means there is no go command: nothing
// is resolved.
type goLister struct {
	goBin string
	plan  *BuildPlan // nil: every configuration, tags over-approximated
}

// configs is what the lister evaluates: the declared configurations, or
// every one.
func (l goLister) configs() []config {
	if l.plan != nil {
		return l.plan.cfgs
	}
	return configs
}

// defaultLister is the go command on PATH, for CheckTrees (tests).
func defaultLister() goLister {
	bin, _ := exec.LookPath("go")
	if bin != "" {
		bin, _ = filepath.Abs(bin)
	}
	return goLister{goBin: bin}
}

// toolTags are, per GOOS/GOARCH, the tool tags the toolchain sets
// (go list -f '{{context.ToolTags}}'), read once per go command.
func (l goLister) toolTags() (map[string][]string, error) {
	toolTagsMu.Lock()
	defer toolTagsMu.Unlock()
	if tt, ok := toolTagsCache[l.goBin]; ok {
		return tt, nil
	}
	if l.goBin == "" {
		return nil, errors.New("the gate has no go command")
	}
	root, err := os.MkdirTemp("", "gate-tooltags-")
	if err != nil {
		return nil, err
	}
	// The directory is the gate's own, made just above.
	defer os.RemoveAll(root)
	mod := filepath.Join(root, "mod")
	if err := os.MkdirAll(mod, 0o755); err != nil {
		return nil, err
	}
	if err := ecoutil.GoHome(filepath.Join(root, "home")); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(mod, "go.mod"), []byte("module gate.invalid/m\n\ngo "+goLine()+"\n"), 0o644); err != nil {
		return nil, err
	}
	targets := map[string]bool{}
	for _, c := range configs {
		targets[c.goos+"/"+c.goarch] = true
	}
	tt := map[string][]string{}
	var mu sync.Mutex
	var firstErr error
	run := func(target string) {
		goos, goarch, _ := strings.Cut(target, "/")
		out, err := ecoutil.RunGo(ecoutil.GoRun{Go: l.goBin, Dir: mod, Timeout: listTimeout,
			Args: []string{"list", "-e", "-f", "{{context.ToolTags}}", "unsafe"},
			Env:  append(listEnv(root), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")})
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("go list for the %s tool tags: %w", target, err)
			}
			return
		}
		s := strings.TrimSpace(string(out))
		if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
			if firstErr == nil {
				firstErr = fmt.Errorf("go list for the %s tool tags printed %q", target, clipped(s))
			}
			return
		}
		tt[target] = strings.Fields(strings.Trim(s, "[]"))
	}
	parallel(slices.Sorted(maps.Keys(targets)), run)
	if firstErr != nil {
		return nil, firstErr
	}
	toolTagsCache[l.goBin] = tt
	return tt, nil
}

var (
	toolTagsMu    sync.Mutex
	toolTagsCache = map[string]map[string][]string{}
)

func clipped(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

// parallel runs f over items, listParallel at a time.
func parallel[T any](items []T, f func(T)) {
	sem := make(chan struct{}, listParallel)
	var wg sync.WaitGroup
	for _, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			f(it)
		}()
	}
	wg.Wait()
}

type listPkg struct {
	Dir                                               string
	GoFiles, CgoFiles, InvalidGoFiles, IgnoredGoFiles []string
	SFiles, SysoFiles                                 []string
	EmbedPatterns, EmbedFiles                         []string
	Error                                             *struct{ Err string }
}

// listDirs runs go list in every configuration over dirs of t and records
// in b, for those directories, what it builds (replacing go/build's
// answer) and embeds, and where it gave no answer.
func (l goLister) listDirs(t *ecoutil.Tree, b *builtSet, dirs []string, old bool, goFiles map[string][]string) {
	fail := func(d, why string) {
		if b.embedFailed[d] == "" {
			b.embedFailed[d] = why
		}
	}
	failAll := func(why string) {
		for _, d := range dirs {
			fail(d, why)
		}
	}
	start := time.Now()
	defer func() { b.listTook = time.Since(start) }()
	root, err := os.MkdirTemp("", "gate-golist-")
	if err != nil {
		failAll("the gate could not make a work directory: " + err.Error())
		return
	}
	// The directory is the gate's own, made just above.
	defer os.RemoveAll(root)
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	mod := filepath.Join(root, "mod")
	if err := copyTree(t, mod); err != nil {
		failAll("the gate could not copy the tree: " + err.Error())
		return
	}
	if err := ecoutil.GoHome(filepath.Join(root, "home")); err != nil {
		failAll("the gate could not prepare the go command's home: " + err.Error())
		return
	}
	env := listEnv(root)
	args := []string{"list", "-e", "-json=Dir,GoFiles,CgoFiles,InvalidGoFiles,IgnoredGoFiles,SFiles,SysoFiles,EmbedPatterns,EmbedFiles,Error"}
	for _, d := range dirs {
		args = append(args, "./"+d)
	}
	type result struct {
		out []byte
		err error
	}
	cfgs := b.cfgs
	results := make([]result, len(cfgs))
	idx := make([]int, len(cfgs))
	for i := range idx {
		idx[i] = i
	}
	parallel(idx, func(i int) {
		if time.Since(start) > listBudget {
			results[i] = result{err: errors.New("the gate's time budget for go list over this tree is spent")}
			return
		}
		c := cfgs[i]
		cgo := "0"
		if c.cgo {
			cgo = "1"
		}
		args := args
		if len(c.tags) > 0 {
			args = append([]string{"list", "-tags=" + strings.Join(c.tags, ",")}, args[1:]...)
		}
		out, err := ecoutil.RunGo(ecoutil.GoRun{Go: l.goBin, Dir: mod, Timeout: listTimeout, Args: args,
			Env: append(slices.Clone(env), "GOOS="+c.goos, "GOARCH="+c.goarch, "CGO_ENABLED="+cgo)})
		results[i] = result{out, err}
	})
	b.listRuns += len(cfgs)
	// overApprox is go list's missing answer for d in configuration i:
	// every file built in the new tree, none in the old.
	overApprox := func(d string, i int) {
		for _, f := range append(slices.Clone(goFiles[d]), b.linkFiles[d]...) {
			b.in[f][i] = !old
		}
	}
	for i, res := range results {
		c := cfgs[i]
		where := fmt.Sprintf("%s/%s, cgo %v", c.goos, c.goarch, c.cgo)
		answered := map[string]bool{}
		err := res.err
		if err == nil {
			dec := json.NewDecoder(bytes.NewReader(res.out))
			for {
				var p listPkg
				if err = dec.Decode(&p); err != nil {
					if errors.Is(err, io.EOF) {
						err = nil
					}
					break
				}
				rel, rerr := filepath.Rel(mod, p.Dir)
				if rerr != nil || strings.HasPrefix(rel, "..") {
					continue
				}
				d := filepath.ToSlash(rel)
				if _, ok := goFiles[d]; !ok {
					continue
				}
				answered[d] = true
				l.record(b, d, i, where, p, old, goFiles[d], fail, overApprox)
			}
		}
		for _, d := range dirs {
			switch {
			case err != nil:
				fail(d, fmt.Sprintf("go list (%s) failed: %v", where, err))
				overApprox(d, i)
			case !answered[d]:
				fail(d, "go list ("+where+") gave no answer for the package")
				overApprox(d, i)
			}
		}
	}
}

// record takes go list's answer p for directory d in configuration i.
func (l goLister) record(b *builtSet, d string, i int, where string, p listPkg, old bool, files []string, fail func(string, string), overApprox func(string, int)) {
	base := func(names ...[]string) map[string]bool {
		m := map[string]bool{}
		for _, ns := range names {
			for _, n := range ns {
				m[path.Join(d, n)] = true
			}
		}
		return m
	}
	if p.Error != nil {
		// Every file excluded (go list's IgnoredGoFiles): nothing built,
		// nothing embedded. Any other error: no answer.
		ignored := base(p.IgnoredGoFiles)
		if len(p.GoFiles)+len(p.CgoFiles)+len(p.InvalidGoFiles) == 0 && !slices.ContainsFunc(files, func(f string) bool { return !ignored[f] }) {
			// go list still lists SFiles and SysoFiles here; the
			// package does not build, so neither is built.
			for _, f := range append(slices.Clone(files), b.linkFiles[d]...) {
				b.in[f][i] = false
			}
			return
		}
		fail(d, fmt.Sprintf("go list (%s): %s", where, p.Error.Err))
		overApprox(d, i)
		return
	}
	built := base(p.GoFiles, p.CgoFiles)
	if !old {
		maps.Copy(built, base(p.InvalidGoFiles))
	}
	b.recordLinked(d, i, len(p.GoFiles)+len(p.CgoFiles) > 0, p.SFiles, p.SysoFiles)
	for _, f := range files {
		b.in[f][i] = built[f]
		if built[f] && hasEmbedComment(f, b.tf.read(f)) {
			if b.embedders[d] == nil {
				b.embedders[d] = map[string][]bool{}
			}
			if b.embedders[d][f] == nil {
				b.embedders[d][f] = make([]bool, len(b.cfgs))
			}
			b.embedders[d][f][i] = true
		}
	}
	for _, pat := range p.EmbedPatterns {
		if why := patternUnmodelled(pat); why != "" {
			fail(d, fmt.Sprintf("//go:embed pattern %q %s", pat, why))
		}
	}
	if b.embedFiles[d] == nil {
		b.embedFiles[d] = map[string][]bool{}
	}
	for _, e := range p.EmbedFiles {
		f := path.Join(d, e)
		if b.embedFiles[d][f] == nil {
			b.embedFiles[d][f] = make([]bool, len(b.cfgs))
		}
		b.embedFiles[d][f][i] = true
	}
}

// patternUnmodelled says why go list's answer for an embed pattern may
// not be a consumer's: a backslash (an escape to the Linux go list the
// gate runs, a path separator on Windows), or a byte module zips do not
// allow in a file path (golang.org/x/mod's CheckFilePath: ASCII letters,
// digits and !#$%&()+,-.=@[]^_{}~ and space, "/" between elements) other
// than the glob characters *?[]-^. "" when it may.
func patternUnmodelled(pat string) string {
	p := strings.TrimPrefix(pat, "all:")
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '\\':
			return "has a backslash: an escape on Linux, a path separator on Windows; a person decides"
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("!#$%&()+,-.=@[]^_{}~ /*?", c) >= 0:
		default:
			return fmt.Sprintf("has the byte 0x%02x, which a module file path cannot hold; a person decides", c)
		}
	}
	return ""
}

// embedded is the sorted list of files dir embeds in some configuration.
func (b *builtSet) embedded(dir string) []string {
	if b == nil {
		return nil
	}
	return slices.Sorted(maps.Keys(b.embedFiles[dir]))
}

// listEnv is go list's complete environment (beyond GOOS, GOARCH and
// CGO_ENABLED), with its homes and caches under root: no PATH, no
// toolchain switch, no network, no inherited variable. root's home must
// be prepared with ecoutil.GoHome (telemetry off).
func listEnv(root string) []string {
	return []string{
		"HOME=" + filepath.Join(root, "home"), "GOPATH=" + filepath.Join(root, "gopath"), "GOCACHE=" + filepath.Join(root, "cache"),
		"GOMODCACHE=" + filepath.Join(root, "gopath", "pkg", "mod"),
		"GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GONOSUMDB=", "GOPRIVATE=",
		"GOFLAGS=-mod=mod -buildvcs=false", "GOWORK=off", "GOENV=off",
	}
}

// copyTree writes t's listed files under dst, replacing the root go.mod
// with the gate's (every other file is copied: a pattern can embed
// go.sum; GOWORK=off ignores go.work).
func copyTree(t *ecoutil.Tree, dst string) error {
	for _, f := range t.Files {
		if f == "go.mod" {
			continue
		}
		p := filepath.Join(dst, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, t.ReadFile(f), 0o644); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dst, "go.mod"), []byte("module gate.invalid/m\n\ngo "+goLine()+"\n"), 0o644)
}

// goLine is the gate toolchain's language version (go1.27.4 -> 1.27).
func goLine() string {
	v := strings.TrimPrefix(runtime.Version(), "go")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return "1.21"
	}
	minor, _, _ := strings.Cut(parts[1], "rc")
	minor, _, _ = strings.Cut(minor, "beta")
	return parts[0] + "." + minor
}

// lister is the fetch's go command for go list, and its version ("none"
// without one: every embed is then unresolved).
func (f Fetcher) lister(ctx context.Context) (goLister, string) {
	bin := f.GoBin
	if bin == "" {
		bin = "go"
	}
	abs, err := exec.LookPath(bin)
	if err == nil {
		abs, err = filepath.Abs(abs)
	}
	if err != nil {
		return goLister{}, "none"
	}
	home, err := os.MkdirTemp("", "gate-gohome-")
	if err != nil {
		return goLister{}, "none"
	}
	// The directory is the gate's own, made just above.
	defer os.RemoveAll(home)
	if err := ecoutil.GoHome(home); err != nil {
		return goLister{}, "none"
	}
	out, err := ecoutil.RunGo(ecoutil.GoRun{Go: abs, Dir: home, Args: []string{"env", "GOVERSION"},
		Env: []string{"GOTOOLCHAIN=local", "GOENV=off", "HOME=" + home, "GOCACHE=" + filepath.Join(home, "cache")}, Timeout: time.Minute})
	if err != nil || ctx.Err() != nil {
		return goLister{}, "none"
	}
	return goLister{goBin: abs, plan: f.Plan}, strings.TrimSpace(string(out))
}

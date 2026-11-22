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
	"time"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
)

// What a package embeds is go list's answer (EmbedFiles), never the
// gate's (README "Design rules"). go list runs over a copy of the tree
// holding only the files the gate lists, with a go.mod the gate writes
// (module gate.invalid/m, the gate toolchain's go version, no
// requirements, no go.sum): embed resolution depends only on the package
// directory's files, and the module's own go.mod could name a newer
// toolchain or a replace directory outside the tree. Dependencies are
// missing (GOPROXY=off); go list -e still resolves every package's embeds.
//
// Plain go list (no -compiled, -export or -test) runs neither cgo nor any
// module code, also with CGO_ENABLED=1 (TestGoListRunsNoCompiler).
//
// Configurations: the union over every dist-list configuration, cgo on
// and off. EmbedPatterns come from the files a configuration builds, and
// go list resolves them against the directory alone, so configurations
// in which go/build (analyzeBuild) builds the same files in the listed
// directories get the same EmbedFiles: go list runs once per such group.
// One go list per configuration would also do (x/net v0.61.0 and v0.63.0:
// 188 runs, 5.1 s on an M-series Mac, TestMeasure), but grouping is 2
// runs there and keeps the many small CheckTrees tests fast. Rewriting
// files so that one go list covers every configuration was not chosen: it
// means deciding which lines are build constraints, a hand port.

const (
	// listTimeout bounds one go list run.
	listTimeout = 2 * time.Minute
	// listBudget bounds all go list runs over one tree; what is left
	// unlisted is unresolved, for a person.
	listBudget = 5 * time.Minute
)

// goLister runs go list. goBin "" means there is no go command: every
// embed is unresolved.
type goLister struct {
	goBin string
}

// defaultLister is the go command on PATH, for CheckTrees (tests).
func defaultLister() goLister {
	bin, _ := exec.LookPath("go")
	if bin != "" {
		bin, _ = filepath.Abs(bin)
	}
	return goLister{goBin: bin}
}

// listed is go list's answer for one tree, per configuration.
type listed struct {
	files  map[string]map[string][]bool // package dir -> embedded file (tree-relative) -> configs that embed it
	failed map[string]string            // package dir -> why go list gave no answer in some configuration
	runs   int
	took   time.Duration
}

// embedded is the sorted list of files dir embeds in some configuration.
func (l listed) embedded(dir string) []string {
	return slices.Sorted(maps.Keys(l.files[dir]))
}

type listPkg struct {
	Dir           string
	EmbedPatterns []string
	EmbedFiles    []string
	Error         *struct{ Err string }
}

// listEmbeds resolves the embeds of dirs in t.
func (l goLister) listEmbeds(t *ecoutil.Tree, b *builtSet, dirs []string) (res listed) {
	res = listed{files: map[string]map[string][]bool{}, failed: map[string]string{}}
	if len(dirs) == 0 {
		return res
	}
	failAll := func(why string) listed {
		for _, d := range dirs {
			if res.failed[d] == "" {
				res.failed[d] = why
			}
		}
		return res
	}
	if l.goBin == "" {
		return failAll("the gate has no go command")
	}
	start := time.Now()
	defer func() { res.took = time.Since(start) }()
	root, err := os.MkdirTemp("", "gate-golist-")
	if err != nil {
		return failAll("the gate could not make a work directory: " + err.Error())
	}
	// The directory is the gate's own, made just above.
	defer os.RemoveAll(root)
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	mod := filepath.Join(root, "mod")
	if err := copyTree(t, mod); err != nil {
		return failAll("the gate could not copy the tree: " + err.Error())
	}
	env := listEnv(root)
	groups := map[string][]int{} // signature -> configs
	var order []string
	for i := range configs {
		var sig strings.Builder
		for _, d := range dirs {
			sig.WriteString(d + "\x00")
			for _, f := range t.Files {
				if path.Dir(f) == d && b.in[f] != nil && b.in[f][i] {
					sig.WriteString(f + "\x01")
				}
			}
		}
		if _, ok := groups[sig.String()]; !ok {
			order = append(order, sig.String())
		}
		groups[sig.String()] = append(groups[sig.String()], i)
	}
	for _, sig := range order {
		c := configs[groups[sig][0]]
		args := dirsBuiltIn(t, b, dirs, groups[sig][0])
		if len(args) == 0 {
			continue
		}
		if time.Since(start) > listBudget {
			for _, a := range args {
				if d := path.Clean(strings.TrimPrefix(a, "./")); res.failed[d] == "" {
					res.failed[d] = "the gate's time budget for go list over this tree is spent"
				}
			}
			continue
		}
		cgo := "0"
		if c.cgo {
			cgo = "1"
		}
		out, err := ecoutil.RunGo(ecoutil.GoRun{
			Go: l.goBin, Dir: mod, Timeout: listTimeout,
			Args: append([]string{"list", "-e", "-json=Dir,EmbedPatterns,EmbedFiles,Error"}, args...),
			Env:  append(slices.Clone(env), "GOOS="+c.goos, "GOARCH="+c.goarch, "CGO_ENABLED="+cgo),
		})
		res.runs++
		answered := map[string]bool{}
		if err == nil {
			dec := json.NewDecoder(bytes.NewReader(out))
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
				answered[d] = true
				if p.Error != nil {
					if res.failed[d] == "" {
						res.failed[d] = fmt.Sprintf("go list (%s/%s, cgo %s): %s", c.goos, c.goarch, cgo, p.Error.Err)
					}
					continue
				}
				if res.files[d] == nil {
					res.files[d] = map[string][]bool{}
				}
				for _, e := range p.EmbedFiles {
					f := path.Join(d, e)
					if res.files[d][f] == nil {
						res.files[d][f] = make([]bool, len(configs))
					}
					for _, i := range groups[sig] {
						res.files[d][f][i] = true
					}
				}
			}
		}
		for _, a := range args {
			d := path.Clean(strings.TrimPrefix(a, "./"))
			switch {
			case err != nil && res.failed[d] == "":
				res.failed[d] = fmt.Sprintf("go list (%s/%s, cgo %s) failed: %v", c.goos, c.goarch, cgo, err)
			case err == nil && !answered[d] && res.failed[d] == "":
				res.failed[d] = "go list gave no answer for the package"
			}
		}
	}
	return res
}

// listEnv is go list's complete environment (beyond GOOS, GOARCH and
// CGO_ENABLED), with its homes and caches under root: no PATH, no
// toolchain switch, no network, no inherited variable.
func listEnv(root string) []string {
	return []string{
		"HOME=" + filepath.Join(root, "home"), "GOPATH=" + filepath.Join(root, "gopath"), "GOCACHE=" + filepath.Join(root, "cache"),
		"GOMODCACHE=" + filepath.Join(root, "gopath", "pkg", "mod"),
		"GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GONOSUMDB=", "GOPRIVATE=",
		"GOFLAGS=-mod=mod -buildvcs=false", "GOWORK=off", "GOENV=off", "GOTELEMETRY=off",
	}
}

// dirsBuiltIn are the go list arguments for configuration i: the dirs in
// which go/build builds some file in it.
func dirsBuiltIn(t *ecoutil.Tree, b *builtSet, dirs []string, i int) []string {
	var args []string
	for _, d := range dirs {
		for _, f := range t.Files {
			if path.Dir(f) == d && b.in[f] != nil && b.in[f][i] {
				args = append(args, "./"+d)
				break
			}
		}
	}
	return args
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
	out, err := ecoutil.RunGo(ecoutil.GoRun{Go: abs, Dir: os.TempDir(), Args: []string{"env", "GOVERSION"},
		Env: []string{"GOTOOLCHAIN=local", "GOENV=off", "GOTELEMETRY=off", "HOME=" + os.TempDir()}, Timeout: time.Minute})
	if err != nil || ctx.Err() != nil {
		return goLister{}, "none"
	}
	return goLister{goBin: abs}, strings.TrimSpace(string(out))
}

package gomod

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/modfile"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
)

// The type-aware init walk. The walk from init code (initCalleesChanged)
// follows names; on its own it reaches every method named Put from one
// bufferPool.Put on a sync.Pool. Here go/types, the Go type checker,
// resolves each declaration's references in the new tree instead:
//   - an identifier that is a package-level object of the package is
//     followed by name, as before; a local, a parameter, a field, an
//     import or a definition is not a reference to follow;
//   - a method selected on a concrete type of the package is followed to
//     exactly that type's method ("T.M"); one on a concrete type of
//     another package (sync.Pool.Put) runs no code of this package from
//     here; one on an interface, which can dispatch to any local method
//     of that name, is followed by name;
//   - whatever the checker cannot resolve (an import outside the module
//     and the standard library, a type error) is followed by name, as
//     before.
//
// Each package is checked once per distinct set of files go/build builds
// in some configuration, with the module's own imports checked from the
// tree in the same configuration and the standard library from GOROOT's
// source (cgo off). A declaration's references are the union over every
// set that holds its file; a file in no set keeps the by-name walk. The
// checker runs on hostile code, so it runs in the types child (memory
// limit, timeout); any failure there leaves the whole walk by name.

// TypesChild names the types child for ecoutil.RunChild.
const TypesChild = "types"

// typesTimeout bounds one module's type checking.
var typesTimeout = 3 * time.Minute

// typedRefs are, per new-tree file, per declaration (its start offset),
// the references the walk follows from it.
type typedRefs map[string]map[int][]string

// typesRequest is one module's work for the types child.
type typesRequest struct {
	Root    string // the module tree
	Module  string // its module path
	GOROOT  string
	Configs []typesConfig
	// Dirs are, per package directory, its file sets and, per
	// configuration, the set it builds (-1: none).
	Dirs map[string]typesDir
	Walk []string // the directories whose declarations are wanted
}

type typesConfig struct{ GOOS, GOARCH string }

type typesDir struct {
	Sets   [][]string
	Config []int
}

// typedWalk type-checks the walk's directories of cur (nil: not available).
func typedWalk(cur *ecoutil.Tree, nb *builtSet, l goLister, walk []string) typedRefs {
	if cur == nil || nb == nil || nb.unresolved() || len(walk) == 0 {
		return nil
	}
	goroot := l.goroot()
	mod := modulePath(cur)
	if goroot == "" || mod == "" {
		return nil
	}
	req := typesRequest{Root: cur.Dir, Module: mod, GOROOT: goroot, Dirs: map[string]typesDir{}, Walk: walk}
	for _, c := range nb.cfgs {
		req.Configs = append(req.Configs, typesConfig{c.goos, c.goarch})
	}
	files := map[string][]string{}
	for rel := range nb.in {
		if path.Ext(rel) == ".go" {
			files[path.Dir(rel)] = append(files[path.Dir(rel)], rel)
		}
	}
	for dir, fs := range files {
		slices.Sort(fs)
		td := typesDir{Config: make([]int, len(nb.cfgs))}
		for i := range nb.cfgs {
			var set []string
			for _, f := range fs {
				if nb.in[f][i] {
					set = append(set, f)
				}
			}
			td.Config[i] = -1
			if len(set) == 0 {
				continue
			}
			j := slices.IndexFunc(td.Sets, func(s []string) bool { return slices.Equal(s, set) })
			if j < 0 {
				td.Sets, j = append(td.Sets, set), len(td.Sets)
			}
			td.Config[i] = j
		}
		req.Dirs[dir] = td
	}
	b, err := json.Marshal(req)
	if err != nil {
		return nil
	}
	out, err := ecoutil.RunChild(TypesChild, b, typesTimeout, func(stdin io.Reader, stdout io.Writer) error {
		return typesChild(stdin, stdout, false)
	})
	if err != nil {
		return nil
	}
	var refs typedRefs
	if err := json.Unmarshal(out, &refs); err != nil {
		return nil
	}
	return refs
}

// modulePath is the module path of cur's go.mod ("" if none).
func modulePath(t *ecoutil.Tree) string {
	if !t.Has("go.mod") {
		return ""
	}
	return modfile.ModulePath(t.ReadFile("go.mod"))
}

// TypesChildMain is the types child: it limits its own memory, reads a
// typesRequest from stdin and writes the typedRefs.
func TypesChildMain(stdin io.Reader, stdout io.Writer) error {
	return typesChild(stdin, stdout, true)
}

func typesChild(stdin io.Reader, stdout io.Writer, limit bool) error {
	if limit {
		if err := ecoutil.LimitChild(); err != nil {
			return err
		}
	}
	b, err := io.ReadAll(io.LimitReader(stdin, 64<<20))
	if err != nil {
		return err
	}
	var req typesRequest
	if err := json.Unmarshal(b, &req); err != nil {
		return err
	}
	refs, err := checkTyped(req)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(refs)
}

// stdMu serializes use of the standard library's source importer, which
// reads go/build's package-level Default.
var stdMu sync.Mutex

// checkTyped does the child's work.
func checkTyped(req typesRequest) (refs typedRefs, err error) {
	defer func() {
		if p := recover(); p != nil {
			refs, err = nil, errors.New("the type checker failed")
		}
	}()
	stdMu.Lock()
	defer stdMu.Unlock()
	saved := build.Default
	defer func() { build.Default = saved }()
	// GOPATH mode, no GOPATH: go/build never runs the go command (in
	// module mode it would, for a path outside GOROOT).
	build.Default.GOROOT, build.Default.CgoEnabled = req.GOROOT, false
	build.Default.GOPATH = ""
	if old, had := os.LookupEnv("GO111MODULE"); had {
		defer os.Setenv("GO111MODULE", old)
	} else {
		defer os.Unsetenv("GO111MODULE")
	}
	os.Setenv("GO111MODULE", "off")
	fset := token.NewFileSet()
	c := &checker{req: req, fset: fset, pkgs: map[[2]int]*checked{},
		dirIDs: map[string]int{}, parsed: map[string]*ast.File{}, sig: make([]int, len(req.Configs))}
	refs = typedRefs{}
	// A package is checked once per configuration signature: the file
	// set of every in-module package in that configuration. Configurations
	// alike in all of them check alike; any difference (a platform-only
	// file in an imported package) is checked on its own. The standard
	// library is the gate host's: what differs by platform or Go version
	// there resolves to another package's object, which the walk follows
	// by name when it is unqualified (a dot import) and which runs no
	// code of this package otherwise.
	var reps []int
	seen := map[string]bool{}
	dirs := slices.Sorted(maps.Keys(req.Dirs))
	for ci := range req.Configs {
		var b strings.Builder
		for _, d := range dirs {
			fmt.Fprintf(&b, " %d", req.Dirs[d].Config[ci])
		}
		if !seen[b.String()] {
			seen[b.String()] = true
			c.sig[ci] = len(reps)
			reps = append(reps, ci)
		} else {
			c.sig[ci] = -1
		}
	}
	for _, ci := range reps {
		for _, dir := range req.Walk {
			td, ok := req.Dirs[dir]
			if !ok || td.Config[ci] < 0 {
				continue
			}
			p := c.check(dir, ci)
			if p == nil {
				continue
			}
			for i, f := range p.files {
				rel := td.Sets[td.Config[ci]][i]
				for off, ts := range declRefs(f, fset, p.pkg, p.info, p.recv) {
					if refs[rel] == nil {
						refs[rel] = map[int][]string{}
					}
					refs[rel][off] = union(refs[rel][off], ts)
				}
			}
		}
	}
	return refs, nil
}

type checked struct {
	pkg   *types.Package
	info  *types.Info
	files []*ast.File
	recv  map[*types.Func]string // each method -> its receiver type as written
}

type checker struct {
	req    typesRequest
	fset   *token.FileSet
	std    types.Importer      // the standard library from source (the host's)
	sig    []int               // per configuration: its signature's index, -1 if another represents it
	pkgs   map[[2]int]*checked // (dir ID, set) -> result; nil value: in progress or failed
	dirIDs map[string]int
	parsed map[string]*ast.File
}

func (c *checker) dirID(dir string) int {
	id, ok := c.dirIDs[dir]
	if !ok {
		id = len(c.dirIDs)
		c.dirIDs[dir] = id
	}
	return id
}

// check type-checks dir with the files configuration ci builds.
func (c *checker) check(dir string, ci int) *checked {
	td, ok := c.req.Dirs[dir]
	if !ok || ci < 0 || ci >= len(td.Config) || td.Config[ci] < 0 {
		return nil
	}
	key := [2]int{c.dirID(dir), ci} // ci is its signature's representative
	if p, seen := c.pkgs[key]; seen {
		return p // nil while in progress: an import cycle does not compile
	}
	c.pkgs[key] = nil
	var files []*ast.File
	for _, rel := range td.Sets[td.Config[ci]] {
		f := c.parsed[rel]
		if f == nil {
			src, err := os.ReadFile(filepath.Join(c.req.Root, filepath.FromSlash(rel)))
			if err != nil {
				return nil
			}
			f, err = parser.ParseFile(c.fset, rel, src, parser.SkipObjectResolution)
			if err != nil && f == nil {
				return nil
			}
			c.parsed[rel] = f
		}
		files = append(files, f)
	}
	cfg := c.req.Configs[ci]
	conf := types.Config{
		Importer:    importerFunc(func(p string) (*types.Package, error) { return c.importPath(p, ci) }),
		Error:       func(error) {}, // keep going: what resolves is used, the rest is by name
		FakeImportC: true,
		Sizes:       types.SizesFor("gc", cfg.GOARCH),
	}
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
	name := "p"
	if len(files) > 0 {
		name = files[0].Name.Name
	}
	pkg, _ := conf.Check(c.req.Module+"/"+dir, c.fset, files, info)
	if pkg == nil {
		pkg = types.NewPackage(c.req.Module+"/"+dir, name)
	}
	p := &checked{pkg: pkg, info: info, files: files, recv: map[*types.Func]string{}}
	for _, f := range files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv != nil && len(fd.Recv.List) == 1 {
				if fn, ok := info.Defs[fd.Name].(*types.Func); ok {
					if r := recvTypeName(fd.Recv.List[0].Type); r != "" {
						p.recv[fn] = r
					}
				}
			}
		}
	}
	c.pkgs[key] = p
	return p
}

// importPath resolves an import: the module's own packages from the tree
// in the same configuration, the standard library from source, nothing
// else.
func (c *checker) importPath(p string, ci int) (*types.Package, error) {
	if p == c.req.Module || strings.HasPrefix(p, c.req.Module+"/") {
		dir := strings.TrimPrefix(strings.TrimPrefix(p, c.req.Module), "/")
		if dir == "" {
			dir = "."
		}
		if q := c.check(dir, ci); q != nil {
			return q.pkg, nil
		}
		return nil, errors.New("not resolved")
	}
	if first, _, _ := strings.Cut(p, "/"); strings.Contains(first, ".") || first == "cmd" || p == "C" {
		return nil, errors.New("outside the module and the standard library")
	}
	if fi, err := os.Stat(filepath.Join(c.req.GOROOT, "src", filepath.FromSlash(p))); err != nil || !fi.IsDir() {
		return nil, errors.New("not in the standard library")
	}
	if c.std == nil {
		c.std = importer.ForCompiler(c.fset, "source", nil)
	}
	return c.std.Import(p)
}

type importerFunc func(string) (*types.Package, error)

func (f importerFunc) Import(p string) (*types.Package, error) { return f(p) }

// declRefs are, per top-level declaration of f (a func or method, or one
// spec of a var, const or type declaration), the references the walk
// follows from it.
func declRefs(f *ast.File, fset *token.FileSet, pkg *types.Package, info *types.Info, recv map[*types.Func]string) map[int][]string {
	out := map[int][]string{}
	off := func(n ast.Node) int { return fset.Position(n.Pos()).Offset }
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			var nodes []ast.Node
			if d.Recv != nil {
				nodes = append(nodes, d.Recv)
			}
			nodes = append(nodes, d.Type)
			if d.Body != nil {
				nodes = append(nodes, d.Body)
			}
			out[off(d)] = refsIn(nodes, pkg, info, recv)
		case *ast.GenDecl:
			for _, s := range d.Specs {
				switch s := s.(type) {
				case *ast.ValueSpec:
					var nodes []ast.Node
					if s.Type != nil {
						nodes = append(nodes, s.Type)
					}
					for _, v := range s.Values {
						nodes = append(nodes, v)
					}
					out[off(s)] = refsIn(nodes, pkg, info, recv)
				case *ast.TypeSpec:
					var nodes []ast.Node
					if s.TypeParams != nil {
						nodes = append(nodes, s.TypeParams)
					}
					nodes = append(nodes, s.Type)
					out[off(s)] = refsIn(nodes, pkg, info, recv)
				}
			}
		}
	}
	return out
}

// refsIn resolves the references in nodes (see the package comment).
func refsIn(nodes []ast.Node, pkg *types.Package, info *types.Info, recv map[*types.Func]string) []string {
	set := map[string]bool{}
	var visit func(n ast.Node) bool
	visit = func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			if sel := info.Selections[n]; sel != nil {
				if sel.Kind() != types.FieldVal {
					if t := methodTarget(sel, pkg, recv); t != "" {
						set[t] = true
					}
				}
				ast.Inspect(n.X, visit)
				return false
			}
			if id, ok := ast.Unparen(n.X).(*ast.Ident); ok {
				if _, isPkg := info.Uses[id].(*types.PkgName); isPkg {
					return false // pkg.Name: another package's object
				}
			}
			// Unresolved: by name.
			set[n.Sel.Name] = true
			ast.Inspect(n.X, visit)
			return false
		case *ast.StructType:
			// Field names are definitions; their types are references.
			for _, f := range n.Fields.List {
				ast.Inspect(f.Type, visit)
			}
			return false
		case *ast.Ident:
			// An embedded field's identifier is both a definition (the
			// field) and a use (its type): the use wins.
			obj := info.Uses[n]
			switch {
			case obj == nil && info.Defs[n] != nil:
			case obj == nil:
				if n.Name != "_" {
					set[n.Name] = true // unresolved: by name
				}
			case obj.Pkg() == pkg && obj.Parent() == pkg.Scope():
				set[n.Name] = true
			case obj.Pkg() != nil && obj.Pkg() != pkg:
				// Unqualified, yet another package's: a dot import, which
				// another configuration or Go version may resolve to a
				// local declaration instead. By name too.
				set[n.Name] = true
			}
			return false
		}
		return true
	}
	for _, n := range nodes {
		ast.Inspect(n, visit)
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// methodTarget is what a method selection reaches: "T.M" for a method of
// a concrete type of pkg, the bare name for one selected on an interface
// (it can dispatch to any method of that name), "" for a method of
// another package's concrete type.
//
// "T" is the receiver type as the method's declaration writes it (recv),
// which is how the walk's index keys it: an alias receiver (type A = T;
// func (A) M()) is "A.M".
func methodTarget(sel *types.Selection, pkg *types.Package, recv map[*types.Func]string) string {
	f, ok := sel.Obj().(*types.Func)
	if !ok {
		return sel.Obj().Name()
	}
	if types.IsInterface(sel.Recv()) {
		return f.Name()
	}
	sig, ok := f.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return f.Name()
	}
	rt := sig.Recv().Type()
	if p, ok := rt.(*types.Pointer); ok {
		rt = p.Elem()
	}
	named, ok := types.Unalias(rt).(*types.Named)
	if !ok {
		return f.Name()
	}
	obj := named.Origin().Obj()
	if obj.Pkg() != pkg {
		if types.IsInterface(named) {
			return f.Name()
		}
		return ""
	}
	if types.IsInterface(named) {
		return f.Name()
	}
	if r, ok := recv[f.Origin()]; ok {
		return r + "." + f.Name()
	}
	return f.Name() // a method the index cannot name exactly: by name
}

func union(a, b []string) []string {
	for _, s := range b {
		if !slices.Contains(a, s) {
			a = append(a, s)
		}
	}
	slices.Sort(a)
	return a
}

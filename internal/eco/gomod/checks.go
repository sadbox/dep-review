package gomod

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"maps"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
	"github.com/sadbox/dep-review/internal/evidence"
	"github.com/sadbox/dep-review/internal/model"
)

// riskyImports are packages whose new use in a non-test file is a hard
// stop. The list was made by classifying every importable package in
// `go list std` (Go 1.27) by what its own API can do:
//
//   - process execution: os (StartProcess), os/exec, syscall (Exec,
//     ForkExec), net/http/cgi, go/build and go/importer (run the go
//     command), plugin (loads native code)
//   - network: net and net/* except the parse-only net/url, net/netip and
//     net/mail; crypto/tls (Dial), log/syslog (Dial), expvar (registers an
//     HTTP handler at init)
//   - filesystem writes: os, io/ioutil, runtime/coverage
//   - memory unsafety and linkname: unsafe
//   - cgo: runtime/cgo (import "C" has its own check)
//   - reflection-driven calls: reflect, and text/template and html/template,
//     which call methods and functions named by template text
//   - raw system calls: syscall, syscall/*, golang.org/x/sys/*
//
// Entries ending in "/" match every package under that path.
var riskyImports = []string{
	"os", "os/exec", "io/ioutil", "syscall", "syscall/", "unsafe", "plugin",
	"reflect", "text/template", "html/template", "runtime/cgo", "runtime/coverage",
	"net", "net/", "crypto/tls", "log/syslog", "expvar",
	"go/build", "go/importer", "net/http/cgi",
	"golang.org/x/sys/",
}

// safeNet are the net/* packages that only parse text.
var safeNet = map[string]bool{"net/url": true, "net/netip": true, "net/mail": true}

// riskyImport returns the riskyImports entry imp falls under, or "".
func riskyImport(imp string) string {
	if safeNet[imp] {
		return ""
	}
	for _, r := range riskyImports {
		if imp == r || (strings.HasSuffix(r, "/") && strings.HasPrefix(imp, r)) {
			return r
		}
	}
	return ""
}

// blobMin is the length past which a base64/hex-looking string literal is
// treated as an embedded blob.
const blobMin = 512

// checkCodes are the hard-stop finding codes, each forcing RouteHuman.
const (
	codeInit       = "gomod.init-changed"
	codeVarInit    = "gomod.var-initializer-call"
	codeInitCallee = "gomod.init-callee-changed"
	codeBlank      = "gomod.blank-import"
	codeCSource    = "gomod.cgo-source-changed"
	codeCgo        = "gomod.cgo"
	codeLinkname   = "gomod.linkname"
	codeImport     = "gomod.risky-import"
	codeGenerate   = "gomod.go-generate"
	codeEmbed      = "gomod.go-embed"
	codeBlob       = "gomod.encoded-blob"
	codeBinary     = "gomod.binary-file"
	codeAsm        = "gomod.assembly-changed"
	codeParse      = "gomod.unparseable"
)

// hits collects file paths per finding code.
type hits map[string][]string

func (h hits) add(code, what string) { h[code] = append(h[code], what) }

// findings turns hits into one finding per code, listing up to 10 paths.
func (h hits) findings(update string) []model.Finding {
	codes := make([]string, 0, len(h))
	for c := range h {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	var out []model.Finding
	for _, c := range codes {
		list := slices.Compact(slices.Sorted(slices.Values(h[c])))
		more := ""
		if len(list) > 10 {
			more = fmt.Sprintf(" and %d more", len(list)-10)
			list = list[:10]
		}
		out = append(out, model.Finding{
			Code:   c,
			Route:  model.RouteHuman,
			Detail: checkText[c] + ": " + strings.Join(list, ", ") + more,
			Update: update,
		})
	}
	return out
}

var checkText = map[string]string{
	codeInit:       "new or changed func init() (runs on import)",
	codeVarInit:    "new or changed package-level var initializer that calls a function (runs on import)",
	codeInitCallee: "package-local declaration reached from a func init or a calling var initializer changed (runs on import)",
	codeBlank:      `new blank import (import _ "...", imported only for its init side effects)`,
	codeCSource:    "C/C++/Objective-C/Fortran/SWIG source added or changed (compiled by cgo)",
	codeCgo:        `cgo (import "C" or //go:cgo_ directives) in a new or changed file`,
	codeLinkname:   "new //go:linkname (reaches into another package's internals)",
	codeImport:     "non-test file newly imports a package that can run processes, make system calls, use the network, write files, break memory safety or call through reflection",
	codeGenerate:   "new //go:generate directive",
	codeEmbed:      "new //go:embed directive",
	codeBlob:       fmt.Sprintf("new base64/hex-looking string literal longer than %d characters", blobMin),
	codeBinary:     "binary file added or changed (testdata/ fixtures other than .syso excepted)",
	codeAsm:        "assembly (.s) file added or changed",
	codeParse:      "Go file the gate could not parse (checked as text only)",
}

// cgoSourceExts are the extensions the go command hands to the C, C++,
// Objective-C, Fortran or SWIG toolchains in a cgo package.
var cgoSourceExts = map[string]bool{
	".c": true, ".h": true, ".cc": true, ".cpp": true, ".cxx": true, ".hh": true, ".hpp": true, ".hxx": true,
	".m": true, ".f": true, ".F": true, ".for": true, ".f90": true, ".swig": true, ".swigcxx": true,
}

// CheckTrees runs the Go hard stops over two module trees. old may be nil
// for a new module.
//
// Every file in the module zip is checked, vendor/ and testdata/ included:
// the zip keeps top-level vendor/*.go (only vendor/<dir>/ is dropped), and
// a package under testdata/ or vendor/ compiles when something imports
// its path explicitly. The only exemption is binary fixtures under
// testdata/ with an extension the toolchain never compiles or links.
//
// Dispatch is on the extension first: a file the toolchain would compile
// or link gets its check whatever its content looks like (a .go file that
// looks binary is still parsed, and fails as unparseable).
func CheckTrees(old, cur *ecoutil.Tree) hits {
	h := hits{}
	shadow := map[string]map[string]bool{} // package directory -> package-level names
	goDirs := map[string]bool{}            // package directories with a changed non-test .go file
	for _, rel := range cur.Files {
		data := cur.ReadFile(rel)
		var prev []byte
		if old.Has(rel) {
			prev = old.ReadFile(rel)
			if bytes.Equal(prev, data) {
				continue
			}
		}
		testdata := slices.Contains(strings.Split(path.Dir(rel), "/"), "testdata")
		ext := path.Ext(rel)
		switch {
		case ext == ".go":
			if strings.HasSuffix(rel, "_test.go") {
				continue // compiled only into the dependency's own tests
			}
			dir := path.Dir(rel)
			if _, ok := shadow[dir]; !ok {
				shadow[dir] = packageNames(cur, dir)
			}
			goDirs[dir] = true
			checkGoFile(h, rel, prev, data, shadow[dir])
		case ext == ".s" || ext == ".S" || ext == ".sx":
			h.add(codeAsm, rel)
		case cgoSourceExts[ext]:
			h.add(codeCSource, rel)
		case ext == ".syso":
			h.add(codeBinary, rel)
		case evidence.IsBinary(data) && !testdata:
			h.add(codeBinary, rel)
		}
	}
	// Deleted .go files change a package too.
	if old != nil {
		for _, rel := range old.Files {
			if path.Ext(rel) == ".go" && !strings.HasSuffix(rel, "_test.go") && !cur.Has(rel) {
				goDirs[path.Dir(rel)] = true
			}
		}
	}
	for _, dir := range slices.Sorted(maps.Keys(goDirs)) {
		if shadow[dir] == nil {
			shadow[dir] = packageNames(cur, dir)
		}
		for _, name := range initCalleesChanged(old, cur, dir, shadow[dir]) {
			h.add(codeInitCallee, path.Join(dir, name))
		}
	}
	return h
}

// declInfo is one package-level declaration: its source text and the
// identifiers it mentions.
type declInfo struct {
	text  string
	refs  []string
	names []string // for a var root: the names it declares
}

// pkgIndex is the package-level declarations of one package directory,
// by name. A function or variable is under its name; a type is under its
// name; a method is under its own name (any x.M() may reach it) and under
// its receiver type's name (fmt and friends call String/Error/Format on a
// value implicitly). roots are what runs at init: each func init and
// each var spec whose initializer may call.
type pkgIndex struct {
	decls map[string][]declInfo
	roots []declInfo
}

func identsIn(n ast.Node) []string {
	var out []string
	ast.Inspect(n, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			out = append(out, id.Name)
		}
		return true
	})
	return out
}

func indexPackage(t *ecoutil.Tree, dir string, shadow map[string]bool) pkgIndex {
	ix := pkgIndex{decls: map[string][]declInfo{}}
	if t == nil {
		return ix
	}
	for _, rel := range t.Files {
		if path.Dir(rel) != dir || path.Ext(rel) != ".go" || strings.HasSuffix(rel, "_test.go") {
			continue
		}
		src := t.ReadFile(rel)
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
		if err != nil {
			continue // checkGoFile reports it as unparseable if it changed
		}
		pkgs := map[string]string{}
		for _, imp := range file.Imports {
			if p, err := strconv.Unquote(imp.Path.Value); err == nil {
				name := path.Base(p)
				if imp.Name != nil {
					name = imp.Name.Name
				}
				pkgs[name] = p
			}
		}
		text := func(n ast.Node) string {
			return string(src[fset.Position(n.Pos()).Offset:fset.Position(n.End()).Offset])
		}
		add := func(key string, n ast.Node) declInfo {
			d := declInfo{text: text(n), refs: identsIn(n)}
			ix.decls[key] = append(ix.decls[key], d)
			return d
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				switch {
				case d.Recv != nil:
					add(d.Name.Name, d)
					if len(d.Recv.List) == 1 {
						if typ := recvTypeName(d.Recv.List[0].Type); typ != "" {
							ix.decls[typ] = append(ix.decls[typ], declInfo{text: text(d), refs: identsIn(d)})
						}
					}
				case d.Name.Name == "init":
					ix.roots = append(ix.roots, declInfo{text: text(d), refs: identsIn(d)})
				default:
					add(d.Name.Name, d)
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.ValueSpec:
						var di declInfo
						for _, n := range s.Names {
							di = add(n.Name, s)
						}
						if d.Tok == token.VAR {
							for _, v := range s.Values {
								if mayCall(v, pkgs, shadow) {
									for _, n := range s.Names {
										di.names = append(di.names, n.Name)
									}
									ix.roots = append(ix.roots, di)
									break
								}
							}
						}
					case *ast.TypeSpec:
						add(s.Name.Name, s)
					}
				}
			}
		}
	}
	return ix
}

func recvTypeName(e ast.Expr) string {
	for {
		switch t := e.(type) {
		case *ast.StarExpr:
			e = t.X
		case *ast.IndexExpr:
			e = t.X
		case *ast.IndexListExpr:
			e = t.X
		case *ast.ParenExpr:
			e = t.X
		case *ast.Ident:
			return t.Name
		default:
			return ""
		}
	}
}

// initCalleesChanged returns the package-level declarations of dir that
// code run at init reaches, transitively and by name, whose source
// differs between old and cur. Reaching by name over-approximates (any
// identifier spelled like a declaration counts), which is the safe side.
// Calls into other packages, even of the same module, are not followed:
// a changed function there is only flagged if it is itself an init root.
func initCalleesChanged(old, cur *ecoutil.Tree, dir string, shadow map[string]bool) []string {
	o, n := indexPackage(old, dir, shadow), indexPackage(cur, dir, shadow)
	seen := map[string]bool{}
	var queue []string
	for _, r := range n.roots {
		queue = append(queue, r.refs...)
		for _, name := range r.names {
			seen[name] = true // the root itself is compared by codeVarInit
		}
	}
	var changed []string
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if seen[name] {
			continue
		}
		seen[name] = true
		ds, ok := n.decls[name]
		if !ok {
			continue
		}
		if !sameDecls(o.decls[name], ds) {
			changed = append(changed, name)
		}
		for _, d := range ds {
			queue = append(queue, d.refs...)
		}
	}
	sort.Strings(changed)
	return changed
}

func sameDecls(a, b []declInfo) bool {
	ta, tb := make([]string, len(a)), make([]string, len(b))
	for i := range a {
		ta[i] = a[i].text
	}
	for i := range b {
		tb[i] = b[i].text
	}
	slices.Sort(ta)
	slices.Sort(tb)
	return slices.Equal(ta, tb)
}

// packageNames returns the package-level names declared by the .go files
// of directory dir, which can shadow a builtin for every file there. The
// value is true when every declaration of the name is a type (so (*T)(x)
// is a conversion). A file that does not parse contributes every builtin
// name, as a non-type.
func packageNames(t *ecoutil.Tree, dir string) map[string]bool {
	names := map[string]bool{}
	nonType := func(n string) { names[n] = false }
	for _, rel := range t.Files {
		if path.Dir(rel) != dir || path.Ext(rel) != ".go" {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), rel, t.ReadFile(rel), parser.SkipObjectResolution)
		if err != nil {
			for b := range pureBuiltins {
				nonType(b)
			}
			continue
		}
		for _, d := range file.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil {
					nonType(d.Name.Name)
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.ValueSpec:
						for _, n := range s.Names {
							nonType(n.Name)
						}
					case *ast.TypeSpec:
						if _, seen := names[s.Name.Name]; !seen {
							names[s.Name.Name] = true
						}
					}
				}
			}
		}
	}
	return names
}

// goFacts is what the checks compare between the old and new file.
type goFacts struct {
	imports    map[string]bool
	cgo        bool
	inits      []string // source text of each func init
	varInits   []string // source text of each package-level var spec whose initializer may call
	blank      map[string]bool
	directives map[string]bool
	blobs      map[string]bool
	parsed     bool
}

func facts(name string, src []byte, shadow map[string]bool) goFacts {
	f := goFacts{imports: map[string]bool{}, blank: map[string]bool{}, directives: map[string]bool{}, blobs: map[string]bool{}}
	if src == nil {
		f.parsed = true
		return f
	}
	for _, line := range strings.Split(string(src), "\n") {
		t := strings.TrimSpace(line)
		for _, d := range []string{"//go:linkname", "//go:generate", "//go:embed", "//go:cgo_"} {
			if strings.HasPrefix(t, d) {
				f.directives[t] = true
			}
		}
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.ParseComments|parser.SkipObjectResolution)
	if err == nil {
		f.parsed = true
		pkgs := map[string]string{} // file-scope name -> import path
		for _, imp := range file.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			f.imports[p] = true
			name := path.Base(p)
			if imp.Name != nil {
				name = imp.Name.Name
			}
			if name == "_" && p != "embed" && p != "unsafe" { // neither has an init; unsafe is a risky import anyway
				f.blank[p] = true
			}
			pkgs[name] = p
		}
		f.cgo = f.imports["C"]
		text := func(n ast.Node) string {
			return string(src[fset.Position(n.Pos()).Offset:fset.Position(n.End()).Offset])
		}
		for _, d := range file.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name.Name == "init" {
					f.inits = append(f.inits, text(d))
				}
			case *ast.GenDecl:
				if d.Tok != token.VAR {
					continue
				}
				for _, s := range d.Specs {
					vs := s.(*ast.ValueSpec)
					for _, v := range vs.Values {
						if mayCall(v, pkgs, shadow) {
							f.varInits = append(f.varInits, text(vs))
							break
						}
					}
				}
			}
		}
	} else {
		// Fall back to text: assume the worst about cgo and init.
		s := string(src)
		f.cgo = strings.Contains(s, `"C"`)
		if strings.Contains(s, "func init(") {
			f.inits = append(f.inits, s)
		}
		if strings.Contains(s, "var") {
			f.varInits = append(f.varInits, s)
		}
	}
	var sc scanner.Scanner
	sfset := token.NewFileSet()
	sc.Init(sfset.AddFile(name, -1, len(src)), src, nil, 0)
	for {
		_, tok, lit := sc.Scan()
		if tok == token.EOF {
			break
		}
		if tok == token.STRING && len(lit) > blobMin && looksEncoded(lit[1:len(lit)-1]) {
			f.blobs[lit] = true
		}
	}
	return f
}

func checkGoFile(h hits, rel string, prev, cur []byte, shadow map[string]bool) {
	o, n := facts(rel, prev, shadow), facts(rel, cur, shadow)
	if !n.parsed {
		h.add(codeParse, rel)
	}
	for imp := range n.imports {
		if riskyImport(imp) != "" && !o.imports[imp] {
			h.add(codeImport, rel+" ("+imp+")")
		}
	}
	for imp := range n.blank {
		if !o.blank[imp] {
			h.add(codeBlank, rel+" ("+imp+")")
		}
	}
	if n.cgo {
		h.add(codeCgo, rel)
	}
	for _, in := range n.inits {
		if !slices.Contains(o.inits, in) {
			h.add(codeInit, rel)
			break
		}
	}
	for _, vi := range n.varInits {
		if !slices.Contains(o.varInits, vi) {
			h.add(codeVarInit, rel)
			break
		}
	}
	for d := range n.directives {
		if o.directives[d] {
			continue
		}
		switch {
		case strings.HasPrefix(d, "//go:linkname"):
			h.add(codeLinkname, rel)
		case strings.HasPrefix(d, "//go:generate"):
			h.add(codeGenerate, rel)
		case strings.HasPrefix(d, "//go:embed"):
			h.add(codeEmbed, rel)
		case strings.HasPrefix(d, "//go:cgo_"):
			h.add(codeCgo, rel)
		}
	}
	for b := range n.blobs {
		if !o.blobs[b] {
			h.add(codeBlob, rel)
			break
		}
	}
}

// pureCalls are standard-library functions a package-level var may call
// without counting as an init-time side effect: they only build a value
// from strings and call no method of an argument (which is why fmt's
// functions are not here: they call String, Error and Format).
var pureCalls = map[string]map[string]bool{
	"errors":  {"New": true},
	"regexp":  {"MustCompile": true, "MustCompilePOSIX": true},
	"strings": {"NewReplacer": true},
}

// builtins that only compute a value. Anything else called by a bare name
// (a local function, a dot-imported one, a conversion to a named type the
// gate cannot tell from a call without type checking) counts as a call.
var pureBuiltins = map[string]bool{
	"len": true, "cap": true, "make": true, "new": true, "append": true, "min": true, "max": true,
	"complex": true, "real": true, "imag": true,
	"string": true, "byte": true, "rune": true, "bool": true, "int": true, "int8": true, "int16": true,
	"int32": true, "int64": true, "uint": true, "uint8": true, "uint16": true, "uint32": true,
	"uint64": true, "uintptr": true, "float32": true, "float64": true, "complex64": true, "complex128": true,
}

// mayCall reports whether a package-level initializer can run code: any
// call other than pureCalls (resolved through the file's imports, so an
// aliased import does not pass) and pureBuiltins not redeclared in the
// package (shadow), or a channel receive. A function literal that is only
// stored is not a call; one that is called is.
func mayCall(e ast.Expr, pkgs map[string]string, shadow map[string]bool) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.UnaryExpr:
			found = found || n.Op == token.ARROW
		case *ast.CallExpr:
			found = found || !pureCall(n.Fun, pkgs, shadow)
		}
		return !found
	})
	return found
}

func pureCall(fun ast.Expr, pkgs map[string]string, shadow map[string]bool) bool {
	switch fn := ast.Unparen(fun).(type) {
	case *ast.Ident:
		_, declared := shadow[fn.Name]
		return pureBuiltins[fn.Name] && !declared
	case *ast.SelectorExpr:
		x, ok := fn.X.(*ast.Ident)
		return ok && pkgs[x.Name] == x.Name && pureCalls[x.Name][fn.Sel.Name]
	case *ast.ArrayType, *ast.MapType, *ast.ChanType, *ast.FuncType, *ast.InterfaceType, *ast.StructType:
		return true // conversion to a type literal
	case *ast.StarExpr:
		// (*T)(nil), the "var _ I = (*T)(nil)" idiom, is a conversion when T
		// is a type of this package; (*p)() with p a variable is a call.
		// (*pkg.T)(x) is treated as a call: the gate cannot see pkg.
		id, ok := fn.X.(*ast.Ident)
		return ok && shadow[id.Name]
	}
	return false
}

// looksEncoded: at least 95% base64/hex alphabet and no spaces, i.e. data,
// not prose or a table of text. Escapes like \x41 count as data too.
func looksEncoded(s string) bool {
	if strings.Count(s, " ") > len(s)/50 {
		return false
	}
	good := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=' || c == '\\' || c == '-' || c == '_' {
			good++
		}
	}
	return good*100 >= len(s)*95
}

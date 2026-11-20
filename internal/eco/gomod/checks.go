package gomod

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
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
// stop: process execution, raw system calls, memory unsafety, networking,
// dynamic code loading. golang.org/x/sys/{unix,windows} are syscall by
// another name.
var riskyImports = []string{
	"os/exec", "syscall", "unsafe", "net", "net/http", "plugin",
	"golang.org/x/sys/unix", "golang.org/x/sys/windows",
}

// blobMin is the length past which a base64/hex-looking string literal is
// treated as an embedded blob.
const blobMin = 512

// checkCodes are the hard-stop finding codes, each forcing RouteHuman.
const (
	codeInit     = "gomod.init-changed"
	codeCgo      = "gomod.cgo"
	codeLinkname = "gomod.linkname"
	codeImport   = "gomod.risky-import"
	codeGenerate = "gomod.go-generate"
	codeEmbed    = "gomod.go-embed"
	codeBlob     = "gomod.encoded-blob"
	codeBinary   = "gomod.binary-file"
	codeAsm      = "gomod.assembly-changed"
	codeParse    = "gomod.unparseable"
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
	codeInit:     "new or changed func init() (runs on import)",
	codeCgo:      `cgo (import "C" or //go:cgo_ directives) in a new or changed file`,
	codeLinkname: "new //go:linkname (reaches into another package's internals)",
	codeImport:   "non-test file newly imports a process/syscall/unsafe/network/plugin package",
	codeGenerate: "new //go:generate directive",
	codeEmbed:    "new //go:embed directive",
	codeBlob:     fmt.Sprintf("new base64/hex-looking string literal longer than %d characters", blobMin),
	codeBinary:   "binary file added or changed outside testdata/",
	codeAsm:      "assembly (.s) file added or changed",
	codeParse:    "Go file the gate could not parse (checked as text only)",
}

// CheckTrees runs the Go hard stops over two module trees. old may be nil
// for a new module.
func CheckTrees(old, cur *ecoutil.Tree) hits {
	h := hits{}
	for _, rel := range cur.Files {
		if isVendor(rel) {
			continue
		}
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
		case testdata:
			// Never compiled into a consumer (see go:embed check for the one way in).
		case ext == ".s" || ext == ".S":
			h.add(codeAsm, rel)
		case evidence.IsBinary(data):
			h.add(codeBinary, rel)
		case ext == ".go" && !strings.HasSuffix(rel, "_test.go"):
			checkGoFile(h, rel, prev, data)
		}
	}
	return h
}

func isVendor(rel string) bool {
	return rel == "vendor" || strings.HasPrefix(rel, "vendor/") || strings.Contains(rel, "/vendor/")
}

// goFacts is what the checks compare between the old and new file.
type goFacts struct {
	imports    map[string]bool
	cgo        bool
	inits      []string // source text of each func init
	directives map[string]bool
	blobs      map[string]bool
	parsed     bool
}

func facts(name string, src []byte) goFacts {
	f := goFacts{imports: map[string]bool{}, directives: map[string]bool{}, blobs: map[string]bool{}}
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
		for _, imp := range file.Imports {
			if p, err := strconv.Unquote(imp.Path.Value); err == nil {
				f.imports[p] = true
			}
		}
		f.cgo = f.imports["C"]
		for _, d := range file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name.Name != "init" {
				continue
			}
			start, end := fset.Position(fd.Pos()).Offset, fset.Position(fd.End()).Offset
			f.inits = append(f.inits, string(src[start:end]))
		}
	} else {
		// Fall back to text: assume the worst about cgo and init.
		s := string(src)
		f.cgo = strings.Contains(s, `"C"`)
		if strings.Contains(s, "func init(") {
			f.inits = append(f.inits, s)
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

func checkGoFile(h hits, rel string, prev, cur []byte) {
	o, n := facts(rel, prev), facts(rel, cur)
	if !n.parsed {
		h.add(codeParse, rel)
	}
	for _, imp := range riskyImports {
		if n.imports[imp] && !o.imports[imp] {
			h.add(codeImport, rel+" ("+imp+")")
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

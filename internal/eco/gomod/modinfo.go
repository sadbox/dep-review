package gomod

import (
	"go/parser"
	"go/token"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
)

// modInfo is what the init walk knows of the module's own packages.
type modInfo struct {
	path string          // the module path ("" when unknown)
	dirs map[string]bool // every directory holding a non-test .go file
	// names: directory -> every name it may be imported under: each
	// non-test file's package clause (whatever its build constraints),
	// the directory's base name, and that without a major version.
	names map[string][]string
	// deps: directory -> the module's directories it imports or pulls
	// with //go:linkname, from every non-test file under any build tags.
	deps map[string]map[string]bool
	// pushes: directory -> name -> the references a //go:linkname in
	// another directory adds to it. A directive is taken both ways (the
	// gate does not tell a pull from a push): its local name refers to
	// the target, and the target to the local name.
	pushes map[string]map[string][]string
}

// linknameRe finds //go:linkname directives anywhere in a file (an
// over-approximation of where the compiler reads them).
var linknameRe = regexp.MustCompile(`//go:linkname[ \t]+(\S+)[ \t]+(\S+)`)

// nonTestGo is a non-test Go source file.
func nonTestGo(rel string) bool { return path.Ext(rel) == ".go" && !strings.HasSuffix(rel, "_test.go") }

func newModInfo(t *ecoutil.Tree, modPath string) *modInfo {
	m := &modInfo{path: modPath, dirs: map[string]bool{}, names: map[string][]string{}, deps: map[string]map[string]bool{}, pushes: map[string]map[string][]string{}}
	if t == nil {
		return m
	}
	for _, rel := range t.Files {
		if nonTestGo(rel) {
			d := path.Dir(rel)
			if !m.dirs[d] {
				m.dirs[d] = true
				base := path.Base(path.Join(m.path, d))
				m.addName(d, base)
				if majorRe.MatchString(base) {
					m.addName(d, path.Base(path.Dir(path.Join(m.path, d))))
				}
			}
		}
	}
	for _, rel := range t.Files {
		if !nonTestGo(rel) {
			continue
		}
		dir := path.Dir(rel)
		src := t.ReadFile(rel)
		f, err := parser.ParseFile(token.NewFileSet(), rel, src, parser.ImportsOnly)
		if err != nil {
			continue
		}
		m.addName(dir, f.Name.Name)
		edge := func(from, to string) {
			if m.deps[from] == nil {
				m.deps[from] = map[string]bool{}
			}
			m.deps[from][to] = true
		}
		for _, imp := range f.Imports {
			if p, err := strconv.Unquote(imp.Path.Value); err == nil {
				if d, ok := m.dirOf(p); ok && d != dir {
					edge(dir, d)
				}
			}
		}
		for _, l := range linkPulls(src) {
			d, ok := m.dirOf(l.pkg)
			if !ok || d == dir {
				continue
			}
			edge(dir, d)
			edge(d, dir)
			if m.pushes[d] == nil {
				m.pushes[d] = map[string][]string{}
			}
			m.pushes[d][l.name] = append(m.pushes[d][l.name], dir+":"+l.local)
		}
	}
	return m
}

var majorRe = regexp.MustCompile(`^v[0-9]+$`)

func (m *modInfo) addName(dir, name string) {
	if name != "" && name != "." && !slices.Contains(m.names[dir], name) {
		m.names[dir] = append(m.names[dir], name)
	}
}

// dir resolves a directory a reference names to one of the module's: the
// same, or the only one equal under case folding (a case-insensitive file
// system builds an import of "B" from b/).
func (m *modInfo) dir(d string) (string, bool) {
	if m.dirs[d] {
		return d, true
	}
	var hit []string
	for x := range m.dirs {
		if strings.EqualFold(x, d) {
			hit = append(hit, x)
		}
	}
	if len(hit) == 1 {
		return hit[0], true
	}
	return "", false
}

// dirOf is the module directory of import path p, if it is one of the
// module's packages.
func (m *modInfo) dirOf(p string) (string, bool) {
	if m.path == "" {
		return "", false
	}
	if p == m.path {
		return m.dir(".")
	}
	if d, ok := strings.CutPrefix(p, m.path+"/"); ok {
		return m.dir(d)
	}
	return "", false
}

// reaching returns, sorted, every directory that is one of changed or
// imports one of them within the module, directly or not.
func (m *modInfo) reaching(changed []string) []string {
	rev := map[string][]string{}
	for d, ds := range m.deps {
		for e := range ds {
			rev[e] = append(rev[e], d)
		}
	}
	seen := map[string]bool{}
	queue := slices.Clone(changed)
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		if seen[d] {
			continue
		}
		seen[d] = true
		queue = append(queue, rev[d]...)
	}
	var out []string
	for d := range seen {
		if m.dirs[d] {
			out = append(out, d)
		}
	}
	slices.Sort(out)
	return out
}

// linkPull is one //go:linkname directive that names a package's symbol:
// local is linked to pkg's name (a function or variable "F", or a method
// "T.M").
type linkPull struct{ local, pkg, name string }

// linkPulls reads the directives of src. The package path ends at the
// first "." after its last "/", as the linker splits a symbol; a method
// "(*T).M" is "T.M".
func linkPulls(src []byte) []linkPull {
	var out []linkPull
	for _, m := range linknameRe.FindAllSubmatch(src, -1) {
		target := string(m[2])
		slash := strings.LastIndex(target, "/")
		i := strings.Index(target[slash+1:], ".")
		if i <= 0 {
			continue
		}
		i += slash + 1
		name := strings.NewReplacer("(*", "", "(", "", ")", "").Replace(target[i+1:])
		out = append(out, linkPull{local: string(m[1]), pkg: target[:i], name: name})
	}
	return out
}

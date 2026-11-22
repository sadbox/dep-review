package gomod

import (
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
)

// typedItems runs the checks on a module (with a go.mod, so the type
// checker runs) and returns the init-callee items.
func typedItems(t *testing.T, old, cur map[string]string) []string {
	t.Helper()
	for _, m := range []map[string]string{old, cur} {
		m["go.mod"] = "module example.com/m\n\ngo 1.24\n"
	}
	h := CheckTrees(writeTree(t, old), writeTree(t, cur))
	if h.typedDirs == 0 {
		t.Fatalf("the type checker did not run")
	}
	return h.items(codeInitCallee)
}

func TestTypedWalk(t *testing.T) {
	const pool = "package m\n\nimport \"sync\"\n\nvar pool sync.Pool\n\nfunc init() { pool.Put(nil) }\n"
	tests := []struct {
		name     string
		old, cur map[string]string
		want     []string
	}{
		// A method of another package's concrete type runs no local code.
		{"sync.Pool.Put is not every local Put",
			map[string]string{"a.go": pool, "u.go": "package m\n\ntype U struct{}\n\nfunc (U) Put(any) {}\n"},
			map[string]string{"a.go": pool, "u.go": "package m\n\ntype U struct{}\n\nfunc (U) Put(any) { println(1) }\n"},
			nil},
		// A method of a local concrete type is exactly that method.
		{"t.M is T's M only",
			map[string]string{"a.go": "package m\n\nfunc init() { var t T; t.M() }\n\ntype T struct{}\n\nfunc (T) M() {}\n\ntype U struct{}\n\nfunc (U) M() {}\n"},
			map[string]string{"a.go": "package m\n\nfunc init() { var t T; t.M() }\n\ntype T struct{}\n\nfunc (T) M() {}\n\ntype U struct{}\n\nfunc (U) M() { println(1) }\n"},
			nil},
		{"t.M changed",
			map[string]string{"a.go": "package m\n\nfunc init() { var t T; t.M() }\n\ntype T struct{}\n\nfunc (T) M() {}\n"},
			map[string]string{"a.go": "package m\n\nfunc init() { var t T; t.M() }\n\ntype T struct{}\n\nfunc (T) M() { println(1) }\n"},
			[]string{"T", "T.M"}},
		// Through an interface, any method of that name.
		{"interface call reaches every M",
			map[string]string{"a.go": "package m\n\ntype I interface{ M() }\n\nvar i I\n\nfunc init() { i.M() }\n\ntype U struct{}\n\nfunc (U) M() {}\n"},
			map[string]string{"a.go": "package m\n\ntype I interface{ M() }\n\nvar i I\n\nfunc init() { i.M() }\n\ntype U struct{}\n\nfunc (U) M() { println(1) }\n"},
			[]string{"M", "U"}},
		{"another package's interface reaches every Write",
			map[string]string{"a.go": "package m\n\nimport \"io\"\n\nvar w io.Writer\n\nfunc init() { w.Write(nil) }\n\ntype U struct{}\n\nfunc (U) Write(b []byte) (int, error) { return 0, nil }\n"},
			map[string]string{"a.go": "package m\n\nimport \"io\"\n\nvar w io.Writer\n\nfunc init() { w.Write(nil) }\n\ntype U struct{}\n\nfunc (U) Write(b []byte) (int, error) { println(1); return 0, nil }\n"},
			[]string{"U", "Write"}},
		// A local named like a package-level function is not a reference.
		{"local shadows a function",
			map[string]string{"a.go": "package m\n\nfunc init() { helper := 1; _ = helper }\n\nfunc helper() {}\n"},
			map[string]string{"a.go": "package m\n\nfunc init() { helper := 1; _ = helper }\n\nfunc helper() { println(1) }\n"},
			nil},
		// Unresolvable (an import outside the module): by name.
		{"unresolved selector by name",
			map[string]string{"a.go": "package m\n\nimport \"example.org/x\"\n\nfunc init() { x.V.Run() }\n\ntype U struct{}\n\nfunc (U) Run() {}\n"},
			map[string]string{"a.go": "package m\n\nimport \"example.org/x\"\n\nfunc init() { x.V.Run() }\n\ntype U struct{}\n\nfunc (U) Run() { println(1) }\n"},
			[]string{"Run", "U"}},
		// A promoted method is its embedded type's.
		{"promoted method",
			map[string]string{"a.go": "package m\n\ntype E struct{}\n\nfunc (E) M() {}\n\ntype T struct{ E }\n\nfunc init() { var t T; t.M() }\n"},
			map[string]string{"a.go": "package m\n\ntype E struct{}\n\nfunc (E) M() { println(1) }\n\ntype T struct{ E }\n\nfunc init() { var t T; t.M() }\n"},
			[]string{"E", "E.M"}},
		// Each configuration's own files: a helper only Windows builds.
		{"platform file",
			map[string]string{"a.go": "package m\n\nfunc init() { helper() }\n", "h_windows.go": "package m\n\nfunc helper() {}\n", "h_other.go": "//go:build !windows\n\npackage m\n\nfunc helper() {}\n"},
			map[string]string{"a.go": "package m\n\nfunc init() { helper() }\n", "h_windows.go": "package m\n\nfunc helper() { println(1) }\n", "h_other.go": "//go:build !windows\n\npackage m\n\nfunc helper() {}\n"},
			[]string{"helper"}},
		// A func value stored and called is followed.
		{"func value",
			map[string]string{"a.go": "package m\n\nvar f = helper\n\nfunc init() { f() }\n\nfunc helper() {}\n"},
			map[string]string{"a.go": "package m\n\nvar f = helper\n\nfunc init() { f() }\n\nfunc helper() { println(1) }\n"},
			[]string{"helper"}},
		// An embedded field's type is a reference (its methods are
		// promoted): the identifier is a use as well as a definition.
		{"embedded field",
			map[string]string{"a.go": "package m\n\nimport \"fmt\"\n\ntype U struct{}\n\nfunc (U) String() string { return \"a\" }\n\ntype T struct{ U }\n\nvar s = fmt.Sprint(T{})\n"},
			map[string]string{"a.go": "package m\n\nimport \"fmt\"\n\ntype U struct{}\n\nfunc (U) String() string { return \"b\" }\n\ntype T struct{ U }\n\nvar s = fmt.Sprint(T{})\n"},
			[]string{"U"}},
		// A method declared on an alias receiver is the index's "A.M".
		{"alias receiver",
			map[string]string{"a.go": "package m\n\ntype T struct{}\n\ntype A = T\n\nfunc (A) M() {}\n\nfunc init() { var t T; t.M() }\n"},
			map[string]string{"a.go": "package m\n\ntype T struct{}\n\ntype A = T\n\nfunc (A) M() { println(1) }\n\nfunc init() { var t T; t.M() }\n"},
			[]string{"A", "A.M"}},
		// Each configuration's in-module imports: a dot-imported name only
		// one platform's file declares resolves to the local function
		// everywhere else.
		{"dot import resolved per configuration",
			map[string]string{"a.go": "package m\n\nfunc init() { helper() }\n", "h.go": "package m\n\nfunc helper() { Foo() }\n", "f.go": "package m\n\nfunc Foo() {}\n", "b/b.go": "package b\n\nvar Bar = 1\n"},
			map[string]string{"a.go": "package m\n\nfunc init() { helper() }\n", "h.go": "package m\n\nimport . \"example.com/m/b\"\n\nvar _ = Bar\n\nfunc helper() { Foo() }\n", "f.go": "package m\n\nfunc Foo() { println(1) }\n", "b/b.go": "package b\n\nvar Bar = 1\n", "b/b_aix.go": "//go:build aix\n\npackage b\n\nfunc Foo() {}\n"},
			[]string{"Foo", "b/Foo"}},
		// Across the module's packages: an unchanged init reaching a
		// changed function of another package of the module.
		{"another package of the module",
			map[string]string{"a.go": "package m\n\nimport \"example.com/m/b\"\n\nfunc init() { b.F() }\n", "b/b.go": "package b\n\nfunc F() { g() }\n\nfunc g() {}\n"},
			map[string]string{"a.go": "package m\n\nimport \"example.com/m/b\"\n\nfunc init() { b.F() }\n", "b/b.go": "package b\n\nfunc F() { g() }\n\nfunc g() { println(1) }\n"},
			[]string{"b/g"}},
		{"another package's method",
			map[string]string{"a.go": "package m\n\nimport \"example.com/m/b\"\n\nfunc init() { var t b.T; t.M() }\n", "b/b.go": "package b\n\ntype T struct{}\n\nfunc (T) M() {}\n\ntype U struct{}\n\nfunc (U) M() {}\n"},
			map[string]string{"a.go": "package m\n\nimport \"example.com/m/b\"\n\nfunc init() { var t b.T; t.M() }\n", "b/b.go": "package b\n\ntype T struct{}\n\nfunc (T) M() { println(1) }\n\ntype U struct{}\n\nfunc (U) M() { println(1) }\n"},
			[]string{"b/T", "b/T.M"}},
		{"init in an unchanged package",
			map[string]string{"c/c.go": "package c\n\nimport \"example.com/m/b\"\n\nfunc init() { b.F() }\n", "b/b.go": "package b\n\nfunc F() {}\n"},
			map[string]string{"c/c.go": "package c\n\nimport \"example.com/m/b\"\n\nfunc init() { b.F() }\n", "b/b.go": "package b\n\nfunc F() { println(1) }\n"},
			[]string{"b/F"}},
		// A value of a local type handed to fmt: its methods (String).
		{"implicit String",
			map[string]string{"a.go": "package m\n\nimport \"fmt\"\n\ntype T struct{}\n\nfunc (T) String() string { return \"a\" }\n\nvar s = fmt.Sprint(T{})\n"},
			map[string]string{"a.go": "package m\n\nimport \"fmt\"\n\ntype T struct{}\n\nfunc (T) String() string { return \"b\" }\n\nvar s = fmt.Sprint(T{})\n"},
			[]string{"T"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := typedItems(t, tt.old, tt.cur)
			if !slices.Equal(got, tt.want) {
				t.Errorf("init-callee items %q, want %q", got, tt.want)
			}
		})
	}
}

// The types child imports only well-formed standard-library paths.
func TestTypedImportPaths(t *testing.T) {
	c := &checker{req: typesRequest{Module: "example.com/m", GOROOT: t.TempDir()}}
	for _, p := range []string{"x/../cmd/compile/internal/ssagen", "cmd/compile", "CMD/compile", "Cmd/go", "C", "example.org/x", "./x", "a//b"} {
		if _, err := c.importPath(p, 0); err == nil {
			t.Errorf("%q imported", p)
		}
	}
}

// Without the type checker, a qualified pkg.Name of the module's own
// package is still that package's.
func TestByNameCrossPackage(t *testing.T) {
	tr := writeTree(t, map[string]string{"go.mod": "module example.com/m\n", "a.go": "package m\n\nimport x \"example.com/m/b\"\n\nfunc init() { x.F() }\n", "b/b.go": "package b\n\nfunc F() {}\n"})
	ix := indexPackage(tr, ".", &pkgScope{declared: map[string]bool{}, types: map[string]map[string]bool{}, valueNames: map[string]bool{}}, nil, nil, newModInfo(tr, "example.com/m"))
	if len(ix.roots) != 1 || !slices.Contains(ix.roots[0].refs, "b:F") {
		t.Errorf("roots %+v", ix.roots)
	}
}

// The security review's cross-package cases, with the type checker and
// without it (the by-name fallback after a child fails), and for a
// module with no go.mod (its path is the update's name).
func TestCrossPackageFallback(t *testing.T) {
	const evil = " println(\"evil\") "
	cases := []struct {
		name    string
		files   map[string]string // old; "~" in a value marks where the new one adds evil
		want    []string
		noTyped bool // the type checker cannot build this tree (by name only)
	}{
		{"dot import", map[string]string{"a.go": "package m\n\nimport . \"example.com/m/b\"\n\nfunc init() { F() }\n", "b/b.go": "package b\n\nfunc F() {~}\n"}, []string{"b/F"}, false},
		{"package name differs from the directory", map[string]string{"a.go": "package m\n\nimport \"example.com/m/go-b\"\n\nfunc init() { b.F() }\n", "go-b/b.go": "package b\n\nfunc F() {~}\n"}, []string{"go-b/F"}, false},
		{"major version directory", map[string]string{"a.go": "package m\n\nimport \"example.com/m/b/v2\"\n\nfunc init() { b.F() }\n", "b/v2/b.go": "package b\n\nfunc F() {~}\n"}, []string{"b/v2/F"}, false},
		{"linkname pull", map[string]string{"a.go": "package m\n\nimport _ \"unsafe\"\n\n//go:linkname hidden example.com/m/c.hidden\nfunc hidden()\n\nfunc init() { hidden() }\n", "c/c.go": "package c\n\nfunc hidden() {~}\n"}, []string{"c/hidden"}, true},
		{"case-folded import", map[string]string{"a.go": "package m\n\nimport B \"example.com/m/B\"\n\nfunc init() { B.F() }\n", "b/b.go": "package b\n\nfunc F() {~}\n"}, []string{"b/F"}, true},
		{"linkname push", map[string]string{"a.go": "package m\n\nimport \"example.com/m/c\"\n\nfunc init() { c.Hook() }\n", "c/c.go": "package c\n\nfunc Hook()\n", "d/d.go": "package d\n\nimport _ \"unsafe\"\n\n//go:linkname impl example.com/m/c.Hook\nfunc impl() {~}\n"}, []string{"d/impl"}, true},
		{"indented linkname to a method", map[string]string{"a.go": "package m\n\nimport _ \"unsafe\"\n\n\t//go:linkname hidden example.com/m/c.(*T).m\nfunc hidden()\n\nfunc init() { hidden() }\n", "c/c.go": "package c\n\ntype T struct{}\n\nfunc (*T) m() {~}\n"}, []string{"c/T", "c/T.m"}, true},
		{"package clause in an ignored file", map[string]string{"a.go": "package m\n\nimport \"example.com/m/x\"\n\nfunc init() { real.F() }\n", "x/doc.go": "//go:build ignore\n\npackage decoy\n", "x/x.go": "package real\n\nfunc F() {~}\n"}, []string{"x/F"}, false},
		{"a package that cannot reach the change", map[string]string{"a.go": "package m\n\nfunc init() { F() }\n\nfunc F() {}\n", "b/b.go": "package b\n\nfunc F() {~}\n"}, nil, false},
	}
	defer func(b time.Duration) { typesBudget = b }(typesBudget)
	for _, c := range cases {
		old, cur := map[string]string{}, map[string]string{}
		for k, v := range c.files {
			old[k] = strings.ReplaceAll(v, "~", "")
			cur[k] = strings.ReplaceAll(v, "~", evil)
		}
		for _, mode := range []string{"typed", "by name", "no go.mod"} {
			if mode == "typed" && c.noTyped {
				continue
			}
			o, n := maps.Clone(old), maps.Clone(cur)
			typesBudget = 6 * time.Minute
			switch mode {
			case "by name":
				typesBudget = -1
				fallthrough
			case "typed":
				o["go.mod"], n["go.mod"] = "module example.com/m\n\ngo 1.24\n", "module example.com/m\n\ngo 1.24\n"
			}
			h := checkTrees(writeTree(t, o), writeTree(t, n), nil, defaultLister(), "example.com/m")
			if mode == "typed" && h.typedDirs == 0 && c.want != nil {
				t.Errorf("%s: the type checker did not run", c.name)
			}
			if got := h.items(codeInitCallee); !slices.Equal(got, c.want) {
				t.Errorf("%s (%s): init-callee items %q, want %q", c.name, mode, got, c.want)
			}
		}
	}
}

// One types child per chunk: a chunk of one directory still resolves a
// call into another package.
func TestTypedChunks(t *testing.T) {
	defer func(n int) { typesChunk = n }(typesChunk)
	typesChunk = 1
	old := map[string]string{"a.go": "package m\n\nimport \"example.com/m/b\"\n\nfunc init() { b.F() }\n", "b/b.go": "package b\n\nfunc F() {}\n"}
	cur := map[string]string{"a.go": old["a.go"], "b/b.go": "package b\n\nfunc F() { println(1) }\n"}
	if got := typedItems(t, old, cur); !slices.Equal(got, []string{"b/F"}) {
		t.Errorf("items %q", got)
	}
}

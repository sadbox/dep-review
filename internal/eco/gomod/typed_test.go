package gomod

import (
	"slices"
	"testing"
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
			[]string{"Foo"}},
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

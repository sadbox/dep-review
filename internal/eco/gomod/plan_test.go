package gomod

import (
	"slices"
	"testing"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
)

func TestParseBuildPlan(t *testing.T) {
	tests := []struct {
		platforms, tags string
		cfgs            int // configurations (cgo off and on per platform); -1: error
		nilPlan         bool
	}{
		{"", "", 0, true},
		{"linux/amd64", "", 2, false},
		{"linux/amd64, linux/arm64 darwin/arm64", "race,purego", 6, false},
		{"linux/amd64,linux/amd64", "", 2, false},
		{"", "race", -1, false},
		{"linux/amd99", "", -1, false},
		{"linux", "", -1, false},
		{"linux/amd64", "a=b", -1, false},
		{"linux/amd64", "-x", -1, false},
		{"linux/amd64", "a,b,c,d,e,f,g,h,i,j,k", -1, false},
	}
	for _, tt := range tests {
		p, err := ParseBuildPlan(tt.platforms, tt.tags)
		switch {
		case tt.cfgs < 0:
			if err == nil {
				t.Errorf("%q %q: no error", tt.platforms, tt.tags)
			}
		case err != nil:
			t.Errorf("%q %q: %v", tt.platforms, tt.tags, err)
		case tt.nilPlan != (p == nil):
			t.Errorf("%q %q: plan %v", tt.platforms, tt.tags, p)
		case p != nil && len(p.cfgs) != tt.cfgs:
			t.Errorf("%q %q: %d configurations, want %d", tt.platforms, tt.tags, len(p.cfgs), tt.cfgs)
		}
	}
}

// planCodes runs the checks under a declared plan (nil: every platform).
func planCodes(t *testing.T, platforms, tags string, old, cur map[string]string) []string {
	t.Helper()
	var plan *BuildPlan
	if platforms != "" {
		var err error
		if plan, err = ParseBuildPlan(platforms, tags); err != nil {
			t.Fatal(err)
		}
	}
	var o *ecoutil.Tree
	if old != nil {
		o = writeTree(t, old)
	}
	h := checkTrees(o, writeTree(t, cur), nil, goLister{goBin: defaultLister().goBin, plan: plan})
	var got []string
	for _, f := range h.findings("m") {
		got = append(got, f.Code)
	}
	return got
}

func TestDeclaredBuilds(t *testing.T) {
	const gomod = "module example.com/m\n\ngo 1.24\n"
	const asm = "TEXT ·f(SB),0,$0\nRET\n"
	base := func(extra map[string]string) map[string]string {
		m := map[string]string{"go.mod": gomod, "a.go": "package m\n"}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	tests := []struct {
		name            string
		platforms, tags string
		old, cur        map[string]string
		want            []string
	}{
		// Files no declared build compiles are skipped...
		{"windows init, linux build", "linux/amd64", "", base(nil), base(map[string]string{"w_windows.go": "package m\n\nfunc init() { println(1) }\n"}), nil},
		{"windows init, every platform", "", "", base(nil), base(map[string]string{"w_windows.go": "package m\n\nfunc init() { println(1) }\n"}), []string{codeInit}},
		{"plan9 assembly, linux build", "linux/amd64", "", base(map[string]string{"f_plan9_amd64.s": asm}), base(map[string]string{"f_plan9_amd64.s": asm + "RET\n"}), nil},
		{"linux assembly, linux build", "linux/amd64", "", base(map[string]string{"f_linux_amd64.s": asm}), base(map[string]string{"f_linux_amd64.s": asm + "RET\n"}), []string{codeAsm}},
		// (go build refuses a package with .c files and no cgo, so nothing
		// compiles them either.)
		{"C source, no cgo in the build", "linux/amd64", "", base(map[string]string{"csrc/x.c": "int f(void){return 0;}\n"}), base(map[string]string{"csrc/x.c": "int f(void){return 1;}\n"}), nil},
		{"C in a package without cgo", "linux/amd64", "", base(map[string]string{"x.c": "int f(void){return 0;}\n"}), base(map[string]string{"x.c": "int f(void){return 1;}\n"}), nil},
		{"C source, cgo in the build", "linux/amd64", "", base(map[string]string{"x.c": "int f(void){return 0;}\n", "c.go": "package m\n\nimport \"C\"\n"}), base(map[string]string{"x.c": "int f(void){return 1;}\n", "c.go": "package m\n\nimport \"C\"\n"}), []string{codeCSource}},
		{"unbuilt assembly a built one includes", "linux/amd64", "", base(map[string]string{"f_linux_amd64.s": "#include \"g_plan9_amd64.s\"\n" + asm, "g_plan9_amd64.s": asm}), base(map[string]string{"f_linux_amd64.s": "#include \"g_plan9_amd64.s\"\n" + asm, "g_plan9_amd64.s": asm + "RET\n"}), []string{codeAsm}},
		// ... and tags are exact.
		{"race file, race declared", "linux/amd64", "race", base(nil), base(map[string]string{"r.go": "//go:build race\n\npackage m\n\nfunc init() { println(1) }\n"}), []string{codeInit}},
		{"race file, race not declared", "linux/amd64", "", base(nil), base(map[string]string{"r.go": "//go:build race\n\npackage m\n\nfunc init() { println(1) }\n"}), nil},
		// The documented sibling limit: under the declared tag the old
		// package had two package clauses (it did not build); a sibling's
		// fix makes it build, so the unchanged init file newly enters it.
		{"sibling fix under a declared tag", "linux/amd64", "mytag",
			base(map[string]string{"t.go": "//go:build mytag\n\npackage m\n\nfunc init() { println(1) }\n", "u.go": "//go:build mytag\n\npackage q\n"}),
			base(map[string]string{"t.go": "//go:build mytag\n\npackage m\n\nfunc init() { println(1) }\n", "u.go": "//go:build mytag\n\npackage m\n"}),
			[]string{codeInit, codeNewlyBuilt}},
		// The init walk follows only compiled declarations.
		{"init callee only windows builds", "linux/amd64", "",
			base(map[string]string{"i.go": "package m\n\nfunc init() { helper() }\n", "h_linux.go": "package m\n\nfunc helper() {}\n", "h_windows.go": "package m\n\nfunc helper() {}\n"}),
			base(map[string]string{"i.go": "package m\n\nfunc init() { helper() }\n", "h_linux.go": "package m\n\nfunc helper() {}\n", "h_windows.go": "package m\n\nfunc helper() { println(1) }\n"}),
			nil},
		{"init callee linux builds", "linux/amd64", "",
			base(map[string]string{"i.go": "package m\n\nfunc init() { helper() }\n", "h_linux.go": "package m\n\nfunc helper() {}\n", "h_windows.go": "package m\n\nfunc helper() {}\n"}),
			base(map[string]string{"i.go": "package m\n\nfunc init() { helper() }\n", "h_linux.go": "package m\n\nfunc helper() { println(1) }\n", "h_windows.go": "package m\n\nfunc helper() {}\n"}),
			[]string{codeInitCallee}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := planCodes(t, tt.platforms, tt.tags, tt.old, tt.cur)
			if !slices.Equal(got, tt.want) {
				t.Errorf("codes = %q, want %q", got, tt.want)
			}
		})
	}
}

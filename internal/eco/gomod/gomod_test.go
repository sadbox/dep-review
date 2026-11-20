package gomod

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
	"github.com/sadbox/dep-review/internal/eco/ecoutil/gittest"
	"github.com/sadbox/dep-review/internal/evidence"
	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/model"
)

func TestParseModFile(t *testing.T) {
	src := `module example.com/m // comment

go 1.27

toolchain go1.27.4

require (
	github.com/a/b v1.2.3
	"github.com/q/r" v0.1.0 // indirect
	golang.org/x/sys v0.50.0 // indirect; for unix
)

require example.com/single v2.0.0+incompatible

replace github.com/a/b => ../b
exclude (
	github.com/a/b v1.2.2
)
retract v0.0.1
godebug default=go1.21
`
	mf, err := ParseModFile([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Require{
		"github.com/a/b":     {"v1.2.3", false},
		"github.com/q/r":     {"v0.1.0", true},
		"golang.org/x/sys":   {"v0.50.0", true},
		"example.com/single": {"v2.0.0+incompatible", false},
	}
	if len(mf.Require) != len(want) {
		t.Errorf("Require = %v", mf.Require)
	}
	for k, v := range want {
		if mf.Require[k] != v {
			t.Errorf("Require[%s] = %v, want %v", k, mf.Require[k], v)
		}
	}
	if mf.Module != "example.com/m" || mf.Go != "1.27" || mf.Toolchain != "go1.27.4" {
		t.Errorf("module/go/toolchain = %q %q %q", mf.Module, mf.Go, mf.Toolchain)
	}
	wantDir := []string{"exclude github.com/a/b v1.2.2", "godebug default=go1.21", "replace github.com/a/b => ../b"}
	if !slices.Equal(mf.Directives, wantDir) {
		t.Errorf("Directives = %q, want %q", mf.Directives, wantDir)
	}

	for _, bad := range []string{"require (\n a v1\n", `module "x`, "go 1.2\n"} {
		if _, err := ParseModFile([]byte(bad)); err == nil {
			t.Errorf("ParseModFile(%q) succeeded", bad)
		}
	}
}

// fixtureRepo builds a two-commit repo from testdata/<name>/{base,head}.
func fixtureRepo(t *testing.T, name string, extraHead map[string][]byte) (string, model.Classification) {
	t.Helper()
	base := gittest.ReadDir(t, filepath.Join("testdata", name, "base"))
	head := gittest.ReadDir(t, filepath.Join("testdata", name, "head"))
	for k, v := range extraHead {
		head[k] = v
	}
	dir, b, h := gittest.Repo(t, base, head)
	return dir, model.Classification{
		Repo: "test/" + name, PR: 1, BaseSHA: b, HeadSHA: h, Kind: model.KindDependabot, Ecosystem: model.GoModules,
	}
}

func TestChangeSetFromFixtures(t *testing.T) {
	tests := []struct {
		fixture string
		want    []string // "name from to type direct"
	}{
		{"sprobot285", []string{"github.com/aws/aws-sdk-go-v2/credentials v1.21.0 v1.21.1 patch true"}},
		{"towngear49", []string{
			"golang.org/x/image v0.47.0 v0.48.0 minor true",
			"golang.org/x/sys v0.49.0 v0.50.0 minor false",
			"golang.org/x/text v0.43.0 v0.44.0 minor false",
			"golang.org/x/sync v0.24.0 v0.25.0 minor false", // go.sum only
		}},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			repo, class := fixtureRepo(t, tt.fixture, nil)
			git := ecoutil.Git{Repo: repo, Home: t.TempDir()}
			var sum bytes.Buffer
			changes, findings, err := moduleChanges(context.Background(), git, class.BaseSHA, class.HeadSHA, ".", &sum)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, c := range changes {
				u := c.update
				got = append(got, strings.Join([]string{u.Name, u.From, u.To, string(u.Type), boolStr(u.Direct)}, " "))
				if u.Directory != "/" || u.Ecosystem != model.GoModules {
					t.Errorf("%s: directory %q ecosystem %q", u.Name, u.Directory, u.Ecosystem)
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("changes:\n got %q\nwant %q", got, tt.want)
			}
			if len(findings) != 0 {
				t.Errorf("findings: %+v", findings)
			}
		})
	}
}

func TestDirectiveFindings(t *testing.T) {
	base := gittest.ReadDir(t, filepath.Join("testdata", "sprobot285", "base"))
	head := gittest.ReadDir(t, filepath.Join("testdata", "sprobot285", "head"))
	tests := []struct {
		name string
		edit func(string) string
		want []string
	}{
		{"toolchain", func(s string) string { return s + "\ntoolchain go1.99.0\n" }, []string{"gomod.toolchain-changed"}},
		{"replace", func(s string) string { return s + "\nreplace github.com/a/b => github.com/evil/b v1.0.0\n" }, []string{"gomod.directive-changed"}},
		{"exclude", func(s string) string { return s + "\nexclude github.com/a/b v1.0.0\n" }, []string{"gomod.directive-changed"}},
		{"major", func(s string) string {
			return strings.Replace(s, "github.com/aws/aws-sdk-go-v2/credentials v1.21.1", "github.com/aws/aws-sdk-go-v2/credentials/v2 v2.0.0", 1)
		}, []string{"gomod.major-path", "gomod.removed"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := map[string][]byte{"go.sum": head["go.sum"], "go.mod": []byte(tt.edit(string(head["go.mod"])))}
			dir, b, hs := gittest.Repo(t, base, h)
			var sum bytes.Buffer
			_, findings, err := moduleChanges(context.Background(), ecoutil.Git{Repo: dir, Home: t.TempDir()}, b, hs, ".", &sum)
			if err != nil {
				t.Fatal(err)
			}
			var codes []string
			for _, f := range findings {
				codes = append(codes, f.Code)
			}
			slices.Sort(codes)
			if !slices.Equal(codes, tt.want) {
				t.Errorf("codes = %q, want %q (%+v)", codes, tt.want, findings)
			}
		})
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func writeTree(t *testing.T, files map[string]string) *ecoutil.Tree {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tree, err := ecoutil.DirTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func TestCheckTrees(t *testing.T) {
	const plain = "package p\n\nimport \"fmt\"\n\nfunc F() { fmt.Println(1) }\n"
	blob := `"` + strings.Repeat("QUJD", 200) + `"`
	tests := []struct {
		name     string
		old, cur map[string]string
		want     []string
	}{
		{"unchanged", map[string]string{"a.go": plain}, map[string]string{"a.go": plain}, nil},
		{"benign edit", map[string]string{"a.go": plain}, map[string]string{"a.go": strings.Replace(plain, "1", "2", 1)}, nil},
		{"new init", map[string]string{"a.go": plain}, map[string]string{"a.go": plain + "func init() {}\n"}, []string{codeInit}},
		{"changed init", map[string]string{"a.go": plain + "func init() { a() }\n"}, map[string]string{"a.go": plain + "func init() { b() }\n"}, []string{codeInit}},
		{"same init, other edit", map[string]string{"a.go": plain + "func init() { a() }\n"}, map[string]string{"a.go": plain + "func init() { a() }\nfunc G() {}\n"}, nil},
		{"method named init is fine", nil, map[string]string{"a.go": "package p\ntype T struct{}\nfunc (T) init() {}\n"}, nil},
		{"cgo", nil, map[string]string{"c.go": "package p\n// #include <stdio.h>\nimport \"C\"\n"}, []string{codeCgo}},
		{"linkname", map[string]string{"a.go": plain}, map[string]string{"a.go": "package p\nimport _ \"unsafe\"\n//go:linkname x runtime.x\nvar x int\n"}, []string{codeLinkname, codeImport}},
		{"exec import", map[string]string{"a.go": plain}, map[string]string{"a.go": "package p\nimport \"os/exec\"\nvar _ = exec.Command\n"}, []string{codeImport}},
		{"existing exec import", map[string]string{"a.go": "package p\nimport \"os/exec\"\nvar _ = exec.Command\n"}, map[string]string{"a.go": "package p\nimport \"os/exec\"\nvar _ = exec.LookPath\n"}, nil},
		{"exec in test file", nil, map[string]string{"a_test.go": "package p\nimport \"os/exec\"\nvar _ = exec.Command\n"}, nil},
		{"net/http", nil, map[string]string{"h.go": "package p\nimport \"net/http\"\nvar _ = http.Get\n"}, []string{codeImport}},
		{"go:generate", nil, map[string]string{"g.go": "package p\n//go:generate sh -c evil\n"}, []string{codeGenerate}},
		{"go:embed", nil, map[string]string{"e.go": "package p\nimport _ \"embed\"\n//go:embed testdata/x\nvar s string\n"}, []string{codeEmbed}},
		{"blob", nil, map[string]string{"b.go": "package p\nvar s = " + blob + "\n"}, []string{codeBlob}},
		{"long prose literal", nil, map[string]string{"b.go": "package p\nvar s = \"" + strings.Repeat("lorem ipsum ", 100) + "\"\n"}, nil},
		{"assembly", nil, map[string]string{"x_amd64.s": "TEXT ·f(SB),0,$0\nRET\n"}, []string{codeAsm}},
		{"binary", nil, map[string]string{"x.syso": "\x7fELF\x00\x00"}, []string{codeBinary}},
		{"testdata binary fixture", nil, map[string]string{"testdata/x.bin": "\x00\x01"}, nil},
		{"testdata syso", nil, map[string]string{"testdata/p/x.syso": "\x7fELF\x00\x00"}, []string{codeBinary}},
		{"vendor checked", nil, map[string]string{"vendor/x/x.go": "package x\nimport \"os/exec\"\n"}, []string{codeImport}},
		{"c source", map[string]string{"x.c": "int f(void) { return 0; }\n"}, map[string]string{"x.c": "int f(void) { return 1; }\n"}, []string{codeCSource}},
		{"net subpackage", nil, map[string]string{"h.go": "package p\nimport \"net/http/httputil\"\nvar _ httputil.BufferPool\n"}, []string{codeImport}},
		{"x/sys subpackage", nil, map[string]string{"h.go": "package p\nimport \"golang.org/x/sys/cpu\"\nvar _ = cpu.X86\n"}, []string{codeImport}},
		{"net/url is parse-only", nil, map[string]string{"h.go": "package p\nimport \"net/url\"\nvar _ url.URL\n"}, nil},
		{"os", map[string]string{"a.go": plain}, map[string]string{"a.go": "package p\nimport \"os\"\nfunc F() { os.Remove(\"x\") }\n"}, []string{codeImport}},
		{"reflect", nil, map[string]string{"a.go": "package p\nimport \"reflect\"\nvar _ reflect.Value\n"}, []string{codeImport}},
		{"new blank import", map[string]string{"a.go": plain}, map[string]string{"a.go": "package p\nimport _ \"example.com/q\"\n"}, []string{codeBlank}},
		{"blank embed is fine", nil, map[string]string{"a.go": "package p\nimport _ \"embed\"\n"}, nil},
		{"var initializer call", map[string]string{"a.go": "package p\nimport \"os\"\nvar x = 1\nvar _ = os.Args\n"},
			map[string]string{"a.go": "package p\nimport \"os\"\nvar x = 1\nvar _ = os.Remove(\"/tmp/x\")\n"}, []string{codeVarInit}},
		{"var initializer unchanged", map[string]string{"a.go": "package p\nvar x = setup()\nfunc setup() int { return 1 }\n"},
			map[string]string{"a.go": "package p\nvar x = setup()\nfunc setup() int { return 2 }\n"}, nil},
		{"called func literal", nil, map[string]string{"a.go": "package p\nvar _ = func() int { return 1 }()\n"}, []string{codeVarInit}},
		{"stored func literal", nil, map[string]string{"a.go": "package p\nvar f = func() int { return g() }\nfunc g() int { return 1 }\n"}, nil},
		{"channel receive", nil, map[string]string{"a.go": "package p\nvar c chan int\nvar x = <-c\n"}, []string{codeVarInit}},
		{"pure initializers", nil, map[string]string{"a.go": "package p\nimport (\"errors\"; \"regexp\")\nvar ErrX = errors.New(\"x\")\nvar re = regexp.MustCompile(\"a+\")\nvar m = make(map[string]int, len(\"ab\"))\nvar b = []byte(\"x\")\nvar n = int64(3)\n"}, nil},
		{"aliased errors package", nil, map[string]string{"a.go": "package p\nimport errors \"example.com/evil\"\nvar _ = errors.New(\"x\")\n"}, []string{codeVarInit}},
		{"shadowed builtin", nil, map[string]string{"a.go": "package p\nvar n = len(\"x\")\n", "b.go": "package p\nfunc len(s string) int { return 0 }\n"}, []string{codeVarInit}},
		{"call through pointer", nil, map[string]string{"a.go": "package p\nvar f = g\nvar pf = &f\nvar _ = (*pf)()\nfunc g() int { return 1 }\n"}, []string{codeVarInit}},
		{"unparseable var", nil, map[string]string{"u.go": "package p\nvar x = {{{\n"}, []string{codeParse, codeVarInit}},
		{"unparseable", nil, map[string]string{"u.go": "package p\nfunc {{{\n"}, []string{codeParse}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var old *ecoutil.Tree
			if tt.old != nil {
				old = writeTree(t, tt.old)
			}
			h := CheckTrees(old, writeTree(t, tt.cur))
			var got []string
			for _, f := range h.findings("m") {
				got = append(got, f.Code)
				if f.Route != model.RouteHuman || f.Update != "m" {
					t.Errorf("finding %+v", f)
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("codes = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestReproVendorSkip is the security review's PoC (finding 7): the module
// zip keeps top-level vendor/*.go, and vendor/ or testdata/ packages
// compile when imported by path. The checks used to skip both and found
// nothing; a var initializer calling os.StartProcess was also invisible.
func TestReproVendorSkip(t *testing.T) {
	gomod := "module example.com/dep\n\ngo 1.24\n"
	old := writeTree(t, map[string]string{"go.mod": gomod, "a.go": "package dep\nfunc F(){}\n"})
	evil := "package vendor\nimport \"os/exec\"\nfunc init(){ exec.Command(\"sh\",\"-c\",\"id\").Run() }\n"
	cur := writeTree(t, map[string]string{"go.mod": gomod,
		"a.go":                 "package dep\nimport _ \"example.com/dep/vendor\"\nimport _ \"example.com/dep/internal/vendor\"\nimport _ \"example.com/dep/testdata/td\"\nfunc F(){}\n",
		"vendor/x.go":          evil,
		"internal/vendor/y.go": evil,
		"testdata/td/z.go":     "package td\nimport \"os/exec\"\nfunc init(){ exec.Command(\"id\").Run() }\n"})
	h := CheckTrees(old, cur)
	for _, want := range []string{"vendor/x.go", "internal/vendor/y.go", "testdata/td/z.go"} {
		if !slices.Contains(h[codeInit], want) || !slices.Contains(h[codeImport], want+" (os/exec)") {
			t.Errorf("%s: init/import not flagged: %v", want, h)
		}
	}
	if len(h[codeBlank]) != 3 {
		t.Errorf("blank imports = %q", h[codeBlank])
	}

	cur = writeTree(t, map[string]string{"go.mod": gomod,
		"a.go": "package dep\nimport \"os\"\nvar _, _ = os.StartProcess(\"/bin/sh\", []string{\"sh\",\"-c\",\"id\"}, &os.ProcAttr{})\nfunc F(){}\n"})
	h = CheckTrees(old, cur)
	if !slices.Equal(h[codeVarInit], []string{"a.go"}) || !slices.Equal(h[codeImport], []string{"a.go (os)"}) {
		t.Errorf("StartProcess initializer: %v", h)
	}
}

// TestSumHashChanged: a go.sum hash for a version on both sides changed
// (finding 9). Every such line is refused, module zip and /go.mod alike,
// whether or not the module is otherwise part of the change set.
func TestSumHashChanged(t *testing.T) {
	base := gittest.ReadDir(t, filepath.Join("testdata", "sprobot285", "base"))
	head := gittest.ReadDir(t, filepath.Join("testdata", "sprobot285", "head"))
	for _, line := range []string{
		"github.com/1password/onepassword-sdk-go v0.4.1 h1:My/Q2QXemep0I0qHgGrOs7EEzpPh2QZ1/II+S3YqOG0=",
		"github.com/1password/onepassword-sdk-go v0.4.1/go.mod h1:j/CbzhucTywjlYrd6SE6k0LcQaFZ2l8OLBsAsOYtvD0=",
	} {
		t.Run(line[strings.Index(line, " ")+1:strings.LastIndex(line, " ")], func(t *testing.T) {
			if !strings.Contains(string(head["go.sum"]), line+"\n") {
				t.Fatalf("fixture lacks %q", line)
			}
			sum := strings.Replace(string(head["go.sum"]), line, line[:len(line)-5]+"AAAA=", 1)
			dir, b, hs := gittest.Repo(t, base, map[string][]byte{"go.mod": head["go.mod"], "go.sum": []byte(sum)})
			var buf bytes.Buffer
			_, findings, err := moduleChanges(context.Background(), ecoutil.Git{Repo: dir, Home: t.TempDir()}, b, hs, ".", &buf)
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 || findings[0].Code != "gomod.sum-changed" || findings[0].Route != model.RouteRefuse {
				t.Errorf("findings = %+v", findings)
			}
		})
	}
}

func TestChangelogExcerpt(t *testing.T) {
	old := writeTree(t, map[string]string{"CHANGELOG.md": "# v1.0.0\n- first\n"})
	cur := writeTree(t, map[string]string{"CHANGELOG.md": "# v1.0.1\n- fix\n\n# v1.0.0\n- first\n"})
	if got := string(changelogExcerpt(old, cur)); got != "# v1.0.1\n- fix\n\n" {
		t.Errorf("excerpt = %q", got)
	}
	if got := changelogExcerpt(old, old); got != nil {
		t.Errorf("unchanged changelog excerpt = %q", got)
	}
}

func TestErrorClass(t *testing.T) {
	tests := map[string]string{
		"verifying github.com/x/y@v1.0.0: checksum mismatch":  "refuse",
		"SECURITY ERROR\nThis download does NOT match":        "refuse",
		"reading https://proxy.golang.org/...: 404 Not Found": "human",
		"dial tcp: i/o timeout":                               "infra",
	}
	for msg, want := range tests {
		if got := errorClass(msg); got != want {
			t.Errorf("errorClass(%q) = %s, want %s", msg, got, want)
		}
	}
}

// TestFetchNetwork runs the whole go_modules path through fetch.Run against
// real Dependabot PRs: downloads from proxy.golang.org, sum.golang.org
// verification, diffs and checks.
func TestFetchNetwork(t *testing.T) {
	if testing.Short() {
		t.Skip("network")
	}
	tests := []struct {
		fixture   string
		declared  []model.Update
		wantRoute model.Route
	}{
		{"sprobot285", []model.Update{{Name: "github.com/aws/aws-sdk-go-v2/credentials", From: "1.21.0", To: "1.21.1"}}, model.RouteReview},
		// x/sys always carries assembly and unsafe: a person decides.
		{"towngear49", []model.Update{{Name: "golang.org/x/image", From: "0.47.0", To: "0.48.0"}}, model.RouteHuman},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			repo, class := fixtureRepo(t, tt.fixture, nil)
			class.Declared = tt.declared
			ev := runFetch(t, repo, class)
			t.Logf("route %s, truncated %v", ev.Route, ev.Truncated)
			for _, f := range ev.Findings {
				t.Logf("finding %s %s: %s", f.Code, f.Route, f.Detail)
			}
			for _, f := range ev.Files {
				t.Logf("file %s (%d bytes, untrusted %v): %s", f.Path, f.Bytes, f.Untrusted, f.Description)
			}
			if ev.Route != tt.wantRoute {
				t.Errorf("route = %s, want %s", ev.Route, tt.wantRoute)
			}
		})
	}

	t.Run("go.sum tampered", func(t *testing.T) {
		head := gittest.ReadDir(t, filepath.Join("testdata", "sprobot285", "head"))
		sum := strings.Replace(string(head["go.sum"]), "h1:4iuMmYSa42WMeClXjzE+HoZIeBud6o/bd00BN6WM9H4=", "h1:AAAAYSa42WMeClXjzE+HoZIeBud6o/bd00BN6WM9H4=", 1)
		repo, class := fixtureRepo(t, "sprobot285", map[string][]byte{"go.sum": []byte(sum)})
		ev := runFetch(t, repo, class)
		if ev.Route != model.RouteRefuse {
			t.Errorf("route = %s, want refuse; findings %+v", ev.Route, ev.Findings)
		}
	})
}

func runFetch(t *testing.T, repo string, class model.Classification) model.Evidence {
	t.Helper()
	out := filepath.Join(t.TempDir(), "evidence")
	dir, err := evidence.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	env := fetch.Env{Class: class, RepoDir: repo, Scratch: t.TempDir(), HTTP: ecoutil.NewClient()}
	ev, err := fetch.Run(context.Background(), env, fetch.Registry{model.GoModules: Fetcher{}}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if testing.Verbose() {
		if b, err := os.ReadFile(filepath.Join(out, "gate", "gomod-summary.md")); err == nil {
			t.Logf("summary:\n%s", b)
		}
	}
	return ev
}

package gomod

import (
	"encoding/json"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
	"github.com/sadbox/dep-review/internal/model"
)

// Differential tests: the gate's reading of what is built and what is
// embedded agrees with the go command's (README "Design rules"), on the
// shapes of the round 8-12 PoCs and scan findings.

type goListPkg struct {
	GoFiles, IgnoredGoFiles, EmbedPatterns, EmbedFiles []string
	Error                                              *struct{ Err string }
}

// goList runs `go list -e -json .` for linux/amd64 without cgo in a fresh
// module holding files, offline: the reference.
func goList(t *testing.T, files map[string]string) goListPkg {
	t.Helper()
	return goListArgs(t, files)
}

// goListArgs is goList with extra go list flags.
func goListArgs(t *testing.T, files map[string]string, flags ...string) goListPkg {
	t.Helper()
	dir := t.TempDir()
	files = maps.Clone(files)
	files["go.mod"] = "module example.com/m\n\ngo 1.24\n"
	for name, data := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(data), 0o644)
	}
	cmd := exec.Command("go", append(append([]string{"list", "-e", "-json"}, flags...), ".")...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOFLAGS=", "GOWORK=off", "GOTOOLCHAIN=local", "GOPROXY=off")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	var p goListPkg
	if err := json.Unmarshal(out, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func needGo(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("runs the go command")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command")
	}
}

// linuxAmd64 is the configs index of linux/amd64 without cgo.
func linuxAmd64(t *testing.T) int {
	i := slices.Index(configs, config{"linux", "amd64", false})
	if i < 0 {
		t.Fatal("linux/amd64 is not in the dist list")
	}
	return i
}

// TestDistListCurrent: the embedded dist list is the toolchain's.
func TestDistListCurrent(t *testing.T) {
	needGo(t)
	out, err := exec.Command("go", "tool", "dist", "list").Output()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(strings.Fields(string(out)), strings.Fields(distList)) {
		t.Errorf("distlist.txt is stale: run `go tool dist list > internal/eco/gomod/distlist.txt`")
	}
}

// buildShapes are files whose build constraint, header or package clause
// decides whether the go command builds them.
var buildShapes = map[string]string{
	"ignore":                    "//go:build ignore\n\npackage p\n",
	"ignore, no blank line":     "//go:build ignore\npackage p\n",
	"after a one-line block":    "/* doc */\n//go:build ignore\n\npackage p\n",
	"inside a block comment":    "/*\n//go:build ignore\n*/\n\npackage p\n",
	"package line in a block":   "/*\npackage doc\n*/\n//go:build ignore\n\npackage p\n",
	"after the package clause":  "package p\n\n//go:build ignore\n",
	"linux && windows":          "//go:build linux && windows\n\npackage p\n",
	"windows":                   "//go:build windows\n\npackage p\n",
	"+build ignore":             "// +build ignore\n\npackage p\n",
	"+build without blank line": "// +build ignore\npackage p\n",
	"BOM, ignore":               "\ufeff//go:build ignore\n\npackage p\n",
	"BOM, windows":              "\ufeff//go:build windows\n\npackage p\n",
	"package documentation":     "package documentation\n",
	"go1.1":                     "//go:build go1.1\n\npackage p\n",
	"go1.99":                    "//go:build go1.99\n\npackage p\n",
	"!go1.1":                    "//go:build !go1.1\n\npackage p\n",
	"user tag":                  "//go:build purego\n\npackage p\n",
	"none":                      "package p\n",
}

// TestBuiltMatchesGoList (rounds 12-13): for linux/amd64, go/build's
// answer the gate uses is go list's.
func TestBuiltMatchesGoList(t *testing.T) {
	needGo(t)
	i := linuxAmd64(t)
	for name, src := range buildShapes {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{"p.go": src, "q.go": "package p\n"}
			p := goList(t, files)
			want := slices.Contains(p.GoFiles, "p.go")
			for _, old := range []bool{false, true} {
				b := analyzeBuild(writeTree(t, files), old, defaultLister())
				if got := b.in["p.go"][i]; got != want {
					t.Errorf("old=%v: gate built=%v, go list %v (GoFiles %q, Ignored %q)", old, got, want, p.GoFiles, p.IgnoredGoFiles)
				}
			}
		})
	}
}

// TestMismatchedPackageOverApproximated: two package clauses in one
// directory (go list: an error) count as built everywhere in the new
// tree and nowhere in the old one.
func TestMismatchedPackageOverApproximated(t *testing.T) {
	needGo(t)
	files := map[string]string{"p.go": "package p\n", "q.go": "package q\n"}
	if p := goList(t, files); p.Error == nil {
		t.Fatalf("precondition: go list reports no error: %+v", p)
	}
	tree := writeTree(t, files)
	if nb := analyzeBuild(tree, false, defaultLister()); !nb.everywhere("p.go") || !nb.everywhere("q.go") {
		t.Errorf("new tree: not built everywhere")
	}
	if ob := analyzeBuild(tree, true, defaultLister()); ob.anywhere("p.go") || ob.anywhere("q.go") {
		t.Errorf("old tree: credited as built")
	}
}

// TestNewlyBuiltIsNew (rounds 12-13, scan HIGHs): an old file the go
// command does not build on linux, and its new version that it does,
// with the same init: the init newly enters the build and is flagged.
// Each pair is checked with go list.
func TestNewlyBuiltIsNew(t *testing.T) {
	body := "import \"os/exec\"\n\nfunc init() { exec.Command(\"sh\", \"-c\", \"id\").Run() }\n"
	for name, tc := range map[string]struct{ old, new string }{
		"into a block comment":             {"//go:build windows\n\npackage p\n\n" + body, "/*\n//go:build windows\n*/\n\npackage p\n\n" + body},
		"after package in a block comment": {"/*\npackage doc\n*/\n//go:build windows\n\npackage p\n\n" + body, "package p\n\n" + body},
		"+build without the blank line":    {"// +build windows\n\npackage p\n\n" + body, "// +build windows\npackage p\n\n" + body},
		"BOM before the constraint":        {"\ufeff//go:build windows\n\npackage p\n\n" + body, "package p\n\n" + body},
		"package documentation":            {"package documentation\n\n" + body, "package p\n\n" + body},
		"mismatched package name":          {"package q\n\n" + body, "package p\n\n" + body},
		"go1.99":                           {"//go:build go1.99\n\npackage p\n\n" + body, "package p\n\n" + body},
	} {
		t.Run(name, func(t *testing.T) {
			if !testing.Short() {
				if p := goList(t, map[string]string{"e.go": tc.old, "q.go": "package p\n"}); slices.Contains(p.GoFiles, "e.go") && p.Error == nil {
					t.Fatalf("precondition: go list should not build the old e.go on linux: %+v", p)
				}
				if p := goList(t, map[string]string{"e.go": tc.new, "q.go": "package p\n"}); !slices.Contains(p.GoFiles, "e.go") {
					t.Fatalf("precondition: go list should build the new e.go on linux: %+v", p)
				}
			}
			h := CheckTrees(writeTree(t, map[string]string{"q.go": "package p\n", "e.go": tc.old}), writeTree(t, map[string]string{"q.go": "package p\n", "e.go": tc.new}))
			if !slices.Contains(h.items(codeInit), "e.go") {
				t.Errorf("init that newly enters the build not flagged: codes %q", h.codes())
			}
		})
	}
}

// TestDefaultTagsNotNoise (round 12 x/net over-count): a file built only
// with the toolchain's release tags (go1.21 && !http2legacy, like x/net's
// go1.27 && !http2legacy) is built in
// both trees: its unchanged init callees are credited.
func TestDefaultTagsNotNoise(t *testing.T) {
	head := "//go:build go1.21 && !http2legacy\n\npackage p\n\n"
	decls := "func helper() int { return 1 }\n\nvar v = helper()\n"
	old := writeTree(t, map[string]string{"w.go": head + decls, "x.go": "package p\n\nfunc other() {}\n"})
	cur := writeTree(t, map[string]string{"w.go": head + decls, "x.go": "package p\n\nfunc other() { _ = 1 }\n"})
	h := CheckTrees(old, cur)
	if got := h.items(codeInitCallee); len(got) != 0 {
		t.Errorf("unchanged callees in a release-tag file flagged: %q", got)
	}
	if b := analyzeBuild(cur, false, defaultLister()); !b.anywhere("w.go") {
		t.Errorf("w.go built nowhere")
	}
}

// gateNewlyEmbedded is what the gate finds newly embedded by cur's
// packages when old embeds nothing, and whether anything was unresolved.
func gateNewlyEmbedded(t *testing.T, old, cur *ecoutil.Tree) ([]string, bool) {
	t.Helper()
	r := newReport()
	r.lister = defaultLister()
	res := r.embeds(old, cur, analyzeBuild(old, true, defaultLister()), analyzeBuild(cur, false, defaultLister()))
	got := slices.Collect(maps.Keys(res.newly))
	got = append(got, slices.Collect(maps.Keys(r.files))...)
	slices.Sort(got)
	return got, len(res.unresolved) > 0
}

// TestEmbedMatchesGoList (rounds 8-12): what the gate finds a package
// newly embeds is go list's EmbedFiles.
func TestEmbedMatchesGoList(t *testing.T) {
	needGo(t)
	data := map[string]string{
		"a.txt": "a\n", "b.txt": "b\n", "tool.bin": "\x7fELF\x02\x01\x01 x",
		"assets/ok.txt": "ok\n", "assets/.hidden": "h\n", "assets/_skip/z.txt": "z\n", "assets/x/y.bin": "\x00\x01",
		"go.mod": "module example.com/m\n\ngo 1.24\n", "go.sum": "example.com/x v1.0.0/go.mod h1:AAAA=\n",
	}
	hdr := "package p\n\nimport _ \"embed\"\n\n"
	for name, src := range map[string]string{
		"raw string":       hdr + "var tmpl = `\n//go:embed b.txt\n`\n\n//go:embed a.txt\nvar A string\n",
		"block comment":    hdr + "/*\n//go:embed b.txt\n*/\n\n//go:embed a.txt\nvar A string\n",
		"tab separated":    hdr + "//go:embed\ta.txt\ttool.bin\nvar F embed.FS\n",
		"quoted":           hdr + "//go:embed \"a.txt\" `b.txt`\nvar F embed.FS\n",
		"directory":        hdr + "//go:embed assets\nvar F embed.FS\n",
		"all: directory":   hdr + "//go:embed all:assets\nvar F embed.FS\n",
		"glob with hidden": hdr + "//go:embed assets/*\nvar F embed.FS\n",
		"glob":             hdr + "//go:embed *.txt\nvar F embed.FS\n",
		"root star":        hdr + "//go:embed *\nvar F embed.FS\n", // go.mod and go.sum too
	} {
		t.Run(name, func(t *testing.T) {
			src = strings.Replace(src, "import _ \"embed\"", "import \"embed\"", 1)
			if !strings.Contains(src, "embed.FS") {
				src = strings.Replace(src, "import \"embed\"", "import _ \"embed\"", 1)
			}
			files := maps.Clone(data)
			files["p.go"] = src
			p := goList(t, files)
			want := slices.Clone(p.EmbedFiles)
			slices.Sort(want)
			oldFiles := maps.Clone(data)
			oldFiles["p.go"] = "package p\n"
			got, unresolved := gateNewlyEmbedded(t, writeTree(t, oldFiles), writeTree(t, files))
			if unresolved || !slices.Equal(got, want) {
				t.Errorf("gate %q (unresolved %v), go list %q (error %+v)", got, unresolved, want, p.Error)
			}
		})
	}
}

// TestMovedEmbedConstraint (round 13 review): the old e.go embeds
// tool.bin on windows only; the new one drops the constraint, so linux
// newly embeds the unchanged tool.bin. Embeds are compared per
// configuration, not as unions.
func TestMovedEmbedConstraint(t *testing.T) {
	bin := "\x7fELF\x02\x01\x01 x"
	body := "package p\n\nimport _ \"embed\"\n\n//go:embed tool.bin\nvar T []byte\n"
	oldFiles := map[string]string{"e.go": "//go:build windows\n\n" + body, "q.go": "package p\n", "tool.bin": bin}
	newFiles := map[string]string{"e.go": body, "q.go": "package p\n", "tool.bin": bin}
	if !testing.Short() {
		if p := goList(t, oldFiles); len(p.EmbedFiles) != 0 {
			t.Fatalf("precondition: the old tree embeds on linux: %q", p.EmbedFiles)
		}
		if p := goList(t, newFiles); !slices.Contains(p.EmbedFiles, "tool.bin") {
			t.Fatalf("precondition: the new tree does not embed tool.bin on linux: %+v", p)
		}
	}
	wantPerson(t, CheckTrees(writeTree(t, oldFiles), writeTree(t, newFiles)), "tool.bin")
}

// TestRenamedConstrainedFile (round 11, C; was in buildkey_test.go): a
// helper that moves from h_windows.go to h.go (now built everywhere) with
// the same text is a new declaration reached from init.
func TestRenamedConstrainedFile(t *testing.T) {
	initFile := "package p\n\nfunc init() { helper() }\n"
	helper := "package p\n\nfunc helper() { println(\"x\") }\n"
	h := CheckTrees(writeTree(t, map[string]string{"p.go": initFile, "h_windows.go": helper}), writeTree(t, map[string]string{"p.go": initFile, "h.go": helper}))
	if !slices.Contains(h.items(codeInitCallee), "helper") {
		t.Errorf("helper newly built for every platform, not flagged: codes %q", h.codes())
	}
}

// TestOldRawStringLinkname (round 11, A; was in buildkey_test.go): a
// directive-looking line in an old raw string cannot mask a new
// directive. (Its other half, "an unchanged directive is not flagged", no
// longer holds by design: every directive of a changed file is flagged.)
func TestOldRawStringLinkname(t *testing.T) {
	old := "package p\n\nimport _ \"unsafe\"\n\nvar doc = `\n//go:linkname now runtime.nanotime\n`\n\nfunc now() int64\n"
	cur := "package p\n\nimport _ \"unsafe\"\n\n//go:linkname now runtime.nanotime\nfunc now() int64\n"
	h := CheckTrees(writeTree(t, map[string]string{"l.go": old}), writeTree(t, map[string]string{"l.go": cur}))
	if !slices.Contains(h.items(codeLinkname), "l.go") {
		t.Errorf("a new //go:linkname masked by an old raw string: codes %q", h.codes())
	}
}

// TestPossiblyBuiltMatchesGoList (round 13 scan HIGH): a file no default
// configuration builds is possibly built when some -tags set builds it;
// each verdict is checked with go list -tags.
func TestPossiblyBuiltMatchesGoList(t *testing.T) {
	needGo(t)
	for name, tc := range map[string]struct {
		src  string
		tags string // a -tags set that builds it ("" when none should)
	}{
		"ignore":                {"//go:build ignore\n\npackage p\n", "ignore"},
		"purego":                {"//go:build purego\n\npackage p\n", "purego"},
		"two user tags":         {"//go:build netgo && !osusergo && http2legacy\n\npackage p\n", "netgo,http2legacy"},
		"go1.99":                {"//go:build go1.99\n\npackage p\n", "go1.99"},
		"linux && windows":      {"//go:build linux && windows\n\npackage p\n", ""},
		"package documentation": {"package documentation\n", ""},
		// Round 16: a go1.0 toolchain builds it; go list cannot show that.
		"!go1.1": {"//go:build !go1.1\n\npackage p\n", "(no go list check)"},
	} {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{"p.go": tc.src, "q.go": "package p\n"}
			tree := writeTree(t, files)
			nb := analyzeBuild(tree, false, defaultLister())
			if nb.anywhere("p.go") {
				t.Fatalf("built with default tags")
			}
			if got := nb.possibly("p.go"); got != (tc.tags != "") {
				t.Errorf("possibly built = %v, want %v", got, tc.tags != "")
			}
			if tc.tags != "" && !strings.HasPrefix(tc.tags, "(") {
				if p := goListArgs(t, files, "-tags="+tc.tags); !slices.Contains(p.GoFiles, "p.go") {
					t.Errorf("go list -tags=%s does not build it: %+v", tc.tags, p)
				}
			}
		})
	}
}

// TestPuregoEmbedUnresolved (round 13 scan HIGH): an unchanged
// //go:build purego file embeds assets; a text file newly added under
// assets is embedded by a purego build, which go list never resolves: a
// person decides. A purego file's new init is flagged.
func TestPuregoEmbedUnresolved(t *testing.T) {
	embedFile := "//go:build purego\n\npackage p\n\nimport \"embed\"\n\n//go:embed assets\nvar F embed.FS\n"
	old := writeTree(t, map[string]string{"q.go": "package p\n", "e.go": embedFile, "assets/a.txt": "a\n",
		"i.go": "//go:build purego\n\npackage p\n"})
	cur := writeTree(t, map[string]string{"q.go": "package p\n", "e.go": embedFile, "assets/a.txt": "a\n", "assets/new.txt": "new\n",
		"i.go": "//go:build purego\n\npackage p\n\nimport \"os/exec\"\n\nfunc init() { exec.Command(\"id\").Run() }\n"})
	h := CheckTrees(old, cur)
	if !slices.Contains(h.incomplete(), codeEmbed+" .") {
		t.Errorf("the purego embed is not for a person: incomplete %q, codes %q", h.incomplete(), h.codes())
	}
	if !slices.Contains(h.items(codeInit), "i.go") {
		t.Errorf("a purego file's new init not flagged: codes %q", h.codes())
	}
}

// TestPossiblyBuiltNewlyIsNew (round 13 scan HIGH): an old file no -tags
// set builds (package documentation) becomes a //go:build purego file
// with the same init: a purego build newly runs it.
func TestPossiblyBuiltNewlyIsNew(t *testing.T) {
	body := "\n\nimport \"os/exec\"\n\nfunc init() { exec.Command(\"id\").Run() }\n"
	old := writeTree(t, map[string]string{"q.go": "package p\n", "e.go": "package documentation" + body})
	cur := writeTree(t, map[string]string{"q.go": "package p\n", "e.go": "//go:build purego\n\npackage p" + body})
	if h := CheckTrees(old, cur); !slices.Contains(h.items(codeInit), "e.go") {
		t.Errorf("init newly possibly built not flagged: codes %q", h.codes())
	}
}

// TestIgnoreToPuregoIsNew (round 14 scan MEDIUM): an old //go:build
// ignore file becomes //go:build purego with the same exec init: both are
// possibly built, but real purego builds never set ignore, so the init is
// new. An unchanged -tags-only file (x/net's defs_*.go) stays credited.
func TestIgnoreToPuregoIsNew(t *testing.T) {
	body := "package p\n\nimport \"os/exec\"\n\nfunc helper() { exec.Command(\"id\").Run() }\n\nfunc init() { helper() }\n"
	h := CheckTrees(writeTree(t, map[string]string{"q.go": "package p\n", "e.go": "//go:build ignore\n\n" + body}),
		writeTree(t, map[string]string{"q.go": "package p\n", "e.go": "//go:build purego\n\n" + body}))
	if !slices.Contains(h.items(codeInit), "e.go") || !slices.Contains(h.items(codeImport), "e.go (os/exec)") {
		t.Errorf("ignore -> purego credited old text: codes %q", h.codes())
	}
	defs := "//go:build ignore\n\npackage p\n\ntype cmsghdr struct{ n int }\n\nfunc init() { _ = cmsghdr{} }\n"
	h = CheckTrees(writeTree(t, map[string]string{"q.go": "package p\n", "defs_linux.go": defs}),
		writeTree(t, map[string]string{"q.go": "package p\n\nvar Y = 2\n", "defs_linux.go": defs}))
	if got := append(h.items(codeInit), h.items(codeInitCallee)...); len(got) != 0 {
		t.Errorf("an unchanged ignore file is not credited: %q", got)
	}
}

// TestUserTagWidensBuild (round 14 scan HIGH): //go:build linux becomes
// //go:build linux || purego with the same exec init: linux is unchanged,
// but darwin with -tags purego newly builds it. A changed file whose
// constraint consults a user tag gets no old text credited.
func TestUserTagWidensBuild(t *testing.T) {
	body := "package p\n\nimport \"os/exec\"\n\nfunc init() { exec.Command(\"id\").Run() }\n"
	h := CheckTrees(writeTree(t, map[string]string{"q.go": "package p\n", "e.go": "//go:build linux\n\n" + body}),
		writeTree(t, map[string]string{"q.go": "package p\n", "e.go": "//go:build linux || purego\n\n" + body}))
	if !slices.Contains(h.items(codeInit), "e.go") {
		t.Errorf("linux -> linux || purego credited the old init: codes %q", h.codes())
	}
	// Platform tags alone keep the per-configuration rule.
	h = CheckTrees(writeTree(t, map[string]string{"q.go": "package p\n", "e.go": "//go:build linux && amd64\n\n" + body}),
		writeTree(t, map[string]string{"q.go": "package p\n", "e.go": "//go:build amd64 && linux\n\n" + body}))
	if slices.Contains(h.items(codeInit), "e.go") {
		t.Errorf("a reordered platform-only constraint is not credited: codes %q", h.codes())
	}
}

// TestPlatformTagsFromGoBuild: GOOS and GOARCH values are go/build's own,
// also ones without a dist port; user tags are not.
func TestPlatformTagsFromGoBuild(t *testing.T) {
	for _, tag := range []string{"linux", "amd64", "zos", "hurd", "nacl", "riscv", "unix", "cgo", "gc"} {
		if !platformTag(tag) {
			t.Errorf("%s is not a platform tag", tag)
		}
	}
	// Round 15: go1.N and gccgo vary between consumers too.
	for _, tag := range []string{"purego", "ignore", "netgo", "http2legacy", "goexperiment.rangefunc", "amd64.v3", "amd64.v1", "go1", "go1.x", "go1.21", "go1.28", "gccgo", "linux_amd64"} {
		if platformTag(tag) {
			t.Errorf("%s is a platform tag", tag)
		}
	}
}

// TestUserTagEmbedder (round 14 scan MEDIUM): an embedding file goes from
// //go:build linux to //go:build linux || purego: what it embeds is
// newly embedded, the unchanged tool.bin goes to a person.
func TestUserTagEmbedder(t *testing.T) {
	bin := "\x7fELF\x02\x01\x01 x"
	body := "package p\n\nimport _ \"embed\"\n\n//go:embed tool.bin\nvar T []byte\n"
	h := CheckTrees(writeTree(t, map[string]string{"q.go": "package p\n", "e.go": "//go:build linux\n\n" + body, "tool.bin": bin}),
		writeTree(t, map[string]string{"q.go": "package p\n", "e.go": "//go:build linux || purego\n\n" + body, "tool.bin": bin}))
	wantPerson(t, h, "tool.bin")
}

// TestBuildBudget (round 14 scan MEDIUM): past the go/build budget the
// tree is unresolved: even an identical file is checked as new, every
// embed goes to a person, and the module goes to a person. A tag search
// past its own budget counts the file as possibly built.
func TestBuildBudget(t *testing.T) {
	bin := "\x7fELF\x02\x01\x01 x"
	init := "package p\n\nimport \"os/exec\"\n\nfunc init() { exec.Command(\"id\").Run() }\n"
	embed := "package p\n\nimport _ \"embed\"\n\n//go:embed tool.bin\nvar T []byte\n"
	files := map[string]string{"i.go": init, "e.go": embed, "tool.bin": bin}
	prev := maxBuildWork
	maxBuildWork = 1
	t.Cleanup(func() { maxBuildWork = prev })
	h := CheckTrees(writeTree(t, files), writeTree(t, files))
	if !slices.Contains(h.items(codeInit), "i.go") {
		t.Errorf("identical init credited past the budget: codes %q", h.codes())
	}
	if !slices.Contains(h.items(codeParse), "(go/build budget)") || routeOf(codeParse) != model.RouteHuman {
		t.Errorf("the module is not for a person: codes %q", h.codes())
	}
	wantPerson(t, h, "tool.bin")
	maxBuildWork = prev

	prevTag := maxTagWork
	maxTagWork = 1
	t.Cleanup(func() { maxTagWork = prevTag })
	b := analyzeBuild(writeTree(t, map[string]string{"p.go": "//go:build linux && windows && foo\n\npackage p\n", "q.go": "package p\n"}), false, defaultLister())
	if !b.possibly("p.go") || b.unresolved() {
		t.Errorf("past the tag-search budget: possibly %v, unresolved %v", b.possibly("p.go"), b.unresolved())
	}
}

// TestUnchangedFileNewlyEmbedded (round 10): an unchanged file a new
// pattern reaches is newly embedded. Since round 14 so is one the old tree
// already embedded, because the embedding file changed.
func TestUnchangedFileNewlyEmbedded(t *testing.T) {
	needGo(t)
	bin := "\x7fELF\x02\x01\x01 x"
	hdr := "package p\n\nimport \"embed\"\n\n"
	old := writeTree(t, map[string]string{"p.go": hdr + "//go:embed a.bin\nvar F embed.FS\n", "a.bin": bin, "b.bin": bin})
	cur := writeTree(t, map[string]string{"p.go": hdr + "//go:embed a.bin b.bin\nvar F embed.FS\n", "a.bin": bin, "b.bin": bin})
	h := CheckTrees(old, cur)
	if got := h.items(codeBinary); !slices.Equal(got, []string{"a.bin", "b.bin"}) {
		t.Errorf("binaries %q, want a.bin and b.bin", got)
	}
}

// TestGoListRunsNoCompiler: go list with the gate's environment and
// CGO_ENABLED=1 runs no C compiler or pkg-config over a cgo package, even
// with ones on PATH.
func TestGoListRunsNoCompiler(t *testing.T) {
	needGo(t)
	bin, _ := exec.LookPath("go")
	bin, _ = filepath.Abs(bin)
	fake := t.TempDir()
	marker := filepath.Join(fake, "RAN")
	for _, n := range []string{"cc", "gcc", "clang", "pkg-config"} {
		os.WriteFile(filepath.Join(fake, n), []byte("#!/bin/sh\ntouch "+marker+"\nexit 1\n"), 0o755)
	}
	tree := writeTree(t, map[string]string{"c/c.go": "package c\n\n// #cgo pkg-config: libfoo\n// #include <stdio.h>\nimport \"C\"\n\nimport _ \"embed\"\n\n//go:embed c.go\nvar S string\n"})
	root := t.TempDir()
	mod := filepath.Join(root, "mod")
	if err := copyTree(tree, mod); err != nil {
		t.Fatal(err)
	}
	if err := ecoutil.GoHome(filepath.Join(root, "home")); err != nil {
		t.Fatal(err)
	}
	out, err := ecoutil.RunGo(ecoutil.GoRun{Go: bin, Dir: mod, Args: []string{"list", "-e", "-json=Dir,CgoFiles,EmbedFiles,Error", "./c"},
		Env: append(listEnv(root), "PATH="+fake, "CC="+filepath.Join(fake, "cc"), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=1")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"c.go"`) {
		t.Errorf("go list gave no CgoFiles/EmbedFiles: %s", out)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Errorf("go list ran a compiler or pkg-config")
	}
}

// TestEmbedWithoutGoCommand: with no go command every embed is for a
// person.
func TestEmbedWithoutGoCommand(t *testing.T) {
	bin := "\x7fELF\x02\x01\x01 x"
	src := "package p\n\nimport _ \"embed\"\n\n//go:embed tool.bin\nvar T []byte\n"
	h := checkTrees(writeTree(t, map[string]string{"p.go": "package p\n", "tool.bin": bin}), writeTree(t, map[string]string{"p.go": src, "tool.bin": bin}), nil, goLister{})
	wantPerson(t, h, "tool.bin")
}

// TestGenGoNothingNewlyEmbedded (round 12): an x/net-style generator
// (//go:build ignore, a raw-string template holding //go:embed lines)
// embeds nothing.
func TestGenGoNothingNewlyEmbedded(t *testing.T) {
	gen := "//go:build ignore\n\npackage main\n\nconst tmpl = `package p\n\nimport _ \"embed\"\n\n//go:embed data/children\nvar children []byte\n`\n\nfunc main() {}\n"
	h := CheckTrees(writeTree(t, map[string]string{"gen.go": "//go:build ignore\n\npackage main\n\nfunc main() {}\n", "data/children": "\x00\x01bin", "p.go": "package p\n"}),
		writeTree(t, map[string]string{"gen.go": gen, "data/children": "\x00\x01bin", "p.go": "package p\n"}))
	if len(h.items(codeBinary)) != 0 || len(h.items(codeEmbed)) != 0 {
		t.Errorf("a raw-string template counted: codes %q binaries %q", h.codes(), h.items(codeBinary))
	}
}

// TestRealEmbedInIgnoredFileCounts (round 12): a real //go:embed comment
// in a changed file go/build builds nowhere goes to a person (a -tags
// build can embed what go list never resolves).
func TestRealEmbedInIgnoredFileCounts(t *testing.T) {
	src := "//go:build ignore\n\npackage p\n\nimport _ \"embed\"\n\n//go:embed tool.bin\nvar T []byte\n"
	h := CheckTrees(writeTree(t, map[string]string{"p.go": "package p\n", "tool.bin": "\x7fELF\x02\x01\x01 x"}), writeTree(t, map[string]string{"p.go": "package p\n", "e.go": src, "tool.bin": "\x7fELF\x02\x01\x01 x"}))
	wantPerson(t, h, "tool.bin")
}

// TestEveryDirectiveFlagged (rounds 12-13): //go:linkname and the like
// are flagged in a changed file whether or not the old version had them;
// the old side is never credited (an old trailing comment or a file that
// does not parse cannot mask one).
func TestEveryDirectiveFlagged(t *testing.T) {
	for name, old := range map[string]string{
		"unchanged directive":     "package p\n\nimport _ \"unsafe\"\n\n//go:linkname now runtime.nanotime\nvar now int\n",
		"old trailing comment":    "package p\n\nimport _ \"unsafe\"\n\nvar now int //go:linkname now runtime.nanotime\n",
		"old file does not parse": "package p\n\nimport _ \"unsafe\"\n\n//go:linkname now runtime.nanotime\nvar now int\nfunc {\n",
	} {
		t.Run(name, func(t *testing.T) {
			cur := "package p\n\nimport _ \"unsafe\"\n\n//go:linkname now runtime.nanotime\nvar now int\n\nvar changed = 1\n"
			h := CheckTrees(writeTree(t, map[string]string{"l.go": old}), writeTree(t, map[string]string{"l.go": cur}))
			if !slices.Contains(h.items(codeLinkname), "l.go") {
				t.Errorf("//go:linkname in a changed file not flagged: codes %q", h.codes())
			}
		})
	}
}

// TestOldMisplacedEmbedNotCredited (round 12 scan HIGH, closed in round
// 14): go list reports an old //go:embed the compiler rejects (trailing,
// or not on a var), but its file changed, so nothing it matched is
// credited: the real new //go:embed of the unchanged tool.bin goes to a
// person.
func TestOldMisplacedEmbedNotCredited(t *testing.T) {
	bin := "\x7fELF\x02\x01\x01 x"
	hdr := "package p\n\nimport _ \"embed\"\n\n"
	newSrc := hdr + "var X = 1\n\n//go:embed tool.bin\nvar T []byte\n"
	for name, oldSrc := range map[string]string{
		"trailing":   hdr + "var X = 1 //go:embed tool.bin\n\nvar T []byte\n",
		"not on var": hdr + "//go:embed tool.bin\nfunc f() {}\n\nvar X = 1\n\nvar T []byte\n",
	} {
		t.Run(name, func(t *testing.T) {
			if !testing.Short() {
				if p := goList(t, map[string]string{"p.go": oldSrc, "tool.bin": bin}); !slices.Contains(p.EmbedFiles, "tool.bin") {
					t.Fatalf("precondition: go list reports the old misplaced //go:embed: %+v", p)
				}
			}
			h := CheckTrees(writeTree(t, map[string]string{"p.go": oldSrc, "tool.bin": bin}), writeTree(t, map[string]string{"p.go": newSrc, "tool.bin": bin}))
			wantPerson(t, h, "tool.bin")
		})
	}
}

// TestUnchangedEmbedderCredited (round 14): when the file holding the
// //go:embed is unchanged and built as before, what the old tree embedded
// is credited although another file of the package changed.
func TestUnchangedEmbedderCredited(t *testing.T) {
	bin := "\x7fELF\x02\x01\x01 x"
	e := "package p\n\nimport _ \"embed\"\n\n//go:embed tool.bin\nvar T []byte\n"
	h := CheckTrees(writeTree(t, map[string]string{"e.go": e, "q.go": "package p\n", "tool.bin": bin}),
		writeTree(t, map[string]string{"e.go": e, "q.go": "package p\n\nvar Y = 2\n", "tool.bin": bin}))
	if got := h.items(codeBinary); len(got) != 0 {
		t.Errorf("an unchanged embed credited nothing: binaries %q", got)
	}
}

// TestEmbedPatternPosPerConfiguration (round 14): the embedding files are
// go/build's per configuration: e_windows.go's pattern counts on windows
// only.
func TestEmbedPatternPosPerConfiguration(t *testing.T) {
	tree := writeTree(t, map[string]string{"e_windows.go": "package p\n\nimport _ \"embed\"\n\n//go:embed a.txt\nvar A string\n", "q.go": "package p\n", "a.txt": "a\n"})
	b := analyzeBuild(tree, false, defaultLister())
	in := b.embedders["."]["e_windows.go"]
	for i, c := range configs {
		if in[i] != (c.goos == "windows") {
			t.Errorf("%v: embedder %v", c, in[i])
		}
	}
}

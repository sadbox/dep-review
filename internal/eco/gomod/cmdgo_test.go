package gomod

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// goList runs `go list -json .` for linux/amd64 in a fresh module holding
// files, offline. It is the reference the gate's reading of directives and
// build constraints is checked against.
type goListPkg struct {
	GoFiles, IgnoredGoFiles, EmbedPatterns []string
	Error                                  *struct{ Err string }
}

func goList(t *testing.T, files map[string]string) goListPkg {
	t.Helper()
	dir := t.TempDir()
	files["go.mod"] = "module example.com/m\n\ngo 1.24\n"
	for name, data := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(data), 0o644)
	}
	cmd := exec.Command("go", "list", "-e", "-json", ".")
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

// goBuild reports go build's error output for a module holding files.
func goBuild(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files["go.mod"] = "module example.com/m\n\ngo 1.24\n"
	for name, data := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(data), 0o644)
	}
	cmd := exec.Command("go", "build", "-o", os.DevNull, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOFLAGS=", "GOWORK=off", "GOTOOLCHAIN=local", "GOPROXY=off")
	out, _ := cmd.CombinedOutput()
	return string(out)
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

// newEmbedPatterns is what the gate reads from a new file.
func newEmbedPatterns(src string) []string {
	var out []string
	for _, l := range embedLinesOf([]byte(src)) {
		out = append(out, l.pats...)
	}
	slices.Sort(out)
	return out
}

// TestEmbedExtractionMatchesCmdGo (round 12): the new side finds
// //go:embed as cmd/go does. Raw strings and block comments hold none;
// a trailing comment is one to go list (the compiler then rejects the
// file), and the gate counts it too.
func TestEmbedExtractionMatchesCmdGo(t *testing.T) {
	needGo(t)
	for name, tc := range map[string]struct {
		src   string
		exact bool
	}{
		"raw string":    {"package p\n\nimport _ \"embed\"\n\nvar tmpl = `\n//go:embed b.txt\n`\n\n//go:embed a.txt\nvar A string\n", true},
		"block comment": {"package p\n\nimport _ \"embed\"\n\n/*\n//go:embed b.txt\n*/\n\n//go:embed a.txt\nvar A string\n", true},
		"gen.go style":  {"//go:build ignore\n\npackage main\n\nimport \"fmt\"\n\nconst tmpl = `package p\n\nimport _ \"embed\"\n\n//go:embed b.txt\nvar B string\n`\n\nfunc main() { fmt.Print(tmpl) }\n", false},
		"trailing":      {"package p\n\nimport _ \"embed\"\n\nvar X = 1 //go:embed b.txt\n\n//go:embed a.txt\nvar A string\n", true},
	} {
		t.Run(name, func(t *testing.T) {
			p := goList(t, map[string]string{"p.go": tc.src, "a.txt": "a\n", "b.txt": "b\n", "q.go": "package p\n"})
			got := newEmbedPatterns(tc.src)
			want := p.EmbedPatterns
			if !tc.exact {
				want = nil // an ignored file: go list reads nothing; neither raw-string line counts
			}
			if !slices.Equal(got, want) && !(len(got) == 0 && len(want) == 0) {
				t.Errorf("gate %q, go list %q", got, want)
			}
		})
	}
}

// TestHonoredMatchesCmdGo (round 12): the build constraint the gate
// reads is the one the go command honors.
func TestHonoredMatchesCmdGo(t *testing.T) {
	needGo(t)
	for name, src := range map[string]string{
		"ignore":                    "//go:build ignore\n\npackage p\n",
		"ignore, no blank line":     "//go:build ignore\npackage p\n",
		"after a one-line block":    "/* doc */\n//go:build ignore\n\npackage p\n",
		"inside a block comment":    "/*\n//go:build ignore\n*/\n\npackage p\n",
		"after the package clause":  "package p\n\n//go:build ignore\n",
		"linux && windows":          "//go:build linux && windows\n\npackage p\n",
		"+build ignore":             "// +build ignore\n\npackage p\n",
		"+build without blank line": "// +build ignore\npackage p\n",
		"none":                      "package p\n",
	} {
		t.Run(name, func(t *testing.T) {
			p := goList(t, map[string]string{"p.go": src, "q.go": "package p\n"})
			ignored := slices.Contains(p.IgnoredGoFiles, "p.go")
			x, err := honored([]byte(src))
			gate := err != nil || (x != nil && !x.Eval(func(tag string) bool { return tag == "linux" || tag == "amd64" || tag == "unix" || tag == "gc" }))
			if gate != ignored {
				t.Errorf("gate says ignored=%v, go list %v (expr %v, err %v)", gate, ignored, x, err)
			}
		})
	}
}

// TestMovedConstraintIsNew (round 12, scan HIGHs): the old file's
// constraint is honored (built on windows only); the new one keeps the
// same constraint text where go/build does not honor it, so it is built
// on linux. Its init code newly enters the build. Each layout is checked
// with go list for linux: old ignored, new built.
func TestMovedConstraintIsNew(t *testing.T) {
	body := "package p\n\nimport \"os/exec\"\n\nfunc init() { exec.Command(\"sh\", \"-c\", \"id\").Run() }\n"
	for name, tc := range map[string]struct{ old, new string }{
		// the same //go:build line, moved into a /* */ comment
		"into a block comment": {"//go:build windows\n\n" + body, "/*\n//go:build windows\n*/\n\n" + body},
		// the old header scan stopped at a "package" line inside /* */
		"after package in a block comment": {"/*\npackage doc\n*/\n//go:build windows\n\n" + body, body},
		// // +build is honored only before a blank line
		"+build without the blank line": {"// +build windows\n\n" + body, "// +build windows\n" + body},
	} {
		t.Run(name, func(t *testing.T) {
			if !testing.Short() {
				if p := goList(t, map[string]string{"e.go": tc.old, "q.go": "package p\n"}); !slices.Contains(p.IgnoredGoFiles, "e.go") {
					t.Fatalf("precondition: go list should ignore the old e.go on linux: %+v", p)
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

// TestOldEmbedNotOnAVarDoesNotMask (round 12, scan HIGH): an old
// //go:embed at column 1 that does not directly precede a var
// declaration is rejected by the compiler, so it is no old embed.
func TestOldEmbedNotOnAVarDoesNotMask(t *testing.T) {
	oldSrc := "package p\n\nimport _ \"embed\"\n\n//go:embed tool.bin\nfunc f() {}\n\nvar T []byte\n"
	newSrc := "package p\n\nimport _ \"embed\"\n\nfunc f() {}\n\n//go:embed tool.bin\nvar T []byte\n"
	if !testing.Short() {
		if out := goBuild(t, map[string]string{"p.go": oldSrc, "tool.bin": "x"}); !strings.Contains(out, "misplaced go:embed directive") {
			t.Fatalf("precondition: the compiler should reject a //go:embed on a func: %q", out)
		}
	}
	bin := "\x7fELF\x02\x01\x01 x"
	h := CheckTrees(writeTree(t, map[string]string{"p.go": oldSrc, "tool.bin": bin}), writeTree(t, map[string]string{"p.go": newSrc, "tool.bin": bin}))
	wantPerson(t, h, "tool.bin")
}

// TestUnsatisfiableConstraintExcluded (round 12): a constraint no
// GOOS/GOARCH satisfies counts as not built on the old side, as go list
// agrees.
func TestUnsatisfiableConstraintExcluded(t *testing.T) {
	src := "//go:build linux && windows\n\npackage p\n"
	if !excluded([]byte(src)) {
		t.Errorf("linux && windows is not excluded")
	}
	if excluded([]byte("//go:build linux || windows\n\npackage p\n")) {
		t.Errorf("linux || windows is excluded")
	}
	if !testing.Short() {
		if p := goList(t, map[string]string{"p.go": src, "q.go": "package p\n"}); !slices.Contains(p.IgnoredGoFiles, "p.go") {
			t.Errorf("go list builds it: %+v", p)
		}
	}
}

// TestGenGoNothingNewlyEmbedded (round 12): an x/net-style generator
// (//go:build ignore, a raw-string template holding //go:embed lines)
// embeds nothing on either side.
func TestGenGoNothingNewlyEmbedded(t *testing.T) {
	gen := "//go:build ignore\n\npackage main\n\nconst tmpl = `package p\n\nimport _ \"embed\"\n\n//go:embed data/children\nvar children []byte\n`\n\nfunc main() {}\n"
	h := CheckTrees(writeTree(t, map[string]string{"gen.go": "//go:build ignore\n\npackage main\n\nfunc main() {}\n", "data/children": "\x00\x01bin", "p.go": "package p\n"}),
		writeTree(t, map[string]string{"gen.go": gen, "data/children": "\x00\x01bin", "p.go": "package p\n"}))
	if len(h.items(codeBinary)) != 0 || len(h.items(codeEmbed)) != 0 {
		t.Errorf("a raw-string template counted: codes %q binaries %q", h.codes(), h.items(codeBinary))
	}
}

// TestRealEmbedInIgnoredFileCounts (round 12): a real //go:embed comment
// in a //go:build ignore file still counts on the new side
// (over-approximating: the gate does not decide what is built).
func TestRealEmbedInIgnoredFileCounts(t *testing.T) {
	src := "//go:build ignore\n\npackage p\n\nimport _ \"embed\"\n\n//go:embed tool.bin\nvar T []byte\n"
	h := CheckTrees(writeTree(t, map[string]string{"p.go": "package p\n", "tool.bin": "\x7fELF\x02\x01\x01 x"}), writeTree(t, map[string]string{"p.go": "package p\n", "e.go": src, "tool.bin": "\x7fELF\x02\x01\x01 x"}))
	wantPerson(t, h, "tool.bin")
}

// TestOldTrailingDirectivesDoNotMask (round 12, scan HIGH): an old
// trailing "//go:embed" or "//go:linkname" comment is no directive (the
// compiler rejects the embed: go build fails), so it cannot make a real
// new one look unchanged.
func TestOldTrailingDirectivesDoNotMask(t *testing.T) {
	oldEmbed := "package p\n\nimport _ \"embed\"\n\nvar X = 1 //go:embed tool.bin\n\nvar T []byte\n"
	newEmbed := "package p\n\nimport _ \"embed\"\n\nvar X = 1\n\n//go:embed tool.bin\nvar T []byte\n"
	if !testing.Short() {
		if out := goBuild(t, map[string]string{"p.go": oldEmbed, "tool.bin": "x"}); !strings.Contains(out, "misplaced compiler directive") {
			t.Fatalf("precondition: the compiler should reject a trailing //go:embed: %q", out)
		}
	}
	bin := "\x7fELF\x02\x01\x01 x"
	h := CheckTrees(writeTree(t, map[string]string{"p.go": oldEmbed, "tool.bin": bin}), writeTree(t, map[string]string{"p.go": newEmbed, "tool.bin": bin}))
	wantPerson(t, h, "tool.bin")

	oldLink := "package p\n\nimport _ \"unsafe\"\n\nvar now int //go:linkname now runtime.nanotime\n"
	newLink := "package p\n\nimport _ \"unsafe\"\n\n//go:linkname now runtime.nanotime\nvar now int\n"
	h = CheckTrees(writeTree(t, map[string]string{"l.go": oldLink}), writeTree(t, map[string]string{"l.go": newLink}))
	if !slices.Contains(h.items(codeLinkname), "l.go") {
		t.Errorf("a new //go:linkname masked by an old trailing comment: codes %q", h.codes())
	}
}

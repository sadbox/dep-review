package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/allow"
)

// The shapes of npm names and versions the gate puts in a registry URL,
// here and in the npm gatherer.
func TestValidNPMNameAndVersion(t *testing.T) {
	for name, want := range map[string]bool{
		"chart.js":                       true,
		"@tailwindcss/oxide-wasm32-wasi": true,
		"JSONStream":                     true,
		"left_pad":                       true,
		"":                               false,
		"@scope":                         false,
		"@scope/":                        false,
		"@scope/a/b":                     false,
		"a/b":                            false,
		"../etc/passwd":                  false,
		".hidden":                        false,
		"a b":                            false,
		"a?x=1":                          false,
		"a#frag":                         false,
		"a%2fb":                          false,
		"-/npm/v1/attestations/x":        false,
		strings.Repeat("a", 214):         true,
		strings.Repeat("a", 215):         false,
	} {
		if got := ValidNPMName(name); got != want {
			t.Errorf("ValidNPMName(%q) = %v, want %v", name, got, want)
		}
	}
	for version, want := range map[string]bool{
		"1.2.3":                  true,
		"1.2.3-beta.1":           true,
		"0.0.0-insiders.00ef99d": true,
		"1.2.3+build":            true,
		"1.2":                    false,
		"":                       false,
		"1.2.3/../x":             false,
		"1.2.3 ":                 false,
		"latest":                 false,
	} {
		if got := ValidNPMVersion(version); got != want {
			t.Errorf("ValidNPMVersion(%q) = %v, want %v", version, got, want)
		}
	}
}

// The whole format, on one small update: a changed file, an added file, a
// removed file, a file that is not text.
func TestPrepareText(t *testing.T) {
	got := prepareNPM(t,
		map[string]string{
			"index.js":     "const a = 1;\nconst b = 2;\nmodule.exports = a + b;\n",
			"package.json": "{\"version\": \"1.0.0\"}\n",
			"old.js":       "gone\n",
			"logo.png":     "\x89PNG\x00old",
		},
		map[string]string{
			"index.js":     "const a = 1;\nconst b = 3;\nmodule.exports = a + b;\n",
			"package.json": "{\"version\": \"1.0.1\"}\n",
			"lib/new.js":   "exports.x = 1\n",
			"logo.png":     "\x89PNG\x00new",
		},
		roomy)

	want := `== file: index.js (changed)
@@ -1,3 +1,3 @@
 const a = 1;
-const b = 2;
+const b = 3;
 module.exports = a + b;
== file: lib/new.js (added)
@@ -0,0 +1 @@
+exports.x = 1
== file: package.json (changed)
@@ -1 +1 @@
-{"version": "1.0.0"}
+{"version": "1.0.1"}
== removed: 1 files of the old version are gone (their text is not shown)
==   old.js
`
	if len(got.Chunks) != 1 || got.Chunks[0].Index != 0 || got.Chunks[0].Text != want {
		t.Errorf("chunks:\n%s\nwant one chunk:\n%s", text(got), want)
	}
	png := sha256.Sum256([]byte("\x89PNG\x00new"))
	wantUnread := []Unread{{Path: "logo.png", Size: 8, SHA256: hex.EncodeToString(png[:])}}
	if !reflect.DeepEqual(got.Unread, wantUnread) {
		t.Errorf("unread %+v, want %+v", got.Unread, wantUnread)
	}
	if got.State != allow.ReadPartial {
		t.Errorf("state %q, want partial: a changed file was not text", got.State)
	}
	if len(got.Key) != 64 {
		t.Errorf("key %q is not a SHA-256 in hex", got.Key)
	}
	if got.Pair.Name != "demo" || got.Pair.From != "1.0.0" || got.Pair.To != "1.0.1" {
		t.Errorf("pair %+v", got.Pair)
	}
}

func TestPrepareFullRead(t *testing.T) {
	got := prepareNPM(t,
		map[string]string{"index.js": "a\n", "same.bin": "\x00\x01\x02"},
		map[string]string{"index.js": "b\n", "same.bin": "\x00\x01\x02"},
		roomy)
	if got.State != allow.ReadFull {
		t.Errorf("state %q, want full: the only file that is not text did not change", got.State)
	}
	if len(got.Unread) != 0 {
		t.Errorf("unread %+v, want none", got.Unread)
	}
	if got.Unread == nil || got.Chunks == nil {
		t.Error("Unread and Chunks must be empty lists, not null, in JSON")
	}
}

func TestPrepareNothingChanged(t *testing.T) {
	files := map[string]string{"index.js": "a\n"}
	got := prepareNPM(t, files, files, roomy)
	if got.State != allow.ReadFull || len(got.Chunks) != 0 || len(got.Unread) != 0 {
		t.Errorf("state %q, %d chunks, unread %v; want full and nothing to read", got.State, len(got.Chunks), got.Unread)
	}
}

// What a read with no chunk means, which the fetch job builds on (spec
// section 11, amendment 53): full only for two artifacts that hold the
// same files. A file that went away is a chunk, and a change that is not
// text is a read in part with nothing in it.
func TestPrepareNoChunkMeans(t *testing.T) {
	t.Run("a file was removed and nothing else: the note is a chunk", func(t *testing.T) {
		got := prepareNPM(t, map[string]string{"index.js": "a\n", "old.js": "b\n"}, map[string]string{"index.js": "a\n"}, roomy)
		if got.State != allow.ReadFull || len(got.Chunks) != 1 || !strings.Contains(text(got), "== removed: 1 files") {
			t.Errorf("state %q, chunks %q; want full and the note about the removed file", got.State, text(got))
		}
	})
	t.Run("only a file that is not text changed: no chunk, and not full", func(t *testing.T) {
		got := prepareNPM(t,
			map[string]string{"index.js": "a\n", "prebuilt/addon.node": "\x7fELF\x00old"},
			map[string]string{"index.js": "a\n", "prebuilt/addon.node": "\x7fELF\x00new"}, roomy)
		if got.State != allow.ReadPartial || len(got.Chunks) != 0 || !reflect.DeepEqual(unreadPaths(got), []string{"prebuilt/addon.node"}) {
			t.Errorf("state %q, %d chunks, unread %v; want partial, no chunk and the one file unread", got.State, len(got.Chunks), unreadPaths(got))
		}
	})
	t.Run("a file became empty: its header is a chunk", func(t *testing.T) {
		got := prepareNPM(t, map[string]string{"index.js": "a\n", "x": "\x00"}, map[string]string{"index.js": "a\n", "x": ""}, roomy)
		if got.State != allow.ReadFull || len(got.Chunks) != 1 {
			t.Errorf("state %q, %d chunks; want full and one chunk", got.State, len(got.Chunks))
		}
	})
}

// A file that is not text is listed as unread, with its size and hash,
// whatever its name says and however little of it is not text. It is
// never dropped without a trace, and never shown.
func TestNotTextIsUnreadNeverDropped(t *testing.T) {
	code := "function run() {\n  return fetch('https://example.com');\n}\n"
	tests := []struct {
		name    string
		path    string
		old     *string // nil: the file is new
		content string
	}{
		{"one NUL byte in a changed .js file", "dist/index.js", ptr(code), strings.Replace(code, "return", "return\x00", 1)},
		{"one NUL byte in an added .js file", "dist/index.js", nil, code + "\x00"},
		{"one NUL byte at the very start", "dist/index.js", ptr(code), "\x00" + code},
		{"one byte that is not UTF-8", "dist/index.js", ptr(code), strings.Replace(code, "run", "r\xffn", 1)},
		{"UTF-16", "dist/index.js", ptr(code), "\xff\xfef\x00u\x00n\x00"},
		{"a truncated UTF-8 sequence at the end", "dist/index.js", ptr(code), code + "\xe2\x82"},
		{"a real binary", "prebuilds/addon.node", ptr("\x7fELF\x00old"), "\x7fELF\x00\x01\x02new"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldFiles := map[string]string{"package.json": "{\"version\": \"1.0.0\"}\n"}
			if tt.old != nil {
				oldFiles[tt.path] = *tt.old
			}
			newFiles := map[string]string{"package.json": "{\"version\": \"1.0.1\"}\n", tt.path: tt.content}
			got := prepareNPM(t, oldFiles, newFiles, roomy)

			sum := sha256.Sum256([]byte(tt.content))
			want := []Unread{{Path: tt.path, Size: int64(len(tt.content)), SHA256: hex.EncodeToString(sum[:])}}
			if !reflect.DeepEqual(got.Unread, want) {
				t.Errorf("unread %+v, want %+v", got.Unread, want)
			}
			if got.State != allow.ReadPartial {
				t.Errorf("state %q, want partial", got.State)
			}
			all := text(got)
			if strings.Contains(all, tt.path) || strings.Contains(all, "fetch") || strings.Contains(all, "ELF") {
				t.Errorf("the file is in the text although it is not text:\n%s", all)
			}
			// The text file beside it is still read.
			if !strings.Contains(all, "== file: package.json (changed)") {
				t.Errorf("package.json is missing from the text:\n%s", all)
			}
		})
	}
}

func ptr(s string) *string { return &s }

// The differ itself never answers "binary". A file with a NUL does not
// reach it (isText comes first and lists the file as unread), but if one
// did, its lines would be printed, not replaced by "Binary files differ".
// What git prints without --text is logged for comparison; that is git's
// behaviour, not this package's, so it is not asserted.
func TestDifferNeverPrintsBinaryFilesDiffer(t *testing.T) {
	r := newReader(t, nil)
	work, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d, err := newDiffer(r.git, work)
	if err != nil {
		t.Fatal(err)
	}
	before, after := []byte("a\nb\n"), []byte("a\nb\x00evil()\n")
	hunks, err := d.diff(context.Background(), before, after)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"@@ -1,2 +1,2 @@\n a\n-b\n+b\x00evil()\n"}; !reflect.DeepEqual(hunks, want) {
		t.Errorf("hunks %q, want %q", hunks, want)
	}

	cmd := exec.Command(r.git, "diff", "--no-index", "--", filepath.Join(d.pair, "old"), filepath.Join(d.pair, "new"))
	cmd.Dir, cmd.Env = d.cwd, d.env
	out, _ := cmd.Output()
	t.Logf("the same two files without --text:\n%s", out)
}

// Attributes cannot hide a file or change how it is shown: not a
// .gitattributes inside the artifacts, not one in a repository the
// scratch directory happens to be in, not that repository's
// configuration.
func TestAttributesDoNotHideAFile(t *testing.T) {
	hostile := strings.Join([]string{
		"* binary",
		"* -diff",
		"* -text",
		"*.js binary",
		"*.js -diff",
		"*.js working-tree-encoding=UTF-16LE",
		"*.js filter=hide",
		"*.js diff=hide",
		"*.js ident",
		"*.js eol=crlf",
		"*.js export-ignore",
		"old binary",
		"new binary",
		"old working-tree-encoding=UTF-16LE",
		"new working-tree-encoding=UTF-16LE",
	}, "\n") + "\n"
	oldFiles := map[string]string{
		".gitattributes":      hostile,
		"dist/.gitattributes": hostile,
		"dist/index.js":       "line1\nline2\nline3\n",
	}
	newFiles := map[string]string{
		".gitattributes":      hostile + "# changed\n",
		"dist/.gitattributes": hostile,
		"dist/index.js":       "line1\nline2 evil()\nline3\n",
		"dist/added.js":       "added()\n",
	}
	want := prepareNPM(t, oldFiles, newFiles, roomy)
	for _, part := range []string{
		"== file: dist/index.js (changed)\n@@ -1,3 +1,3 @@\n line1\n-line2\n+line2 evil()\n line3\n",
		"== file: dist/added.js (added)\n@@ -0,0 +1 @@\n+added()\n",
		"== file: .gitattributes (changed)\n",
		"+# changed\n",
	} {
		if !strings.Contains(text(want), part) {
			t.Fatalf("the text lacks\n%s\nit is:\n%s", part, text(want))
		}
	}
	if want.State != allow.ReadFull || len(want.Unread) != 0 {
		t.Fatalf("state %q, unread %v; want a full read", want.State, want.Unread)
	}

	// The same again with the scratch directory inside a git repository
	// whose attributes and configuration are hostile too. Run there
	// without care, "git diff --no-index" would apply all of it: the
	// repository's .gitattributes covers every path below it.
	repo := t.TempDir()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(git, args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q", ".")
	run("config", "diff.hide.textconv", "printf hidden")
	run("config", "diff.hide.command", "true")
	run("config", "filter.hide.clean", "printf hidden")
	run("config", "diff.external", "true")
	run("config", "core.attributesFile", filepath.Join(repo, "attrs"))
	for _, name := range []string{".gitattributes", "attrs", filepath.Join(".git", "info", "attributes")} {
		if err := os.WriteFile(filepath.Join(repo, name), []byte(hostile), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	scratch := filepath.Join(repo, "scratch")
	if err := os.Mkdir(scratch, 0o700); err != nil {
		t.Fatal(err)
	}

	// Whether the trap works is git's business, so it is only logged: with
	// git 2.56 a plain diff of two files in this repository hides the
	// change. The assertion below holds either way.
	if err := os.WriteFile(filepath.Join(scratch, "a.js"), []byte("line1\nline2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scratch, "b.js"), []byte("line1\nline2 evil()\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plain := exec.Command(git, "diff", "--no-index", "--", "a.js", "b.js")
	plain.Dir = scratch
	plain.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	if out, _ := plain.CombinedOutput(); strings.Contains(string(out), "evil") {
		t.Logf("this git does not let the hostile repository hide the change from a plain diff:\n%s", out)
	} else {
		t.Logf("a plain git diff in the hostile repository hides the change: %q", out)
	}

	p, f := npmPair(t, oldFiles, newFiles)
	r := newReader(t, f)
	r.scratch = scratch
	got, err := r.Prepare(context.Background(), p, roomy)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("inside a hostile repository the read differs:\n%s\nwant:\n%s", text(got), text(want))
	}
}

// git gets its whole environment from this package. Whatever the job's
// environment says (a configuration file, an external diff, a
// repository) changes nothing.
func TestGitIgnoresTheEnvironment(t *testing.T) {
	oldFiles := map[string]string{"index.js": "line1\nline2\n"}
	newFiles := map[string]string{"index.js": "line1\nline2 evil()\n"}
	want := prepareNPM(t, oldFiles, newFiles, roomy)

	home := t.TempDir()
	config := "[diff]\n\texternal = true\n\tnoprefix = true\n\tcontext = 0\n[core]\n\tattributesFile = " + filepath.Join(home, "attrs") + "\n"
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "attrs"), []byte("* binary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".config", "git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".config", "git", "attributes"), []byte("* binary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, ".gitconfig"))
	t.Setenv("GIT_EXTERNAL_DIFF", "true")
	t.Setenv("GIT_DIR", filepath.Join(home, "no-such-repository"))
	t.Setenv("GIT_DIFF_OPTS", "--unified=0")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "diff.external")
	t.Setenv("GIT_CONFIG_VALUE_0", "true")

	got := prepareNPM(t, oldFiles, newFiles, roomy)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("with a hostile environment the read differs:\n%s\nwant:\n%s", text(got), text(want))
	}
	if !strings.Contains(text(got), "+line2 evil()") {
		t.Errorf("the change is not in the text:\n%s", text(got))
	}
}

// Every line of a file that a publisher wrote goes through the escaper.
// A file's name does not get that far when it has such a character in
// it: the update is refused (TestPathNamesOnGateLines).
func TestPrepareEscapes(t *testing.T) {
	rlo, ls := u(0x202E), u(0x2028)
	got := prepareNPM(t,
		map[string]string{"index.js": "a\n"},
		map[string]string{
			"index.js": "a\nif (admin" + rlo + ") {\rhidden()" + ls + "\x1b[2K\n== file: forged.js (changed)\n",
			"bin.dat":  "\x00",
			"crlf.txt": "one\r\ntwo\r\n",
		},
		roomy)
	all := text(got)
	for _, bad := range []string{rlo, ls, "\x1b", "{\rhidden"} {
		if strings.Contains(all, bad) {
			t.Errorf("%q is in the text unescaped:\n%q", bad, all)
		}
	}
	for _, want := range []string{
		"+if (admin<U+202E>) {<0x0D>hidden()<U+2028><0x1B>[2K\n",
		"+one<0x0D>\n+two<0x0D>\n",
		// A line of the file that imitates the gate's header is still a
		// line of the file: it has its "+".
		"\n+== file: forged.js (changed)\n",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("the text lacks %q:\n%q", want, all)
		}
	}
	if strings.Contains(all, "\n== file: forged.js") {
		t.Errorf("the file's own text produced a gate header:\n%s", all)
	}
	if got := unreadPaths(got); !reflect.DeepEqual(got, []string{"bin.dat"}) {
		t.Errorf("unread paths %q", got)
	}
	// Every line of every chunk is the gate's, a hunk header, or text
	// behind a marker.
	for _, line := range strings.Split(strings.TrimSuffix(all, "\n"), "\n") {
		if !strings.HasPrefix(line, "== ") && !strings.HasPrefix(line, "@@ ") && !strings.ContainsAny(line[:1], "+- \\~") {
			t.Errorf("a line that is neither the gate's nor marked: %q", line)
		}
	}
}

// A file over 256 KB in an npm or Actions artifact is shown as the lines
// that are new, with three lines around each. The same file in a Go
// module is diffed like any other.
func TestBundleView(t *testing.T) {
	var lines []string
	for i := range 20000 {
		lines = append(lines, "function f"+strings.Repeat("0", 5)+string(rune('a'+i%26))+hexInt(i)+"() {}")
	}
	before := strings.Join(lines, "\n") + "\n"
	if len(before) <= bundleBytes {
		t.Fatalf("test bundle is only %d bytes", len(before))
	}
	changed := append([]string{}, lines...)
	// One new line in the middle, one block moved from the start to the
	// end, one line removed.
	changed[10000] = "exfiltrate(process.env)"
	moved := append([]string{}, changed[5:15]...)
	changed = append(changed[:5], changed[15:]...)
	changed = append(changed, moved...)
	changed = append(changed[:300], changed[301:]...)
	after := strings.Join(changed, "\n") + "\n"

	t.Run("npm", func(t *testing.T) {
		got := prepareNPM(t, map[string]string{"dist/index.js": before}, map[string]string{"dist/index.js": after}, roomy)
		all := text(got)
		if !strings.HasPrefix(all, "== file: dist/index.js (changed; larger than 256 KB, so only the lines that occur nowhere in the old version are shown, with 3 lines around each)\n") {
			t.Errorf("header: %q", strings.SplitN(all, "\n", 2)[0])
		}
		body := strings.SplitN(all, "\n", 2)[1]
		gotLines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
		if len(gotLines) != 8 {
			t.Fatalf("%d lines, want a hunk header, 3 lines of context, the new line, 3 lines of context:\n%s", len(gotLines), body)
		}
		if !strings.HasPrefix(gotLines[0], "@@ +") || gotLines[4] != "+exfiltrate(process.env)" {
			t.Errorf("hunk:\n%s", body)
		}
		for _, i := range []int{1, 2, 3, 5, 6, 7} {
			if !strings.HasPrefix(gotLines[i], " function f") {
				t.Errorf("line %d is not context: %q", i, gotLines[i])
			}
		}
		if got.State != allow.ReadFull {
			t.Errorf("state %q, want full: the bundle view is the read of a bundle", got.State)
		}
	})

	t.Run("actions", func(t *testing.T) {
		oldCommit, newCommit := strings.Repeat("a", 40), strings.Repeat("b", 40)
		p := Pair{Ecosystem: allow.GitHubActions, Name: "owner/repo", From: "v1.0.0", To: "v1.0.1",
			Old: Ref{Kind: ActionTarball, Name: "owner/repo", Version: "v1.0.0", Hash: oldCommit},
			New: Ref{Kind: ActionTarball, Name: "owner/repo", Version: "v1.0.1", Hash: newCommit}}
		f := fakeFetcher{
			p.Old: actionTarball(t, oldCommit, map[string]string{"action.yml": nodeAction, "dist/index.js": before}),
			p.New: actionTarball(t, newCommit, map[string]string{"action.yml": nodeAction, "dist/index.js": after}),
		}
		got, err := newReader(t, f).Prepare(context.Background(), p, roomy)
		if err != nil {
			t.Fatal(err)
		}
		if all := text(got); !strings.Contains(all, "larger than 256 KB") || strings.Count(all, "\n") != 9 {
			t.Errorf("not the bundle view:\n%s", all)
		}
	})

	t.Run("a Go module gets a plain diff", func(t *testing.T) {
		oldZip := moduleZip(t, "example.com/mod", "v1.0.0", map[string]string{"go.mod": "module example.com/mod\n", "big.go": before})
		newZip := moduleZip(t, "example.com/mod", "v1.0.1", map[string]string{"go.mod": "module example.com/mod\n", "big.go": after})
		p := Pair{Ecosystem: allow.GoModules, Name: "example.com/mod", From: "v1.0.0", To: "v1.0.1",
			Old: Ref{Kind: GoModuleZip, Name: "example.com/mod", Version: "v1.0.0", Hash: h1(t, oldZip)},
			New: Ref{Kind: GoModuleZip, Name: "example.com/mod", Version: "v1.0.1", Hash: h1(t, newZip)}}
		got, err := newReader(t, fakeFetcher{p.Old: oldZip, p.New: newZip}).Prepare(context.Background(), p, roomy)
		if err != nil {
			t.Fatal(err)
		}
		all := text(got)
		if !strings.HasPrefix(all, "== file: big.go (changed)\n") {
			t.Errorf("header: %q", strings.SplitN(all, "\n", 2)[0])
		}
		// A diff shows what the bundle view leaves out: removed lines,
		// and the moved block as added again.
		if !strings.Contains(all, "\n-function f") || strings.Count(all, "\n+function f") != 10 {
			t.Errorf("not a plain diff:\n%.2000s", all)
		}
	})

	t.Run("an added bundle is shown whole", func(t *testing.T) {
		got := prepareNPM(t, map[string]string{"a.js": "x\n"}, map[string]string{"a.js": "x\n", "dist/index.js": before}, Limits{ChunkBytes: 2 << 20, MaxChunks: 1})
		if n := strings.Count(text(got), "\n+function f"); n != 20000 {
			t.Errorf("%d added lines shown, want all 20000", n)
		}
	})

	t.Run("a bundle with nothing new says so", func(t *testing.T) {
		got := prepareNPM(t, map[string]string{"dist/index.js": before}, map[string]string{"dist/index.js": strings.Join(lines[:19000], "\n") + "\n"}, roomy)
		all := text(got)
		if !strings.Contains(all, "there are none: lines were only removed or moved") || strings.Contains(all, "@@") {
			t.Errorf("text:\n%s", all)
		}
		if got.State != allow.ReadFull {
			t.Errorf("state %q", got.State)
		}
	})
}

func hexInt(i int) string { return hex.EncodeToString([]byte{byte(i >> 16), byte(i >> 8), byte(i)}) }

func TestNewLines(t *testing.T) {
	tests := []struct {
		name   string
		before string
		after  string
		want   []string
	}{
		{"nothing new", "a\nb\nc\n", "c\na\n", nil},
		{"all new", "", "a\nb\n", []string{"@@ +1,2 @@\n+a\n+b\n"}},
		{"no final newline", "a\n", "a\nb", []string{"@@ +1,2 @@\n a\n+b\n"}},
		{"context is cut at the ends", "1\n2\n", "1\nX\n2\n", []string{"@@ +1,3 @@\n 1\n+X\n 2\n"}},
		{"three lines around", "1\n2\n3\n4\n5\n6\n7\n8\n9\n", "1\n2\n3\n4\nX\n5\n6\n7\n8\n9\n",
			[]string{"@@ +2,7 @@\n 2\n 3\n 4\n+X\n 5\n 6\n 7\n"}},
		{"changes whose context touches share a hunk",
			"1\n2\n3\n4\n5\n6\n7\n8\n9\n", "X\n1\n2\n3\n4\n5\n6\nY\n7\n8\n9\n",
			[]string{"@@ +1,11 @@\n+X\n 1\n 2\n 3\n 4\n 5\n 6\n+Y\n 7\n 8\n 9\n"}},
		{"changes further apart do not",
			"1\n2\n3\n4\n5\n6\n7\n8\n9\n", "X\n1\n2\n3\n4\n5\n6\n7\nY\n8\n9\n",
			[]string{"@@ +1,4 @@\n+X\n 1\n 2\n 3\n", "@@ +6,6 @@\n 5\n 6\n 7\n+Y\n 8\n 9\n"}},
		{"a line that exists anywhere in the old file is not new", "a\nb\n", "b\nb\na\nb\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newLines([]byte(tt.before), []byte(tt.after)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOldSideNotText(t *testing.T) {
	got := prepareNPM(t,
		map[string]string{"data.js": "\x00\x01binary", "empty.js": "\x00"},
		map[string]string{"data.js": "module.exports = 1\n", "empty.js": ""},
		roomy)
	want := "== file: data.js (changed; the old version is not text, so the whole file is shown as added)\n@@ -0,0 +1 @@\n+module.exports = 1\n" +
		"== file: empty.js (changed; the old version is not text, so the whole file is shown as added; empty)\n"
	if text(got) != want {
		t.Errorf("text:\n%s\nwant:\n%s", text(got), want)
	}
	if got.State != allow.ReadFull {
		t.Errorf("state %q, want full: every changed file is text now and was sent", got.State)
	}
}

func TestNewNameIsAllAdded(t *testing.T) {
	got := prepareNPM(t, nil, map[string]string{"index.js": "a\nb\n", "empty.js": "", "addon.node": "\x00"}, roomy)
	want := "== file: empty.js (added; empty)\n== file: index.js (added)\n@@ -0,0 +1,2 @@\n+a\n+b\n"
	if text(got) != want {
		t.Errorf("text:\n%s\nwant:\n%s", text(got), want)
	}
	if !reflect.DeepEqual(unreadPaths(got), []string{"addon.node"}) || got.State != allow.ReadPartial {
		t.Errorf("unread %v, state %q", unreadPaths(got), got.State)
	}
	if got.Pair.Old != (Ref{}) || got.Pair.From != "" {
		t.Errorf("pair %+v", got.Pair)
	}
}

func TestRemovedFilesAreNamedUpToALimit(t *testing.T) {
	oldFiles := map[string]string{"keep.js": "a\n"}
	for i := range maxRemovedListed + 50 {
		oldFiles["gone/"+hexInt(i)+".js"] = "x\n"
	}
	got := prepareNPM(t, oldFiles, map[string]string{"keep.js": "b\n"}, roomy)
	all := text(got)
	if !strings.Contains(all, "== removed: 250 files of the old version are gone") ||
		strings.Count(all, "\n==   gone/") != maxRemovedListed || !strings.Contains(all, "==   and 50 more\n") {
		t.Errorf("text:\n%s", all)
	}
	if got.State != allow.ReadFull {
		t.Errorf("state %q: a removed file is not an unread file", got.State)
	}
}

// Two runs in different directories give the same chunks and the same
// key: nothing of the machine, the time or the temporary paths is in the
// text.
func TestPrepareIsDeterministic(t *testing.T) {
	oldFiles := map[string]string{"a.js": "1\n2\n3\n", "b/c.js": "x\n", "gone.js": "g\n", "bin": "\x00a"}
	newFiles := map[string]string{"a.js": "1\n2\n4\n", "b/c.js": "y\n", "new.js": "n\n", "bin": "\x00b"}
	first := prepareNPM(t, oldFiles, newFiles, roomy)
	second := prepareNPM(t, oldFiles, newFiles, roomy)
	if !reflect.DeepEqual(first, second) {
		t.Errorf("two runs differ:\n%+v\n%+v", first, second)
	}
	if strings.Contains(text(first), os.TempDir()) || strings.Contains(text(first), "/pair/") {
		t.Errorf("a temporary path is in the text:\n%s", text(first))
	}
}

func TestContentKey(t *testing.T) {
	oldFiles := map[string]string{"a.js": "1\n"}
	newFiles := map[string]string{"a.js": "2\n"}
	base := prepareNPM(t, oldFiles, newFiles, roomy)

	differs := func(name string, other Prepared) {
		t.Helper()
		if other.Key == base.Key {
			t.Errorf("%s: same key %s", name, base.Key)
		}
	}
	differs("other text", prepareNPM(t, oldFiles, map[string]string{"a.js": "3\n"}, roomy))
	differs("other chunking", prepareNPM(t, map[string]string{"a.js": "1\n", "b.js": strings.Repeat("x\n", 200)},
		map[string]string{"a.js": "2\n", "b.js": strings.Repeat("y\n", 200)}, Limits{ChunkBytes: 256, MaxChunks: 100}))

	// The same chunks, but a binary file changed too: the verdict for
	// one must not be reused for the other.
	withBinary := prepareNPM(t, map[string]string{"a.js": "1\n", "x.bin": "\x00a"}, map[string]string{"a.js": "2\n", "x.bin": "\x00b"}, roomy)
	if !reflect.DeepEqual(withBinary.Chunks, base.Chunks) {
		t.Fatalf("test is wrong: chunks differ")
	}
	differs("an unread file", withBinary)

	// The same chunks for another update.
	other := base
	other.Pair.Name = "other"
	differs("another package", Prepared{Key: contentKey(other)})
	other = base
	other.Pair.New.Hash = integrity([]byte("other bytes"))
	differs("another bound hash", Prepared{Key: contentKey(other)})

	// No chunks at all is not one key for every update.
	none := prepareNPM(t, oldFiles, oldFiles, roomy)
	noneOther := none
	noneOther.Pair.To = "9.9.9"
	if none.Key == contentKey(noneOther) {
		t.Error("two updates with nothing to read share a key")
	}

	// Fields cannot run into each other.
	a, b := base, base
	a.Chunks = []Chunk{{Text: "ab"}, {Index: 1, Text: "c"}}
	b.Chunks = []Chunk{{Text: "a"}, {Index: 1, Text: "bc"}}
	if contentKey(a) == contentKey(b) {
		t.Error("chunk boundaries are not part of the key")
	}
}

func TestPrepareRefusesBadInput(t *testing.T) {
	good := integrity([]byte("x"))
	npm := func(edit func(*Pair)) Pair {
		p := Pair{Ecosystem: allow.NPM, Name: "demo", From: "1.0.0", To: "1.0.1",
			Old: Ref{Kind: NPMTarball, Name: "demo", Version: "1.0.0", Hash: good},
			New: Ref{Kind: NPMTarball, Name: "demo", Version: "1.0.1", Hash: good}}
		edit(&p)
		return p
	}
	commit := strings.Repeat("a", 40)
	action := func(edit func(*Pair)) Pair {
		p := Pair{Ecosystem: allow.GitHubActions, Name: "owner/repo", From: "v1", To: "v2",
			Old: Ref{Kind: ActionTarball, Name: "owner/repo", Version: "v1", Hash: commit},
			New: Ref{Kind: ActionTarball, Name: "owner/repo", Version: "v2", Hash: commit}}
		edit(&p)
		return p
	}
	h := "h1:" + strings.Repeat("A", 43) + "="
	mod := func(edit func(*Pair)) Pair {
		p := Pair{Ecosystem: allow.GoModules, Name: "example.com/m", From: "v1.0.0", To: "v1.0.1",
			Old: Ref{Kind: GoModuleZip, Name: "example.com/m", Version: "v1.0.0", Hash: h},
			New: Ref{Kind: GoModuleZip, Name: "example.com/m", Version: "v1.0.1", Hash: h}}
		edit(&p)
		return p
	}
	tests := []struct {
		name string
		pair Pair
		lim  Limits
	}{
		{"chunk too small", npm(func(*Pair) {}), Limits{ChunkBytes: 10, MaxChunks: 1}},
		{"no chunk size", npm(func(*Pair) {}), Limits{MaxChunks: 1}},
		{"no chunks", npm(func(*Pair) {}), Limits{ChunkBytes: 1000}},
		{"negative chunks", npm(func(*Pair) {}), Limits{ChunkBytes: 1000, MaxChunks: -1}},
		{"chunk too large", npm(func(*Pair) {}), Limits{ChunkBytes: maxBudgetBytes + 1, MaxChunks: 1}},
		{"too many chunks of that size", npm(func(*Pair) {}), Limits{ChunkBytes: 1 << 20, MaxChunks: 257}},
		{"so many chunks the product overflows", npm(func(*Pair) {}), Limits{ChunkBytes: 1 << 20, MaxChunks: 1 << 62}},
		{"no new artifact", npm(func(p *Pair) { p.New = Ref{} }), roomy},
		{"unknown kind", npm(func(p *Pair) { p.New.Kind = "docker-image" }), roomy},
		{"docker has nothing to read", npm(func(p *Pair) { p.Ecosystem = allow.Docker }), roomy},
		{"ecosystem and kind disagree", npm(func(p *Pair) { p.Ecosystem = allow.GoModules }), roomy},
		{"old and new of different kinds", npm(func(p *Pair) { p.Old = Ref{Kind: ActionTarball, Name: "demo/demo", Version: "1.0.0", Hash: commit} }), roomy},
		{"new artifact of another package", npm(func(p *Pair) { p.New.Name = "other" }), roomy},
		{"old artifact of another package", npm(func(p *Pair) { p.Old.Name = "other" }), roomy},
		{"new artifact of another version", npm(func(p *Pair) { p.New.Version = "2.0.0" }), roomy},
		{"old artifact of another version", npm(func(p *Pair) { p.Old.Version = "0.9.0" }), roomy},
		{"a from without an old artifact", npm(func(p *Pair) { p.Old = Ref{} }), roomy},
		{"npm name with a path", npm(func(p *Pair) { p.Name, p.Old.Name, p.New.Name = "a/../b", "a/../b", "a/../b" }), roomy},
		{"npm name with a URL", npm(func(p *Pair) { p.Name, p.Old.Name, p.New.Name = "x?y", "x?y", "x?y" }), roomy},
		{"npm name with two slashes", npm(func(p *Pair) { p.Name, p.Old.Name, p.New.Name = "@a/b/c", "@a/b/c", "@a/b/c" }), roomy},
		{"npm version that is a path", npm(func(p *Pair) { p.To, p.New.Version = "1.0.1/../x", "1.0.1/../x" }), roomy},
		{"npm sha1 integrity", npm(func(p *Pair) { p.New.Hash = "sha1-2jmj7l5rSw0yVb/vlWAYkK/YBwk=" }), roomy},
		{"npm two integrity tokens", npm(func(p *Pair) { p.New.Hash = good + " " + good }), roomy},
		{"npm no integrity", npm(func(p *Pair) { p.New.Hash = "" }), roomy},
		{"action name with a path", action(func(p *Pair) { p.Name, p.Old.Name, p.New.Name = "owner/repo/sub", "owner/repo/sub", "owner/repo/sub" }), roomy},
		{"action without owner", action(func(p *Pair) { p.Name, p.Old.Name, p.New.Name = "repo", "repo", "repo" }), roomy},
		{"action short commit", action(func(p *Pair) { p.New.Hash = "abc1234" }), roomy},
		{"action upper-case commit", action(func(p *Pair) { p.New.Hash = strings.Repeat("A", 40) }), roomy},
		{"action tag as hash", action(func(p *Pair) { p.New.Hash = "v2" }), roomy},
		{"action without a tag", action(func(p *Pair) { p.To, p.New.Version = "", "" }), roomy},
		{"action tag with a space", action(func(p *Pair) { p.To, p.New.Version = "v2 (trusted)", "v2 (trusted)" }), roomy},
		{"action tag with a line break", action(func(p *Pair) { p.To, p.New.Version = "v2\n== file: x", "v2\n== file: x" }), roomy},
		{"action tag with a hidden character", action(func(p *Pair) { p.To, p.New.Version = "v2"+u(0x202E), "v2"+u(0x202E) }), roomy},
		{"action tag too long", action(func(p *Pair) { p.To, p.New.Version = "v"+strings.Repeat("1", 200), "v"+strings.Repeat("1", 200) }), roomy},
		{"old action tag with a line break", action(func(p *Pair) { p.From, p.Old.Version = "v1\nx", "v1\nx" }), roomy},
		{"module path not a module path", mod(func(p *Pair) { p.Name, p.Old.Name, p.New.Name = "../m", "../m", "../m" }), roomy},
		{"module version not canonical", mod(func(p *Pair) { p.To, p.New.Version = "v1.0", "v1.0" }), roomy},
		{"module version is a flag", mod(func(p *Pair) { p.To, p.New.Version = "-json", "-json" }), roomy},
		{"module major does not fit the path", mod(func(p *Pair) { p.To, p.New.Version = "v2.0.0", "v2.0.0" }), roomy},
		{"module hash of the go.mod kind", mod(func(p *Pair) { p.New.Hash = "h2:" + strings.Repeat("A", 43) + "=" }), roomy},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A fetcher that fails the test if it is asked: bad input
			// must be refused before any download.
			_, err := newReader(t, fetchNothing{t}).Prepare(context.Background(), tt.pair, tt.lim)
			if !errors.Is(err, ErrBadRef) {
				t.Errorf("error %v, want ErrBadRef", err)
			}
		})
	}
}

type fetchNothing struct{ t *testing.T }

func (f fetchNothing) fetch(_ context.Context, ref Ref, _ string) (string, error) {
	f.t.Errorf("fetched %+v", ref)
	return "", errors.New("nothing to fetch")
}

func TestPrepareStopsWhenTheContextEnds(t *testing.T) {
	p, f := npmPair(t, map[string]string{"a.js": "1\n"}, map[string]string{"a.js": "2\n"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newReader(t, f).Prepare(ctx, p, roomy); !errors.Is(err, context.Canceled) {
		t.Errorf("error %v, want context.Canceled", err)
	}
}

func TestPrepareCleansUp(t *testing.T) {
	p, f := npmPair(t, map[string]string{"a.js": "1\n"}, map[string]string{"a.js": "2\n"})
	r := newReader(t, f)
	if _, err := r.Prepare(context.Background(), p, roomy); err != nil {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(r.scratch); len(ents) != 0 {
		t.Errorf("left behind in the scratch directory: %v", ents)
	}
}

// Past the limits on what one Prepare holds in memory, a changed file is
// listed as unread like any other file that is not shown.
func TestHeldTextIsBounded(t *testing.T) {
	oldFiles := map[string]string{"a.js": "1\n", "b.js": "1\n", "c.js": "1\n", "huge.js": "1\n"}
	newFiles := map[string]string{
		"a.js":    strings.Repeat("a\n", 100),
		"b.js":    strings.Repeat("b\n", 100),
		"c.js":    strings.Repeat("c\n", 100),
		"huge.js": strings.Repeat("h\n", 1000),
	}
	p, f := npmPair(t, oldFiles, newFiles)

	t.Run("one file too large to diff", func(t *testing.T) {
		r := newReader(t, f)
		r.maxFile = 1000
		got, err := r.Prepare(context.Background(), p, roomy)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(newFiles["huge.js"]))
		want := []Unread{{Path: "huge.js", Size: 2000, SHA256: hex.EncodeToString(sum[:])}}
		if !reflect.DeepEqual(got.Unread, want) || got.State != allow.ReadPartial {
			t.Errorf("unread %+v, state %q", got.Unread, got.State)
		}
		if strings.Count(text(got), "== file: ") != 3 || strings.Contains(text(got), "huge.js") {
			t.Errorf("text:\n%s", text(got))
		}
	})

	t.Run("an old version too large to diff against", func(t *testing.T) {
		big, f := npmPair(t, map[string]string{"x.js": strings.Repeat("old\n", 500)}, map[string]string{"x.js": "new\n"})
		r := newReader(t, f)
		r.maxFile = 1000
		got, err := r.Prepare(context.Background(), big, roomy)
		if err != nil {
			t.Fatal(err)
		}
		if want := "== file: x.js (changed; the old version is too large to compare with, so the whole file is shown as added)\n@@ -0,0 +1 @@\n+new\n"; text(got) != want {
			t.Errorf("text:\n%s", text(got))
		}
	})

	t.Run("more text than is held", func(t *testing.T) {
		r := newReader(t, f)
		r.maxText = 400 // a.js is 317 bytes of diff; with b.js it is past
		got, err := r.Prepare(context.Background(), p, roomy)
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"c.js", "huge.js"}; !reflect.DeepEqual(unreadPaths(got), want) || got.State != allow.ReadPartial {
			t.Errorf("unread %v, state %q; want %v", unreadPaths(got), got.State, want)
		}
		if strings.Count(text(got), "== file: ") != 2 {
			t.Errorf("text:\n%s", text(got))
		}
	})
}

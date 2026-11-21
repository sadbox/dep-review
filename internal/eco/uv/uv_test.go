package uv

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
	"github.com/sadbox/dep-review/internal/eco/ecoutil/gittest"
	"github.com/sadbox/dep-review/internal/evidence"
	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/model"
)

func TestParseTOML(t *testing.T) {
	src := `# comment
version = 1
"quoted key" = 'literal \n'
a.b.c = true
f = 1.5
n = 1_000
d = 2026-11-04T20:12:16Z
s = "esc \"q\" é \t"
ml = """
line1 \
  line2"""
ll = '''
raw\n'''
arr = [
    1, # trailing comment
    2,
]
it = { x = "1", y = [ "a", "b" ], z = { w = 0 } }

[[package]]
name = "p1"
[package.metadata]
requires-dist = [{ name = "a", specifier = "==1" }]

[[package]]
name = "p2"
[package.metadata]
k = "v"

[tool.uv]
package = false
`
	got, err := ParseTOML(src)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"version":    int64(1),
		"quoted key": `literal \n`,
		"a":          map[string]any{"b": map[string]any{"c": true}},
		"f":          1.5,
		"n":          int64(1000),
		"d":          "2026-11-04T20:12:16Z",
		"s":          "esc \"q\" é \t",
		"ml":         "line1 line2",
		"ll":         `raw\n`,
		"arr":        []any{int64(1), int64(2)},
		"it":         map[string]any{"x": "1", "y": []any{"a", "b"}, "z": map[string]any{"w": int64(0)}},
		"package": []any{
			map[string]any{"name": "p1", "metadata": map[string]any{"requires-dist": []any{map[string]any{"name": "a", "specifier": "==1"}}}},
			map[string]any{"name": "p2", "metadata": map[string]any{"k": "v"}},
		},
		"tool": map[string]any{"uv": map[string]any{"package": false}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %#v\nwant %#v", got, want)
	}

	for _, bad := range []string{
		"a = 1\na = 2\n",
		"[t]\n[t]\n",
		"a = \"unterminated\n",
		"a = [1, 2\n",
		"a = { b = 1\n",
		"a = nope\n",
		"a = 1 b = 2\n",
		"a.b = 1\n[a.b]\n",
	} {
		if _, err := ParseTOML(bad); err == nil {
			t.Errorf("ParseTOML(%q) succeeded", bad)
		}
	}
}

func TestParseLockFixture(t *testing.T) {
	b, err := os.ReadFile("testdata/homelab/head/uv.lock")
	if err != nil {
		t.Fatal(err)
	}
	l, err := ParseLock(string(b))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range l.Packages {
		names = append(names, p.Name+"=="+p.Version)
		if _, ok := p.projectPath(); ok {
			if !slices.Equal(p.Deps, []string{"ansible", "ansible-core"}) {
				t.Errorf("project deps = %v", p.Deps)
			}
			continue
		}
		if p.Registry() != pypiRegistry || p.Sdist == nil || len(p.Wheels) == 0 {
			t.Errorf("%s: source %v sdist %v wheels %d", p.Name, p.Source, p.Sdist, len(p.Wheels))
		}
		for _, w := range append([]Artifact{*p.Sdist}, p.Wheels...) {
			if !strings.HasPrefix(w.Hash, "sha256:") || w.Size <= 0 || ecoutil.CheckHost(w.URL, filesHost) != nil {
				t.Errorf("%s: artifact %+v", p.Name, w)
			}
		}
	}
	want := []string{"ansible==14.6.0", "ansible-core==2.21.6", "bonnet-ansible==0", "cffi==2.1.1", "cryptography==50.0.2",
		"jinja2==3.1.6", "markupsafe==3.0.4", "packaging==26.3", "pycparser==3.12", "pyyaml==6.0.3", "resolvelib==1.2.1"}
	if !slices.Equal(names, want) {
		t.Errorf("packages = %q\nwant %q", names, want)
	}
}

func fixtureRepo(t *testing.T, edit func(head map[string][]byte)) (string, model.Classification) {
	t.Helper()
	base := gittest.ReadDir(t, "testdata/homelab/base")
	head := gittest.ReadDir(t, "testdata/homelab/head")
	if edit != nil {
		edit(head)
	}
	dir, b, h := gittest.Repo(t, prefix("ansible/", base), prefix("ansible/", head))
	return dir, model.Classification{Repo: "test/homelab", PR: 1, BaseSHA: b, HeadSHA: h, Kind: model.KindDependabot, Ecosystem: model.UV}
}

func prefix(p string, m map[string][]byte) map[string][]byte {
	out := map[string][]byte{}
	for k, v := range m {
		out[p+k] = v
	}
	return out
}

func TestChangeSetFixture(t *testing.T) {
	tests := []struct {
		name  string
		edit  func(map[string][]byte)
		want  []string
		codes []string
	}{
		{"upgrade", nil, []string{"/ansible packaging 26.2->26.3 minor false", "/ansible resolvelib 1.2.0->1.2.1 patch false"}, nil},
		{"same version, new hash", func(h map[string][]byte) {
			h["uv.lock"] = bytes.Replace(h["uv.lock"], []byte("sha256:47cd013f4b6462f15b65485d09b713ae64697036733078f0623f636a94f5df45"),
				[]byte("sha256:0000013f4b6462f15b65485d09b713ae64697036733078f0623f636a94f5df45"), 1)
		}, []string{"/ansible packaging 26.2->26.3 minor false", "/ansible resolvelib 1.2.0->1.2.1 patch false"}, []string{"uv.same-version-changed"}},
		{"git source", func(h map[string][]byte) {
			h["uv.lock"] = bytes.Replace(h["uv.lock"], []byte("name = \"resolvelib\"\nversion = \"1.2.1\"\nsource = { registry = \"https://pypi.org/simple\" }"),
				[]byte("name = \"resolvelib\"\nversion = \"1.2.1\"\nsource = { git = \"https://github.com/evil/resolvelib\" }"), 1)
		}, []string{"/ansible packaging 26.2->26.3 minor false", "/ansible resolvelib 1.2.0->1.2.1 patch false"}, []string{"uv.source-off-registry"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			edit := func(h map[string][]byte) {
				if tt.edit != nil {
					tt.edit(h)
				}
			}
			repo, class := fixtureRepo(t, edit)
			var sum bytes.Buffer
			changes, findings, err := dirChanges(context.Background(), ecoutil.Git{Repo: repo, Home: t.TempDir()}, class.BaseSHA, class.HeadSHA, "ansible", &sum)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, c := range changes {
				u := c.update
				got = append(got, fmt.Sprintf("%s %s %s->%s %s %v", u.Directory, u.Name, u.From, u.To, u.Type, u.Direct))
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("changes = %q, want %q", got, tt.want)
			}
			var codes []string
			for _, f := range findings {
				codes = append(codes, f.Code)
				if f.Route != model.RouteRefuse {
					t.Errorf("%s route %s", f.Code, f.Route)
				}
			}
			if !slices.Equal(codes, tt.codes) {
				t.Errorf("codes = %q, want %q", codes, tt.codes)
			}
		})
	}
}

func TestPick(t *testing.T) {
	b, _ := os.ReadFile("testdata/homelab/head/uv.lock")
	l, err := ParseLock(string(b))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range l.Packages {
		w, s := pick(p, "")
		switch p.Name {
		case "packaging":
			if w == nil || !strings.HasSuffix(w.URL, "-py3-none-any.whl") || s != nil {
				t.Errorf("packaging: %v %v", w, s)
			}
		case "pyyaml":
			if w == nil || !strings.Contains(w.URL, "manylinux") || !strings.Contains(w.URL, "x86_64") || s == nil {
				t.Errorf("pyyaml: %v %v", w, s)
			}
			tags := wheelTags(artifactName(w.URL))
			if w2, _ := pick(p, tags); w2 != w {
				t.Errorf("pyyaml like %q picked %v", tags, w2)
			}
		}
	}
}

func zipTree(t *testing.T, files map[string]string) *ecoutil.Tree {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		w, _ := zw.Create(name)
		w.Write([]byte(data))
	}
	zw.Close()
	p := filepath.Join(t.TempDir(), "w.whl")
	os.WriteFile(p, buf.Bytes(), 0o644)
	tr, err := ecoutil.ExtractZip(p, filepath.Join(t.TempDir(), "x"), false)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestCheckPackage(t *testing.T) {
	const md = "Metadata-Version: 2.4\nName: p\nVersion: 1.0\nRequires-Dist: a>=1\nRequires-Dist: b; extra == \"x\"\n\nDescription Requires-Dist: evil\n"
	const eps = "[console_scripts]\np = p.cli:main\n"
	oldWheel := map[string]string{"p/__init__.py": "x = 1\n", "p-1.0.dist-info/METADATA": md, "p-1.0.dist-info/entry_points.txt": eps}
	with := func(over map[string]string) map[string]string {
		m := map[string]string{"p/__init__.py": "x = 2\n", "p-1.1.dist-info/METADATA": strings.Replace(md, "1.0", "1.1", 1), "p-1.1.dist-info/entry_points.txt": eps}
		for k, v := range over {
			m[k] = v
		}
		return m
	}
	const pyproject = "[build-system]\nrequires = [\"setuptools\"]\nbuild-backend = \"setuptools.build_meta\"\n"
	tests := []struct {
		name               string
		wheel              map[string]string
		oldSdist, newSdist map[string]string
		want               []string
	}{
		{"clean", with(nil), nil, nil, nil},
		{"pth", with(map[string]string{"evil.pth": "import os"}), nil, nil, []string{"uv.pth-file"}},
		{"native", with(map[string]string{"p/_x.cpython-312-x86_64-linux-gnu.so": "\x7fELF"}), nil, nil, []string{"uv.native-extension"}},
		{"new requires", with(map[string]string{"p-1.1.dist-info/METADATA": md[:len(md)-len("\nDescription Requires-Dist: evil\n")] + "Requires-Dist: requests\n\n"}), nil, nil, []string{"uv.new-requires-dist"}},
		{"new entry point", with(map[string]string{"p-1.1.dist-info/entry_points.txt": eps + "q = p.evil:main\n"}), nil, nil, []string{"uv.new-entry-point"}},
		{"setup.py changed", nil, map[string]string{"setup.py": "setup()", "PKG-INFO": md}, map[string]string{"setup.py": "import os; setup()", "PKG-INFO": md}, []string{"uv.setup-py-changed"}},
		{"backend changed", nil, map[string]string{"pyproject.toml": pyproject, "PKG-INFO": md}, map[string]string{"pyproject.toml": strings.Replace(pyproject, "setuptools.build_meta", "evil_backend", 1), "PKG-INFO": md}, []string{"uv.build-backend-changed"}},
		{"sdist new script", nil, map[string]string{"pyproject.toml": pyproject, "PKG-INFO": md}, map[string]string{"pyproject.toml": pyproject + "[project.scripts]\nx = \"p:x\"\n", "PKG-INFO": md}, []string{"uv.new-entry-point"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var old, cur sideTrees
			if tt.wheel != nil {
				old.wheel, cur.wheel = zipTree(t, oldWheel), zipTree(t, tt.wheel)
			}
			if tt.newSdist != nil {
				old.sdist, cur.sdist = zipTree(t, tt.oldSdist), zipTree(t, tt.newSdist)
			}
			var got []string
			for _, f := range checkPackage(old, cur) {
				got = append(got, f.Code)
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.want) {
				t.Errorf("codes = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHashMismatchRefused(t *testing.T) {
	good := []byte("PK-not-really")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(good) }))
	defer srv.Close()
	sum := sha256.Sum256([]byte("something else"))
	a := Artifact{URL: srv.URL + "/p-1.0-py3-none-any.whl", Hash: "sha256:" + hex.EncodeToString(sum[:])}
	f := Fetcher{AllowHost: strings.TrimPrefix(srv.URL, "http://")}
	_, bad, err := f.fetchArtifact(context.Background(), fetch.Env{HTTP: srv.Client()}, filepath.Join(t.TempDir(), "w"), a)
	if err != nil {
		t.Fatal(err)
	}
	if bad == nil || bad.Code != "uv.hash-mismatch" || bad.Route != model.RouteRefuse {
		t.Errorf("finding = %+v", bad)
	}
	_, bad, _ = Fetcher{}.fetchArtifact(context.Background(), fetch.Env{HTTP: srv.Client()}, filepath.Join(t.TempDir(), "w"), Artifact{URL: "https://evil.example/x.whl", Hash: a.Hash})
	if bad == nil || bad.Code != "uv.artifact-off-registry" {
		t.Errorf("off-registry finding = %+v", bad)
	}
}

// TestFetchNetwork runs the homelab-configs ansible/uv.lock (packaging
// 26.2 -> 26.3, resolvelib 1.2.0 -> 1.2.1, real PyPI hashes) end to end.
func TestFetchNetwork(t *testing.T) {
	if testing.Short() {
		t.Skip("network")
	}
	repo, class := fixtureRepo(t, nil)
	class.Declared = []model.Update{{Name: "resolvelib", From: "1.2.0", To: "1.2.1", Directory: "/ansible"}}
	out := filepath.Join(t.TempDir(), "ev")
	ev, err := evidence.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer ev.Close()
	env := fetch.Env{Class: class, RepoDir: repo, Scratch: t.TempDir(), HTTP: ecoutil.NewClient()}
	res, err := fetch.Run(context.Background(), env, fetch.Registry{model.UV: Fetcher{}}, ev)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("route %s, truncated %v", res.Route, res.Truncated)
	for _, f := range res.Findings {
		t.Logf("finding %s %s: %s", f.Code, f.Route, f.Detail)
	}
	for _, f := range res.Files {
		t.Logf("file %s (%d bytes)", f.Path, f.Bytes)
	}
	if b, err := os.ReadFile(filepath.Join(out, "gate", "uv-summary.md")); err == nil {
		t.Logf("summary:\n%s", b)
	}
	if res.Route != model.RouteReview {
		t.Errorf("route = %s, want review", res.Route)
	}
}

// TestEveryCopyAndArtifactValidated: duplicate [[package]] entries and
// wheels the gate does not download are all checked.
func TestEveryCopyAndArtifactValidated(t *testing.T) {
	head, err := os.ReadFile("testdata/homelab/head/uv.lock")
	if err != nil {
		t.Fatal(err)
	}
	const resolvelib = "[[package]]\nname = \"resolvelib\"\nversion = \"1.2.1\"\n"
	i := bytes.Index(head, []byte(resolvelib))
	if i < 0 {
		t.Fatal("fixture changed")
	}
	block := string(head[i:])
	dup := func(edit func(string) string) []byte {
		return append(append([]byte(nil), head...), []byte("\n"+edit(block))...)
	}
	tests := []struct {
		name string
		lock []byte
		want string
	}{
		{"shadowed duplicate off PyPI", dup(func(b string) string {
			return strings.Replace(b, "https://files.pythonhosted.org/packages/e2/23", "https://evil.example/packages/e2/23", 1)
		}), "uv.artifact-off-registry"},
		{"duplicates disagree", dup(func(b string) string {
			return strings.Replace(b, "sha256:fb06b66c", "sha256:00000000", 1)
		}), "uv.duplicate-disagrees"},
		{"duplicate from git", dup(func(b string) string {
			return strings.Replace(b, `source = { registry = "https://pypi.org/simple" }`, `source = { git = "https://github.com/evil/x" }`, 1)
		}), "uv.source-off-registry"},
		{"changed package's undownloaded sdist off PyPI", bytes.Replace(head,
			[]byte("https://files.pythonhosted.org/packages/7d/fa/3944b40b07da9ce895c0e6303a5ab7d53da063554f534556b134a54d6093/packaging-26.3.tar.gz"),
			[]byte("https://evil.example/packaging-26.3.tar.gz"), 1), "uv.artifact-off-registry"},
		{"unchanged version, one platform wheel moved", bytes.Replace(head,
			[]byte("https://files.pythonhosted.org/packages/de/94/980b50a6531b3019e45ddeada0626d45fa85cbe22300844a7983285bed3b/pyyaml"),
			[]byte("https://evil.example/pyyaml"), 1), "uv.same-version-changed"},
		{"weak hash on a changed package's other artifact", bytes.Replace(head,
			[]byte("sha256:94edc256424af38762eb31306eed28beb9f0efc50a8837492c9d6fd6004aed79"), []byte("md5:0123"), 1), "uv.weak-hash"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, class := fixtureRepo(t, func(h map[string][]byte) { h["uv.lock"] = tt.lock })
			var sum bytes.Buffer
			_, findings, err := dirChanges(context.Background(), ecoutil.Git{Repo: repo, Home: t.TempDir()}, class.BaseSHA, class.HeadSHA, "ansible", &sum)
			if err != nil {
				t.Fatal(err)
			}
			want := tt.want
			found := false
			for _, f := range findings {
				if f.Code == want {
					found = true
				}
				if f.Route != model.RouteRefuse {
					t.Errorf("%s route %s", f.Code, f.Route)
				}
			}
			if !found {
				t.Errorf("findings %+v lack %s", findings, want)
			}
		})
	}
}

func TestCrossCheckPyPI(t *testing.T) {
	b, _ := os.ReadFile("testdata/homelab/head/uv.lock")
	l, err := ParseLock(string(b))
	if err != nil {
		t.Fatal(err)
	}
	var pyyaml Package
	for _, p := range l.Packages {
		if p.Name == "pyyaml" {
			pyyaml = p
		}
	}
	win := artifactName(pyyaml.Wheels[len(pyyaml.Wheels)-1].URL) // never downloaded by the gate
	release := func(skip string, tamper string, sizeOff int64) []byte {
		var urls []map[string]any
		for _, a := range pyyaml.Artifacts() {
			name := artifactName(a.URL)
			if name == skip {
				continue
			}
			h := strings.TrimPrefix(a.Hash, "sha256:")
			if name == tamper {
				h = strings.Repeat("0", 64)
			}
			size := a.Size
			if name == win {
				size += sizeOff
			}
			urls = append(urls, map[string]any{"filename": name, "size": size, "digests": map[string]string{"sha256": h}})
		}
		out, _ := json.Marshal(map[string]any{"urls": urls})
		return out
	}
	tests := []struct {
		name string
		body []byte
		want string
	}{
		{"matches", release("", "", 0), ""},
		{"lock size understated", release("", "", 1000), "uv.hash-not-on-pypi"},
		{"PyPI gives no size", release("", "", -1<<40), "uv.hash-not-on-pypi"},
		{"lock has a file PyPI lacks", release(win, "", 0), "uv.hash-not-on-pypi"},
		{"lock hash differs from PyPI", release("", win, 0), "uv.hash-not-on-pypi"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/pypi/pyyaml/6.0.3/json" {
					http.NotFound(w, r)
					return
				}
				w.Write(tt.body)
			}))
			defer srv.Close()
			c := change{update: model.Update{Name: "pyyaml", From: "6.0.2", To: "6.0.3"}, head: pyyaml}
			fs, err := Fetcher{PyPI: srv.URL}.crossCheckPyPI(context.Background(), fetch.Env{HTTP: srv.Client()}, c)
			if err != nil {
				t.Fatal(err)
			}
			if tt.want == "" {
				if len(fs) != 0 {
					t.Errorf("findings %+v", fs)
				}
				return
			}
			if len(fs) != 1 || fs[0].Code != tt.want || fs[0].Route != model.RouteRefuse {
				t.Errorf("findings %+v, want %s refuse", fs, tt.want)
			}
		})
	}
}

func wantRefuse(t *testing.T, fs []model.Finding, code string) {
	t.Helper()
	for _, f := range fs {
		if f.Code == code {
			if f.Route != model.RouteRefuse {
				t.Errorf("%s route %s, want refuse", code, f.Route)
			}
			return
		}
	}
	t.Errorf("findings %+v lack %s", fs, code)
}

func codesOf(fs []model.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Code)
	}
	return out
}

// TestPoCDualKeySource: the review's uv.lock lists six with
// { registry = "https://evil.example/simple", editable = "." }; the gate
// took it for the project and skipped it, uv fetches it from the index.
func TestPoCDualKeySource(t *testing.T) {
	head := gittest.ReadDir(t, "testdata/poc/dualsource")
	base := map[string][]byte{"pyproject.toml": head["pyproject.toml"]}
	for name, lock := range map[string][]byte{
		"dual key":               head["uv.lock"],
		"editable, not a member": bytes.Replace(head["uv.lock"], []byte(`{ registry = "https://evil.example/simple", editable = "." }`), []byte(`{ editable = "." }`), 1),
		"virtual elsewhere":      bytes.Replace(head["uv.lock"], []byte(`{ registry = "https://evil.example/simple", editable = "." }`), []byte(`{ virtual = "vendor/six" }`), 1),
		"outside the workspace":  bytes.Replace(head["uv.lock"], []byte(`{ registry = "https://evil.example/simple", editable = "." }`), []byte(`{ editable = "../six" }`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			h := map[string][]byte{"pyproject.toml": head["pyproject.toml"], "uv.lock": lock}
			dir, b, hs := gittest.Repo(t, base, h)
			var sum bytes.Buffer
			_, findings, err := dirChanges(context.Background(), ecoutil.Git{Repo: dir, Home: t.TempDir()}, b, hs, ".", &sum)
			if err != nil {
				t.Fatal(err)
			}
			code := "uv.project-source-invalid"
			if name == "dual key" {
				code = "uv.source-ambiguous"
			}
			wantRefuse(t, findings, code)
			// Never silently skipped: it is also an off-registry package.
			wantRefuse(t, findings, "uv.source-off-registry")
		})
	}
}

func TestWorkspaceMembers(t *testing.T) {
	root := []byte("[project]\nname = \"root\"\nversion = \"0\"\n\n[tool.uv.workspace]\nmembers = [\"packages/*\"]\nexclude = [\"packages/skip\"]\n")
	member := func(name string) []byte { return []byte("[project]\nname = \"" + name + "\"\nversion = \"1\"\n") }
	lock := func(pkgs ...string) []byte {
		s := "version = 1\nrevision = 3\n\n[[package]]\nname = \"root\"\nversion = \"0\"\nsource = { virtual = \".\" }\n"
		for _, p := range pkgs {
			s += "\n" + p
		}
		return []byte(s)
	}
	files := map[string][]byte{"pyproject.toml": root, "packages/a/pyproject.toml": member("a"), "packages/skip/pyproject.toml": member("skip")}
	tests := []struct {
		name string
		pkg  string
		want string
	}{
		{"declared member", "[[package]]\nname = \"a\"\nversion = \"1\"\nsource = { editable = \"packages/a\" }\n", ""},
		{"excluded member", "[[package]]\nname = \"skip\"\nversion = \"1\"\nsource = { editable = \"packages/skip\" }\n", "uv.project-source-invalid"},
		{"member named differently", "[[package]]\nname = \"evil\"\nversion = \"1\"\nsource = { editable = \"packages/a\" }\n", "uv.project-source-invalid"},
		{"no pyproject there", "[[package]]\nname = \"b\"\nversion = \"1\"\nsource = { editable = \"packages/b\" }\n", "uv.project-source-invalid"},
		{"root name taken", "[[package]]\nname = \"evil\"\nversion = \"1\"\nsource = { virtual = \".\" }\n", "uv.project-source-invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := maps.Clone(files)
			base["uv.lock"] = lock()
			head := maps.Clone(files)
			head["uv.lock"] = lock(tt.pkg)
			dir, b, h := gittest.Repo(t, base, head)
			var sum bytes.Buffer
			_, findings, err := dirChanges(context.Background(), ecoutil.Git{Repo: dir, Home: t.TempDir()}, b, h, ".", &sum)
			if err != nil {
				t.Fatal(err)
			}
			if tt.want == "" {
				if len(findings) != 0 {
					t.Errorf("findings %+v", findings)
				}
				return
			}
			wantRefuse(t, findings, tt.want)
		})
	}
}

func TestManifestChanges(t *testing.T) {
	base, err := os.ReadFile("testdata/homelab/base/pyproject.toml")
	if err != nil {
		t.Fatal(err)
	}
	declared := []model.Update{{Name: "ansible-core", From: "2.21.6", To: "2.21.7", Directory: "/ansible"}}
	bump := strings.Replace(string(base), `"ansible-core==2.21.6"`, `"ansible-core==2.21.7"`, 1)
	tests := []struct {
		name     string
		head     string
		declared []model.Update
		want     string
	}{
		{"unchanged", string(base), nil, ""},
		{"declared bump", bump, declared, ""},
		{"undeclared bump", bump, []model.Update{{Name: "ansible", To: "2.21.7"}}, "uv.manifest-changed"},
		{"other version", strings.Replace(bump, "2.21.7", "2.21.8", 1), declared, "uv.manifest-changed"},
		{"operator changed", strings.Replace(string(base), `"ansible-core==2.21.6"`, `"ansible-core>=2.21.7"`, 1), declared, "uv.manifest-changed"},
		{"marker added", strings.Replace(string(base), `"ansible-core==2.21.6"`, `"ansible-core==2.21.7; sys_platform == 'linux'"`, 1), declared, "uv.manifest-changed"},
		{"requirement added", strings.Replace(bump, `"ansible==14.6.0",`, `"ansible==14.6.0", "evil",`, 1), declared, "uv.manifest-changed"},
		{"index added", bump + "\n[[tool.uv.index]]\nurl = \"https://evil.example/simple\"\ndefault = true\n", declared, "uv.manifest-changed"},
		{"source added", bump + "\n[tool.uv.sources]\nansible = { git = \"https://github.com/evil/ansible\" }\n", declared, "uv.manifest-changed"},
		{"package flipped", strings.Replace(bump, "package = false", "package = true", 1), declared, "uv.manifest-changed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, b, h := gittest.Repo(t, map[string][]byte{"ansible/pyproject.toml": base}, map[string][]byte{"ansible/pyproject.toml": []byte(tt.head)})
			fs, err := manifestChanges(context.Background(), ecoutil.Git{Repo: dir, Home: t.TempDir()}, b, h, "ansible", tt.declared)
			if err != nil {
				t.Fatal(err)
			}
			if tt.want == "" {
				if len(fs) != 0 {
					t.Errorf("findings %+v", fs)
				}
				return
			}
			wantRefuse(t, fs, tt.want)
		})
	}
}

// TestPoCBuildSystem: the review's pyproject.toml adds an attacker build
// backend and a default index with uv.lock unchanged.
func TestPoCBuildSystem(t *testing.T) {
	base := gittest.ReadDir(t, "testdata/poc/buildsystem/base")
	head := gittest.ReadDir(t, "testdata/poc/buildsystem/head")
	if !bytes.Equal(base["uv.lock"], head["uv.lock"]) {
		t.Fatal("fixture: the lock must not change")
	}
	dir, b, h := gittest.Repo(t, base, head)
	fs, err := manifestChanges(context.Background(), ecoutil.Git{Repo: dir, Home: t.TempDir()}, b, h, ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	var details []string
	for _, f := range fs {
		details = append(details, f.Detail)
	}
	for _, want := range []string{"[build-system.requires]", "[tool.uv.index]"} {
		if !strings.Contains(strings.Join(details, "\n"), want) {
			t.Errorf("findings %q do not name %s", details, want)
		}
	}
	wantRefuse(t, fs, "uv.manifest-changed")
}

// TestCompiledAndBinaryFiles: .pyc (the review's unchecked-hash one), and
// binaries anywhere, including tests/ and testdata/.
func TestCompiledAndBinaryFiles(t *testing.T) {
	pyc, err := os.ReadFile("testdata/poc/pyc/mod.cpython-315.pyc")
	if err != nil {
		t.Fatal(err)
	}
	md := "Metadata-Version: 2.4\nName: p\nVersion: 1.0\n"
	old := zipTree(t, map[string]string{"p/__init__.py": "", "p-1.0.dist-info/METADATA": md, "tests/data.bin": "\x00\x01"})
	cur := zipTree(t, map[string]string{"p/__init__.py": "", "p-1.0.dist-info/METADATA": md, "tests/data.bin": "\x00\x01",
		"p/__pycache__/mod.cpython-315.pyc": string(pyc), "testdata/blob.bin": "\x00\x02\x03", "tests/tool": "\x7fELF\x02\x01"})
	fs := checkPackage(sideTrees{wheel: old}, sideTrees{wheel: cur})
	got := codesOf(fs)
	slices.Sort(got)
	if !slices.Equal(got, []string{"uv.binary-file", "uv.compiled-bytecode"}) {
		t.Fatalf("codes = %q", got)
	}
	for _, f := range fs {
		if f.Route != model.RouteHuman {
			t.Errorf("%s route %s", f.Code, f.Route)
		}
		switch f.Code {
		case "uv.compiled-bytecode":
			if !strings.Contains(f.Detail, "unchecked-hash") {
				t.Errorf("detail %q does not name the unchecked-hash pyc", f.Detail)
			}
		case "uv.binary-file":
			if !strings.Contains(f.Detail, "testdata/blob.bin") || !strings.Contains(f.Detail, "tests/tool") || strings.Contains(f.Detail, "tests/data.bin") {
				t.Errorf("detail %q", f.Detail)
			}
		}
	}
}

// TestPoCWheelVariants: the review's three wheels of demo 1.0. The gate
// diffed only the py3-none-any one; uv on macOS or Linux installs a
// platform wheel with different code.
func TestPoCWheelVariants(t *testing.T) {
	names := []string{"demo-1.0-py3-none-any.whl", "demo-1.0-py3-none-macosx_11_0_arm64.whl", "demo-1.0-py3-none-manylinux_2_17_x86_64.whl"}
	files := map[string][]byte{}
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join("testdata/poc/wheels", n))
		if err != nil {
			t.Fatal(err)
		}
		files[n] = b
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := files[filepath.Base(r.URL.Path)]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	defer srv.Close()
	p := Package{Name: "demo", Version: "1.0", Source: map[string]string{"registry": pypiRegistry}}
	for _, n := range names {
		sum := sha256.Sum256(files[n])
		p.Wheels = append(p.Wheels, Artifact{URL: srv.URL + "/" + n, Hash: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(files[n]))})
	}
	out := filepath.Join(t.TempDir(), "ev")
	ev, err := evidence.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer ev.Close()
	env := fetch.Env{Scratch: t.TempDir(), Evidence: ev, HTTP: srv.Client()}
	c := change{update: model.Update{Name: "demo", To: "1.0", Directory: "/"}, head: p}
	var sum bytes.Buffer
	fs, err := Fetcher{AllowHost: strings.TrimPrefix(srv.URL, "http://")}.verifyAndDiff(context.Background(), env, t.TempDir(), filepath.Join(env.Scratch, "w"), c, &sum)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range fs {
		if f.Code == "uv.wheel-variant-differs" {
			n++
			if f.Route != model.RouteHuman || !strings.Contains(f.Detail, "demo/__init__.py") {
				t.Errorf("finding %+v", f)
			}
		}
	}
	if n != 2 {
		t.Errorf("findings %+v: want uv.wheel-variant-differs for both platform wheels", fs)
	}
	variants := 0
	for _, f := range ev.Files() {
		if strings.HasSuffix(f.Path, ".variant.diff") {
			variants++
			if !f.Untrusted {
				t.Errorf("%s is not untrusted", f.Path)
			}
		}
	}
	if variants != 2 {
		t.Errorf("evidence %+v: want two variant diffs", ev.Files())
	}
}

// TestArtifactCapCountsDownloads: the cap on further artifacts trusts no
// size from the lock. A missing size stops before any download; an
// understated one is caught by counting the bytes that arrive.
func TestArtifactCapCountsDownloads(t *testing.T) {
	names := []string{"demo-1.0-py3-none-any.whl", "demo-1.0-py3-none-macosx_11_0_arm64.whl", "demo-1.0-py3-none-manylinux_2_17_x86_64.whl"}
	files := map[string][]byte{}
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join("testdata/poc/wheels", n))
		if err != nil {
			t.Fatal(err)
		}
		files[n] = b
	}
	old := maxArtifactsBytes
	maxArtifactsBytes = int64(len(files[names[1]])) + 10 // room for one further wheel
	defer func() { maxArtifactsBytes = old }()
	tests := []struct {
		name      string
		size      func(n string) int64
		wantCode  bool
		downloads int // of the further wheels
	}{
		{"declared sizes honest", func(n string) int64 { return int64(len(files[n])) }, true, 0}, // declared total already over the cap
		{"declared sizes understated", func(string) int64 { return 1 }, true, 2},
		{"size missing", func(n string) int64 {
			if n == names[2] {
				return 0
			}
			return 1
		}, true, 0},
		{"one further wheel fits", func(string) int64 { return 1 }, false, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wheels := names
			if !tt.wantCode {
				wheels = names[:2]
			}
			var mu sync.Mutex
			got := map[string]int{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				got[filepath.Base(r.URL.Path)]++
				mu.Unlock()
				w.Write(files[filepath.Base(r.URL.Path)])
			}))
			defer srv.Close()
			p := Package{Name: "demo", Version: "1.0", Source: map[string]string{"registry": pypiRegistry}}
			for _, n := range wheels {
				sum := sha256.Sum256(files[n])
				p.Wheels = append(p.Wheels, Artifact{URL: srv.URL + "/" + n, Hash: "sha256:" + hex.EncodeToString(sum[:]), Size: tt.size(n)})
			}
			ev, err := evidence.Create(filepath.Join(t.TempDir(), "ev"))
			if err != nil {
				t.Fatal(err)
			}
			defer ev.Close()
			env := fetch.Env{Scratch: t.TempDir(), Evidence: ev, HTTP: srv.Client()}
			c := change{update: model.Update{Name: "demo", To: "1.0", Directory: "/"}, head: p}
			var sum bytes.Buffer
			fs, err := Fetcher{AllowHost: strings.TrimPrefix(srv.URL, "http://")}.verifyAndDiff(context.Background(), env, t.TempDir(), filepath.Join(env.Scratch, "w"), c, &sum)
			if err != nil {
				t.Fatal(err)
			}
			if has := slices.Contains(codesOf(fs), "uv.not-verified"); has != tt.wantCode {
				t.Errorf("codes %q: uv.not-verified %v, want %v", codesOf(fs), has, tt.wantCode)
			}
			further := got[names[1]] + got[names[2]]
			if further != tt.downloads {
				t.Errorf("further wheels downloaded %d times, want %d (%v)", further, tt.downloads, got)
			}
		})
	}
}

// TestPoCRoute runs the review's PoCs through fetch.Run end to end: the
// route is refuse, for the gate's own reason, and not a job error.
func TestPoCRoute(t *testing.T) {
	dual := gittest.ReadDir(t, "testdata/poc/dualsource")
	tests := []struct {
		name       string
		base, head map[string][]byte
		declared   []model.Update
		code       string
		network    bool
	}{
		{"buildsystem", gittest.ReadDir(t, "testdata/poc/buildsystem/base"), gittest.ReadDir(t, "testdata/poc/buildsystem/head"), nil, "uv.manifest-changed", false},
		{"dualsource", map[string][]byte{"pyproject.toml": dual["pyproject.toml"]}, dual, []model.Update{{Name: "six", To: "1.16.0"}}, "uv.source-ambiguous", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.network && testing.Short() {
				t.Skip("network")
			}
			dir, b, h := gittest.Repo(t, tt.base, tt.head)
			class := model.Classification{Repo: "test/poc", PR: 1, BaseSHA: b, HeadSHA: h, Kind: model.KindDependabot, Ecosystem: model.UV, Declared: tt.declared}
			ev, err := evidence.Create(filepath.Join(t.TempDir(), "ev"))
			if err != nil {
				t.Fatal(err)
			}
			defer ev.Close()
			env := fetch.Env{Class: class, RepoDir: dir, Scratch: t.TempDir(), HTTP: ecoutil.NewClient()}
			res, err := fetch.Run(context.Background(), env, fetch.Registry{model.UV: Fetcher{}}, ev)
			if err != nil {
				t.Fatal(err)
			}
			if res.Route != model.RouteRefuse {
				t.Errorf("route = %s", res.Route)
			}
			wantRefuse(t, res.Findings, tt.code)
		})
	}
}

package uv

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
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
		if p.IsProject() {
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

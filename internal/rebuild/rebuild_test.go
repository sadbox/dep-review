package rebuild

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/model"
)

const okLock = `{"name":"a","lockfileVersion":3,"packages":{"":{"name":"a"},
"node_modules/x":{"version":"1.0.0","resolved":"https://registry.npmjs.org/x/-/x-1.0.0.tgz","integrity":"sha512-AAAA"},
"node_modules/@s/y":{"version":"2.0.0","resolved":"https://registry.npmjs.org/@s/y/-/y-2.0.0.tgz","integrity":"sha512-BBBB"},
"node_modules/@s/y/node_modules/z":{"version":"1.0.0","inBundle":true}}}`

const okPkg = `{"name":"a","scripts":{"test":"jest","package":"ncc build","build":"tsc"}}`

func TestScripts(t *testing.T) {
	if _, err := Scripts([]byte(`{"scripts":{"build":"x"},"dependencies":{"a":"^1.2.3","b":">=1 <2 || 3.x","c":"npm:@s/y@~2.0.0","d":"latest"}}`), []byte(okLock)); err != nil {
		t.Errorf("registry specs: %v", err)
	}
	got, err := Scripts([]byte(okPkg), []byte(okLock))
	if err != nil || !slices.Equal(got, []string{"build", "package"}) {
		t.Fatalf("Scripts = %v, %v", got, err)
	}
	for name, c := range map[string]struct{ pkg, lock string }{
		"git dependency":     {okPkg, strings.Replace(okLock, "https://registry.npmjs.org/x/-/x-1.0.0.tgz", "git+ssh://git@github.com/x/x.git#abc", 1)},
		"other registry":     {okPkg, strings.Replace(okLock, "registry.npmjs.org/x", "registry.example.com/x", 1)},
		"no integrity":       {okPkg, strings.Replace(okLock, `"integrity":"sha512-AAAA"`, `"integrity":"sha1-AAAA"`, 1)},
		"lockfile v1":        {okPkg, strings.Replace(okLock, `"lockfileVersion":3`, `"lockfileVersion":1`, 1)},
		"link":               {okPkg, strings.Replace(okLock, `"node_modules/x":{`, `"node_modules/x":{"link":true,`, 1)},
		"workspace entry":    {okPkg, strings.Replace(okLock, `"node_modules/x":{`, `"packages/w":{"version":"1.0.0"},"node_modules/x":{`, 1)},
		"workspaces":         {`{"workspaces":["packages/*"],"scripts":{"build":"tsc"}}`, okLock},
		"no build script":    {`{"scripts":{"test":"jest"}}`, okLock},
		"duplicate key":      {`{"scripts":{"build":"tsc"},"scripts":{"build":"evil"}}`, okLock},
		"traversal":          {okPkg, strings.Replace(okLock, "x/-/x-1.0.0.tgz", "x/-/../../evil.tgz", 1)},
		"http dependency":    {`{"scripts":{"build":"x"},"dependencies":{"a":"http://evil.example/a.tgz"}}`, okLock},
		"github dependency":  {`{"scripts":{"build":"x"},"devDependencies":{"a":"github:o/r#0123"}}`, okLock},
		"shorthand":          {`{"scripts":{"build":"x"},"dependencies":{"a":"o/r"}}`, okLock},
		"file dependency":    {`{"scripts":{"build":"x"},"optionalDependencies":{"a":"file:../a"}}`, okLock},
		"overrides":          {`{"scripts":{"build":"x"},"overrides":{"a":"1.0.0"}}`, okLock},
		"alias to a URL":     {`{"scripts":{"build":"x"},"dependencies":{"a":"npm:b@http://x/b.tgz"}}`, okLock},
		"lock entry dep URL": {okPkg, strings.Replace(okLock, `"node_modules/x":{`, `"node_modules/x":{"dependencies":{"q":"https://evil.example/q.tgz"},`, 1)},
		"top-level inBundle": {okPkg, strings.Replace(okLock, `"node_modules/x":{"version":"1.0.0","resolved":"https://registry.npmjs.org/x/-/x-1.0.0.tgz","integrity":"sha512-AAAA"}`, `"node_modules/x":{"version":"1.0.0","inBundle":true}`, 1)},
		"inBundle resolved":  {okPkg, strings.Replace(okLock, `"inBundle":true}`, `"inBundle":true,"resolved":"https://evil.example/z.tgz"}`, 1)},
	} {
		if _, err := Scripts([]byte(c.pkg), []byte(c.lock)); !errors.As(err, new(ErrNotRebuildable)) {
			t.Errorf("%s: Scripts error %v, want not rebuildable", name, err)
		}
	}
}

func file(p, data string) model.RebuildFile {
	s := sha256.Sum256([]byte(data))
	return model.RebuildFile{Path: p, SHA256: hex.EncodeToString(s[:]), Size: int64(len(data))}
}

func TestCheckPlan(t *testing.T) {
	ok := model.RebuildPlan{Update: "o/r", Repo: "o/r", Commit: strings.Repeat("a", 40), Node: 24, Scripts: []string{"build"},
		Dirs: []string{"dist/a", "dist/b"}, Files: []model.RebuildFile{file("dist/a/index.js", "x")}}
	if err := CheckPlan(ok); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*model.RebuildPlan){
		"repo":         func(p *model.RebuildPlan) { p.Repo = "o/../r" },
		"repo shape":   func(p *model.RebuildPlan) { p.Repo = "o/r/x" },
		"commit":       func(p *model.RebuildPlan) { p.Commit = "HEAD" },
		"node":         func(p *model.RebuildPlan) { p.Node = 18 },
		"script":       func(p *model.RebuildPlan) { p.Scripts = []string{"build; curl x"} },
		"overlap":      func(p *model.RebuildPlan) { p.Dirs = []string{"dist", "dist/a"} },
		"dir dotdot":   func(p *model.RebuildPlan) { p.Dirs = []string{"dist/../src"} },
		"dir option":   func(p *model.RebuildPlan) { p.Dirs = []string{"--to-command=x"} },
		"outside":      func(p *model.RebuildPlan) { p.Files = []model.RebuildFile{file("src/index.js", "x")} },
		"duplicate":    func(p *model.RebuildPlan) { p.Files = append(p.Files, p.Files[0]) },
		"no files":     func(p *model.RebuildPlan) { p.Files = nil },
		"bad sha":      func(p *model.RebuildPlan) { p.Files[0].SHA256 = "x" },
		"too large":    func(p *model.RebuildPlan) { p.Files[0].Size = MaxBundleSize + 1 },
		"many scripts": func(p *model.RebuildPlan) { p.Scripts = []string{"build", "package", "bundle", "release"} },
	} {
		p := ok
		p.Files = slices.Clone(ok.Files)
		mut(&p)
		if CheckPlan(p) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// upstream makes a repository at base/o/r with files and returns its head.
func upstream(t *testing.T, base string, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(base, "o", "r")
	for p, data := range files {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q")
	run("add", "-A")
	run("commit", "-q", "-m", "x")
	return run("rev-parse", "HEAD")
}

func tarFiles(t *testing.T, entries ...*tar.Header) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, h := range entries {
		data := h.Linkname
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(data))
			h.Linkname = ""
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	// What GNU tar does: pad to a whole 10240-byte record.
	if pad := (10240 - b.Len()%10240) % 10240; pad > 0 {
		b.Write(make([]byte, pad))
	}
	return b.Bytes()
}

// reg is a regular file entry whose content is data (carried in Linkname
// until tarFiles writes it).
func reg(name, data string) *tar.Header {
	return &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Linkname: data}
}

// names lists a tar stream's entries, reading concatenated archives the
// way the build container's `tar -i` does.
func names(t *testing.T, r io.Reader) map[string]string {
	t.Helper()
	br := bufio.NewReader(r)
	out := map[string]string{}
	for {
		tr := tar.NewReader(br)
		read := 0
		for {
			h, err := tr.Next()
			if err != nil {
				break
			}
			b, _ := io.ReadAll(tr)
			out[h.Name] = string(b)
			read++
		}
		if read == 0 {
			return out
		}
	}
}

type fake struct {
	t           *testing.T
	installIn   map[string]string
	buildIn     map[string]string
	args        [][]string
	out         []byte
	buildErr    error
	builds      int
	failInstall bool
}

func (f *fake) run(ctx context.Context, name string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	f.args = append(f.args, args)
	if strings.HasPrefix(name, "dep-review-install-") {
		f.installIn = names(f.t, stdin)
		if f.failInstall {
			return errors.New("exit status 1")
		}
		_, err := stdout.Write(tarFiles(f.t, reg("node_modules/x/index.js", "module.exports=1")))
		return err
	}
	f.builds++
	f.buildIn = names(f.t, stdin)
	if f.buildErr != nil {
		return f.buildErr
	}
	_, err := stdout.Write(f.out)
	return err
}

// registry serves fixed tarballs for registry.npmjs.org URLs.
type registry map[string][]byte

func (r registry) RoundTrip(req *http.Request) (*http.Response, error) {
	data, ok := r[req.URL.String()]
	if !ok {
		return &http.Response{StatusCode: 404, Status: "404 Not Found", Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
	}
	return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(data)), Request: req}, nil
}

func integrity(data []byte) string {
	s := sha512.Sum512(data)
	return "sha512-" + base64.StdEncoding.EncodeToString(s[:])
}

// realLock is okLock with the registry's real digests.
func realLock(reg registry) string {
	l := okLock
	l = strings.Replace(l, "sha512-AAAA", integrity(reg["https://registry.npmjs.org/x/-/x-1.0.0.tgz"]), 1)
	return strings.Replace(l, "sha512-BBBB", integrity(reg["https://registry.npmjs.org/@s/y/-/y-2.0.0.tgz"]), 1)
}

func setup(t *testing.T) (Config, model.RebuildPlan, *fake) {
	base := t.TempDir()
	reg := registry{"https://registry.npmjs.org/x/-/x-1.0.0.tgz": []byte("tarball x"), "https://registry.npmjs.org/@s/y/-/y-2.0.0.tgz": []byte("tarball y")}
	head := upstream(t, base, map[string]string{
		"package.json":         okPkg,
		"package-lock.json":    realLock(reg),
		"src/index.ts":         "export const a = 1",
		".npmrc":               "registry=https://evil.example/",
		"dist/a/index.js":      "built a",
		"dist/a/package.json":  "{}",
		"dist/b/index.js":      "built b",
		"dist/other/notes.txt": "not a bundle dir",
	})
	f := &fake{t: t}
	cfg := Config{CloneBase: "file://" + base + "/", Work: t.TempDir(), Runtime: "runsc", Images: map[int]string{24: "img24"}, container: f.run, HTTP: &http.Client{Transport: reg}}
	p := model.RebuildPlan{Update: "o/r", Repo: "o/r", Commit: head, Node: 24, Scripts: []string{"build", "package"}, Dirs: []string{"dist/a", "dist/b"},
		Files: []model.RebuildFile{file("dist/a/index.js", "built a"), file("dist/a/package.json", "{}"), file("dist/b/index.js", "built b")}}
	return cfg, p, f
}

func TestRunVerified(t *testing.T) {
	cfg, p, f := setup(t)
	f.out = tarFiles(t, &tar.Header{Name: "dist/a/", Typeflag: tar.TypeDir, Mode: 0o755}, reg("dist/a/index.js", "built a"), reg("dist/a/package.json", "{}"), reg("dist/b/index.js", "built b"))
	r := Run(context.Background(), cfg, []model.RebuildPlan{p})
	if len(r) != 1 || r[0].Outcome != model.RebuildVerified || r[0].Script != "build" || r[0].Commit != p.Commit {
		t.Fatalf("results %+v", r)
	}
	// The install sees only the two npm files; the build sees the tree
	// without the bundle directories (but with other dist/ files), and
	// the installed modules.
	if len(f.installIn) != 4 || f.installIn["package.json"] != okPkg || !slices.Contains(slices.Collect(maps.Values(f.installIn)), "tarball x") {
		t.Errorf("install input %v", slices.Sorted(mapKeys(f.installIn)))
	}
	for _, want := range []string{"package.json", "src/index.ts", ".npmrc", "dist/other/notes.txt", "node_modules/x/index.js"} {
		if _, ok := f.buildIn[want]; !ok {
			t.Errorf("build input lacks %s: %v", want, slices.Sorted(mapKeys(f.buildIn)))
		}
	}
	for n := range f.buildIn {
		if Under(n, p.Dirs) {
			t.Errorf("build input has the committed bundle file %s", n)
		}
	}
	install, build := strings.Join(f.args[0], " "), strings.Join(f.args[1], " ")
	for _, a := range []string{"--runtime runsc", "--cap-drop ALL", "--read-only", "--security-opt no-new-privileges", "--user 1000:1000", "--pids-limit"} {
		if !strings.Contains(install, a) || !strings.Contains(build, a) {
			t.Errorf("a container lacks %q", a)
		}
	}
	if !strings.Contains(install, "--network none") || !strings.Contains(install, "--ignore-scripts") || !strings.Contains(install, "--offline") || !strings.Contains(build, "--network none") {
		t.Errorf("networks or scripts: install %q build %q", install, build)
	}
	if !strings.HasSuffix(build, "sh build dist/a dist/b") {
		t.Errorf("build args %q", build)
	}
}

func TestRunDiffers(t *testing.T) {
	cfg, p, f := setup(t)
	f.out = tarFiles(t, reg("dist/a/index.js", "evil a"), reg("dist/a/package.json", "{}"), reg("dist/b/index.js", "built b"), reg("dist/b/extra.js", "x"))
	r := Run(context.Background(), cfg, []model.RebuildPlan{p})[0]
	if r.Outcome != model.RebuildDiffers || f.builds != 2 || !strings.Contains(r.Detail, "dist/a/index.js") || !strings.Contains(r.Detail, "dist/b/extra.js") {
		t.Fatalf("result %+v after %d builds", r, f.builds)
	}
}

func TestRunRejectsOutput(t *testing.T) {
	for name, out := range map[string][]*tar.Header{
		"symlink":    {{Name: "dist/a/index.js", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}},
		"outside":    {reg("src/x.js", "x")},
		"traversal":  {reg("dist/a/../../x", "x")},
		"absolute":   {reg("/dist/a/index.js", "x")},
		"duplicate":  {reg("dist/a/index.js", "built a"), reg("dist/a/index.js", "built a")},
		"hard link":  {{Name: "dist/a/index.js", Typeflag: tar.TypeLink, Linkname: "dist/b/index.js"}},
		"device":     {{Name: "dist/a/index.js", Typeflag: tar.TypeChar}},
		"dir escape": {{Name: "src/", Typeflag: tar.TypeDir}},
	} {
		cfg, p, f := setup(t)
		f.out = tarFiles(t, out...)
		if r := Run(context.Background(), cfg, []model.RebuildPlan{p})[0]; r.Outcome != model.RebuildDiffers {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

func TestRunTrailingOutput(t *testing.T) {
	cfg, p, f := setup(t)
	f.out = append(tarFiles(t, reg("dist/a/index.js", "built a"), reg("dist/a/package.json", "{}"), reg("dist/b/index.js", "built b")), bytes.Repeat([]byte("x"), maxTrailer+1)...)
	if r := Run(context.Background(), cfg, []model.RebuildPlan{p})[0]; r.Outcome == model.RebuildVerified {
		t.Errorf("verified with %d bytes after the archive: %+v", maxTrailer+1, r)
	}
}

func TestRunFailures(t *testing.T) {
	cfg, p, f := setup(t)
	f.buildErr = errors.New("exit status 2")
	if r := Run(context.Background(), cfg, []model.RebuildPlan{p})[0]; r.Outcome != model.RebuildFailed || f.builds != 2 {
		t.Errorf("failed builds: %+v", r)
	}
	cfg, p, f = setup(t)
	f.failInstall = true
	if r := Run(context.Background(), cfg, []model.RebuildPlan{p})[0]; r.Outcome != model.RebuildFailed || f.builds != 0 {
		t.Errorf("failed install: %+v", r)
	}
	cfg, p, f = setup(t)
	p.Files = p.Files[:2]
	if r := Run(context.Background(), cfg, []model.RebuildPlan{p})[0]; r.Outcome != model.RebuildFailed || f.builds != 0 || !strings.Contains(r.Detail, "fetch listed") {
		t.Errorf("plan not the commit's: %+v", r)
	}
	cfg, p, f = setup(t)
	p.Commit = strings.Repeat("b", 40)
	if r := Run(context.Background(), cfg, []model.RebuildPlan{p})[0]; r.Outcome != model.RebuildFailed || len(f.args) != 0 {
		t.Errorf("missing commit: %+v", r)
	}
	cfg, p, _ = setup(t)
	delete(cfg.Images, 24)
	if r := Run(context.Background(), cfg, []model.RebuildPlan{p})[0]; r.Outcome != model.RebuildFailed {
		t.Errorf("no image: %+v", r)
	}
}

func TestRunTarballChecks(t *testing.T) {
	cfg, p, f := setup(t)
	reg := cfg.HTTP.Transport.(registry)
	reg["https://registry.npmjs.org/x/-/x-1.0.0.tgz"] = []byte("tampered")
	if r := Run(context.Background(), cfg, []model.RebuildPlan{p})[0]; r.Outcome != model.RebuildFailed || len(f.args) != 0 || !strings.Contains(r.Detail, "sha512") {
		t.Errorf("tampered tarball: %+v", r)
	}
	cfg, p, f = setup(t)
	delete(cfg.HTTP.Transport.(registry), "https://registry.npmjs.org/@s/y/-/y-2.0.0.tgz")
	if r := Run(context.Background(), cfg, []model.RebuildPlan{p})[0]; r.Outcome != model.RebuildFailed || len(f.args) != 0 {
		t.Errorf("missing tarball: %+v", r)
	}
	if c := registryClient(); c.CheckRedirect(&http.Request{URL: &url.URL{Scheme: "https", Host: "evil.example"}}, nil) == nil {
		t.Error("the registry client follows a redirect off the registry")
	}
}

func TestReadBundleCaps(t *testing.T) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	_ = tw.WriteHeader(&tar.Header{Name: "dist/a/big", Typeflag: tar.TypeReg, Size: MaxOutput + 1})
	if _, err := readBundle(&b, []string{"dist/a"}); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("oversized: %v", err)
	}
}

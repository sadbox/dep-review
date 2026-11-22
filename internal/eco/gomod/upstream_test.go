package gomod

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
	modzip "golang.org/x/mod/zip"

	"github.com/sadbox/dep-review/internal/model"
)

func TestPlanUpstream(t *testing.T) {
	h1, h2 := strings.Repeat("a", 40), strings.Repeat("b", 40)
	o := func(url, sub, hash string) *Origin { return &Origin{VCS: "git", URL: url, Subdir: sub, Hash: hash} }
	u := model.Update{Name: "example.com/m", From: "v1.0.0", To: "v1.1.0"}
	tests := []struct {
		name     string
		u        model.Update
		from, to *Origin
		ok       bool
	}{
		{"github", u, o("https://github.com/o/r", "", h1), o("https://github.com/o/r", "", h2), true},
		{"googlesource subdir", u, o("https://go.googlesource.com/x", "sub/dir", h1), o("https://go.googlesource.com/x", "sub/dir", h2), true},
		{"new module", model.Update{Name: "example.com/m", To: "v1.0.0"}, nil, o("https://github.com/o/r", "", h2), false},
		{"no origin", u, nil, o("https://github.com/o/r", "", h2), false},
		{"other vcs", u, &Origin{VCS: "hg", URL: "https://github.com/o/r", Hash: h1}, o("https://github.com/o/r", "", h2), false},
		{"moved repository", u, o("https://github.com/o/r", "", h1), o("https://github.com/o/s", "", h2), false},
		{"moved subdir", u, o("https://github.com/o/r", "a", h1), o("https://github.com/o/r", "b", h2), false},
		{"short hash", u, o("https://github.com/o/r", "", "abc"), o("https://github.com/o/r", "", h2), false},
		{"host off the list", u, o("https://git.example.com/o/r", "", h1), o("https://git.example.com/o/r", "", h2), false},
		{"http", u, o("http://github.com/o/r", "", h1), o("http://github.com/o/r", "", h2), false},
		{"userinfo", u, o("https://x:y@github.com/o/r", "", h1), o("https://x:y@github.com/o/r", "", h2), false},
		{"port", u, o("https://github.com:8443/o/r", "", h1), o("https://github.com:8443/o/r", "", h2), false},
		{"query", u, o("https://github.com/o/r?x=1", "", h1), o("https://github.com/o/r?x=1", "", h2), false},
		{"look-alike host", u, o("https://github.com.evil.example/o/r", "", h1), o("https://github.com.evil.example/o/r", "", h2), false},
		{"dotdot subdir", u, o("https://github.com/o/r", "../x", h1), o("https://github.com/o/r", "../x", h2), false},
		{"absolute subdir", u, o("https://github.com/o/r", "/x", h1), o("https://github.com/o/r", "/x", h2), false},
		{"option-like subdir", u, o("https://github.com/o/r", "-x", h1), o("https://github.com/o/r", "-x", h2), false},
		{"option-like subdir element", u, o("https://github.com/o/r", "a/--output=x", h1), o("https://github.com/o/r", "a/--output=x", h2), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, why := planUpstream(tt.u, Downloaded{Origin: tt.from}, Downloaded{Origin: tt.to})
			if (why == "") != tt.ok {
				t.Errorf("why = %q, want ok=%v", why, tt.ok)
			}
		})
	}
}

func TestModuleFiles(t *testing.T) {
	raw := "sub/a.go\x00other/b.go\x00sub/t\u00e9st.go\x00sub/ lead.go\x00LICENSE\x00"
	if got := moduleFiles([]byte(raw), "sub"); !slices.Equal(got, []string{"a.go", "tést.go", " lead.go", "LICENSE"}) {
		t.Errorf("files = %q", got)
	}
	if got := moduleFiles([]byte("a.go\x00p/b.go\x00"), ""); !slices.Equal(got, []string{"a.go", "p/b.go"}) {
		t.Errorf("root files = %q", got)
	}
}

// gitRepo makes a repository with a module in sub/ at two tagged commits
// and an unrelated commit between them, returning its URL and hashes.
func gitRepo(t *testing.T) (url, from, mid, to string) {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull,
			"GIT_AUTHOR_NAME=a", "GIT_AUTHOR_EMAIL=a@example.com", "GIT_COMMITTER_NAME=a", "GIT_COMMITTER_EMAIL=a@example.com")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(rel, s string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("init", "-q", "-b", "main")
	write("LICENSE", "license\n")
	write("sub/go.mod", "module example.com/r/sub\n\ngo 1.24\n")
	write("sub/a.go", "package sub\n\nfunc init() {}\n")
	write("sub/p/b.go", "package p\n")
	run("add", "-A")
	run("commit", "-q", "-m", "v1")
	from = run("rev-parse", "HEAD")
	write("README", "unrelated\n")
	write("sub/p/b.go", "package p\n\nvar X = 1\n")
	run("add", "-A")
	run("commit", "-q", "-m", "p: add X")
	mid = run("rev-parse", "HEAD")
	write("sub/a.go", "package sub\n\nfunc init() { println(1) }\n")
	run("add", "-A")
	run("commit", "-q", "-m", "sub: print at init")
	to = run("rev-parse", "HEAD")
	return "file://" + dir, from, mid, to
}

// moduleSum is the go.sum hash of the module at rev, built the way the
// gate checks it (the proxy builds it with the go command).
func moduleSum(t *testing.T, url, rev, ver string) string {
	t.Helper()
	repo := strings.TrimPrefix(url, "file://")
	wt := t.TempDir()
	if out, err := exec.Command("git", "clone", "-q", repo, wt).CombinedOutput(); err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	zf := filepath.Join(t.TempDir(), "m.zip")
	f, err := os.Create(zf)
	if err != nil {
		t.Fatal(err)
	}
	if err := modzip.CreateFromVCS(f, module.Version{Path: "example.com/r/sub", Version: ver}, wt, rev, "sub"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	h, err := dirhash.HashZip(zf, dirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestRunUpstream(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	url, from, mid, to := gitRepo(t)
	fromSum, toSum := moduleSum(t, url, from, "v1.0.0"), moduleSum(t, url, to, "v1.1.0")
	git, _ := exec.LookPath("git")
	req := func(fs, ts string) upstreamRequest {
		return upstreamRequest{Git: git, Dir: t.TempDir(), URL: url, Subdir: "sub", From: from, To: to,
			Module: "example.com/r/sub", FromVer: "v1.0.0", ToVer: "v1.1.0", FromSum: fs, ToSum: ts,
			PATH: os.Getenv("PATH"), Protocols: "file"}
	}
	r := runUpstream(req(fromSum, toSum), false)
	if r.Status != model.UpstreamVerified {
		t.Fatalf("status %s: %s", r.Status, r.Detail)
	}
	if len(r.Commits) != 2 || r.Commits[0].Hash != to || r.Commits[1].Hash != mid {
		t.Fatalf("commits %+v", r.Commits)
	}
	if !slices.Equal(r.Commits[1].Files, []string{"p/b.go"}) {
		t.Errorf("mid files %q (README is outside the module)", r.Commits[1].Files)
	}

	// Each item gets the commits that touched its file or package.
	items := []model.FlaggedItem{
		{Update: "k", Code: codeInit, Item: "a.go"},
		{Update: "k", Code: codeInitCallee, Item: "p/X"},
		{Update: "k", Code: codeImport, Item: "a.go (os)"},
		{Update: "k", Code: codeNewlyBuilt, Item: "untouched.go"},
	}
	has := func(p string) bool { return p == "a.go" || p == "p/b.go" || p == "untouched.go" }
	up, md := attachUpstream("k", r, items, has, []string{"a.go", "p/b.go"})
	want := map[string][]string{"a.go": {to}, "p/X": {mid}, "a.go (os)": {to}}
	if len(up.Items) != len(want) {
		t.Fatalf("items %+v", up.Items)
	}
	for _, it := range up.Items {
		if !slices.Equal(it.Commits, want[it.Item]) {
			t.Errorf("%s: commits %q, want %q", it.Item, it.Commits, want[it.Item])
		}
	}
	if !strings.Contains(string(md), "untouched.go: no commit") || !strings.Contains(string(md), "sub: print at init") {
		t.Errorf("upstream.md:\n%s", md)
	}

	// A flagged file that changed with no commit touching it: the history
	// does not explain the change, so nothing is attached.
	for _, changed := range [][]string{{"a.go", "untouched.go"}, {"p/c.go"}} {
		if up, _ := attachUpstream("k", r, items, has, changed); up.Status != model.UpstreamUnavailable {
			t.Errorf("unexplained change %q: status %s", changed, up.Status)
		}
	}

	// A zip that is not what go.sum says: the update goes to a person.
	for _, bad := range [][2]string{{fromSum, "h1:AAAA"}, {"h1:AAAA", toSum}} {
		if r := runUpstream(req(bad[0], bad[1]), false); r.Status != model.UpstreamMismatch {
			t.Errorf("wrong sum %q: status %s (%s)", bad, r.Status, r.Detail)
		}
	}
	// A commit the repository does not have: nothing attached.
	bad := req(fromSum, toSum)
	bad.To = strings.Repeat("d", 40)
	if r := runUpstream(bad, false); r.Status != model.UpstreamUnavailable {
		t.Errorf("unknown commit: status %s", r.Status)
	}
	// https only in production: a file URL is refused.
	https := req(fromSum, toSum)
	https.Protocols = "https"
	if r := runUpstream(https, false); r.Status != model.UpstreamUnavailable {
		t.Errorf("file URL under https only: status %s", r.Status)
	}
	// Commit text cannot hide a commit: a record separator in a message
	// or an author name is just text.
	sneaky := filepath.Join(t.TempDir(), "sneaky")
	if out, err := exec.Command("git", "clone", "-q", strings.TrimPrefix(url, "file://"), sneaky).CombinedOutput(); err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	commit := func(author, msg, file, text string) string {
		if err := os.WriteFile(filepath.Join(sneaky, file), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		env := append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull,
			"GIT_AUTHOR_NAME="+author, "GIT_AUTHOR_EMAIL=a@example.com", "GIT_COMMITTER_NAME=a", "GIT_COMMITTER_EMAIL=a@example.com")
		for _, args := range [][]string{{"add", "-A"}, {"commit", "-q", "--cleanup=verbatim", "-m", msg}} {
			cmd := exec.Command("git", append([]string{"-C", sneaky}, args...)...)
			cmd.Env = env
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v %s", args, err, out)
			}
		}
		out, _ := exec.Command("git", "-C", sneaky, "rev-parse", "HEAD").Output()
		return strings.TrimSpace(string(out))
	}
	c1 := commit("a\x1eb", "one\x1e", "sub/a.go", "package sub\n\nfunc init() { println(2) }\n")
	c2 := commit("a", "two\x1e"+strings.Repeat("0", 40), "sub/p/b.go", "package p\n\nvar X = 2\n")
	sr := req(fromSum, moduleSum(t, "file://"+sneaky, c2, "v1.1.0"))
	sr.URL, sr.To = "file://"+sneaky, c2
	got := runUpstream(sr, false)
	var hs []string
	for _, c := range got.Commits {
		hs = append(hs, c.Hash)
	}
	if got.Status != model.UpstreamVerified || !slices.Equal(hs, []string{c2, c1, to, mid}) {
		t.Errorf("record separators: status %s, commits %q, want %q", got.Status, hs, []string{c2, c1, to, mid})
	}

	// A second update from the same repository reuses its clone.
	shared := req(fromSum, toSum)
	for i := range 2 {
		if r := runUpstream(shared, false); r.Status != model.UpstreamVerified {
			t.Errorf("run %d in a shared directory: status %s (%s)", i, r.Status, r.Detail)
		}
	}
	// Past the commit budget: nothing attached.
	defer func(n int) { maxUpstreamCommits = n }(maxUpstreamCommits)
	maxUpstreamCommits = 1
	if r := runUpstream(req(fromSum, toSum), false); r.Status != model.UpstreamUnavailable {
		t.Errorf("over budget: status %s", r.Status)
	}
}

// A change made in a merge commit (not in either parent) is listed under
// the merge.
func TestUpstreamMergeChange(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	dir := t.TempDir()
	run := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull,
			"GIT_AUTHOR_NAME=a", "GIT_AUTHOR_EMAIL=a@example.com", "GIT_COMMITTER_NAME=a", "GIT_COMMITTER_EMAIL=a@example.com")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(rel, s string) {
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("init", "-q", "-b", "main")
	write("go.mod", "module example.com/r\n\ngo 1.24\n")
	write("a.go", "package r\n")
	write("c.go", "package r\n")
	run("add", "-A")
	run("commit", "-q", "-m", "v1")
	from := run("rev-parse", "HEAD")
	run("switch", "-q", "-c", "side")
	write("c.go", "package r\n\nvar C = 1\n")
	run("commit", "-q", "-am", "side: C")
	run("switch", "-q", "main")
	run("merge", "-q", "--no-ff", "--no-commit", "side")
	write("a.go", "package r\n\nfunc init() { println(1) }\n")
	run("add", "-A")
	run("commit", "-q", "-m", "Merge branch side")
	to := run("rev-parse", "HEAD")
	url := "file://" + dir
	git, _ := exec.LookPath("git")
	sum := func(rev, ver string) string {
		wt := t.TempDir()
		if out, err := exec.Command("git", "clone", "-q", dir, wt).CombinedOutput(); err != nil {
			t.Fatalf("clone: %v %s", err, out)
		}
		zf := filepath.Join(t.TempDir(), "m.zip")
		f, _ := os.Create(zf)
		if err := modzip.CreateFromVCS(f, module.Version{Path: "example.com/r", Version: ver}, wt, rev, ""); err != nil {
			t.Fatal(err)
		}
		f.Close()
		h, _ := dirhash.HashZip(zf, dirhash.Hash1)
		return h
	}
	r := runUpstream(upstreamRequest{Git: git, Dir: t.TempDir(), URL: url, From: from, To: to, Module: "example.com/r",
		FromVer: "v1.0.0", ToVer: "v1.1.0", FromSum: sum(from, "v1.0.0"), ToSum: sum(to, "v1.1.0"),
		PATH: os.Getenv("PATH"), Protocols: "file"}, false)
	if r.Status != model.UpstreamVerified {
		t.Fatalf("status %s: %s", r.Status, r.Detail)
	}
	if len(r.Commits) == 0 || r.Commits[0].Hash != to || !slices.Contains(r.Commits[0].Files, "a.go") {
		t.Errorf("the merge's own change to a.go is not listed under it: %+v", r.Commits)
	}
}

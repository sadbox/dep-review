package gather

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/facts"
)

// testRepoAt is a repository built for one test: a base commit on main, a
// branch with the pull request's commit, and main moved on since.
type testRepoAt struct {
	dir string
	// fork is where the branch left main, tip is main now, head is the
	// branch.
	fork, tip, head string
	env             []string
}

// git runs git in the repository with nothing of this machine's
// configuration: no signing, no hooks, no identity but the one given.
func (r *testRepoAt) git(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.dir
	cmd.Env = r.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r *testRepoAt) write(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	full := filepath.Join(r.dir, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(full, mode); err != nil {
		t.Fatal(err)
	}
}

func newTestRepo(t *testing.T) *testRepoAt {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	r := &testRepoAt{dir: t.TempDir()}
	r.env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com", "GIT_AUTHOR_DATE=2026-11-01T00:00:00Z",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com", "GIT_COMMITTER_DATE=2026-11-01T00:00:00Z",
	}
	r.git(t, "init", "-q", "-b", "main")

	r.write(t, "go.mod", "module example.com/app\n\nrequire example.com/m v1.2.3\n", 0o644)
	r.write(t, "go.sum", "example.com/m v1.2.3 h1:old=\n", 0o644)
	r.write(t, "script.sh", "#!/bin/sh\n", 0o755)
	r.write(t, "old.txt", "going away\n", 0o644)
	r.write(t, "README.md", "one\n", 0o644)
	r.git(t, "add", "-A")
	r.git(t, "commit", "-q", "-m", "base")
	r.fork = r.git(t, "rev-parse", "HEAD")

	r.git(t, "checkout", "-q", "-b", "dependabot/go_modules/example.com/m-1.3.0")
	r.write(t, "go.mod", "module example.com/app\n\nrequire example.com/m v1.3.0\n", 0o644)
	r.write(t, "go.sum", "example.com/m v1.3.0 h1:new=\n", 0o644)
	r.write(t, "script.sh", "#!/bin/sh\n", 0o644) // the mode alone
	r.write(t, "empty.txt", "", 0o644)
	r.write(t, "dir/with space/café.txt", "a name git would quote\n", 0o644)
	if err := os.Remove(filepath.Join(r.dir, "old.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("go.mod", filepath.Join(r.dir, "link")); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}
	r.git(t, "add", "-A")
	// A submodule entry: a commit of another repository, with no object
	// in this one.
	r.git(t, "update-index", "--add", "--cacheinfo", "160000,"+strings.Repeat("9", 40)+",vendor/sub")
	r.git(t, "commit", "-q", "-m", "bump")
	r.head = r.git(t, "rev-parse", "HEAD")

	r.git(t, "checkout", "-q", "-f", "main")
	r.write(t, "README.md", "two\n", 0o644)
	r.git(t, "add", "-A")
	r.git(t, "commit", "-q", "-m", "main moves on")
	r.tip = r.git(t, "rev-parse", "HEAD")
	return r
}

// The change set is the paths that differ between the merge base and the
// head, with git's modes and the blobs' own bytes.
func TestReadChanges(t *testing.T) {
	r := newTestRepo(t)
	// Everything a repository's configuration and attributes could have
	// git run for a file, each wired to leave a mark. Set up after the
	// commits, which would run them too. The "#" swallows the arguments
	// git appends, so a run leaves the one mark and nothing in the
	// working directory.
	marker := filepath.Join(t.TempDir(), "ran")
	mark := "touch " + marker + " #"
	for _, kv := range [][2]string{
		{"filter.mark.clean", mark}, {"filter.mark.smudge", mark},
		{"diff.mark.textconv", mark}, {"diff.external", mark}, {"core.fsmonitor", mark},
		{"core.pager", mark}, {"alias.cat-file", "!" + mark},
	} {
		r.git(t, "config", kv[0], kv[1])
	}
	if err := os.WriteFile(filepath.Join(r.dir, ".git", "info", "attributes"), []byte("* filter=mark diff=mark\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, hook := range []string{"post-index-change", "reference-transaction", "post-checkout"} {
		if err := os.WriteFile(filepath.Join(r.dir, ".git", "hooks", hook), []byte("#!/bin/sh\n"+mark+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The working tree is not what is read: main is checked out, and this
	// is not committed anywhere.
	r.write(t, "go.mod", "module example.com/evil\n", 0o644)

	got, err := ReadChanges(context.Background(), r.dir, r.tip, r.head)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Error("reading the change set ran something the repository configures")
	}
	// Relative to where the branch left main, not to main's tip: README.md
	// changed on main and is not the pull request's.
	if got.Base != r.fork || got.Head != r.head || got.Refused != "" {
		t.Errorf("base %s head %s refused %q, want base %s head %s", got.Base, got.Head, got.Refused, r.fork, r.head)
	}
	want := []facts.File{
		{Path: "dir/with space/café.txt", HeadMode: "100644", Head: []byte("a name git would quote\n")},
		// Empty is not absent: the mode says which.
		{Path: "empty.txt", HeadMode: "100644", Head: []byte{}},
		{Path: "go.mod", BaseMode: "100644", HeadMode: "100644",
			Base: []byte("module example.com/app\n\nrequire example.com/m v1.2.3\n"),
			Head: []byte("module example.com/app\n\nrequire example.com/m v1.3.0\n")},
		{Path: "go.sum", BaseMode: "100644", HeadMode: "100644",
			Base: []byte("example.com/m v1.2.3 h1:old=\n"), Head: []byte("example.com/m v1.3.0 h1:new=\n")},
		// A symbolic link's blob is its target.
		{Path: "link", HeadMode: "120000", Head: []byte("go.mod")},
		{Path: "old.txt", BaseMode: "100644", Base: []byte("going away\n")},
		{Path: "script.sh", BaseMode: "100755", HeadMode: "100644", Base: []byte("#!/bin/sh\n"), Head: []byte("#!/bin/sh\n")},
		// A submodule has a mode and nothing to read.
		{Path: "vendor/sub", HeadMode: "160000"},
	}
	if !reflect.DeepEqual(got.Files, want) {
		for _, f := range got.Files {
			t.Logf("got %q base %s %q head %s %q", f.Path, f.BaseMode, f.Base, f.HeadMode, f.Head)
		}
		t.Errorf("files differ from the %d wanted", len(want))
	}

	// A pull request that changes nothing has no files and is not refused.
	same, err := ReadChanges(context.Background(), r.dir, r.head, r.head)
	if err != nil || len(same.Files) != 0 || same.Refused != "" || same.Base != r.head {
		t.Errorf("no change: %+v, %v", same, err)
	}
}

// A change set over the limits is refused, in the gate's words, without
// an error: it becomes a Shape that does not hold.
func TestReadChangesRefused(t *testing.T) {
	r := newTestRepo(t)
	roomy := changeLimits{files: 100, blob: 1 << 20, total: 1 << 20}
	for _, tc := range []struct {
		name   string
		change func(*changeLimits)
		want   string
	}{
		{"too many paths", func(l *changeLimits) { l.files = 7 }, "the pull request changes 8 paths, more than 7"},
		{"too many paths to list", func(l *changeLimits) { l.files = 0 }, "the pull request changes more than 0 paths"},
		{"one file too large", func(l *changeLimits) { l.blob = 40 }, "a changed file is more than 40 bytes"},
		{"too much together", func(l *changeLimits) { l.total = 100 }, "the changed files are more than 100 bytes together"},
	} {
		lim := roomy
		tc.change(&lim)
		got, err := readChanges(context.Background(), r.dir, r.tip, r.head, lim)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got.Refused != tc.want || len(got.Files) != 0 || got.Base != r.fork {
			t.Errorf("%s: refused %q with %d files, want %q", tc.name, got.Refused, len(got.Files), tc.want)
		}
	}
	if got, err := readChanges(context.Background(), r.dir, r.tip, r.head, roomy); err != nil || got.Refused != "" || len(got.Files) != 8 {
		t.Errorf("within the limits: %d files, refused %q, %v", len(got.Files), got.Refused, err)
	}
}

// A checkout that cannot be read is an error: there is nothing to gather
// from.
func TestReadChangesErrors(t *testing.T) {
	r := newTestRepo(t)
	absent := strings.Repeat("e", 40)
	for _, tc := range []struct {
		name            string
		dir, base, head string
	}{
		{"a short base", r.dir, "abc123", r.head},
		{"a branch name for the head", r.dir, r.tip, "main"},
		{"an option for the head", r.dir, r.tip, "--output=/tmp/x"},
		{"a head that is not in the checkout", r.dir, r.tip, absent},
		{"a base that is not in the checkout", r.dir, absent, r.head},
		{"not a repository", t.TempDir(), r.tip, r.head},
	} {
		if got, err := ReadChanges(context.Background(), tc.dir, tc.base, tc.head); err == nil {
			t.Errorf("%s: no error, %d files", tc.name, len(got.Files))
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReadChanges(ctx, r.dir, r.tip, r.head); err == nil {
		t.Error("a context that ended: no error")
	}
}

// The records git prints, and what is not one.
func TestParseRaw(t *testing.T) {
	a, b := strings.Repeat("a", 40), strings.Repeat("b", 40)
	zero := strings.Repeat("0", 40)
	good := ":100644 100755 " + a + " " + b + " M\x00go.mod\x00" +
		":000000 120000 " + zero + " " + b + " A\x00dir/new link\x00" +
		":160000 000000 " + a + " " + zero + " D\x00sub\x00"
	got, err := parseRaw([]byte(good))
	want := []record{
		{path: "go.mod", baseMode: "100644", headMode: "100755", baseObject: a, headObject: b},
		{path: "dir/new link", headMode: "120000", baseObject: zero, headObject: b},
		{path: "sub", baseMode: "160000", baseObject: a, headObject: zero},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("parseRaw: %+v, %v", got, err)
	}
	if got, err := parseRaw(nil); err != nil || got != nil {
		t.Errorf("no output: %+v, %v", got, err)
	}
	for name, raw := range map[string]string{
		"a rename":           ":100644 100644 " + a + " " + b + " R100\x00old\x00new\x00",
		"abbreviated IDs":    ":100644 100644 aaaaaaa bbbbbbb M\x00go.mod\x00",
		"no path":            ":100644 100644 " + a + " " + b + " M\x00",
		"an empty path":      ":100644 100644 " + a + " " + b + " M\x00\x00",
		"a line, not a NUL":  ":100644 100644 " + a + " " + b + " M\tgo.mod\n",
		"something else":     "fatal: bad object\x00x\x00",
		"an unmerged status": ":100644 100644 " + a + " " + b + " U\x00go.mod\x00",
	} {
		if got, err := parseRaw([]byte(raw)); err == nil {
			t.Errorf("%s: parsed as %+v", name, got)
		}
	}
}

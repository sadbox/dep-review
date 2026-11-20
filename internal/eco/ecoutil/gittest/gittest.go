// Package gittest builds throwaway git repositories for fetcher tests.
package gittest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Repo creates a repository with two commits: base (the files in base) and
// head (base's files replaced/extended by head; a nil value deletes the
// file). It returns the directory and both commit SHAs.
func Repo(t testing.TB, base, head map[string][]byte) (dir, baseSHA, headSHA string) {
	t.Helper()
	dir = t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "commit.gpgsign=false", "-c", "user.name=test", "-c", "user.email=test@example.invalid"}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(files map[string][]byte) {
		for name, data := range files {
			p := filepath.Join(dir, filepath.FromSlash(name))
			if data == nil {
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				continue
			}
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	git("init", "-q", "-b", "main")
	write(base)
	git("add", "-A")
	git("commit", "-q", "--allow-empty", "-m", "base")
	baseSHA = git("rev-parse", "HEAD")
	write(head)
	git("add", "-A")
	git("commit", "-q", "--allow-empty", "-m", "head")
	headSHA = git("rev-parse", "HEAD")
	return dir, baseSHA, headSHA
}

// ReadDir loads every file under dir (fixtures) keyed by slash path.
func ReadDir(t testing.TB, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		out[filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

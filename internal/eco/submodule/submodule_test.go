package submodule

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/model"
)

func TestGitlinkUpdates(t *testing.T) {
	a := strings.Repeat("a", 40)
	b := strings.Repeat("b", 40)
	tests := []struct {
		name string
		raw  string
		want int
	}{
		{"gitlink", ":160000 160000 " + a + " " + b + " M\x00vendor/lib\x00", 1},
		{"regular file", ":100644 100644 " + a + " " + b + " M\x00README.md\x00", 0},
		{"new submodule", ":000000 160000 " + strings.Repeat("0", 40) + " " + b + " A\x00x\x00", 0},
		{"empty", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := gitlinkUpdates([]byte(tt.raw))
			if len(got) != tt.want {
				t.Fatalf("got %d updates, want %d: %+v", len(got), tt.want, got)
			}
			if tt.want == 1 && (got[0].Name != "vendor/lib" || got[0].FromRef != a || got[0].ToRef != b || got[0].Type != model.Digest) {
				t.Fatalf("bad update %+v", got[0])
			}
		})
	}
}

func TestFetchAlwaysHuman(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q")
	run("commit", "-q", "--allow-empty", "-m", "base")
	sub := strings.Repeat("c", 40)
	run("update-index", "--add", "--cacheinfo", "160000,"+sub+",lib")
	run("commit", "-q", "-m", "add")
	mid := run("rev-parse", "HEAD")
	sub2 := strings.Repeat("d", 40)
	run("update-index", "--cacheinfo", "160000,"+sub2+",lib")
	run("commit", "-q", "-m", "bump")
	head := run("rev-parse", "HEAD")

	res, err := New().Fetch(context.Background(), fetch.Env{
		Class:   model.Classification{BaseSHA: mid, HeadSHA: head},
		RepoDir: dir,
		Scratch: filepath.Join(dir, "scratch"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Route != model.RouteHuman || res.Findings[0].Detail != "git submodule updates are reviewed by a human" {
		t.Fatalf("findings = %+v", res.Findings)
	}
	if len(res.Updates) != 1 || res.Updates[0].FromRef != sub || res.Updates[0].ToRef != sub2 {
		t.Fatalf("updates = %+v", res.Updates)
	}
}

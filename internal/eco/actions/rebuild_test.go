package actions

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func rebuildRepo(t *testing.T, files map[string]string) (git, string) {
	t.Helper()
	dir := t.TempDir()
	for p, data := range files {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "-A"}, {"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "x"}} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return git{bin: "git", dir: dir}, strings.TrimSpace(string(out))
}

const rbLock = `{"lockfileVersion":3,"packages":{"":{},"node_modules/x":{"version":"1.0.0","resolved":"https://registry.npmjs.org/x/-/x-1.0.0.tgz","integrity":"sha512-AA"}}}`

func TestPlanRebuild(t *testing.T) {
	base := map[string]string{
		"package.json":        `{"scripts":{"build":"tsc && ncc build"}}`,
		"package-lock.json":   rbLock,
		"src/main.ts":         "x",
		"dist/setup/index.js": "a",
		"dist/setup/x.js":     "b",
		"dist/post/index.js":  "c",
		"dist/other/index.js": "d",
	}
	g, head := rebuildRepo(t, base)
	p := &pair{owner: "actions", repo: "setup-go", newRef: head}
	plan, why, err := planRebuild(context.Background(), g, p, []string{"dist/setup/index.js", "dist/post/index.js"}, []string{"node24"})
	if err != nil || plan == nil {
		t.Fatalf("plan %v, %q, %v", plan, why, err)
	}
	var paths []string
	for _, f := range plan.Files {
		paths = append(paths, f.Path)
	}
	if plan.Node != 24 || !slices.Equal(plan.Dirs, []string{"dist/post", "dist/setup"}) || !slices.Equal(paths, []string{"dist/post/index.js", "dist/setup/index.js", "dist/setup/x.js"}) || plan.Commit != head || !slices.Equal(plan.Scripts, []string{"build"}) {
		t.Errorf("plan %+v", plan)
	}

	for name, c := range map[string]struct {
		files   map[string]string
		entries []string
		usings  []string
		want    string
	}{
		"node16":       {base, []string{"dist/setup/index.js"}, []string{"node16"}, "no rebuild image"},
		"mixed nodes":  {base, []string{"dist/setup/index.js"}, []string{"node20", "node24"}, "different Node"},
		"composite":    {base, []string{"dist/setup/index.js"}, []string{"composite"}, "nodeNN"},
		"root entry":   {base, []string{"index.js"}, []string{"node24"}, "bundle directory"},
		"no lock":      {map[string]string{"package.json": `{"scripts":{"build":"x"}}`, "dist/a/i.js": "a"}, []string{"dist/a/i.js"}, []string{"node24"}, "package-lock.json"},
		"git dep":      {map[string]string{"package.json": `{"scripts":{"build":"x"}}`, "package-lock.json": strings.Replace(rbLock, "https://registry.npmjs.org/x/-/x-1.0.0.tgz", "git+https://github.com/x/x.git", 1), "dist/a/i.js": "a"}, []string{"dist/a/i.js"}, []string{"node24"}, "registry.npmjs.org"},
		"odd filename": {map[string]string{"package.json": `{"scripts":{"build":"x"}}`, "package-lock.json": rbLock, "dist/a/i.js": "a", "dist/a/$(x).js": "b"}, []string{"dist/a/i.js"}, []string{"node24"}, "not one the gate passes"},
	} {
		g, head := rebuildRepo(t, c.files)
		plan, why, err := planRebuild(context.Background(), g, &pair{owner: "o", repo: "r", newRef: head}, c.entries, c.usings)
		if err != nil || plan != nil || !strings.Contains(why, c.want) {
			t.Errorf("%s: plan %v, why %q, err %v", name, plan, why, err)
		}
	}
}

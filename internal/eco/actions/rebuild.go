package actions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/rebuild"
)

// planRebuild is the rebuild job's plan for p's new commit (see package
// rebuild), or why the gate cannot rebuild it. entries are the action.yml
// entrypoints of every subpath used, usings their runs.using.
func planRebuild(ctx context.Context, up git, p *pair, entries, usings []string) (*model.RebuildPlan, string, error) {
	node := 0
	for _, u := range usings {
		n, err := strconv.Atoi(strings.TrimPrefix(u, "node"))
		switch {
		case !strings.HasPrefix(u, "node") || err != nil:
			return nil, "runs.using is not nodeNN", nil
		case node != 0 && n != node:
			return nil, "the subpaths used run on different Node versions", nil
		}
		node = n
	}
	if node == 0 || !slices.Contains(rebuild.Nodes, node) {
		return nil, fmt.Sprintf("there is no rebuild image for Node %d", node), nil
	}
	var dirs []string
	for _, e := range entries {
		d := path.Dir(e)
		if d == "." || !rebuild.CleanPath(d) {
			return nil, "an entrypoint is not inside a bundle directory", nil
		}
		dirs = append(dirs, d)
	}
	if len(dirs) == 0 {
		return nil, "no entrypoints", nil
	}
	// The outermost directories only; sorted, a parent precedes its children.
	slices.Sort(dirs)
	var outer []string
	for _, d := range slices.Compact(dirs) {
		if !rebuild.Under(d, outer) {
			outer = append(outer, d)
		}
	}
	pkg, err := up.show(ctx, p.newRef, "package.json")
	if errors.Is(err, errMissing) {
		return nil, "no package.json at the repository root", nil
	}
	if err != nil {
		return nil, "", err
	}
	lock, err := up.show(ctx, p.newRef, "package-lock.json")
	if errors.Is(err, errMissing) {
		return nil, "no package-lock.json at the repository root", nil
	}
	if err != nil {
		return nil, "", err
	}
	scripts, err := rebuild.Scripts(pkg, lock)
	var nr rebuild.ErrNotRebuildable
	if errors.As(err, &nr) {
		return nil, nr.Why, nil
	}
	if err != nil {
		return nil, "", err
	}
	out, err := up.run(ctx, "ls-tree", "-r", "-z", "--full-tree", p.newRef)
	if err != nil {
		return nil, "", err
	}
	plan := &model.RebuildPlan{Update: p.name(), Repo: p.name(), Commit: p.newRef, Node: node, Scripts: scripts, Dirs: outer}
	var total int64
	for _, rec := range strings.Split(string(out), "\x00") {
		meta, rel, ok := strings.Cut(rec, "\t")
		f := strings.Fields(meta)
		if rec == "" {
			continue
		}
		if !ok || len(f) != 3 {
			return nil, "", errors.New("unexpected ls-tree output")
		}
		if f[1] == "commit" {
			return nil, "the repository has submodules", nil
		}
		if !rebuild.Under(rel, outer) {
			continue
		}
		if !rebuild.CleanPath(rel) {
			return nil, "a bundle file's name is not one the gate passes to a build", nil
		}
		if f[1] != "blob" || (f[0] != "100644" && f[0] != "100755") {
			return nil, fmt.Sprintf("%s is not a regular file", safePath(rel)), nil
		}
		if len(plan.Files) == rebuild.MaxFiles {
			return nil, "the bundle directories hold too many files", nil
		}
		data, err := up.run(ctx, "cat-file", "blob", f[2])
		if err != nil {
			return nil, "", err
		}
		total += int64(len(data))
		if total > rebuild.MaxBundleSize {
			return nil, "the bundle directories are too large", nil
		}
		sum := sha256.Sum256(data)
		plan.Files = append(plan.Files, model.RebuildFile{Path: rel, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))})
	}
	if err := rebuild.CheckPlan(*plan); err != nil {
		return nil, "the plan is not one the rebuild job accepts: " + err.Error(), nil
	}
	return plan, "", nil
}

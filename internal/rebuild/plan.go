// Package rebuild rebuilds a GitHub Action's committed bundle from its
// source and compares the result byte for byte (gate.yml, job rebuild).
//
// The build runs the action's own code, so it runs in two containers
// under gVisor, and nothing it produces is executed or trusted on the
// host:
//
//   - install: package.json, package-lock.json and every tarball the
//     lockfile pins, which the gate downloads from registry.npmjs.org
//     and checks against its sha512 first; `npm ci --offline
//     --ignore-scripts` with no network. Every dependency spec, in
//     package.json and the lockfile, must be a registry version (no git,
//     URL, file or link), and anything the lockfile does not pin fails
//     for want of a network.
//   - build: the commit's tree without its bundle directories, plus the
//     installed node_modules, `npm run <script>` with no network. Its
//     only output is a tar of the bundle directories on stdout, read
//     with caps: regular files only, inside those directories.
//
// A match shows that the committed bundle is what the commit's source,
// lockfile and build script produce. It does not show that they are
// benign: a build-only package (a compiler, a bundler plugin) is in no
// bundle diff the reviewer reads, and the build may copy any file of the
// tree. So a result is information for the people and the reviewer, and
// never relaxes a route by itself.
package rebuild

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/strictjson"
)

// Nodes are the Node majors the rebuild job has an image for
// (sandbox/rebuild/Dockerfile, one stage per major).
var Nodes = []int{20, 22, 24}

// CandidateScripts are the package.json scripts tried, in this order.
// The first that reproduces every file wins; at most MaxAttempts run.
var CandidateScripts = []string{"build", "package", "bundle", "release"}

// MaxAttempts bounds the builds per plan.
const MaxAttempts = 3

// Caps on what a plan covers.
const (
	MaxFiles      = 2000
	MaxBundleSize = 100 << 20 // the committed bundle directories' total size
)

var (
	repoRe   = regexp.MustCompile(`^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$`)
	commitRe = regexp.MustCompile(`^[0-9a-f]{40}$`)
	shaRe    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// A path the build's shell and tar receive as an argument.
	pathRe = regexp.MustCompile(`^[A-Za-z0-9._@+-]+(/[A-Za-z0-9._@+-]+)*$`)
	// The canonical registry tarball URL npm writes into a lockfile.
	resolvedRe = regexp.MustCompile(`^https://registry\.npmjs\.org/(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9._~-]+/-/[A-Za-z0-9._~-]+\.tgz$`)
)

// CleanPath reports whether p is a plain relative path inside the tree.
func CleanPath(p string) bool {
	if !pathRe.MatchString(p) || path.Clean(p) != p {
		return false
	}
	for _, e := range strings.Split(p, "/") {
		if e == "." || e == ".." {
			return false
		}
	}
	return true
}

// Under reports whether p is inside one of dirs.
func Under(p string, dirs []string) bool {
	for _, d := range dirs {
		if strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// CheckPlan validates a plan read from the evidence before anything acts
// on it.
func CheckPlan(p model.RebuildPlan) error {
	switch {
	case !repoRe.MatchString(p.Repo) || strings.Contains(p.Repo, ".."):
		return fmt.Errorf("repository %q", p.Repo)
	case !commitRe.MatchString(p.Commit):
		return fmt.Errorf("commit %q", p.Commit)
	case !slices.Contains(Nodes, p.Node):
		return fmt.Errorf("node %d has no image", p.Node)
	case len(p.Scripts) == 0 || len(p.Scripts) > MaxAttempts:
		return errors.New("scripts")
	case len(p.Dirs) == 0 || len(p.Files) == 0 || len(p.Files) > MaxFiles:
		return errors.New("dirs or files")
	}
	for _, s := range p.Scripts {
		if !slices.Contains(CandidateScripts, s) {
			return fmt.Errorf("script %q", s)
		}
	}
	for i, d := range p.Dirs {
		if !CleanPath(d) {
			return fmt.Errorf("dir %q", d)
		}
		for j, e := range p.Dirs {
			if i != j && (d == e || strings.HasPrefix(d, e+"/")) {
				return fmt.Errorf("dir %q overlaps %q", d, e)
			}
		}
	}
	seen := map[string]bool{}
	var total int64
	for _, f := range p.Files {
		if !CleanPath(f.Path) || !Under(f.Path, p.Dirs) || seen[f.Path] || !shaRe.MatchString(f.SHA256) || f.Size < 0 {
			return fmt.Errorf("file %q", f.Path)
		}
		seen[f.Path] = true
		total += f.Size
	}
	if total > MaxBundleSize {
		return errors.New("bundle too large")
	}
	return nil
}

// ErrNotRebuildable says why an action cannot be rebuilt by the gate.
type ErrNotRebuildable struct{ Why string }

func (e ErrNotRebuildable) Error() string { return e.Why }

func notRebuildable(format string, args ...any) error {
	return ErrNotRebuildable{fmt.Sprintf(format, args...)}
}

// Scripts checks package.json and package-lock.json at the root of the
// action's repository and returns the build scripts to try. Only a plain
// npm project is rebuilt: lockfile version 2 or 3, no workspaces, and
// every package from the public registry with sha512 integrity (npm
// verifies each tarball against it). Anything else is not rebuildable.
func Scripts(pkgJSON, lock []byte) ([]string, error) {
	var pj struct {
		Scripts    map[string]string `json:"scripts"`
		Workspaces json.RawMessage   `json:"workspaces"`
		Overrides  json.RawMessage   `json:"overrides"`
		deps
	}
	if err := strictjson.Unmarshal(pkgJSON, &pj); err != nil {
		return nil, notRebuildable("package.json could not be read strictly")
	}
	if len(pj.Workspaces) > 0 && !bytes.Equal(bytes.TrimSpace(pj.Workspaces), []byte("null")) {
		return nil, notRebuildable("package.json declares workspaces")
	}
	if len(pj.Overrides) > 0 && !bytes.Equal(bytes.TrimSpace(pj.Overrides), []byte("null")) {
		return nil, notRebuildable("package.json declares overrides")
	}
	if !pj.registryOnly() {
		return nil, notRebuildable("package.json names a dependency that is not a registry version (git, URL, file or link)")
	}
	var lf struct {
		LockfileVersion int `json:"lockfileVersion"`
		Packages        map[string]struct {
			Resolved  string `json:"resolved"`
			Integrity string `json:"integrity"`
			Link      bool   `json:"link"`
			InBundle  bool   `json:"inBundle"`
			deps
		} `json:"packages"`
	}
	if err := strictjson.Unmarshal(lock, &lf); err != nil {
		return nil, notRebuildable("package-lock.json could not be read strictly")
	}
	if lf.LockfileVersion != 2 && lf.LockfileVersion != 3 {
		return nil, notRebuildable("package-lock.json is lockfile version %d (2 or 3 is rebuilt)", lf.LockfileVersion)
	}
	if _, ok := lf.Packages[""]; !ok {
		return nil, notRebuildable("package-lock.json has no root package")
	}
	for k, e := range lf.Packages {
		if !e.registryOnly() {
			return nil, notRebuildable("package-lock.json names a dependency that is not a registry version")
		}
		switch {
		case k == "":
		case !strings.HasPrefix(k, "node_modules/") && !strings.Contains(k, "/node_modules/"):
			return nil, notRebuildable("package-lock.json has a workspace or linked package")
		case e.Link:
			return nil, notRebuildable("package-lock.json links a package")
		case e.InBundle && strings.Contains(k, "/node_modules/") && e.Resolved == "" && e.Integrity == "":
			// Shipped inside its parent's tarball, which integrity covers;
			// npm fetches nothing for it.
		case !resolvedRe.MatchString(e.Resolved) || !strings.HasPrefix(e.Integrity, "sha512-"):
			return nil, notRebuildable("a locked package is not a registry.npmjs.org tarball with sha512 integrity")
		}
	}
	var out []string
	for _, s := range CandidateScripts {
		if _, ok := pj.Scripts[s]; ok && len(out) < MaxAttempts {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, notRebuildable("package.json has none of the scripts %s", strings.Join(CandidateScripts, ", "))
	}
	return out, nil
}

// deps are the dependency maps of package.json and of a lockfile entry.
type deps struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

var (
	// A semver range or a dist-tag: no ":", "/", "#" or "@", so no git,
	// URL, file, link or GitHub shorthand.
	rangeRe = regexp.MustCompile(`^[0-9A-Za-z.*^~<>=|_+ -]*$`)
	nameRe  = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9._~-]+$`)
)

// registrySpec reports whether a dependency spec can only be resolved
// from the registry: a range or tag, or an npm: alias of one.
func registrySpec(s string) bool {
	// npm reads ".", "..", "./x" and "x.tgz" as a directory or a file.
	l := strings.ToLower(strings.TrimSpace(s))
	if strings.HasPrefix(l, ".") || strings.HasSuffix(l, ".tgz") || strings.HasSuffix(l, ".tar") || strings.HasSuffix(l, ".tar.gz") {
		return false
	}
	if rest, ok := strings.CutPrefix(s, "npm:"); ok {
		i := strings.LastIndex(rest, "@")
		if i <= 0 {
			return nameRe.MatchString(rest)
		}
		return nameRe.MatchString(rest[:i]) && rangeRe.MatchString(rest[i+1:])
	}
	return rangeRe.MatchString(s)
}

func (d deps) registryOnly() bool {
	for _, m := range []map[string]string{d.Dependencies, d.DevDependencies, d.OptionalDependencies, d.PeerDependencies} {
		for _, spec := range m {
			if !registrySpec(spec) {
				return false
			}
		}
	}
	return true
}

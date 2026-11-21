package uv

import (
	"bytes"
	"path"
	"slices"
	"strings"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
)

// wheelKey names a wheel file by where it installs, so that the same file
// in two versions compares equal: "<name>-<version>.data/scripts/x"
// becomes "<name>.data/scripts/x" (the .data directory carries the
// version in its name).
func wheelKey(rel string) string {
	first, rest, ok := strings.Cut(rel, "/")
	if !ok || !strings.HasSuffix(first, ".data") {
		return rel
	}
	name, _, _ := strings.Cut(strings.TrimSuffix(first, ".data"), "-")
	return name + ".data/" + rest
}

// installHook reports whether a wheel file installs somewhere that runs
// or shadows code outside the package's own import path: anything under
// <name>.data/ (scripts land on PATH and can shadow CI tools; purelib and
// platlib land at the site-packages root; data and headers anywhere under
// the prefix), and a top-level sitecustomize/usercustomize module (run at
// every interpreter start). .pth files are uv.pth-file's: any .pth in a
// wheel is flagged, new or not.
func installHook(key string) bool {
	if first, _, ok := strings.Cut(key, "/"); ok && strings.HasSuffix(first, ".data") {
		return true
	}
	top, _, _ := strings.Cut(key, "/")
	mod := strings.TrimSuffix(top, ".py")
	return mod == "sitecustomize" || mod == "usercustomize"
}

// installHookFiles lists the wheel files of cur that installHook selects
// and that are new or changed since old.
func installHookFiles(old, cur *ecoutil.Tree) []string {
	prev := map[string]string{}
	if old != nil {
		for _, f := range old.Files {
			prev[wheelKey(f)] = f
		}
	}
	var out []string
	for _, f := range cur.Files {
		k := wheelKey(f)
		if !installHook(k) {
			continue
		}
		if p, ok := prev[k]; ok && bytes.Equal(old.ReadFile(p), cur.ReadFile(f)) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// buildFiles are sdist files a build backend runs or reads as build
// configuration besides setup.py (checked on its own).
var buildFiles = []string{"setup.cfg", "hatch_build.py", "pdm_build.py", "build.py"}

// buildCodeFiles lists the sdist files that the build runs and that are
// new or changed since old: buildFiles, a hatch custom hook's path, and
// the in-tree backend named by [build-system] backend-path/build-backend
// (its module file, or its whole top-level package), on either side.
func buildCodeFiles(old, cur *ecoutil.Tree) []string {
	targets := slices.Clone(buildFiles)
	var prefixes []string
	for _, t := range []*ecoutil.Tree{old, cur} {
		doc, err := ParseTOML(string(t.ReadFile("pyproject.toml")))
		if err != nil {
			continue
		}
		if p, ok := table(doc, "tool", "hatch", "build", "hooks", "custom")["path"].(string); ok {
			targets = append(targets, path.Clean(p))
		}
		bs := table(doc, "build-system")
		backend, _ := bs["build-backend"].(string)
		mod, _, _ := strings.Cut(backend, ":")
		if mod == "" {
			continue
		}
		for _, dir := range stringList(bs["backend-path"]) {
			dir = path.Clean(dir)
			modPath := path.Join(dir, strings.ReplaceAll(mod, ".", "/"))
			targets = append(targets, modPath+".py", path.Join(modPath, "__init__.py"))
			top, _, _ := strings.Cut(mod, ".")
			prefixes = append(prefixes, path.Join(dir, top)+"/")
		}
	}
	var out []string
	for _, f := range cur.Files {
		hit := slices.Contains(targets, f)
		for _, p := range prefixes {
			hit = hit || strings.HasPrefix(f, p)
		}
		if !hit {
			continue
		}
		if old.Has(f) && bytes.Equal(old.ReadFile(f), cur.ReadFile(f)) {
			continue
		}
		out = append(out, f)
	}
	return out
}

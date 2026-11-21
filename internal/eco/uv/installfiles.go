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

// installHook reports whether a wheel file installs under <name>.data/:
// scripts land on PATH and can shadow CI tools, purelib and platlib land
// at the site-packages root, data and headers anywhere under the prefix.
func installHook(key string) bool {
	first, _, ok := strings.Cut(key, "/")
	return ok && strings.HasSuffix(first, ".data")
}

// rootPath is where a wheel file lands relative to site-packages, or ""
// for files that do not land there (.dist-info, .data scripts/data/
// headers). <name>.data/purelib and platlib install at the root.
func rootPath(rel string) string {
	first, rest, _ := strings.Cut(wheelKey(rel), "/")
	switch {
	case strings.HasSuffix(first, ".dist-info"):
		return ""
	case strings.HasSuffix(first, ".data"):
		scheme, inside, ok := strings.Cut(rest, "/")
		if !ok || (scheme != "purelib" && scheme != "platlib") {
			return ""
		}
		return inside
	}
	return rel
}

// topLevel is the set of import names a wheel puts at the site-packages
// root: package directories ("requests/") and modules ("yaml.py",
// "_yaml.cpython-312-x86_64-linux-gnu.so" -> "_yaml"). .pth files are not
// import names (uv.pth-file flags every one).
func topLevel(t *ecoutil.Tree) map[string]bool {
	out := map[string]bool{}
	if t == nil {
		return out
	}
	for _, f := range t.Files {
		r := rootPath(f)
		if r == "" {
			continue
		}
		top, _, isDir := strings.Cut(r, "/")
		if !isDir {
			if path.Ext(top) == ".pth" {
				continue
			}
			top, _, _ = strings.Cut(top, ".")
		}
		if top == "" || top == "__pycache__" {
			continue
		}
		out[top] = true
	}
	return out
}

// startupModules lists the files of a wheel that make a sitecustomize or
// usercustomize module, which the interpreter imports at every start-up.
func startupModules(t *ecoutil.Tree) []string {
	var out []string
	for _, f := range t.Files {
		r := rootPath(f)
		if r == "" {
			continue
		}
		top, _, isDir := strings.Cut(r, "/")
		if !isDir {
			top, _, _ = strings.Cut(top, ".")
		}
		if top == "sitecustomize" || top == "usercustomize" {
			out = append(out, f)
		}
	}
	return out
}

// installHookFiles lists the wheel files of cur under <name>.data/ that
// are new or changed since old.
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

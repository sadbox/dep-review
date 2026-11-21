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

// inertSdistFile: files no build backend runs: documentation, licences,
// images and the generated metadata (PKG-INFO, *.egg-info/), which
// changes with every release.
func inertSdistFile(rel string) bool {
	base := path.Base(rel)
	upper := strings.ToUpper(base)
	for _, p := range []string{"LICENSE", "LICENCE", "COPYING", "AUTHORS", "NOTICE", "CHANGELOG", "CHANGES", "HISTORY", "README", "CONTRIBUTING"} {
		if strings.HasPrefix(upper, p) && (path.Ext(base) == "" || slices.Contains([]string{".md", ".rst", ".txt"}, strings.ToLower(path.Ext(base)))) {
			return true
		}
	}
	first, _, _ := strings.Cut(rel, "/")
	switch {
	case rel == "PKG-INFO", strings.HasSuffix(first, ".egg-info"):
		return true
	}
	switch strings.ToLower(path.Ext(base)) {
	case ".md", ".rst", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico":
		return true
	}
	return false
}

// sdistBuildChanges is the fail-closed rule for an sdist uv may build (no
// wheel fits some platform): every file added, changed or removed since
// old counts, except inert files and files inside the package's own
// import directories (imports: the wheel's top-level names, at the root
// or under src/), which the normal checks cover. Any pyproject.toml,
// setup.cfg or setup.py, and anything under a [build-system] backend-path
// directory, counts even there. Listing hook locations (hatch, pdm,
// setuptools cmdclass, poetry build scripts, ...) one by one would never
// be complete.
func sdistBuildChanges(old, cur *ecoutil.Tree, imports map[string]bool) []string {
	var backendDirs []string
	for _, t := range []*ecoutil.Tree{old, cur} {
		if doc, err := ParseTOML(string(t.ReadFile("pyproject.toml"))); err == nil {
			for _, d := range stringList(table(doc, "build-system")["backend-path"]) {
				backendDirs = append(backendDirs, path.Clean(d))
			}
		}
	}
	inBackend := func(f string) bool {
		for _, d := range backendDirs {
			if d == "." || f == d || strings.HasPrefix(f, d+"/") {
				return true
			}
		}
		return false
	}
	inImports := func(f string) bool {
		first, rest, _ := strings.Cut(f, "/")
		if first == "src" {
			first, _, _ = strings.Cut(rest, "/")
		}
		first = strings.TrimSuffix(first, path.Ext(first)) // "mod.py"
		return imports[first]
	}
	var changed []string
	for _, f := range cur.Files {
		if !old.Has(f) || !bytes.Equal(old.ReadFile(f), cur.ReadFile(f)) {
			changed = append(changed, f)
		}
	}
	if old != nil {
		for _, f := range old.Files {
			if !cur.Has(f) {
				changed = append(changed, f)
			}
		}
	}
	var out []string
	for _, f := range changed {
		switch base := path.Base(f); {
		case inBackend(f), base == "pyproject.toml", base == "setup.cfg", base == "setup.py":
		case inertSdistFile(f), inImports(f):
			continue
		}
		out = append(out, f)
	}
	slices.Sort(out)
	return out
}

package uv

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
	"github.com/sadbox/dep-review/internal/model"
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

// identRE is an ASCII Python identifier (stricter than Python's, so a
// name that is not one is an odd root entry, never an import name).
var identRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// nativeRE is a native extension module at the wheel root: stem.so,
// stem.pyd, stem.cpython-<tag>.so, stem.abi3.so, stem.cp<NN>-win_<arch>.pyd.
var nativeRE = regexp.MustCompile(`^([^.]+)(\.cpython-[A-Za-z0-9_-]+|\.abi3|\.cp[0-9]+-win[A-Za-z0-9_]*)?\.(so|pyd)$`)

// importNames parses the entries a wheel puts at the site-packages root
// (its own root and <name>.data/purelib, platlib) into import names: a
// directory, a .py or .pyc module, or a native extension with a valid ABI
// suffix, whose stem is a Python identifier. Every other root entry is
// odd. The always-human set (sitecustomize/usercustomize, .pth, the rest
// of .data/) is checked separately and left out here, as is __pycache__
// (uv.compiled-bytecode).
func importNames(t *ecoutil.Tree) (names map[string]bool, odd []string) {
	names = map[string]bool{}
	if t == nil {
		return names, nil
	}
	seenOdd := map[string]bool{}
	for _, f := range t.Files {
		r := rootPath(f)
		if r == "" {
			continue
		}
		top, _, isDir := strings.Cut(r, "/")
		stem := top
		switch {
		case isDir:
		case path.Ext(top) == ".pth":
			continue
		case path.Ext(top) == ".py" || path.Ext(top) == ".pyc":
			stem = strings.TrimSuffix(top, path.Ext(top))
		default:
			m := nativeRE.FindStringSubmatch(top)
			if m == nil {
				stem = ""
			} else {
				stem = m[1]
			}
		}
		switch {
		case stem == "__pycache__", stem == "sitecustomize", stem == "usercustomize":
		case identRE.MatchString(stem):
			names[stem] = true
		case !seenOdd[top]:
			seenOdd[top] = true
			odd = append(odd, f)
		}
	}
	return names, odd
}

// hookNames are module names build and test tools run by convention;
// they are never an exempt import name, whatever the old wheel had.
var hookNames = []string{"setup", "conftest", "hatch_build", "pdm_build", "build", "noxfile", "fabfile", "tasks"}

// rootFindings checks a new wheel's root entries against the old
// version's wheel: an import name is exempt only if the old wheel had it
// too (and it is not a hook name), so a new package, or one whose old
// version had no wheel, gets no exemption at all. Any odd root entry
// needs a person as well. A new import name can shadow another
// distribution's (requests/, yaml.py).
func rootFindings(oldWheel, cur *ecoutil.Tree) []model.Finding {
	exempt, _ := importNames(oldWheel)
	for _, h := range hookNames {
		delete(exempt, h)
	}
	names, odd := importNames(cur)
	var added []string
	for n := range names {
		if !exempt[n] {
			added = append(added, n)
		}
	}
	slices.Sort(added)
	var out []model.Finding
	if len(added) > 0 {
		why := "not in the previous version's wheel"
		if oldWheel == nil {
			why = "no previous version's wheel to compare with"
		}
		out = append(out, model.Finding{Code: "uv.new-top-level", Route: model.RouteHuman,
			Detail: fmt.Sprintf("wheel installs top-level import names (%s): %s", why, ecoutil.List(added, 10))})
	}
	if len(odd) > 0 {
		out = append(out, model.Finding{Code: "uv.root-file", Route: model.RouteHuman,
			Detail: fmt.Sprintf("wheel installs files at the site-packages root that are not import names: %s", ecoutil.List(odd, 10))})
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

// sdistDiff lists every file added, changed or removed between the old
// and new sdist except PKG-INFO (which carries the version). uv may build
// an sdist on any platform a wheel does not cover, and its build can run
// anything in it, so no other file is exempt: past attempts to exempt
// "inert" files, import directories or "pure" packages each leaked.
func sdistDiff(old, cur *ecoutil.Tree) []string {
	var out []string
	for _, f := range cur.Files {
		if f != "PKG-INFO" && (!old.Has(f) || !bytes.Equal(old.ReadFile(f), cur.ReadFile(f))) {
			out = append(out, f)
		}
	}
	if old != nil {
		for _, f := range old.Files {
			if f != "PKG-INFO" && !cur.Has(f) {
				out = append(out, f)
			}
		}
	}
	slices.Sort(out)
	return out
}

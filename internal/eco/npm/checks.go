package npm

import (
	"bytes"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
	"github.com/sadbox/dep-review/internal/evidence"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/strictjson"
)

// installScripts run on `npm install` (prepare also runs for git deps;
// prepublish ran on install in npm < 7).
var installScripts = []string{"preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare", "prepublish"}

// checkPackage runs the npm hard stops on the new version against the old
// one (nil for a new package). Every finding forces RouteHuman.
func checkPackage(old, cur *side) []model.Finding {
	var out []model.Finding
	add := func(code, format string, args ...any) {
		out = append(out, model.Finding{Code: code, Route: model.RouteHuman, Detail: fmt.Sprintf(format, args...)})
	}
	var op manifest
	var oldDoc *versionDoc
	var oldTree *ecoutil.Tree
	if old != nil {
		op, oldDoc, oldTree = old.pkg, old.doc, old.tree
	}
	np := cur.pkg

	// What the tarball says and what the registry says must agree
	// ("manifest confusion"): npm installs from the tarball but resolves
	// dependencies from the registry document.
	if !maps.Equal(np.Scripts, cur.doc.Scripts) || !maps.Equal(np.bins(), cur.doc.bins()) ||
		!maps.Equal(np.runtimeDeps(), cur.doc.runtimeDeps()) {
		add("npm.manifest-mismatch", "the tarball's package.json and the registry's metadata disagree on scripts, bin or dependencies")
	}
	for _, s := range installScripts {
		for _, m := range []manifest{np, cur.doc.manifest} {
			if v := m.Scripts[s]; v != "" && v != op.Scripts[s] {
				add("npm.install-script", "lifecycle script %q added or changed: %q", s, v)
				break
			}
		}
	}
	ob := op.bins()
	for name, target := range np.bins() {
		if prev, ok := ob[name]; !ok || prev != target {
			add("npm.new-bin", "bin %q -> %q is new or retargeted", name, target)
		}
	}
	od := op.runtimeDeps()
	var newDeps []string
	for name := range np.runtimeDeps() {
		if !od[name] {
			newDeps = append(newDeps, name)
		}
	}
	if len(newDeps) > 0 {
		slices.Sort(newDeps)
		add("npm.new-package-dependency", "package.json declares new dependencies: %s", strings.Join(newDeps, ", "))
	}

	// Who published it.
	if oldDoc != nil {
		if publisher(oldDoc) != publisher(cur.doc) {
			add("npm.publisher-changed", "published by %s, previous version by %s", publisher(cur.doc), publisher(oldDoc))
		}
		if a, b := maintainers(oldDoc), maintainers(cur.doc); !slices.Equal(a, b) {
			add("npm.maintainers-changed", "maintainers changed from %v to %v", a, b)
		}
		if hasProvenance(oldDoc) && !hasProvenance(cur.doc) {
			add("npm.provenance-lost", "the previous version had a provenance attestation; this one has none")
		}
	}

	// Native code and unreadable code.
	if np.Gypfile != nil && *np.Gypfile {
		add("npm.native-addon", "package.json sets gypfile")
	}
	var native, binaries, opaque, minified, obfuscated []string
	for _, rel := range cur.tree.Files {
		base := path.Base(rel)
		if base == "binding.gyp" || path.Ext(rel) == ".node" {
			native = append(native, rel)
		}
		data := cur.tree.ReadFile(rel)
		var prev []byte
		inOld := oldTree.Has(rel)
		if inOld {
			prev = oldTree.ReadFile(rel)
			if bytes.Equal(prev, data) {
				continue
			}
		}
		// No directory is exempt: everything in the tarball lands in
		// node_modules and can be required.
		switch {
		case isExecutable(data) && path.Ext(rel) != ".node":
			binaries = append(binaries, rel)
		case evidence.IsBinary(data) && path.Ext(rel) != ".node":
			opaque = append(opaque, rel)
		}
		if !isJS(rel) || evidence.IsBinary(data) {
			continue
		}
		if !inOld && isMinified(data) {
			minified = append(minified, rel)
		}
		if obfuscationScore(data) > obfuscationScore(prev) {
			obfuscated = append(obfuscated, rel)
		}
	}
	if len(native) > 0 {
		add("npm.native-addon", "native addon files: %s", ecoutil.List(native, 10))
	}
	if len(binaries) > 0 {
		add("npm.executable", "executable binaries added or changed: %s", ecoutil.List(binaries, 10))
	}
	if len(opaque) > 0 {
		add("npm.binary-file", "binary files added or changed (not reviewable as text): %s", ecoutil.List(opaque, 10))
	}
	if len(minified) > 0 {
		add("npm.minified-new-file", "new minified files nobody can review: %s", ecoutil.List(minified, 10))
	}
	if len(obfuscated) > 0 {
		add("npm.obfuscated", "obfuscation patterns (hex identifiers, escaped strings, eval of decoded text) increased: %s", ecoutil.List(obfuscated, 10))
	}
	return out
}

func publisher(d *versionDoc) string {
	if d.NPMUser == nil {
		return "(unknown)"
	}
	s := d.NPMUser.Name + " <" + d.NPMUser.Email + ">"
	if len(d.NPMUser.TrustedPublisher) > 0 {
		var tp struct {
			ID           string `json:"id"`
			OIDCConfigID string `json:"oidcConfigId"`
		}
		_ = strictjson.Unmarshal(d.NPMUser.TrustedPublisher, &tp)
		s += " via trusted publisher " + tp.ID + " " + tp.OIDCConfigID
	}
	return s
}

func maintainers(d *versionDoc) []string {
	var out []string
	for _, m := range d.Maintainers {
		out = append(out, m.Name)
	}
	slices.Sort(out)
	return out
}

func hasProvenance(d *versionDoc) bool {
	var a struct {
		Provenance *struct {
			PredicateType string `json:"predicateType"`
		} `json:"provenance"`
	}
	return len(d.Dist.Attestations) > 0 && strictjson.Unmarshal(d.Dist.Attestations, &a) == nil && a.Provenance != nil
}

func isJS(rel string) bool {
	switch path.Ext(rel) {
	case ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts":
		return true
	}
	return false
}

// isExecutable: ELF, Mach-O, PE or WebAssembly.
func isExecutable(b []byte) bool {
	for _, magic := range [][]byte{
		{0x7f, 'E', 'L', 'F'}, {0xfe, 0xed, 0xfa, 0xce}, {0xfe, 0xed, 0xfa, 0xcf},
		{0xce, 0xfa, 0xed, 0xfe}, {0xcf, 0xfa, 0xed, 0xfe}, {0xca, 0xfe, 0xba, 0xbe},
		{'M', 'Z'}, {0x00, 'a', 's', 'm'},
	} {
		if bytes.HasPrefix(b, magic) {
			return true
		}
	}
	return false
}

// isMinified: code a person cannot read line by line: some line over 1000
// characters and an average line over 200, in a file of real size.
func isMinified(b []byte) bool {
	if len(b) < 2048 {
		return false
	}
	lines := bytes.Split(b, []byte("\n"))
	longest := 0
	for _, l := range lines {
		longest = max(longest, len(l))
	}
	return longest > 1000 && len(b)/len(lines) > 200
}

var (
	hexIdentRE = regexp.MustCompile(`\b_0x[0-9a-fA-F]{4,}\b`)
	escapeRE   = regexp.MustCompile(`\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}`)
	evalRE     = regexp.MustCompile(`\beval\s*\(|\bnew\s+Function\s*\(|\batob\s*\(|Buffer\.from\([^)]*['"]base64['"]`)
)

// obfuscationScore counts javascript-obfuscator style identifiers, dense
// escape sequences and dynamic evaluation of decoded strings.
func obfuscationScore(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	score := len(hexIdentRE.FindAllIndex(b, 200))
	if esc := len(escapeRE.FindAllIndex(b, 5000)); esc*6*20 > len(b) { // escapes are >5% of the text
		score += esc / 10
	}
	score += 5 * len(evalRE.FindAllIndex(b, 50))
	if score < 10 {
		return 0 // noise: a few hex names or one eval are common
	}
	return score
}

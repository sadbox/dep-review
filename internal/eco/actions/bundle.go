package actions

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Residual reasons: changed bundle bytes that no changed first-party file
// or changed locked package explains.
const (
	resUnnamed    = "unnamed-module" // a numbered/anonymous bundler module (or the bundler runtime)
	resPkgNoLock  = "package-without-lock-change"
	resFirstParty = "first-party-source-unchanged" // bundled first-party code changed but its file did not
	resGenSrcSame = "output-changed-source-same"   // source map: same sourcesContent, different generated code
	resUnmapped   = "unmapped-generated-code"      // source map: generated code mapped to no source
	resWhole      = "unattributable-file"          // no module markers and no usable source map
	resNullNoLock = "null-source-content-without-lock-change"
)

// Diff groups, written to evidence in this order.
const (
	grpResidual   = "residual"
	grpFirstParty = "first-party"
	grpPackage    = "package"
)

type residualItem struct {
	reason string
	name   string
	bytes  int
}

type namedDiff struct {
	group, name, text string
}

type pkgStat struct {
	files, bytes int
}

type bundleReport struct {
	path, mode string
	note       string
	oldBytes   int
	newBytes   int
	unchanged  int
	attributed int
	residual   int
	residuals  []residualItem
	// Source-map mode: changed sources whose sourcesContent is null, so the
	// reviewer cannot see a source diff for them.
	nullContent      []string
	nullContentBytes int
	byPkg            map[string]*pkgStat
	diffs            []namedDiff
}

func (r *bundleReport) residualFraction() float64 {
	if r.newBytes == 0 {
		if r.residual > 0 {
			return 1
		}
		return 0
	}
	return float64(r.residual) / float64(r.newBytes)
}

// attribution says whether a changed piece of bundled code is explained.
type attribution struct {
	lockChanged map[string]bool // npm package names whose locked versions changed
	// lockPaths are install paths (node_modules/a/node_modules/b) whose
	// locked version changed, from path-keyed lockfiles (package-lock).
	lockPaths  map[string]bool
	firstParty []string // upstream files changed outside dist/ and lockfiles
	// lockNew is the new lockfile's versions, to recognize numbered
	// modules that are a package's own package.json.
	lockNew lockSet
}

var webpackGutterRx = regexp.MustCompile(`^/\*+/`)

var pkgJSONModuleRx = regexp.MustCompile(`^\s*module\.exports = (?:/\*#__PURE__\*/)?JSON\.parse\('\{"name":"((?:@[a-z0-9._~-]+/)?[a-z0-9._~-]+)","version":"([0-9A-Za-z.+-]+)"`)

// jsonModulePackage recognizes a numbered module that is only an npm
// package's package.json (bundled for its version string) whose name and
// version match a changed locked package.
func (a attribution) jsonModulePackage(body string) bool {
	var code []string
	for _, l := range strings.Split(body, "\n") {
		t := strings.TrimSpace(webpackGutterRx.ReplaceAllString(l, ""))
		switch t {
		case "", "((module) => {", "})", "}),", "});", `"use strict";`:
			continue
		}
		code = append(code, l)
	}
	if len(code) != 1 {
		return false
	}
	m := pkgJSONModuleRx.FindStringSubmatch(code[0])
	return m != nil && strings.HasSuffix(code[0], "');") && a.lockChanged[m[1]] && a.lockNew[m[1]][m[2]]
}

// firstPartyChanged reports whether a bundled first-party module path
// (relative to the bundle's directory or the repository root, possibly a
// compiled lib/ path for a src/ file) corresponds to a changed file.
func (a attribution) firstPartyChanged(bundleDir, p string) bool {
	p = strings.TrimPrefix(strings.ReplaceAll(p, `\`, "/"), "webpack://")
	if i := strings.Index(p, "/./"); i >= 0 {
		p = p[i+1:] // webpack://<name>/./src/x.ts
	}
	cands := []string{path.Clean(p), path.Clean(path.Join(bundleDir, p))}
	for _, f := range a.firstParty {
		for _, c := range cands {
			if f == c {
				return true
			}
		}
	}
	// lib/foo.js compiled from src/foo.ts: compare without the top
	// directory and the extension.
	st := stem(cands[0])
	st2 := stem(cands[1])
	for _, f := range a.firstParty {
		if s := stem(f); s != "" && (s == st || s == st2) {
			return true
		}
	}
	return false
}

func stem(p string) string {
	p = strings.TrimPrefix(p, "./")
	for strings.HasPrefix(p, "../") {
		p = p[3:]
	}
	if i := strings.Index(p, "/"); i >= 0 {
		p = p[i+1:]
	} else {
		return ""
	}
	return strings.TrimSuffix(p, path.Ext(p))
}

func (a attribution) classify(bundleDir, name string) (attributed bool, reason, group string) {
	pkg := pkgOf(name)
	if pkg == "" {
		if a.firstPartyChanged(bundleDir, name) {
			return true, "", grpFirstParty
		}
		return false, resFirstParty, grpResidual
	}
	if a.lockChanged[pkg] {
		return true, "", grpPackage
	}
	for _, c := range []string{name, path.Join(bundleDir, name)} {
		if ip := installPath(c); ip != "" && a.lockPaths[ip] {
			return true, "", grpPackage
		}
	}
	return false, resPkgNoLock, grpResidual
}

// installPath returns the node_modules install directory a module path is
// in, relative to the project root: "./node_modules/a/node_modules/b/x.js"
// -> "node_modules/a/node_modules/b".
func installPath(p string) string {
	p = path.Clean(strings.ReplaceAll(p, `\`, "/"))
	for strings.HasPrefix(p, "../") {
		p = p[3:]
	}
	i := strings.LastIndex(p, "node_modules/")
	if i < 0 {
		return ""
	}
	rest := strings.Split(p[i+len("node_modules/"):], "/")
	n := 1
	if strings.HasPrefix(rest[0], "@") && len(rest) > 1 {
		n = 2
	}
	return p[:i] + "node_modules/" + strings.Join(rest[:n], "/")
}

func (r *bundleReport) addPkg(name string, n int) {
	pkg := pkgOf(name)
	if pkg == "" {
		pkg = "(first-party)"
	}
	if r.byPkg == nil {
		r.byPkg = map[string]*pkgStat{}
	}
	s := r.byPkg[pkg]
	if s == nil {
		s = &pkgStat{}
		r.byPkg[pkg] = s
	}
	s.files++
	s.bytes += n
}

// ---- module mode (unminified ncc/webpack or esbuild bundles) ----

type markerKind int

const (
	mkPath markerKind = iota
	mkID
	mkExternal
	mkRuntime
)

var moduleMarkers = []struct {
	rx   *regexp.Regexp
	kind markerKind
}{
	{regexp.MustCompile(`^;// CONCATENATED MODULE: external "([^"]+)"`), mkExternal},
	{regexp.MustCompile(`^;// CONCATENATED MODULE: (\S+)`), mkPath},
	{regexp.MustCompile(`^;// (\./\S+)$`), mkPath},
	{regexp.MustCompile(`^// ((?:\.\./)*(?:node_modules|src|lib|scripts)/\S+)\s*$`), mkPath},
	{regexp.MustCompile(`^/\*\*\*/ (\d+):`), mkID},
	{regexp.MustCompile(`^/\*\*\*/ "([^"]+)":`), mkPath},
	{regexp.MustCompile(`^;// external "([^"]+)"`), mkExternal},
	// The webpack runtime follows the module table.
	{regexp.MustCompile(`^/\*{20,}/$`), mkRuntime},
	// "// EXTERNAL MODULE: x" marks a require of another module inside a
	// concatenated module, not a boundary; it stays part of the module.
}

const preamble = "(bundle runtime)"

// splitModules splits an unminified bundle at bundler module-boundary
// comments. Keys are module paths, "webpack#<id>" for numbered modules,
// "external:<name>" for externals; duplicates get "#n" suffixes.
func splitModules(text string) (mods map[string]string, order []string, named int) {
	mods = map[string]string{}
	seen := map[string]int{}
	cur := preamble
	var buf []string
	flush := func() {
		key := cur
		seen[cur]++
		if seen[cur] > 1 {
			key = fmt.Sprintf("%s#%d", cur, seen[cur])
		}
		mods[key] = strings.Join(buf, "\n")
		order = append(order, key)
	}
	for _, line := range strings.Split(text, "\n") {
		hit := false
		if line != "" && (line[0] == ';' || line[0] == '/') {
			for _, m := range moduleMarkers {
				if g := m.rx.FindStringSubmatch(line); g != nil {
					flush()
					switch m.kind {
					case mkPath:
						cur = g[1]
						named++
					case mkID:
						cur = "webpack#" + g[1]
					case mkExternal:
						cur = "external:" + g[1]
					case mkRuntime:
						cur = preamble
					}
					buf = buf[:0]
					hit = true
					break
				}
			}
		}
		if !hit {
			buf = append(buf, line)
		}
	}
	flush()
	return mods, order, named
}

func unnamedModule(k string) bool {
	return strings.HasPrefix(k, "webpack#") || strings.HasPrefix(k, "external:") || strings.HasPrefix(k, preamble)
}

func analyzeModules(r *bundleReport, oldText, newText string, a attribution) {
	r.mode = "modules"
	om, _, _ := splitModules(oldText)
	nm, order, _ := splitModules(newText)
	oldHashes := map[[32]byte]bool{}
	for _, v := range om {
		oldHashes[sha256.Sum256([]byte(v))] = true
	}
	dir := path.Dir(r.path)
	for _, k := range order {
		body := nm[k]
		n := len(body) + 1
		ob, had := om[k]
		if had && ob == body {
			r.unchanged += n
			continue
		}
		if oldHashes[sha256.Sum256([]byte(body))] {
			r.unchanged += n // moved or renumbered, same body
			continue
		}
		if had && pureRename(ob, body) {
			r.unchanged += n // bundler identifier renames only
			continue
		}
		var attributed bool
		var reason, group string
		if unnamedModule(k) {
			reason, group = resUnnamed, grpResidual
			if a.jsonModulePackage(body) {
				attributed, reason, group = true, "", grpPackage
			}
		} else {
			attributed, reason, group = a.classify(dir, k)
		}
		changed := n
		if had {
			changed = insertedBytes(ob, body)
		}
		if attributed {
			r.attributed += n
			r.addPkg(k, n)
		} else {
			r.residual += changed
			r.residuals = append(r.residuals, residualItem{reason, k, changed})
		}
		r.diffs = append(r.diffs, namedDiff{group, k, unifiedDiff("a/"+k, "b/"+k, ob, body, 3)})
	}
}

var tokRx = regexp.MustCompile(`[A-Za-z_$][\w$]*|\s+|.`)

func isIdent(t string) bool { return t != "" && isIdentStart(t[0]) }

// pureRename reports whether a and b differ only by a consistent
// one-to-one renaming of identifiers.
func pureRename(a, b string) bool {
	ta, tb := tokRx.FindAllString(a, -1), tokRx.FindAllString(b, -1)
	if len(ta) != len(tb) {
		return false
	}
	fwd, rev := map[string]string{}, map[string]string{}
	for i := range ta {
		x, y := ta[i], tb[i]
		_, fx := fwd[x]
		_, ry := rev[y]
		if x == y && !fx && !ry {
			if isIdent(x) {
				fwd[x], rev[y] = y, x
			}
			continue
		}
		if !isIdent(x) || !isIdent(y) {
			return false
		}
		if v, ok := fwd[x]; ok && v != y {
			return false
		}
		if v, ok := rev[y]; ok && v != x {
			return false
		}
		fwd[x], rev[y] = y, x
	}
	return true
}

// ---- source-map mode (minified esbuild bundles) ----

func relInPackage(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if i := strings.LastIndex(p, "node_modules/"); i >= 0 {
		return p[i+len("node_modules/"):]
	}
	return p
}

func analyzeSourceMap(r *bundleReport, oldJS string, oldMap *sourceMap, newJS string, newMap *sourceMap, a attribution) error {
	r.mode = "sourcemap"
	var ob *mappedBundle
	if oldMap != nil {
		var err error
		if ob, err = splitByMap(oldJS, oldMap); err != nil {
			return fmt.Errorf("old source map: %w", err)
		}
	} else {
		ob = &mappedBundle{sources: map[string]*mappedSource{}}
	}
	nb, err := splitByMap(newJS, newMap)
	if err != nil {
		return fmt.Errorf("new source map: %w", err)
	}
	dir := path.Dir(r.path)
	root := path.Join(dir, newMap.SourceRoot)

	// Relocation: a source removed at one node_modules nesting and added
	// at another with the same content and output is unchanged.
	type relKey struct {
		rel       string
		src, gen  [32]byte
		hasSource bool
	}
	removed := map[relKey][]string{}
	for p, o := range ob.sources {
		if _, ok := nb.sources[p]; !ok {
			k := relKey{relInPackage(p), o.srcHash, o.genNorm, o.content != nil}
			removed[k] = append(removed[k], p)
		}
	}
	relocated := map[string]bool{}
	relocatedOld := map[string]bool{}
	for _, p := range nb.order {
		if _, ok := ob.sources[p]; ok {
			continue
		}
		n := nb.sources[p]
		k := relKey{relInPackage(p), n.srcHash, n.genNorm, n.content != nil}
		if l := removed[k]; len(l) > 0 {
			relocated[p] = true
			relocatedOld[l[len(l)-1]] = true
			removed[k] = l[:len(l)-1]
		}
	}

	for _, p := range nb.order {
		n := nb.sources[p]
		if relocated[p] {
			r.unchanged += n.genLen
			continue
		}
		o := ob.sources[p]
		srcKnown := n.content != nil && (o == nil || o.content != nil)
		if o != nil {
			genSame := o.genNorm == n.genNorm
			if srcKnown && o.srcHash == n.srcHash && genSame {
				r.unchanged += n.genLen
				continue
			}
			if !srcKnown && genSame {
				r.unchanged += n.genLen
				continue
			}
			if srcKnown && o.srcHash == n.srcHash {
				// Same source, different output: the bundler, its
				// configuration or the map changed, or the map lies.
				r.residual += n.genLen
				r.residuals = append(r.residuals, residualItem{resGenSrcSame, p, n.genLen})
				r.diffs = append(r.diffs, namedDiff{grpResidual, p, generatedExcerpt(o.gen.String(), n.gen.String())})
				continue
			}
		}
		if n.genLen == 0 {
			continue // a source that contributes no code (types, empty modules)
		}
		attributed, reason, group := a.classify(root, p)
		if !srcKnown {
			r.nullContent = append(r.nullContent, p)
			r.nullContentBytes += n.genLen
			if !attributed {
				reason = resNullNoLock
			}
		}
		if attributed {
			r.attributed += n.genLen
			r.addPkg(p, n.genLen)
		} else {
			r.residual += n.genLen
			r.residuals = append(r.residuals, residualItem{reason, p, n.genLen})
		}
		var oc, nc string
		if o != nil && o.content != nil {
			oc = *o.content
		}
		if n.content != nil {
			nc = *n.content
		}
		var text string
		if srcKnown {
			text = unifiedDiff("a/"+p, "b/"+p, oc, nc, 3)
		} else {
			text = "(sourcesContent is null; generated code excerpt)\n" + generatedExcerpt(genOf(o), n.gen.String())
		}
		r.diffs = append(r.diffs, namedDiff{group, p, text})
	}

	// Unmapped generated code: count chunks that are new by normalized
	// content (the bundler runtime and glue moves around between builds).
	oldChunks := map[string]int{}
	for _, c := range ob.unmapped {
		oldChunks[normalizeMinified(c)]++
	}
	unm := 0
	var samples []string
	for _, c := range nb.unmapped {
		k := normalizeMinified(c)
		if oldChunks[k] > 0 {
			oldChunks[k]--
			continue
		}
		if strings.TrimSpace(c) == "" {
			continue
		}
		unm += len(c)
		if len(samples) < 20 {
			samples = append(samples, truncate(c, 300))
		}
	}
	if unm > 0 {
		r.residual += unm
		r.residuals = append(r.residuals, residualItem{resUnmapped, "(unmapped)", unm})
		r.diffs = append(r.diffs, namedDiff{grpResidual, "(unmapped generated code)", "+" + strings.Join(samples, "\n+") + "\n"})
	}
	return nil
}

func genOf(m *mappedSource) string {
	if m == nil {
		return ""
	}
	return m.gen.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// generatedExcerpt shows where two generated (minified) chunks differ.
func generatedExcerpt(o, n string) string {
	i := 0
	for i < len(o) && i < len(n) && o[i] == n[i] {
		i++
	}
	j := 0
	for j < len(o)-i && j < len(n)-i && o[len(o)-1-j] == n[len(n)-1-j] {
		j++
	}
	from := max(i-80, 0)
	return fmt.Sprintf("generated bytes old=%d new=%d, first difference at %d\n-%s\n+%s\n",
		len(o), len(n), i, truncate(o[from:len(o)-j], 2000), truncate(n[from:len(n)-j], 2000))
}

// ---- whole-file mode ----

func analyzeWhole(r *bundleReport, oldText, newText string) {
	r.mode = "whole"
	ins := insertedBytes(oldText, newText)
	r.residual += ins
	r.unchanged += r.newBytes - ins
	r.residuals = append(r.residuals, residualItem{resWhole, r.path, ins})
	r.diffs = append(r.diffs, namedDiff{grpResidual, r.path, unifiedDiff("a/"+r.path, "b/"+r.path, oldText, newText, 3)})
}

// ---- dispatch ----

type bundleInput struct {
	path           string
	old, new       []byte // old is nil for an added file
	oldMap, newMap []byte // nil when the bundle has no source map
	mapNote        string
}

var sourceMappingURLRx = regexp.MustCompile(`(?m)^//[#@] sourceMappingURL=(\S+)\s*$`)

// mapReference returns the source map a bundle names in its trailing
// sourceMappingURL comment: an inline data: map, or a repository path.
func mapReference(bundlePath string, js []byte) (inline []byte, ref string) {
	tail := js
	if len(tail) > 4096 {
		tail = tail[len(tail)-4096:]
	}
	m := sourceMappingURLRx.FindAllSubmatch(tail, -1)
	if m == nil {
		return nil, ""
	}
	u := string(m[len(m)-1][1])
	if strings.HasPrefix(u, "data:") {
		if i := strings.Index(u, ";base64,"); i >= 0 {
			if b, err := base64.StdEncoding.DecodeString(u[i+len(";base64,"):]); err == nil {
				return b, ""
			}
		}
		return nil, ""
	}
	if strings.Contains(u, "://") {
		return nil, ""
	}
	p := path.Clean(path.Join(path.Dir(bundlePath), u))
	if strings.HasPrefix(p, "../") || p == ".." {
		return nil, ""
	}
	return nil, p
}

func analyzeBundle(in bundleInput, a attribution) *bundleReport {
	r := &bundleReport{path: in.path, oldBytes: len(in.old), newBytes: len(in.new), note: in.mapNote}
	oldText, newText := string(in.old), string(in.new)
	if in.newMap != nil {
		nm, err := parseSourceMap(in.newMap)
		var om *sourceMap
		if err == nil && in.old != nil {
			if in.oldMap == nil {
				err = fmt.Errorf("the old bundle has no source map")
			} else {
				om, err = parseSourceMap(in.oldMap)
			}
		}
		if err == nil {
			if err = analyzeSourceMap(r, oldText, om, newText, nm, a); err == nil {
				return r
			}
		}
		// Fall through to the unminified/whole analysis, starting over.
		r = &bundleReport{path: in.path, oldBytes: len(in.old), newBytes: len(in.new),
			note: strings.TrimSpace(in.mapNote + " source map unusable: " + err.Error())}
	}
	if _, _, named := splitModules(newText); named >= 2 {
		analyzeModules(r, oldText, newText, a)
		return r
	}
	analyzeWhole(r, oldText, newText)
	return r
}

// renderBundle writes the per-bundle attribution report (untrusted: it
// carries upstream module paths) followed by its diffs, residual first.
func renderBundle(r *bundleReport) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "bundle %s (mode %s)\n", r.path, r.mode)
	if r.note != "" {
		fmt.Fprintf(&sb, "note: %s\n", r.note)
	}
	fmt.Fprintf(&sb, "bytes old=%d new=%d unchanged=%d attributed=%d residual=%d (%.3f%% of new)\n",
		r.oldBytes, r.newBytes, r.unchanged, r.attributed, r.residual, 100*r.residualFraction())
	if len(r.nullContent) > 0 {
		fmt.Fprintf(&sb, "changed sources with null sourcesContent: %d (%d generated bytes)\n", len(r.nullContent), r.nullContentBytes)
	}
	sb.WriteString("\nresidual (changed bytes not explained by a changed first-party file or a changed locked package):\n")
	if len(r.residuals) == 0 {
		sb.WriteString("  none\n")
	}
	for _, it := range r.residuals {
		fmt.Fprintf(&sb, "  %-40s %8d  %s\n", it.reason, it.bytes, it.name)
	}
	if len(r.byPkg) > 0 {
		sb.WriteString("\nattributed changes by package:\n")
		var names []string
		for k := range r.byPkg {
			names = append(names, k)
		}
		sort.Slice(names, func(i, j int) bool {
			if r.byPkg[names[i]].bytes != r.byPkg[names[j]].bytes {
				return r.byPkg[names[i]].bytes > r.byPkg[names[j]].bytes
			}
			return names[i] < names[j]
		})
		for _, k := range names {
			fmt.Fprintf(&sb, "  %-50s files=%-4d bytes=%d\n", k, r.byPkg[k].files, r.byPkg[k].bytes)
		}
	}
	for _, g := range []string{grpResidual, grpFirstParty} {
		for _, d := range r.diffs {
			if d.group == g && d.text != "" {
				fmt.Fprintf(&sb, "\n==== %s: %s\n%s", g, d.name, d.text)
			}
		}
	}
	return sb.String()
}

// renderBundlePackages renders the package-attributed diffs, which are
// large and least informative, separately so caps cut them first.
func renderBundlePackages(r *bundleReport) string {
	var sb strings.Builder
	for _, d := range r.diffs {
		if d.group == grpPackage && d.text != "" {
			fmt.Fprintf(&sb, "\n==== %s: %s\n%s", d.group, d.name, d.text)
		}
	}
	return sb.String()
}

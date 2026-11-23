package npm

import (
	"context"
	json "encoding/json/v2"
	"fmt"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/facts"
)

// update is one package the pull request moves: a name and version that
// the head lock has and the base lock does not.
type update struct {
	Name string
	// From is the version this one replaces; empty for a new name.
	From string
	To   string
	// NewName: the base lock has no package of this name.
	NewName bool
	// Old is every base lock entry for Name at From; New is every head
	// lock entry for Name at To. New is never empty.
	Old []node
	New []node
	// Bundled names the dependencies a head entry for Name at To carries
	// inside its own tarball, or "(declared)" when the entry only says it
	// bundles some.
	Bundled []string
	// Indirect is the Indirect fact: the root package does not name this
	// package among its own dependencies. readChangeSet sets it from the
	// two root entries. An update made any other way has none, which is a
	// dependency the repository declares.
	Indirect allow.Fact
}

// changeSet is what the base and head files amount to.
type changeSet struct {
	// problems are the reasons Shape does not hold. When there are any,
	// updates is not to be used.
	problems []string
	// summary is Shape's Value when there are no problems.
	summary string
	updates []update
}

// readChangeSet checks the pull request's files, has npm read the lock at
// both commits and compares the two readings. The error is for a failed
// run of npm itself; everything about the files is a problem.
func readChangeSet(ctx context.Context, t tool, files []facts.File) (changeSet, error) {
	manifest, lock, problem := splitFiles(files)
	if problem != "" {
		return changeSet{problems: []string{problem}}, nil
	}

	baseLock, problem := readLock(lock.Base)
	if problem != "" {
		return changeSet{problems: []string{"base: " + problem}}, nil
	}
	headLock, problem := readLock(lock.Head)
	if problem != "" {
		return changeSet{problems: []string{"head: " + problem}}, nil
	}
	if baseLock.Version != headLock.Version {
		return changeSet{problems: []string{fmt.Sprintf("lockfileVersion changes from %d to %d", baseLock.Version, headLock.Version)}}, nil
	}

	// A package.json that did not change is not among the files the
	// gatherer is given. npm then takes the root's dependencies from the
	// lock's own root entry, which is compared below like package.json.
	var baseManifest, headManifest []byte
	if manifest != nil {
		baseManifest, headManifest = manifest.Base, manifest.Head
	}
	baseOut, err := t.List(ctx, baseManifest, lock.Base)
	if err != nil {
		return changeSet{}, fmt.Errorf("npm ls at base: %w", err)
	}
	headOut, err := t.List(ctx, headManifest, lock.Head)
	if err != nil {
		return changeSet{}, fmt.Errorf("npm ls at head: %w", err)
	}
	base, problems := readTree("base", baseOut)
	head, more := readTree("head", headOut)
	problems = append(problems, more...)
	if len(problems) > 0 {
		return changeSet{problems: problems}, nil
	}

	// npm prints what it can reach from the root. npm ci installs every
	// entry. The two must be the same set.
	for _, side := range []struct {
		name  string
		lock  lockFile
		nodes map[string]node
	}{{"base", baseLock, base}, {"head", headLock, head}} {
		notPrinted, notInLock := unlisted(side.lock, side.nodes)
		if len(notPrinted) > 0 {
			problems = append(problems, fmt.Sprintf("%s: the lock has entries npm ls does not show (nothing depends on them, or they are outside node_modules): %s", side.name, list(notPrinted, 5)))
		}
		if len(notInLock) > 0 {
			problems = append(problems, fmt.Sprintf("%s: npm ls shows packages the lock's \"packages\" does not have: %s", side.name, list(notInLock, 5)))
		}
	}
	if len(problems) > 0 {
		return changeSet{problems: problems}, nil
	}

	updates, problems := diffTrees(base, head)

	// package.json, and the lock's copy of it, may change only in the
	// version range of a package that moved.
	moved := map[string]bool{}
	for _, u := range updates {
		moved[u.Name] = true
	}
	if why := sameButRanges(baseLock.Root, headLock.Root, moved); why != "" {
		problems = append(problems, "the lock's root entry: "+why)
	}
	manifestNote := "package.json unchanged"
	if manifest != nil {
		var b, h map[string]any
		switch {
		case json.Unmarshal(manifest.Base, &b) != nil || b == nil:
			problems = append(problems, "base: package.json is not a JSON object the gate can read")
		case json.Unmarshal(manifest.Head, &h) != nil || h == nil:
			problems = append(problems, "head: package.json is not a JSON object the gate can read")
		default:
			if why := sameButRanges(b, h, moved); why != "" {
				problems = append(problems, "package.json: "+why)
			}
		}
		manifestNote = "package.json changes only their version ranges"
	}
	if len(problems) > 0 {
		return changeSet{problems: problems}, nil
	}
	for i := range updates {
		updates[i].Indirect = indirectFact(updates[i], baseLock.Root, headLock.Root)
	}

	var names []string
	for _, u := range updates {
		names = append(names, fmt.Sprintf("%s %s -> %s", show(u.Name), orNew(u.From), show(u.To)))
	}
	summary := fmt.Sprintf("%s (lockfileVersion %d, %d packages at head) moves %d: %s; %s",
		show(lock.Path), headLock.Version, len(head), len(updates), list(names, 20), manifestNote)
	if len(updates) == 0 {
		summary = fmt.Sprintf("%s (lockfileVersion %d) moves no package to a version it did not have at base; %s", show(lock.Path), headLock.Version, manifestNote)
	}
	return changeSet{summary: summary, updates: updates}, nil
}

// splitFiles finds the one package.json (nil when it did not change) and
// the one package-lock.json among the files the pull request changes. The
// string says why the files are not an npm update's.
func splitFiles(files []facts.File) (manifest, lock *facts.File, problem string) {
	if len(files) == 0 {
		return nil, nil, "the pull request changes no files"
	}
	var other []string
	dirs := map[string]bool{}
	for i := range files {
		f := &files[i]
		switch path.Base(f.Path) {
		case "package.json":
			manifest = f
			dirs[path.Dir(f.Path)] = true
		case "package-lock.json":
			lock = f
			dirs[path.Dir(f.Path)] = true
		default:
			// yarn.lock, npm-shrinkwrap.json and .npmrc land here too:
			// the gate has no rule for them.
			other = append(other, show(f.Path))
		}
	}
	if len(other) > 0 {
		return nil, nil, "the pull request changes files other than package.json and package-lock.json: " + list(other, 5)
	}
	if len(dirs) > 1 || len(files) > 2 {
		return nil, nil, "the pull request changes npm files in more than one directory: " + list(sortedKeys(dirs), 5)
	}
	if lock == nil {
		return nil, nil, "package-lock.json did not change, so nothing pins what this pull request installs"
	}
	for _, f := range []*facts.File{manifest, lock} {
		if f == nil {
			continue
		}
		// Present and a regular file at both commits. An added or removed
		// lock, a symlink and a mode change are not version tokens.
		regular := f.BaseMode == "100644" || f.BaseMode == "100755"
		if !regular || f.BaseMode != f.HeadMode {
			return nil, nil, fmt.Sprintf("%s is not the same regular file at both commits (mode %s at base, %s at head)", show(f.Path), quote(f.BaseMode), quote(f.HeadMode))
		}
	}
	return manifest, lock, ""
}

// pkg is a package name at one version.
type pkg struct{ name, version string }

// diffTrees compares npm's two readings. It returns the updates, and the
// changes that are not a version moving: those are Shape's problems.
//
// The change set is by name: a name and version the head has and the base
// has not. A second copy of a version the base already had, at a new path,
// is not an update, but it must be the same bytes from the same place.
func diffTrees(base, head map[string]node) ([]update, []string) {
	var problems []string
	baseCopies := copiesByPkg(base)
	headCopies := copiesByPkg(head)

	// Bundled entries have no source or hash of their own: their bytes
	// are their bundler's. They may change only together with it.
	bundled := map[string][]string{} // head path of a bundler -> names it carries
	for _, p := range sortedKeys(head) {
		n := head[p]
		if !n.InBundle {
			continue
		}
		owner, ok := bundler(head, p)
		if !ok {
			problems = append(problems, fmt.Sprintf("%s is marked as bundled but is inside no package", show(p)))
			continue
		}
		bundled[owner.Path] = append(bundled[owner.Path], show(n.Name))
		if _, established := baseCopies[pkg{owner.Name, owner.Version}]; established && base[p] != n {
			problems = append(problems, fmt.Sprintf("the bundled %s changes inside %s@%s, whose version does not", show(p), show(owner.Name), show(owner.Version)))
		}
	}
	for _, p := range sortedKeys(base) {
		n := base[p]
		if !n.InBundle {
			continue
		}
		owner, ok := bundler(base, p)
		if !ok {
			continue
		}
		if now, kept := head[owner.Path]; kept && now.Name == owner.Name && now.Version == owner.Version {
			if _, still := head[p]; !still {
				problems = append(problems, fmt.Sprintf("the bundled %s disappears from %s@%s, whose version does not change", show(p), show(owner.Name), show(owner.Version)))
			}
		}
	}

	// A package that keeps its version must keep everything else the
	// gate reads of it.
	for _, p := range sortedKeys(head) {
		n := head[p]
		if n.InBundle {
			continue
		}
		olds, established := baseCopies[pkg{n.Name, n.Version}]
		if !established {
			continue
		}
		if !slices.ContainsFunc(olds, func(b node) bool { return sameInstall(b, n) }) {
			problems = append(problems, fmt.Sprintf("%s@%s at %s keeps its version, but its source, hash, install-script flag, bundling or installed name is not what the base lock has", show(n.Name), show(n.Version), show(p)))
		}
	}

	var updates []update
	for _, k := range sortedPkgs(headCopies) {
		if _, established := baseCopies[k]; established {
			continue
		}
		copies := headCopies[k]
		u := update{Name: k.name, To: k.version, New: copies}
		for _, c := range copies {
			if c.Bundles && len(bundled[c.Path]) == 0 {
				u.Bundled = append(u.Bundled, "(declared)")
			}
			u.Bundled = append(u.Bundled, bundled[c.Path]...)
		}
		slices.Sort(u.Bundled)
		u.Bundled = slices.Compact(u.Bundled)

		baseVersions := versionsOf(baseCopies, k.name)
		if len(baseVersions) == 0 {
			u.NewName = true
			updates = append(updates, u)
			continue
		}
		// From is what the same lock path held at base. That is exact,
		// and it shows a downgrade for what it is.
		var froms []string
		for _, c := range copies {
			b, ok := base[c.Path]
			if ok && !b.InBundle && b.Name == k.name && !slices.Contains(froms, b.Version) {
				froms = append(froms, b.Version)
			}
		}
		if len(froms) == 0 {
			froms = []string{unpairedFrom(baseVersions, versionsOf(headCopies, k.name))}
		}
		slices.Sort(froms)
		for _, from := range froms {
			u.From = from
			u.Old = baseCopies[pkg{k.name, from}]
			updates = append(updates, u)
		}
	}
	return updates, problems
}

// unpairedFrom chooses From for a version that appears at a lock path the
// base did not have (a new nested copy, or a copy that moved). When
// exactly one base version of the name is gone, the new one replaced it.
// Otherwise it is measured against the highest version the base had, so
// that not knowing what it replaced can only cost a merge: an update that
// is not above everything the base had fails Increase.
func unpairedFrom(baseVersions, headVersions []string) string {
	var gone []string
	for _, v := range baseVersions {
		if !slices.Contains(headVersions, v) {
			gone = append(gone, v)
		}
	}
	if len(gone) == 1 {
		return gone[0]
	}
	sorted := slices.Clone(baseVersions)
	slices.Sort(sorted)
	for _, v := range sorted {
		if !semver.IsValid("v" + v) {
			// It cannot be ranked. Increase says no to it.
			return v
		}
	}
	return slices.MaxFunc(sorted, func(a, b string) int { return semver.Compare("v"+a, "v"+b) })
}

// copiesByPkg indexes the entries that have a source of their own (the
// ones that are not bundled) by name and version. Each list is in path
// order.
func copiesByPkg(nodes map[string]node) map[pkg][]node {
	out := map[pkg][]node{}
	for _, p := range sortedKeys(nodes) {
		n := nodes[p]
		if n.InBundle {
			continue
		}
		k := pkg{n.Name, n.Version}
		out[k] = append(out[k], n)
	}
	return out
}

// versionsOf lists the versions of name in copies, in order.
func versionsOf(copies map[pkg][]node, name string) []string {
	var versions []string
	for k := range copies {
		if k.name == name {
			versions = append(versions, k.version)
		}
	}
	slices.Sort(versions)
	return versions
}

// sortedPkgs returns the keys of copies by name, then version.
func sortedPkgs(copies map[pkg][]node) []pkg {
	keys := make([]pkg, 0, len(copies))
	for k := range copies {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b pkg) int {
		if c := strings.Compare(a.name, b.name); c != 0 {
			return c
		}
		return strings.Compare(a.version, b.version)
	})
	return keys
}

// sameInstall reports whether two entries for one name and version
// install the same thing the same way.
func sameInstall(a, b node) bool {
	return a.Resolved == b.Resolved && a.Integrity == b.Integrity &&
		a.HasInstallScript == b.HasInstallScript && a.Bundles == b.Bundles &&
		installedName(a.Path) == installedName(b.Path)
}

// installedName is the name a lock path installs its package under: what
// follows the last "node_modules/". It is empty for a path outside
// node_modules. When it differs from the package's own name the entry is
// an alias.
func installedName(lockPath string) string {
	i := strings.LastIndex(lockPath, "node_modules/")
	if i < 0 || (i > 0 && lockPath[i-1] != '/') {
		return ""
	}
	return lockPath[i+len("node_modules/"):]
}

// bundler finds the package a bundled entry is inside: the nearest
// enclosing lock path that is not itself bundled.
func bundler(nodes map[string]node, lockPath string) (node, bool) {
	for {
		i := strings.LastIndex(lockPath, "/node_modules/")
		if i < 0 {
			return node{}, false
		}
		lockPath = lockPath[:i]
		if n, ok := nodes[lockPath]; ok && !n.InBundle {
			return n, true
		}
	}
}

// depSections are the package.json objects that map a dependency's name
// to a version range.
var depSections = []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}

// rangeRE is the one shape of version range the gate lets a pull request
// rewrite: an optional operator and a plain version. Anything else that
// changes (a union, a tag, an alias, a URL, a git reference) is for a
// person.
var rangeRE = regexp.MustCompile(`^(|\^|~|>=|=)([0-9]+(?:\.[0-9]+){0,2})$`)

// sameButRanges compares two package.json objects (or two lock root
// entries, which have the same layout). They must be equal except for the
// version range of a package in moved, which may change its version and
// nothing else. The string says what else differs; empty means nothing.
func sameButRanges(base, head map[string]any, moved map[string]bool) string {
	for _, key := range sortedKeys(head) {
		if _, ok := base[key]; !ok {
			return "adds " + show(key)
		}
	}
	for _, key := range sortedKeys(base) {
		h, ok := head[key]
		if !ok {
			return "removes " + show(key)
		}
		b := base[key]
		if reflect.DeepEqual(b, h) {
			continue
		}
		if !slices.Contains(depSections, key) {
			return "changes " + show(key)
		}
		bs, bok := b.(map[string]any)
		hs, hok := h.(map[string]any)
		if !bok || !hok {
			return "changes " + show(key)
		}
		for _, name := range sortedKeys(hs) {
			if _, ok := bs[name]; !ok {
				return fmt.Sprintf("adds %s to %s", show(name), key)
			}
		}
		for _, name := range sortedKeys(bs) {
			hv, ok := hs[name]
			if !ok {
				return fmt.Sprintf("removes %s from %s", show(name), key)
			}
			bv := bs[name]
			if reflect.DeepEqual(bv, hv) {
				continue
			}
			if !moved[name] {
				return fmt.Sprintf("changes the range of %s in %s, a package the lock does not move", show(name), key)
			}
			br, _ := bv.(string)
			hr, _ := hv.(string)
			bm, hm := rangeRE.FindStringSubmatch(br), rangeRE.FindStringSubmatch(hr)
			if bm == nil || hm == nil || bm[1] != hm[1] {
				return fmt.Sprintf("changes the range of %s in %s by more than its version (%s to %s)", show(name), key, quote(fmt.Sprint(bv)), quote(fmt.Sprint(hv)))
			}
		}
	}
	return ""
}

// indirectFact is the Indirect fact of one update (spec section 11,
// amendment 23): it holds when the root package declares the package
// nowhere, and the package is in the lock only because another one asks
// for it.
func indirectFact(u update, baseRoot, headRoot map[string]any) allow.Fact {
	const source = "the root entry of package-lock.json at base and head"
	if where := declared(u, baseRoot, headRoot); where != "" {
		return allow.No("the root package declares it: "+where, source)
	}
	return allow.Yes("in none of the root package's dependencies, devDependencies, optionalDependencies and peerDependencies: another package asks for it", source)
}

// declared says where the root package names u among its own
// dependencies, at head or at base, and is empty when it does not. The
// lock's root entry is npm's copy of package.json's dependency maps, and
// it is there whether or not package.json changed. It is the only
// manifest the repository has: a lock with workspace members, whose own
// package.json files would declare dependencies too, does not have the
// shape (npm does not read it without them).
//
// A package is declared under the name it is installed as, which for an
// alias is not its own, so both are looked for. A dependency map that is
// not an object declares everything: that a package is indirect has to
// be shown, never assumed.
func declared(u update, baseRoot, headRoot map[string]any) string {
	names := []string{u.Name}
	for _, copies := range [][]node{u.Old, u.New} {
		for _, c := range copies {
			if n := installedName(c.Path); n != "" && !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
	}
	for _, side := range []struct {
		name string
		root map[string]any
	}{{"head", headRoot}, {"base", baseRoot}} {
		for _, section := range depSections {
			value, ok := side.root[section]
			if !ok {
				continue
			}
			deps, isObject := value.(map[string]any)
			if !isObject {
				return fmt.Sprintf("%s at %s is not an object", section, side.name)
			}
			for _, n := range names {
				if _, ok := deps[n]; ok {
					return fmt.Sprintf("in %s at %s", section, side.name)
				}
			}
		}
	}
	return ""
}

// orNew shows a From version, which is empty for a new name.
func orNew(from string) string {
	if from == "" {
		return "(new)"
	}
	return show(from)
}

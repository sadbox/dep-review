package gomod

import (
	"bytes"
	"fmt"
	"go/version"
	"path"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"

	"github.com/sadbox/dep-review/internal/facts"
)

const (
	// regularFile is git's mode for a plain, non-executable file. A go.mod
	// or go.sum that is a symlink, a submodule or executable is not one.
	regularFile = "100644"
	// maxManifest bounds a go.mod or go.sum the gatherer parses. Real ones
	// are a few hundred kilobytes at most.
	maxManifest = 8 << 20
	// oldestGo is the first go version whose go.mod lists every module
	// that provides a package to the build. Below it a version can move
	// without go.mod showing it, so go.mod is not the whole change set.
	oldestGo = "go1.17"
	// sourceManifests is the Source of every fact read from the two files.
	sourceManifests = "go.mod and go.sum at the base and head commits"
)

// update is one module the pull request moves to another version or adds.
type update struct {
	name string
	// from is the version required at base; empty when base does not
	// require the module.
	from string
	to   string
}

// changeSet is what base and head go.mod and go.sum say the pull request
// does. It is computed from the two files alone.
type changeSet struct {
	// updates is every moved and added require, direct and indirect,
	// sorted by module path.
	updates []update
	// removed is every module base requires and head does not, sorted.
	// Nothing new runs because of a removal, so it has no facts.
	removed []string
	// baseSum and headSum are the hashes go.sum pins at each commit, by
	// sumKey. Both are nil when the pull request does not change go.sum:
	// the gatherer is only given files that differ.
	baseSum, headSum map[string]string
}

// readChange checks the pull request's files against the Go shape and
// computes the change set. A non-empty problem says why Shape does not
// hold; the change set is then not to be used.
func readChange(files []facts.File) (cs changeSet, problem string) {
	mod, sum, problem := manifests(files)
	if problem != "" {
		return cs, problem
	}

	base, err := parseMod(mod.Base)
	if err != nil {
		return cs, "go.mod at base: " + err.Error()
	}
	head, err := parseMod(mod.Head)
	if err != nil {
		return cs, "go.mod at head: " + err.Error()
	}
	if problem := otherChanges(base, head); problem != "" {
		return cs, problem
	}
	cs.updates, cs.removed, problem = diffRequires(base, head)
	if problem != "" {
		return cs, problem
	}

	if sum == nil {
		return cs, ""
	}
	if cs.baseSum, err = parseSum(sum.Base); err != nil {
		return cs, "go.sum at base: " + err.Error()
	}
	if cs.headSum, err = parseSum(sum.Head); err != nil {
		return cs, "go.sum at head: " + err.Error()
	}
	return cs, sumProblem(cs)
}

// manifests picks go.mod and go.sum out of the changed files. Shape is
// about there being nothing else: one directory's go.mod, with or without
// its go.sum, both plain files at both commits.
func manifests(files []facts.File) (mod, sum *facts.File, problem string) {
	if len(files) == 0 {
		return nil, nil, "the pull request changes no file"
	}
	dir := path.Dir(files[0].Path)
	for i := range files {
		f := &files[i]
		name := path.Base(f.Path)
		switch {
		case name != "go.mod" && name != "go.sum":
			return nil, nil, fmt.Sprintf("changes %s, which is not go.mod or go.sum", show(f.Path))
		case path.Dir(f.Path) != dir:
			return nil, nil, fmt.Sprintf("changes Go files in more than one directory (%s and %s)", show(dir), show(path.Dir(f.Path)))
		case f.BaseMode != regularFile || f.HeadMode != regularFile:
			return nil, nil, fmt.Sprintf("%s is not a regular file at both commits (mode %s at base, %s at head)", show(f.Path), show(f.BaseMode), show(f.HeadMode))
		case len(f.Base) > maxManifest || len(f.Head) > maxManifest:
			return nil, nil, fmt.Sprintf("%s is larger than the gate reads", show(f.Path))
		case name == "go.mod" && mod != nil, name == "go.sum" && sum != nil:
			return nil, nil, fmt.Sprintf("%s is listed twice", show(f.Path))
		case name == "go.mod":
			mod = f
		default:
			sum = f
		}
	}
	if mod == nil {
		return nil, nil, "go.sum changes and go.mod does not"
	}
	return mod, sum, ""
}

// require is one require line.
type require struct {
	version  string
	indirect bool
}

// modFile is the part of a go.mod the gatherer compares.
type modFile struct {
	// requires is every require line by module path.
	requires map[string]require
	// goVersion and toolchain are the go and toolchain lines, without
	// the directive; empty when the line is absent.
	goVersion string
	toolchain string
	// rest is the file with every require, go and toolchain line taken
	// out, as x/mod formats it. Base and head must agree on it byte for
	// byte, so a directive this package never heard of cannot change
	// unseen.
	rest []byte
}

// canonicalVersion is the version fixer handed to x/mod. Left to itself
// x/mod reads "v1.2" as v1.2.0 and drops build metadata. The go command
// never writes either, and the version the facts are gathered for must
// be the one a person sees in the diff.
func canonicalVersion(path, version string) (string, error) {
	if module.CanonicalVersion(version) != version {
		return "", fmt.Errorf("version %q is not in canonical form", version)
	}
	return version, nil
}

// parseMod reads a go.mod with x/mod's strict parser, which refuses
// directives it does not know.
func parseMod(data []byte) (modFile, error) {
	f, err := modfile.Parse("go.mod", data, canonicalVersion)
	if err != nil {
		return modFile{}, fmt.Errorf("does not parse: %s", show(err.Error()))
	}
	if f.Module == nil {
		return modFile{}, fmt.Errorf("has no module line")
	}
	m := modFile{requires: map[string]require{}}
	if f.Go != nil {
		m.goVersion = f.Go.Version
	}
	if f.Toolchain != nil {
		m.toolchain = f.Toolchain.Name
	}
	for _, r := range f.Require {
		// The go command keeps the last of two lines for one module; the
		// gate does not guess which one the author meant.
		if _, dup := m.requires[r.Mod.Path]; dup {
			return modFile{}, fmt.Errorf("requires %s twice", show(r.Mod.Path))
		}
		if err := module.Check(r.Mod.Path, r.Mod.Version); err != nil {
			return modFile{}, fmt.Errorf("has an invalid require: %s", show(err.Error()))
		}
		m.requires[r.Mod.Path] = require{version: r.Mod.Version, indirect: r.Indirect}
	}

	f.SetRequire(nil)
	f.DropGoStmt()
	f.DropToolchainStmt()
	f.Cleanup()
	m.rest = modfile.Format(f.Syntax)
	return m, nil
}

// otherChanges reports a change outside the require versions: anything
// in the rest of the file, or a go or toolchain line that does not only
// go up.
func otherChanges(base, head modFile) string {
	if !bytes.Equal(base.rest, head.rest) {
		return "go.mod changes something other than require lines and the go and toolchain lines" + firstDifference(base.rest, head.rest)
	}

	baseGo, headGo := "go"+base.goVersion, "go"+head.goVersion
	if !version.IsValid(baseGo) || version.Compare(baseGo, oldestGo) < 0 {
		return fmt.Sprintf("go.mod at base has go line %s; below 1.17 go.mod does not list every module the build uses", show(base.goVersion))
	}
	if !version.IsValid(headGo) || version.Compare(headGo, baseGo) < 0 {
		return fmt.Sprintf("the go line does not stay or go up (%s to %s)", show(base.goVersion), show(head.goVersion))
	}
	if head.toolchain == base.toolchain {
		return ""
	}
	// A new toolchain name must be a plain release: a name with a suffix
	// selects a custom toolchain.
	if head.toolchain != "" && (!version.IsValid(head.toolchain) || strings.Contains(head.toolchain, "-")) {
		return fmt.Sprintf("the toolchain line changes to %s, which is not a plain go release", show(head.toolchain))
	}
	// The go command drops the toolchain line once the go line has caught
	// up with it, so the line itself may disappear. What must not go down
	// is the toolchain the file asks for: the newer of the two lines.
	if version.Compare(minimumToolchain(head), minimumToolchain(base)) < 0 {
		return fmt.Sprintf("the toolchain go.mod asks for goes down (%s to %s)", show(minimumToolchain(base)), show(minimumToolchain(head)))
	}
	return ""
}

// minimumToolchain is the toolchain a go.mod asks for: the newer of its
// go line and its toolchain line.
func minimumToolchain(m modFile) string {
	g := "go" + m.goVersion
	if m.toolchain != "" && version.Compare(m.toolchain, g) > 0 {
		return m.toolchain
	}
	return g
}

// firstDifference names the first line two formatted files disagree on,
// for the Shape fact's value.
func firstDifference(base, head []byte) string {
	b := strings.Split(string(base), "\n")
	h := strings.Split(string(head), "\n")
	for i := 0; i < len(b) || i < len(h); i++ {
		var bl, hl string
		if i < len(b) {
			bl = b[i]
		}
		if i < len(h) {
			hl = h[i]
		}
		if bl != hl {
			return fmt.Sprintf(": base has %s where head has %s", show(bl), show(hl))
		}
	}
	return ""
}

// diffRequires computes the change set from the two require lists. Only
// versions may differ on a module both commits require: its indirect
// marker says whether the repository's own code imports it, which a pull
// request that touches no code cannot change.
func diffRequires(base, head modFile) (updates []update, removed []string, problem string) {
	for _, name := range sortedKeys(head.requires) {
		h := head.requires[name]
		b, atBase := base.requires[name]
		switch {
		case !atBase:
			updates = append(updates, update{name: name, to: h.version})
		case b.indirect != h.indirect:
			return nil, nil, fmt.Sprintf("go.mod changes the // indirect marker of %s", show(name))
		case b.version != h.version:
			updates = append(updates, update{name: name, from: b.version, to: h.version})
		}
	}
	for _, name := range sortedKeys(base.requires) {
		if _, atHead := head.requires[name]; !atHead {
			removed = append(removed, name)
		}
	}
	return updates, removed, ""
}

// sumLine is the one shape a go.sum line may have: a module path, a
// version (with "/go.mod" when the hash is of the go.mod file alone) and
// an h1 hash, which is 32 bytes in base64, separated by single spaces.
var sumLine = regexp.MustCompile(`^([^ \t\r\n]+) ([^ \t\r\n/]+)(/go\.mod)? (h1:[A-Za-z0-9+/]{43}=)$`)

// sumKey is the key of a go.sum hash: of the module zip, or of the go.mod
// file alone.
func sumKey(name, version string, goMod bool) string {
	if goMod {
		return name + " " + version + "/go.mod"
	}
	return name + " " + version
}

// parseSum reads a go.sum by exact line shape. A file with any other
// line, or with two hashes for one key, is not read at all.
func parseSum(data []byte) (map[string]string, error) {
	sums := map[string]string{}
	if len(data) == 0 {
		return sums, nil
	}
	if data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("does not end in a newline")
	}
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	for i, line := range lines {
		m := sumLine.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("line %d is not \"module version h1:hash\"", i+1)
		}
		name, ver, hash := m[1], m[2], m[4]
		// module.Check accepts "v1.2" for v1.2.0; the go command only
		// ever writes the canonical form.
		if module.Check(name, ver) != nil || module.CanonicalVersion(ver) != ver {
			return nil, fmt.Errorf("line %d does not name a module version", i+1)
		}
		key := sumKey(name, ver, m[3] != "")
		if old, ok := sums[key]; ok && old != hash {
			return nil, fmt.Errorf("has two hashes for %s", show(key))
		}
		sums[key] = hash
	}
	return sums, nil
}

// sumProblem checks the go.sum change: a hash that is already pinned must
// not change. Lines may be added and removed freely otherwise. The go
// command also records hashes for modules go.mod does not list (it reads
// the go.mod of every module in the graph, and the zip of a module whose
// path is a prefix of an imported package), so a new line that belongs to
// no moved require is ordinary: real Dependabot pull requests have one
// now and then. Only the hashes of the versions go.mod moves to are checked
// against the checksum database, by the Bound fact.
func sumProblem(cs changeSet) string {
	for _, key := range sortedKeys(cs.headSum) {
		if old, atBase := cs.baseSum[key]; atBase && old != cs.headSum[key] {
			return fmt.Sprintf("go.sum changes the hash it pins for %s", show(key))
		}
	}
	return ""
}

// sortedKeys returns the keys of m in order, so problems and updates
// come out the same way every time.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// show quotes text that came from the pull request or from a tool for a
// fact's value: one line, control characters escaped, clipped. The value
// is shown to a person; it never decides anything.
func show(s string) string {
	const max = 200
	if len(s) > max {
		s = s[:max] + "..."
	}
	q := fmt.Sprintf("%+q", s)
	return q[1 : len(q)-1]
}

package npm

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// lsNode is one package in npm's printed tree. Only the fields the
// gatherer decides on are declared; npm prints many more, and with --long
// it copies every member of the lock entry into the node.
type lsNode struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	// Path is the absolute directory the package would be installed in.
	// npm sets it after copying the lock entry, so the lock cannot.
	Path             string `json:"path"`
	InBundle         bool   `json:"inBundle"`
	HasInstallScript bool   `json:"hasInstallScript"`
	Extraneous       bool   `json:"extraneous"`
	Missing          bool   `json:"missing"`

	// The rest is looked at only for being there.
	Invalid  jsontext.Value `json:"invalid"`
	Problems jsontext.Value `json:"problems"`
	Error    jsontext.Value `json:"error"`

	Dependencies map[string]*lsNode `json:"dependencies"`
}

// node is one lock entry as npm reads it.
type node struct {
	// Path is the lock's key for the entry, which is also where npm
	// installs it: "node_modules/a/node_modules/@scope/b".
	Path      string
	Name      string
	Version   string
	Resolved  string
	Integrity string
	// InBundle: the package's bytes are inside its parent's tarball. The
	// entry has no source or hash of its own.
	InBundle bool
	// HasInstallScript is the lock's flag. npm ci only looks for install
	// scripts in a package whose entry has it.
	HasInstallScript bool
	// Fixed is the lock's own text of the entry's members that decide
	// what is installed or run (entryKeys). An entry that keeps its
	// version must keep all of it.
	Fixed string
}

// readTree turns one npm run into the nodes by lock path, and the reasons
// npm's reading cannot be used. side is "base" or "head", for the
// problems' wording. lock is the same lock as the gate read it.
func readTree(side string, out lsOutput, lock lockFile) (map[string]node, []string) {
	if out.Truncated {
		return nil, []string{fmt.Sprintf("%s: npm ls printed more than %d MB", side, maxLSBytes>>20)}
	}
	var root lsNode
	if err := json.Unmarshal(out.Stdout, &root); err != nil {
		return nil, []string{fmt.Sprintf("%s: npm ls (exit %d) did not print a tree the gate can read: %s", side, out.Exit, quote(err.Error()))}
	}
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, side+": "+fmt.Sprintf(format, args...))
	}
	if present(root.Error) {
		// npm's own error object ("code": "ELSPROBLEMS", and a summary),
		// on one line.
		_ = root.Error.Compact()
		add("npm ls failed: %s", quote(string(root.Error)))
	}
	if out.Exit != 0 {
		add("npm ls exited with status %d", out.Exit)
	}
	if present(root.Problems) {
		add("npm reports problems with the lock: %s", quote(string(root.Problems)))
	}
	if root.Path == "" {
		add("npm ls printed no project path")
		return nil, problems
	}

	nodes := map[string]node{}
	var walk func(parent *lsNode)
	walk = func(parent *lsNode) {
		for _, dep := range slices.Sorted(maps.Keys(parent.Dependencies)) {
			n := parent.Dependencies[dep]
			if n == nil {
				add("npm printed no package for the dependency %s", show(dep))
				continue
			}
			if n.Missing {
				add("the dependency %s is missing from the lock", show(dep))
				continue
			}
			// The lock key is the install path below the project. A path
			// that is not below it is an entry such as "../x".
			rel, below := strings.CutPrefix(n.Path, root.Path+"/")
			if !below || rel == "" {
				add("npm printed %s outside the project", show(dep))
				continue
			}
			if n.Extraneous {
				add("%s is extraneous: nothing depends on it", show(rel))
			}
			if present(n.Invalid) {
				add("%s does not satisfy what depends on it", show(rel))
			}
			if present(n.Problems) {
				add("npm reports a problem with %s", show(rel))
			}
			if n.Name == "" || n.Version == "" {
				add("the lock entry %s has no name or version", show(rel))
				continue
			}
			got := node{
				Path:             rel,
				Name:             n.Name,
				Version:          n.Version,
				Resolved:         n.Resolved,
				Integrity:        n.Integrity,
				InBundle:         n.InBundle,
				HasInstallScript: n.HasInstallScript,
				Fixed:            lock.Fixed[rel],
			}
			// npm prints a package once for every dependent. The repeats
			// must say the same thing.
			if seen, ok := nodes[rel]; ok && seen != got {
				add("npm printed %s twice with different contents", show(rel))
			}
			nodes[rel] = got
			walk(n)
		}
	}
	walk(&root)
	return nodes, problems
}

// entryKeys is the closed set of members a lock entry may have, and what
// a change to each means on an entry that keeps its version: true, the
// member decides what is installed or run and the change is a Shape
// problem; false, the change is ignored.
//
// The set is what npm 9 to 11 write into a "packages" entry: the fields
// npm's documentation of package-lock.json lists, and the rest of what
// arborist copies from the package's package.json (Shrinkwrap.metaFromNode
// in npm 9.9.4, 10.9.11 and 11.20.0). It is closed because npm takes the
// whole entry for the package's package.json: npm ci ran a postinstall
// that was added to an entry as "scripts" (seen with npm 11.20.0), and
// arborist's rebuild step reads "gypfile" from the same object. A member
// that is not here is for a person, and so is one a later npm starts to
// write, until it is given a row.
//
// Two members npm does write are left out: "extraneous" (a package
// nothing depends on) and "devDependencies" (a workspace member). A lock
// that has either has no Shape.
var entryKeys = map[string]bool{
	"version":   true,
	"resolved":  true,
	"integrity": true,
	// A link installs another directory, and a name makes the entry an
	// alias: the package is not the one its path names.
	"link":             true,
	"name":             true,
	"inBundle":         true,
	"hasInstallScript": true,
	// The package brings a lock of its own, which npm follows for what is
	// below it.
	"hasShrinkwrap":      true,
	"bundleDependencies": true,
	// Not known to be inert for a dependency, so it must not change.
	"workspaces": true,

	// Ranges: what they select is in the entries themselves.
	"dependencies":         false,
	"optionalDependencies": false,
	"peerDependencies":     false,
	"peerDependenciesMeta": false,
	"acceptDependencies":   false,
	// Why the package is in the tree, and where it can be installed.
	"dev":         false,
	"optional":    false,
	"devOptional": false,
	"peer":        false,
	"os":          false,
	"cpu":         false,
	"libc":        false,
	"engines":     false,
	// Facts about the version that the registry can change after it was
	// published, and names for files that are in the pinned tarball.
	"deprecated": false,
	"funding":    false,
	"license":    false,
	"bin":        false,
}

// lockFile is what the gatherer reads of package-lock.json itself. npm
// reads the rest.
type lockFile struct {
	// Version is lockfileVersion: 2 or 3.
	Version int
	// Fixed has every key of "packages" other than the root's "", with
	// the entry's members that entryKeys marks, in the lock's own words.
	Fixed map[string]string
	// Root is the root entry, packages[""]: the lock's copy of
	// package.json's dependency ranges.
	Root map[string]any
}

// readLock reads what the gatherer needs from the lock file's own JSON.
// The string is why the lock is not one the gate reads.
func readLock(data []byte) (lockFile, string) {
	var raw struct {
		LockfileVersion jsontext.Value            `json:"lockfileVersion"`
		Packages        map[string]jsontext.Value `json:"packages"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return lockFile{}, "package-lock.json is not JSON the gate can read: " + quote(err.Error())
	}
	lf := lockFile{Fixed: map[string]string{}}
	// npm reads a version 1 lock without a word, and a yarn.lock is not
	// JSON at all. Only the exact numbers 2 and 3 pass.
	switch string(raw.LockfileVersion) {
	case "2":
		lf.Version = 2
	case "3":
		lf.Version = 3
	default:
		return lockFile{}, "package-lock.json has lockfileVersion " + quote(string(raw.LockfileVersion)) + "; the gate reads 2 and 3"
	}
	rootRaw, ok := raw.Packages[""]
	if !ok {
		return lockFile{}, "package-lock.json has no root entry in \"packages\""
	}
	if err := json.Unmarshal(rootRaw, &lf.Root); err != nil || lf.Root == nil {
		return lockFile{}, "package-lock.json's root entry is not an object"
	}
	for _, key := range slices.Sorted(maps.Keys(raw.Packages)) {
		if key == "" {
			continue
		}
		var members map[string]jsontext.Value
		if err := json.Unmarshal(raw.Packages[key], &members); err != nil || members == nil {
			return lockFile{}, "the lock entry " + show(key) + " is not an object"
		}
		var fixed strings.Builder
		for _, name := range slices.Sorted(maps.Keys(members)) {
			decides, known := entryKeys[name]
			if !known {
				return lockFile{}, fmt.Sprintf("the lock entry %s has a member npm does not write, %s", show(key), show(name))
			}
			if !decides {
				continue
			}
			// The canonical form, so that only a change of the value is
			// a change, and not how it is laid out.
			value := members[name]
			if err := value.Canonicalize(); err != nil {
				return lockFile{}, fmt.Sprintf("%s of the lock entry %s cannot be read: %s", name, show(key), quote(err.Error()))
			}
			fixed.WriteString(name + "=" + string(value) + "\n")
		}
		lf.Fixed[key] = fixed.String()
	}
	return lf, ""
}

// unlisted returns the lock keys npm did not print and the paths npm
// printed that are not lock keys. Both are empty for a lock npm read in
// full.
func unlisted(lock lockFile, nodes map[string]node) (notPrinted, notInLock []string) {
	for _, key := range slices.Sorted(maps.Keys(lock.Fixed)) {
		if _, ok := nodes[key]; !ok {
			notPrinted = append(notPrinted, show(key))
		}
	}
	for _, path := range slices.Sorted(maps.Keys(nodes)) {
		if _, ok := lock.Fixed[path]; !ok {
			notInLock = append(notInLock, show(path))
		}
	}
	return notPrinted, notInLock
}

// present reports whether a field npm or the registry printed is there
// and is neither null nor false. Any other value counts, whatever its
// type.
func present(raw jsontext.Value) bool {
	switch strings.TrimSpace(string(raw)) {
	case "", "null", "false":
		return false
	}
	return true
}

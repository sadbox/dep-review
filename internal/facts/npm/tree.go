package npm

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"strings"
)

// lsNode is one package in npm's printed tree. Only the fields the
// gatherer decides on are declared; npm prints many more, and with --long
// it copies every field of the lock entry into the node.
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
	Invalid             jsontext.Value `json:"invalid"`
	Problems            jsontext.Value `json:"problems"`
	Error               jsontext.Value `json:"error"`
	Scripts             jsontext.Value `json:"scripts"`
	BundleDependencies  jsontext.Value `json:"bundleDependencies"`
	BundledDependencies jsontext.Value `json:"bundledDependencies"`

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
	// Bundles: the entry declares bundled dependencies.
	Bundles bool
}

// readTree turns one npm run into the nodes by lock path, and the reasons
// npm's reading cannot be used. side is "base" or "head", for the
// problems' wording.
func readTree(side string, out lsOutput) (map[string]node, []string) {
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
		add("npm ls failed: %s", npmErrorCode(root.Error))
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
		for _, dep := range sortedKeys(parent.Dependencies) {
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
			// npm never writes "scripts" into a lock entry, and npm ci
			// runs the ones it finds there, whatever the package's own
			// package.json says (seen with npm 11.20.0: a postinstall
			// added to a lock entry ran). No fact covers such a script.
			if present(n.Scripts) {
				add("the lock entry %s carries scripts", show(rel))
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
				Bundles:          declaresBundle(n.BundleDependencies) || declaresBundle(n.BundledDependencies),
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

// npmErrorCode is the code of npm's error object ("ELSPROBLEMS",
// "ENOLOCK"), or a placeholder when it has none the gate would print.
func npmErrorCode(raw jsontext.Value) string {
	var e struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(raw, &e); err != nil || !npmCodeRE.MatchString(e.Code) {
		return "an error without a code"
	}
	return e.Code
}

// lockFile is what the gatherer reads of package-lock.json itself. npm
// reads the rest.
type lockFile struct {
	// Version is lockfileVersion: 2 or 3.
	Version int
	// Keys are the keys of "packages" other than the root's "".
	Keys []string
	// Root is the root entry, packages[""]: the lock's copy of
	// package.json's dependency ranges.
	Root map[string]any
}

// readLock reads the three things the gatherer needs from the lock file's
// own JSON. The string is why the lock is not one the gate reads.
func readLock(data []byte) (lockFile, string) {
	var raw struct {
		LockfileVersion jsontext.Value            `json:"lockfileVersion"`
		Packages        map[string]jsontext.Value `json:"packages"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return lockFile{}, "package-lock.json is not JSON the gate can read: " + quote(err.Error())
	}
	var lf lockFile
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
	for _, key := range sortedKeys(raw.Packages) {
		if key != "" {
			lf.Keys = append(lf.Keys, key)
		}
	}
	return lf, ""
}

// unlisted returns the lock keys npm did not print and the paths npm
// printed that are not lock keys. Both are empty for a lock npm read in
// full.
func unlisted(lock lockFile, nodes map[string]node) (notPrinted, notInLock []string) {
	inLock := map[string]bool{}
	for _, key := range lock.Keys {
		inLock[key] = true
		if _, ok := nodes[key]; !ok {
			notPrinted = append(notPrinted, show(key))
		}
	}
	for _, path := range sortedKeys(nodes) {
		if !inLock[path] {
			notInLock = append(notInLock, show(path))
		}
	}
	return notPrinted, notInLock
}

// present reports whether a field npm printed is there and is neither
// null nor false. Any other value counts, whatever its type.
func present(raw jsontext.Value) bool {
	switch strings.TrimSpace(string(raw)) {
	case "", "null", "false":
		return false
	}
	return true
}

// declaresBundle reports whether a bundleDependencies value bundles
// anything. npm writes a list of names; true means "all dependencies".
// Only absent, null, false and the empty list bundle nothing.
func declaresBundle(raw jsontext.Value) bool {
	if !present(raw) {
		return false
	}
	var names []jsontext.Value
	if err := json.Unmarshal(raw, &names); err == nil && len(names) == 0 {
		return false
	}
	return true
}

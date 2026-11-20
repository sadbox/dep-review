package npm

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Entry is one installed package in a lockfile.
type Entry struct {
	Location  string // package-lock "node_modules/a/node_modules/b"; yarn: the first spec
	Name      string
	Version   string
	Resolved  string
	Integrity string
	Link      bool // workspace symlink (package-lock "link": true)
	Bundled   bool // shipped inside its parent's tarball
}

// Lock is a parsed lockfile plus the root manifest's direct dependencies.
type Lock struct {
	Kind    string // "npm" or "yarn"
	Entries []Entry
	Direct  map[string]bool
}

// ParsePackageLock parses package-lock.json / npm-shrinkwrap.json with
// lockfileVersion 2 or 3 (the "packages" map). Version 1 lockfiles carry no
// per-location data the gate relies on and are rejected.
func ParsePackageLock(data []byte) (*Lock, error) {
	var raw struct {
		LockfileVersion int `json:"lockfileVersion"`
		Packages        map[string]struct {
			Name                 string            `json:"name"`
			Version              string            `json:"version"`
			Resolved             string            `json:"resolved"`
			Integrity            string            `json:"integrity"`
			Link                 bool              `json:"link"`
			InBundle             bool              `json:"inBundle"`
			Dependencies         map[string]string `json:"dependencies"`
			DevDependencies      map[string]string `json:"devDependencies"`
			OptionalDependencies map[string]string `json:"optionalDependencies"`
			PeerDependencies     map[string]string `json:"peerDependencies"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("package-lock.json: %w", err)
	}
	if raw.LockfileVersion < 2 || raw.Packages == nil {
		return nil, fmt.Errorf("package-lock.json: lockfileVersion %d is not supported (need 2 or 3)", raw.LockfileVersion)
	}
	l := &Lock{Kind: "npm", Direct: map[string]bool{}}
	if root, ok := raw.Packages[""]; ok {
		for _, m := range []map[string]string{root.Dependencies, root.DevDependencies, root.OptionalDependencies, root.PeerDependencies} {
			for k := range m {
				l.Direct[k] = true
			}
		}
	}
	for loc, p := range raw.Packages {
		if loc == "" {
			continue
		}
		i := strings.LastIndex(loc, "node_modules/")
		if i < 0 {
			// A workspace's own directory entry ("packages/x"); its
			// node_modules/ link entry is what gets installed.
			continue
		}
		name := loc[i+len("node_modules/"):]
		if p.Name != "" && !p.Link {
			name = p.Name // npm alias: "node_modules/alias" installs package "name"
		}
		l.Entries = append(l.Entries, Entry{
			Location: loc, Name: name, Version: p.Version,
			Resolved: p.Resolved, Integrity: p.Integrity, Link: p.Link, Bundled: p.InBundle,
		})
	}
	sort.Slice(l.Entries, func(i, j int) bool { return l.Entries[i].Location < l.Entries[j].Location })
	return l, nil
}

// ParseYarnLock parses a yarn v1 lockfile. Yarn 2+ ("__metadata:") is
// rejected.
func ParseYarnLock(data []byte) (*Lock, error) {
	l := &Lock{Kind: "yarn", Direct: map[string]bool{}}
	var cur *Entry
	flush := func() {
		if cur != nil {
			l.Entries = append(l.Entries, *cur)
			cur = nil
		}
	}
	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			flush()
			if strings.HasPrefix(line, "__metadata:") {
				return nil, fmt.Errorf("yarn.lock: Yarn 2+ (berry) lockfiles are not supported")
			}
			if !strings.HasSuffix(line, ":") {
				return nil, fmt.Errorf("yarn.lock:%d: expected a package header", n+1)
			}
			specs := strings.Split(strings.TrimSuffix(line, ":"), ",")
			first, err := unquoteYarn(strings.TrimSpace(specs[0]))
			if err != nil {
				return nil, fmt.Errorf("yarn.lock:%d: %w", n+1, err)
			}
			at := strings.LastIndex(first, "@")
			if at <= 0 {
				return nil, fmt.Errorf("yarn.lock:%d: spec %q has no version range", n+1, first)
			}
			cur = &Entry{Location: first, Name: first[:at]}
			continue
		}
		if cur == nil || strings.HasPrefix(line, "    ") {
			continue // dependency lists under a field
		}
		key, val, _ := strings.Cut(strings.TrimSpace(line), " ")
		v, err := unquoteYarn(strings.TrimSpace(val))
		if err != nil {
			return nil, fmt.Errorf("yarn.lock:%d: %w", n+1, err)
		}
		switch key {
		case "version":
			cur.Version = v
		case "resolved":
			cur.Resolved = v
		case "integrity":
			cur.Integrity = v
		}
	}
	flush()
	return l, nil
}

func unquoteYarn(s string) (string, error) {
	if strings.HasPrefix(s, `"`) {
		return strconv.Unquote(s)
	}
	return s, nil
}

// ManifestDirect returns the dependency names declared in a package.json.
func ManifestDirect(data []byte) (map[string]bool, error) {
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, d := range []map[string]string{m.Dependencies, m.DevDependencies, m.OptionalDependencies, m.PeerDependencies} {
		for k := range d {
			out[k] = true
		}
	}
	return out, nil
}

// manifest is the part of a package.json the checks read.
type manifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Scripts              map[string]string `json:"scripts"`
	Bin                  json.RawMessage   `json:"bin"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	BundleDependencies   json.RawMessage   `json:"bundleDependencies"`
	BundledDependencies  json.RawMessage   `json:"bundledDependencies"`
	Gypfile              *bool             `json:"gypfile"`
}

// bins normalizes "bin" (a string or a map) to name -> path.
func (m manifest) bins() map[string]string {
	out := map[string]string{}
	if len(m.Bin) == 0 {
		return out
	}
	var s string
	if json.Unmarshal(m.Bin, &s) == nil {
		name := m.Name
		if i := strings.LastIndex(name, "/"); i >= 0 {
			name = name[i+1:]
		}
		out[name] = s
		return out
	}
	_ = json.Unmarshal(m.Bin, &out)
	return out
}

// runtimeDeps is every dependency npm installs for this package.
func (m manifest) runtimeDeps() map[string]bool {
	out := map[string]bool{}
	for _, d := range []map[string]string{m.Dependencies, m.OptionalDependencies, m.PeerDependencies} {
		for k := range d {
			out[k] = true
		}
	}
	for _, raw := range []json.RawMessage{m.BundleDependencies, m.BundledDependencies} {
		var list []string
		if json.Unmarshal(raw, &list) == nil {
			for _, k := range list {
				out[k] = true
			}
		}
	}
	return out
}

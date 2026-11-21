package npm

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/sadbox/dep-review/internal/strictjson"
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

// errAmbiguous marks lockfile or manifest content that npm or yarn could
// read differently from the gate. It routes to RouteRefuse, unlike a
// merely unsupported lockfile (RouteHuman).
var errAmbiguous = errors.New("ambiguous")

func ambiguous(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errAmbiguous, fmt.Sprintf(format, args...))
}

// isAmbiguous: a strictjson rejection or an ambiguous lockfile.
func isAmbiguous(err error) bool {
	return errors.Is(err, errAmbiguous) || errors.Is(err, strictjson.ErrRejected)
}

type lockPackage struct {
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
}

// ParsePackageLock parses package-lock.json / npm-shrinkwrap.json with
// lockfileVersion 2 or 3 (the "packages" map). Version 1 lockfiles carry no
// per-location data the gate relies on and are rejected.
func ParsePackageLock(data []byte) (*Lock, error) { return parsePackageLock(data, nil) }

// parsePackageLock is ParsePackageLock with the workspaces globs of the
// root package.json (see Workspaces).
func parsePackageLock(data []byte, workspaces []string) (*Lock, error) {
	var raw struct {
		LockfileVersion int                    `json:"lockfileVersion"`
		Packages        map[string]lockPackage `json:"packages"`
	}
	if err := strictjson.Unmarshal(data, &raw); err != nil {
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
	// Entries outside node_modules/ are not installed from the registry,
	// so the gate does not verify them. Only two kinds are legitimate: a
	// workspace the root package.json declares, and the target of a link
	// entry ("node_modules/x": {"link": true, "resolved": "packages/x"}).
	// Anything else fails closed, whatever it carries.
	linkTargets := map[string]bool{}
	for loc, p := range raw.Packages {
		if p.Link && strings.Contains(loc, "node_modules/") {
			linkTargets[p.Resolved] = true
		}
	}
	local := func(dir string) bool {
		if linkTargets[dir] {
			return true
		}
		for _, g := range workspaces {
			if ok, err := path.Match(path.Clean(g), dir); err == nil && ok && path.Clean(dir) == dir {
				return true
			}
		}
		return false
	}
	for loc, p := range raw.Packages {
		if loc == "" {
			continue
		}
		first := strings.Index(loc, "node_modules/")
		if first < 0 {
			if !local(loc) {
				return nil, ambiguous("package-lock.json: %q is neither under node_modules/, a declared workspace, nor a link target", loc)
			}
			// A workspace's own directory entry; its node_modules/ link
			// entry is what gets installed. It never carries a download.
			if p.Resolved != "" || p.Integrity != "" {
				return nil, ambiguous("package-lock.json: %q is not under node_modules/ but has resolved/integrity", loc)
			}
			continue
		}
		if prefix := strings.TrimSuffix(loc[:first], "/"); prefix != "" && (!strings.HasSuffix(loc[:first], "/") || !local(prefix)) {
			// "packages/x/node_modules/y" is the workspace's own dependency;
			// "elsewhere/node_modules/y" is not something npm ci lays out.
			return nil, ambiguous("package-lock.json: %q is under %q, which is neither a declared workspace nor a link target", loc, prefix)
		}
		i := strings.LastIndex(loc, "node_modules/")
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
// rejected as unsupported. Yarn's own parser accepts more than yarn
// writes (quoted keys, "key: value", JSON escapes, comments after values,
// repeated keys where the last wins), so anything outside exactly what
// yarn writes is an ambiguity error, never a guess:
//
//	"spec", spec:            header, column 0, every spec one package name
//	  key value              column 2: version, resolved, integrity, uid
//	  dependencies:          column 2: dependencies, optionalDependencies
//	    name range           column 4, only inside such a block
//
// A key or value may be "quoted" (no backslashes) or bare.
func ParseYarnLock(data []byte) (*Lock, error) {
	l := &Lock{Kind: "yarn", Direct: map[string]bool{}}
	var cur *Entry
	var fields map[string]bool
	inBlock := false
	specs := map[string]bool{}
	flush := func() error {
		if cur != nil {
			if cur.Version == "" {
				return ambiguous("yarn.lock: %s has no version", cur.Location)
			}
			l.Entries = append(l.Entries, *cur)
			cur = nil
		}
		return nil
	}
	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		bad := func(format string, args ...any) error {
			return ambiguous("yarn.lock:%d: %s", n+1, fmt.Sprintf(format, args...))
		}
		if strings.ContainsAny(line, "\t\r\\") {
			return nil, bad("tab, carriage return or backslash")
		}
		trimmed := strings.TrimLeft(line, " ")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		switch indent := len(line) - len(trimmed); indent {
		case 0:
			if err := flush(); err != nil {
				return nil, err
			}
			if strings.HasPrefix(line, "__metadata:") {
				return nil, fmt.Errorf("yarn.lock: Yarn 2+ (berry) lockfiles are not supported")
			}
			head, ok := strings.CutSuffix(line, ":")
			if !ok {
				return nil, bad("expected a package header")
			}
			var name string
			for i, raw := range strings.Split(head, ",") {
				tok, rest, err := yarnToken(strings.TrimLeft(raw, " "))
				if err != nil || rest != "" {
					return nil, bad("bad spec %q", raw)
				}
				pn, rng, err := splitSpec(tok)
				if err != nil {
					return nil, fmt.Errorf("yarn.lock:%d: %w", n+1, err)
				}
				if rng == "" {
					return nil, bad("spec %q has no version range", tok)
				}
				if i == 0 {
					name = pn
					cur = &Entry{Location: tok, Name: pn}
				} else if pn != name {
					return nil, bad("one entry for two packages: %q and %q", name, pn)
				}
				if specs[tok] {
					return nil, bad("spec %q appears twice", tok)
				}
				specs[tok] = true
			}
			fields, inBlock = map[string]bool{}, false
		case 2:
			if cur == nil {
				return nil, bad("field outside an entry")
			}
			key, rest, err := yarnToken(trimmed)
			if err != nil {
				return nil, bad("%v", err)
			}
			if fields[key] {
				return nil, bad("%s repeated", key)
			}
			fields[key] = true
			inBlock = false
			switch key {
			case "dependencies", "optionalDependencies":
				if rest != ":" {
					return nil, bad("%s must start a block", key)
				}
				inBlock = true
				continue
			case "version", "resolved", "integrity", "uid":
			default:
				return nil, bad("unknown field %q", key)
			}
			v, after, err := yarnToken(strings.TrimPrefix(rest, " "))
			if err != nil || after != "" || !strings.HasPrefix(rest, " ") || strings.HasPrefix(rest, "  ") {
				return nil, bad("expected `%s value`", key)
			}
			switch key {
			case "version":
				cur.Version = v
			case "resolved":
				cur.Resolved = v
			case "integrity":
				cur.Integrity = v
			}
		case 4:
			if !inBlock {
				return nil, bad("unexpected indentation")
			}
			_, rest, err := yarnToken(trimmed)
			if err == nil && strings.HasPrefix(rest, " ") && !strings.HasPrefix(rest, "  ") {
				_, rest, err = yarnToken(rest[1:])
			} else if err == nil {
				err = errors.New("expected `name range`")
			}
			if err != nil || rest != "" {
				return nil, bad("bad dependency line")
			}
		default:
			return nil, bad("unexpected indentation of %d spaces", indent)
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return l, nil
}

// yarnToken reads one quoted or bare token from the start of s and returns
// it and the rest of s.
func yarnToken(s string) (tok, rest string, err error) {
	if strings.HasPrefix(s, `"`) {
		end := strings.IndexByte(s[1:], '"')
		if end < 0 {
			return "", "", errors.New("unterminated string")
		}
		return s[1 : end+1], s[end+2:], nil
	}
	end := strings.IndexAny(s, ` ":,#`)
	if end < 0 {
		end = len(s)
	}
	if end == 0 {
		return "", "", fmt.Errorf("expected a token at %q", s)
	}
	return s[:end], s[end:], nil
}

// splitSpec splits "name@range" ("@scope/name@range").
func splitSpec(spec string) (name, rng string, err error) {
	start := 0
	if strings.HasPrefix(spec, "@") {
		start = 1
	}
	at := strings.IndexByte(spec[start:], '@')
	if at < 0 {
		return "", "", ambiguous("spec %q has no version range", spec)
	}
	at += start
	name, rng = spec[:at], spec[at+1:]
	if strings.HasPrefix(rng, "npm:") {
		return "", "", fmt.Errorf("spec %q is an npm alias, which the gate does not support in yarn.lock", spec)
	}
	return name, rng, nil
}

// ManifestDirect returns the dependency names declared in a package.json.
func ManifestDirect(data []byte) (map[string]bool, error) {
	var m manifest
	if err := strictjson.Unmarshal(data, &m); err != nil {
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
	if strictjson.Unmarshal(m.Bin, &s) == nil {
		name := m.Name
		if i := strings.LastIndex(name, "/"); i >= 0 {
			name = name[i+1:]
		}
		out[name] = s
		return out
	}
	_ = strictjson.Unmarshal(m.Bin, &out)
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
		if strictjson.Unmarshal(raw, &list) == nil {
			for _, k := range list {
				out[k] = true
			}
		}
	}
	return out
}

// Workspaces returns the "workspaces" globs of a package.json: an array,
// or {"packages": [...]} (yarn's form, which npm also reads).
func Workspaces(pkgJSON []byte) ([]string, error) {
	if pkgJSON == nil {
		return nil, nil
	}
	var m struct {
		Workspaces json.RawMessage `json:"workspaces"`
	}
	if err := strictjson.Unmarshal(pkgJSON, &m); err != nil {
		return nil, err
	}
	if len(m.Workspaces) == 0 || string(m.Workspaces) == "null" {
		return nil, nil
	}
	var list []string
	if err := strictjson.Unmarshal(m.Workspaces, &list); err == nil {
		return list, nil
	}
	var obj struct {
		Packages []string `json:"packages"`
	}
	if err := strictjson.Unmarshal(m.Workspaces, &obj); err != nil {
		return nil, fmt.Errorf("package.json workspaces: %w", err)
	}
	return obj.Packages, nil
}

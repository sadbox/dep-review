package actions

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/sadbox/dep-review/internal/strictjson"
)

// lockSet maps an npm package name to the set of versions locked for it.
type lockSet map[string]map[string]bool

// lockData is one parsed lockfile: versions by package name and, for
// path-keyed lockfiles (package-lock.json), by install path.
type lockData struct {
	names lockSet
	paths map[string]string
}

func (s lockSet) add(name, version string) {
	if name == "" || version == "" {
		return
	}
	if s[name] == nil {
		s[name] = map[string]bool{}
	}
	s[name][version] = true
}

func (s lockSet) versions(name string) []string {
	var vs []string
	for v := range s[name] {
		vs = append(vs, v)
	}
	sortVersions(vs)
	return vs
}

func sortVersions(vs []string) {
	sort.Slice(vs, func(i, j int) bool {
		a, aok := parseNPMVersion(vs[i])
		b, bok := parseNPMVersion(vs[j])
		if aok && bok {
			if c := a.cmp(b); c != 0 {
				return c < 0
			}
		}
		return vs[i] < vs[j]
	})
}

var lockBasenames = map[string]bool{
	"package-lock.json":   true,
	"npm-shrinkwrap.json": true,
	"yarn.lock":           true,
	"pnpm-lock.yaml":      true,
	"bun.lock":            true,
}

func isLockfile(p string) bool { return lockBasenames[path.Base(p)] }

// parseLockfile reads the package versions out of a lockfile. It never
// resolves or installs anything.
func parseLockfile(name string, data []byte) (*lockData, error) {
	d := &lockData{names: lockSet{}, paths: map[string]string{}}
	var err error
	switch path.Base(name) {
	case "package-lock.json", "npm-shrinkwrap.json":
		err = parseNPMLock(data, d.names, d.paths, path.Dir(name))
	case "yarn.lock":
		err = parseYarnLock(string(data), d.names)
	case "pnpm-lock.yaml":
		err = parsePNPMLock(string(data), d.names)
	default:
		err = fmt.Errorf("unsupported lockfile %s", name)
	}
	if err != nil {
		return nil, err
	}
	return d, nil
}

// changedPaths lists install paths whose version differs between two
// path maps.
func changedPaths(old, new map[string]string) map[string]bool {
	out := map[string]bool{}
	for p, v := range old {
		if new[p] != v {
			out[p] = true
		}
	}
	for p, v := range new {
		if old[p] != v {
			out[p] = true
		}
	}
	return out
}

func parseNPMLock(data []byte, s lockSet, paths map[string]string, dir string) error {
	var lf struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	// strictjson, not encoding/json: a case-folded duplicate such as
	// "version"/"Version" would otherwise pick a version npm does not read.
	if err := strictjson.Unmarshal(data, &lf); err != nil {
		return err
	}
	for k, v := range lf.Packages {
		i := strings.LastIndex(k, "node_modules/")
		if i < 0 {
			continue // the root project or a workspace
		}
		s.add(k[i+len("node_modules/"):], v.Version)
		paths[path.Join(dir, k)] = v.Version
	}
	if len(lf.Packages) == 0 {
		// lockfileVersion 1: nested "dependencies".
		var walk func(map[string]json.RawMessage) error
		walk = func(deps map[string]json.RawMessage) error {
			for name, raw := range deps {
				var d struct {
					Version      string                     `json:"version"`
					Dependencies map[string]json.RawMessage `json:"dependencies"`
				}
				if err := strictjson.Unmarshal(raw, &d); err != nil {
					return err
				}
				s.add(name, d.Version)
				if err := walk(d.Dependencies); err != nil {
					return err
				}
			}
			return nil
		}
		return walk(lf.Dependencies)
	}
	return nil
}

var (
	yarnBerryRx = regexp.MustCompile(`(?m)^\s+resolution:\s+"?(@?[^@"\s]+)@npm:([^"\s]+)"?\s*$`)
	yarnV1Head  = regexp.MustCompile(`^"?(@?[^@"\s,]+)@`)
	yarnV1Ver   = regexp.MustCompile(`^\s+version:?\s+"?([^"\s]+)"?\s*$`)
)

func parseYarnLock(text string, s lockSet) error {
	if strings.Contains(text, "__metadata:") {
		for _, m := range yarnBerryRx.FindAllStringSubmatch(text, -1) {
			s.add(m[1], m[2])
		}
		return nil
	}
	cur := ""
	for _, l := range strings.Split(text, "\n") {
		switch {
		case l == "" || strings.HasPrefix(l, "#"):
			cur = ""
		case l[0] != ' ':
			cur = ""
			if m := yarnV1Head.FindStringSubmatch(l); m != nil {
				cur = m[1]
			}
		case cur != "":
			if m := yarnV1Ver.FindStringSubmatch(l); m != nil {
				s.add(cur, m[1])
				cur = ""
			}
		}
	}
	return nil
}

func parsePNPMLock(text string, s lockSet) error {
	in := false
	for _, l := range strings.Split(text, "\n") {
		if l == "" {
			continue
		}
		if l[0] != ' ' {
			in = strings.TrimSpace(l) == "packages:"
			continue
		}
		if !in || lineIndent(l) != 2 || !strings.HasSuffix(strings.TrimSpace(l), ":") {
			continue
		}
		k := strings.TrimSuffix(strings.TrimSpace(l), ":")
		k = strings.Trim(k, `'"`)
		k = strings.TrimPrefix(k, "/")
		if i := strings.Index(k, "("); i >= 0 {
			k = k[:i] // peer-dependency suffix
		}
		if i := strings.LastIndex(k, "@"); i > 0 {
			s.add(k[:i], k[i+1:])
			continue
		}
		if i := strings.LastIndex(k, "/"); i > 0 { // pnpm v5: /name/1.2.3
			s.add(k[:i], k[i+1:])
		}
	}
	return nil
}

// pkgChange is one npm package whose locked version set changed.
type pkgChange struct {
	name      string
	old, new  []string
	added     bool // not locked before
	removed   bool // not locked after
	downgrade bool // the highest locked version went down
}

func lockChanges(old, new lockSet) []pkgChange {
	names := map[string]bool{}
	for n := range old {
		names[n] = true
	}
	for n := range new {
		names[n] = true
	}
	var out []pkgChange
	for n := range names {
		o, w := old.versions(n), new.versions(n)
		if strings.Join(o, ",") == strings.Join(w, ",") {
			continue
		}
		c := pkgChange{name: n, old: o, new: w, added: len(o) == 0, removed: len(w) == 0}
		if len(o) > 0 && len(w) > 0 {
			a, aok := parseNPMVersion(o[len(o)-1])
			b, bok := parseNPMVersion(w[len(w)-1])
			c.downgrade = aok && bok && b.cmp(a) < 0
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// pkgOf returns the npm package a bundled module path belongs to, or "" for
// first-party code.
func pkgOf(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	i := strings.LastIndex(p, "node_modules/")
	if i < 0 {
		return ""
	}
	parts := strings.Split(p[i+len("node_modules/"):], "/")
	if strings.HasPrefix(parts[0], "@") && len(parts) > 1 {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

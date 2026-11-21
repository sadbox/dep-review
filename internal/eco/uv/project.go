package uv

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/model"
)

// workspace is what the pyproject.toml files at one commit say the
// workspace's own packages are. uv.lock lists them with a virtual or
// editable source; the lock is the PR's, so the gate believes only the
// manifests.
type workspace struct {
	git     ecoutil.Git
	sha     string
	dir     string
	root    string   // normalized [project].name of dir/pyproject.toml, "" if none
	members []string // [tool.uv.workspace] members globs
	exclude []string
}

func readTOML(ctx context.Context, git ecoutil.Git, sha, p string) (map[string]any, error) {
	b, err := git.Show(ctx, sha, p)
	if errors.Is(err, ecoutil.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	doc, err := ParseTOML(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return doc, nil
}

func table(doc map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		doc, _ = doc[k].(map[string]any)
	}
	return doc
}

func stringList(v any) []string {
	list, _ := v.([]any)
	var out []string
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func loadWorkspace(ctx context.Context, git ecoutil.Git, sha, dir string) (*workspace, error) {
	w := &workspace{git: git, sha: sha, dir: dir}
	doc, err := readTOML(ctx, git, sha, path.Join(dir, "pyproject.toml"))
	if err != nil || doc == nil {
		return w, err
	}
	if n, ok := table(doc, "project")["name"].(string); ok {
		w.root = Normalize(n)
	}
	ws := table(doc, "tool", "uv", "workspace")
	w.members, w.exclude = stringList(ws["members"]), stringList(ws["exclude"])
	return w, nil
}

// checkProject explains why p, whose source is {virtual|editable = rel},
// is not the root project or a declared workspace member, or returns "".
func (w *workspace) checkProject(ctx context.Context, p Package, rel string) (string, error) {
	name := Normalize(p.Name)
	clean := path.Clean(rel)
	if clean == "." {
		if w.root == "" || name != w.root {
			return fmt.Sprintf("%s claims the workspace root, whose pyproject.toml names %q", p.Name, w.root), nil
		}
		return "", nil
	}
	if path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Sprintf("%s points outside the workspace (%q)", p.Name, rel), nil
	}
	match := func(globs []string) bool {
		for _, g := range globs {
			if ok, err := path.Match(path.Clean(g), clean); err == nil && ok {
				return true
			}
		}
		return false
	}
	if !match(w.members) || match(w.exclude) {
		return fmt.Sprintf("%s (%q) is not a declared workspace member", p.Name, rel), nil
	}
	doc, err := readTOML(ctx, w.git, w.sha, path.Join(w.dir, clean, "pyproject.toml"))
	if err != nil {
		var exit interface{ ExitCode() int }
		if errors.As(err, &exit) {
			return "", err
		}
		return fmt.Sprintf("%s: %v", p.Name, err), nil
	}
	if n, _ := table(doc, "project")["name"].(string); Normalize(n) != name {
		return fmt.Sprintf("%s: the member at %q is named %q", p.Name, rel, n), nil
	}
	return "", nil
}

// depLists are the pyproject.toml lists of requirement strings whose
// version specifiers a Dependabot update may rewrite, as paths of keys;
// "*" is every key of that table.
var depLists = [][]string{
	{"project", "dependencies"},
	{"project", "optional-dependencies", "*"},
	{"dependency-groups", "*"},
	{"tool", "uv", "dev-dependencies"},
	{"build-system", "requires"},
}

// buildRequires is the build backend's own requirement list: any change
// to it needs a person, whatever Dependabot declares.
const buildRequires = "build-system.requires"

// manifestChanges compares dir/pyproject.toml at base and head. It is
// where uv takes its build backend ([build-system]), its indexes
// ([[tool.uv.index]]) and its sources ([tool.uv.sources]) from. The
// expected change is rewriting the version of a declared update in a
// dependency list, keeping name, extras, operator and marker. Other
// dependency-list changes (another specifier form, added or removed
// requirements or groups, any [build-system] requires change) need a
// person (uv.manifest-requirement, RouteHuman). A rewrite to a version
// Dependabot did not declare, and any change outside the dependency
// lists, refuse (uv.manifest-changed).
func manifestChanges(ctx context.Context, git ecoutil.Git, base, head, dir string, declared []model.Update) ([]model.Finding, error) {
	depDir := path.Clean("/" + dir)
	p := path.Join(dir, "pyproject.toml")
	var findings []model.Finding
	refuse := func(name, format string, args ...any) {
		findings = append(findings, model.Finding{Code: "uv.manifest-changed", Route: model.RouteRefuse, Update: name,
			Detail: path.Join(depDir, "pyproject.toml") + ": " + fmt.Sprintf(format, args...)})
	}
	review := func(name, format string, args ...any) {
		findings = append(findings, model.Finding{Code: "uv.manifest-requirement", Route: model.RouteHuman, Update: name,
			Detail: path.Join(depDir, "pyproject.toml") + ": " + fmt.Sprintf(format, args...)})
	}
	var docs [2]map[string]any
	for i, sha := range []string{base, head} {
		doc, err := readTOML(ctx, git, sha, p)
		if err != nil {
			var exit interface{ ExitCode() int }
			if errors.As(err, &exit) {
				return nil, err
			}
			return []model.Finding{human("uv.manifest-unparseable", "", fmt.Sprintf("%s at %s: %v", path.Join(depDir, "pyproject.toml"), sha, err))}, nil
		}
		docs[i] = doc
	}
	bd, hd := docs[0], docs[1]
	switch {
	case bd == nil && hd == nil:
		return nil, nil
	case bd == nil:
		refuse("", "added by the PR")
		return findings, nil
	case hd == nil:
		refuse("", "deleted by the PR")
		return findings, nil
	}
	bRest, bLists := splitDeps(bd)
	hRest, hLists := splitDeps(hd)
	var changed []string
	diffPaths(bRest, hRest, "", &changed)
	for _, c := range changed {
		refuse("", "%s changed; a dependency update changes only dependency versions", c)
	}
	for _, key := range slices.Sorted(maps.Keys(ecoutil.Union(bLists, hLists))) {
		bl, inBase := bLists[key]
		hl, inHead := hLists[key]
		switch {
		case reflect.DeepEqual(bl, hl):
			continue
		case key == buildRequires:
			review("", "[build-system] requires changed")
			continue
		case !inBase || !inHead:
			review("", "%s added or removed", key)
			continue
		case len(bl) != len(hl):
			review("", "%s: requirements added or removed", key)
			continue
		}
		for i := range bl {
			if reflect.DeepEqual(bl[i], hl[i]) {
				continue
			}
			from, ok1 := bl[i].(string)
			to, ok2 := hl[i].(string)
			if !ok1 || !ok2 {
				review("", "%s[%d] changed", key, i)
				continue
			}
			switch name, route, why := requirementBump(from, to, depDir, declared); route {
			case model.RouteRefuse:
				refuse(name, "%s: %q -> %q: %s", key, from, to, why)
			case model.RouteHuman:
				review(name, "%s: %q -> %q: %s", key, from, to, why)
			}
		}
	}
	return findings, nil
}

// splitDeps returns doc without the dependency lists, and those lists by
// dotted path.
func splitDeps(doc map[string]any) (map[string]any, map[string][]any) {
	rest := deepCopy(doc).(map[string]any)
	lists := map[string][]any{}
	for _, keys := range depLists {
		last := keys[len(keys)-1]
		holder := table(rest, keys[:len(keys)-1]...)
		if holder == nil {
			continue
		}
		dotted := strings.Join(keys[:len(keys)-1], ".")
		take := func(k string) {
			if l, ok := holder[k].([]any); ok {
				lists[dotted+"."+k] = l
				delete(holder, k)
			}
		}
		if last == "*" {
			for _, k := range slices.Sorted(maps.Keys(holder)) {
				take(k)
			}
		} else {
			take(last)
		}
	}
	return rest, lists
}

func deepCopy(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = deepCopy(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = deepCopy(e)
		}
		return out
	}
	return v
}

// diffPaths lists the dotted paths at which a and b differ.
func diffPaths(a, b any, at string, out *[]string) {
	am, ok1 := a.(map[string]any)
	bm, ok2 := b.(map[string]any)
	if a == nil && ok2 {
		am, ok1 = map[string]any{}, true
	}
	if b == nil && ok1 {
		bm, ok2 = map[string]any{}, true
	}
	if !ok1 || !ok2 {
		if !reflect.DeepEqual(a, b) {
			*out = append(*out, "["+strings.TrimPrefix(at, ".")+"]")
		}
		return
	}
	for _, k := range slices.Sorted(maps.Keys(ecoutil.Union(am, bm))) {
		diffPaths(am[k], bm[k], at+"."+k, out)
	}
}

// requirementRE is a PEP 508 requirement with one version specifier.
var requirementRE = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[A-Za-z0-9._, -]*\])?\s*(===|==|~=|>=|<=|!=|>|<)\s*([0-9][0-9A-Za-z.+!_-]*)(\s*;.*)?$`)

// requirementBump returns the requirement's name and routes from -> to:
// "" for a declared update's version rewrite, RouteHuman for any other
// form, RouteRefuse for a version Dependabot did not declare. Name,
// extras, operator and marker must be unchanged, and the new version must
// be the declared one ("ansible-core==2.21.6" -> "ansible-core==2.21.7").
func requirementBump(from, to, dir string, declared []model.Update) (string, model.Route, string) {
	fm, tm := requirementRE.FindStringSubmatch(from), requirementRE.FindStringSubmatch(to)
	if fm == nil || tm == nil {
		return "", model.RouteHuman, "not a single-specifier version rewrite"
	}
	name := Normalize(tm[1])
	if fm[1] != tm[1] || fm[2] != tm[2] || fm[3] != tm[3] || fm[5] != tm[5] {
		return name, model.RouteHuman, "more than the version changed"
	}
	for _, d := range declared {
		if fetch.SameName(model.UV, d.Name, name) && sameDir(dir, d.Directory) && d.To == tm[4] {
			return name, "", ""
		}
	}
	return name, model.RouteRefuse, fmt.Sprintf("Dependabot declares no update of %s to %s in %s", name, tm[4], dir)
}

// sameDir is fetch's rule: a declaration without a directory matches any.
func sameDir(real, declared string) bool {
	return declared == "" || path.Clean("/"+real) == path.Clean("/"+declared)
}

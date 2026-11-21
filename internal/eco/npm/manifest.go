package npm

import (
	"context"
	"fmt"
	"maps"
	"path"
	"reflect"
	"regexp"
	"slices"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/strictjson"
)

// depSections are the package.json tables whose version ranges a
// Dependabot update may rewrite.
var depSections = []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}

// overrideKeys are the top-level tables that pin dependency versions
// outside the dependency sections; a change there needs a person.
var overrideKeys = []string{"overrides", "resolutions"}

// manifestChanges compares dir/package.json at base and head. The root
// package.json is the one file npm runs code from (scripts.preinstall,
// prepare, ...) and resolves from (overrides, workspaces). The expected
// change is rewriting the range of a declared update to its new version
// with the same operator. Other dependency changes (another range form,
// an added or removed dependency, overrides/resolutions) need a person
// (npm.manifest-range, RouteHuman). Malformed input, a range rewrite to
// a version Dependabot did not declare, and any change outside the
// dependency fields refuse (npm.manifest-changed).
func manifestChanges(ctx context.Context, git ecoutil.Git, base, head, dir string, declared []model.Update) ([]model.Finding, error) {
	depDir := path.Clean("/" + dir)
	p := path.Join(dir, "package.json")
	var findings []model.Finding
	refuse := func(name, format string, args ...any) {
		findings = append(findings, model.Finding{Code: "npm.manifest-changed", Route: model.RouteRefuse, Update: name,
			Detail: path.Join(depDir, "package.json") + ": " + fmt.Sprintf(format, args...)})
	}
	review := func(name, format string, args ...any) {
		findings = append(findings, model.Finding{Code: "npm.manifest-range", Route: model.RouteHuman, Update: name,
			Detail: path.Join(depDir, "package.json") + ": " + fmt.Sprintf(format, args...)})
	}
	var docs [2]map[string]any
	for i, sha := range []string{base, head} {
		b, err := readAt(ctx, git, sha, p)
		if err != nil {
			return nil, err
		}
		if b == nil {
			continue
		}
		if err := strictjson.Unmarshal(b, &docs[i]); err != nil {
			findings = append(findings, model.Finding{Code: "npm.manifest-ambiguous", Route: model.RouteRefuse,
				Detail: fmt.Sprintf("%s at %s: %v", path.Join(depDir, "package.json"), sha, err)})
			return findings, nil
		}
		if docs[i] == nil {
			docs[i] = map[string]any{} // a literal null
		}
	}
	bm, hm := docs[0], docs[1]
	switch {
	case bm == nil && hm == nil:
		return nil, nil
	case bm == nil:
		refuse("", "added by the PR")
		return findings, nil
	case hm == nil:
		refuse("", "deleted by the PR")
		return findings, nil
	}
	for _, k := range slices.Sorted(maps.Keys(ecoutil.Union(bm, hm))) {
		if !slices.Contains(depSections, k) {
			switch {
			case reflect.DeepEqual(bm[k], hm[k]):
			case slices.Contains(overrideKeys, k):
				review("", "%q changed", k)
			default:
				refuse("", "%q changed; a dependency update changes only dependency versions", k)
			}
			continue
		}
		bs, ok1 := asRanges(bm[k])
		hs, ok2 := asRanges(hm[k])
		if !ok1 || !ok2 {
			if !reflect.DeepEqual(bm[k], hm[k]) {
				refuse("", "%q changed and is not a name -> range table", k)
			}
			continue
		}
		for _, name := range slices.Sorted(maps.Keys(ecoutil.Union(bs, hs))) {
			from, inBase := bs[name]
			to, inHead := hs[name]
			switch {
			case !inBase:
				review(name, "%s.%s added", k, name)
			case !inHead:
				review(name, "%s.%s removed", k, name)
			case from != to:
				switch route, why := rangeBump(name, from, to, depDir, declared); route {
				case model.RouteRefuse:
					refuse(name, "%s.%s %q -> %q: %s", k, name, from, to, why)
				case model.RouteHuman:
					review(name, "%s.%s %q -> %q: %s", k, name, from, to, why)
				}
			}
		}
	}
	return findings, nil
}

func asRanges(v any) (map[string]string, bool) {
	if v == nil {
		return map[string]string{}, true
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	out := map[string]string{}
	for k, x := range m {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out[k] = s
	}
	return out, true
}

// simpleRangeRE is one comparator: an optional operator and a version.
var simpleRangeRE = regexp.MustCompile(`^(\^|~|>=|=|v)?([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)$`)

// rangeBump routes a range rewrite from -> to: "" for a declared update's
// rewrite that keeps the operator ("^4.3.4" -> "^4.3.5"), RouteHuman with
// a reason for any other range form or a changed operator (a widened
// range, a multi-comparator range, a git URL or alias), RouteRefuse when
// the simple form names a version Dependabot did not declare.
func rangeBump(name, from, to, dir string, declared []model.Update) (model.Route, string) {
	fm, tm := simpleRangeRE.FindStringSubmatch(from), simpleRangeRE.FindStringSubmatch(to)
	if fm == nil || tm == nil {
		return model.RouteHuman, "not a single \"<operator><version>\" range rewrite"
	}
	if fm[1] != tm[1] {
		return model.RouteHuman, "the range operator changed"
	}
	for _, d := range declared {
		if fetch.SameName(model.NPM, d.Name, name) && sameDir(dir, d.Directory) && d.To == tm[2] {
			return "", ""
		}
	}
	return model.RouteRefuse, fmt.Sprintf("Dependabot declares no update of %s to %s in %s", name, tm[2], dir)
}

// sameDir is fetch's rule: a declaration without a directory matches any.
func sameDir(real, declared string) bool {
	return declared == "" || path.Clean("/"+real) == path.Clean("/"+declared)
}

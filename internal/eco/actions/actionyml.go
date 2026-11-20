package actions

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/sadbox/dep-review/internal/model"
)

// actionMeta is what matters in an action.yml for routing.
type actionMeta struct {
	using           string
	main, pre, post string
	preIf, postIf   string
	image           string
	stepUses        []string // runs.steps[].uses, in order
	inputs, outputs *yMap
	raw             any
}

func parseActionMeta(text string) (*actionMeta, error) {
	v, err := parseYAML(text)
	if err != nil {
		return nil, err
	}
	root, ok := v.(*yMap)
	if !ok {
		return nil, fmt.Errorf("action metadata is not a mapping")
	}
	runs := root.sub("runs")
	if runs == nil {
		return nil, fmt.Errorf("no runs: mapping")
	}
	if err := noFlow("runs", runs); err != nil {
		return nil, err
	}
	m := &actionMeta{
		using:   runs.str("using"),
		main:    runs.str("main"),
		pre:     runs.str("pre"),
		post:    runs.str("post"),
		preIf:   runs.str("pre-if"),
		postIf:  runs.str("post-if"),
		image:   runs.str("image"),
		inputs:  root.sub("inputs"),
		outputs: root.sub("outputs"),
		raw:     v,
	}
	if steps, ok := runs.get("steps").([]any); ok {
		for _, s := range steps {
			if sm, ok := s.(*yMap); ok {
				if u := sm.str("uses"); u != "" {
					m.stepUses = append(m.stepUses, u)
				}
			}
		}
	}
	return m, nil
}

// noFlow rejects flow collections anywhere under v: the YAML subset keeps
// them as raw text, so a uses: or image: inside one would go unseen.
func noFlow(at string, v any) error {
	switch t := v.(type) {
	case yFlow:
		return fmt.Errorf("%s: flow collections are not supported under runs", at)
	case *yMap:
		for _, k := range t.keys {
			if err := noFlow(at+"."+k, t.m[k]); err != nil {
				return err
			}
		}
	case []any:
		for i, e := range t {
			if err := noFlow(fmt.Sprintf("%s[%d]", at, i), e); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *actionMeta) isNode() bool {
	return strings.HasPrefix(m.using, "node")
}

// entrypoints returns the repository paths runs.main/pre/post name for an
// action in directory sub, or an error if one escapes the repository.
func (m *actionMeta) entrypoints(sub string) ([]string, error) {
	var out []string
	for _, e := range []string{m.main, m.pre, m.post} {
		if e == "" {
			continue
		}
		p := path.Clean(path.Join(sub, e))
		if p == ".." || strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/") {
			return nil, fmt.Errorf("entrypoint %q escapes the repository", e)
		}
		out = append(out, p)
	}
	return out, nil
}

type metaFinding struct {
	route  model.Route
	code   string
	detail string
}

// compareActionMeta applies the human-routing rules to an action.yml
// change and returns a structured diff for the reviewer.
func compareActionMeta(sub string, old, new *actionMeta) ([]metaFinding, string) {
	var fs []metaFinding
	add := func(code, format string, args ...any) {
		fs = append(fs, metaFinding{model.RouteHuman, code, fmt.Sprintf(format, args...)})
	}
	where := safePath(path.Join(sub, "action.yml"))
	if old.using != new.using {
		add("actions.runs-using-changed", "%s: runs.using changed", where)
	}
	if !new.isNode() && new.using != "composite" && new.using != "docker" {
		add("actions.unsupported-runtime", "%s: runs.using is not a node runtime or composite; the gate cannot attribute its code", where)
	}
	if new.using == "docker" || new.image != "" {
		add("actions.docker-action", "%s: Docker action; its image is not analyzed", where)
	}
	for _, e := range []struct{ name, o, n string }{
		{"main", old.main, new.main}, {"pre", old.pre, new.pre}, {"post", old.post, new.post},
	} {
		switch {
		case e.o == "" && e.n != "":
			add("actions.entrypoint-added", "%s: new runs.%s entrypoint", where, e.name)
		case e.o != e.n && e.n != "":
			add("actions.entrypoint-changed", "%s: runs.%s points to a different file", where, e.name)
		}
	}
	if old.image != new.image && new.image != "" {
		add("actions.docker-image-changed", "%s: runs.image changed", where)
	}
	oldUses := map[string]bool{}
	for _, u := range old.stepUses {
		oldUses[u] = true
	}
	for _, u := range new.stepUses {
		if !oldUses[u] {
			if strings.HasPrefix(u, "docker://") {
				add("actions.docker-image-changed", "%s: a composite step uses a new or changed docker:// image", where)
			} else {
				add("actions.nested-uses-changed", "%s: a composite step uses a new or changed action reference", where)
			}
		}
	}

	// Structured diff (untrusted: names and values come from upstream).
	var sb strings.Builder
	fmt.Fprintf(&sb, "## %s\n", where)
	pairs := []struct{ k, o, n string }{
		{"runs.using", old.using, new.using}, {"runs.main", old.main, new.main},
		{"runs.pre", old.pre, new.pre}, {"runs.pre-if", old.preIf, new.preIf},
		{"runs.post", old.post, new.post}, {"runs.post-if", old.postIf, new.postIf},
		{"runs.image", old.image, new.image},
	}
	for _, p := range pairs {
		if p.o != p.n {
			fmt.Fprintf(&sb, "~ %s: %q -> %q\n", p.k, p.o, p.n)
		} else if p.n != "" {
			fmt.Fprintf(&sb, "  %s: %q\n", p.k, p.n)
		}
	}
	diffKeys(&sb, "input", old.inputs, new.inputs)
	diffKeys(&sb, "output", old.outputs, new.outputs)
	if strings.Join(old.stepUses, "\n") != strings.Join(new.stepUses, "\n") {
		fmt.Fprintf(&sb, "~ runs.steps[].uses: %q -> %q\n", old.stepUses, new.stepUses)
	}
	var fo, fn []string
	flatten("", old.raw, &fo)
	flatten("", new.raw, &fn)
	if d := unifiedDiff("a/"+where, "b/"+where, strings.Join(fo, "\n")+"\n", strings.Join(fn, "\n")+"\n", 1); d != "" {
		sb.WriteString("\nflattened diff:\n" + d)
	}
	return fs, sb.String()
}

func diffKeys(sb *strings.Builder, what string, o, n *yMap) {
	ok := map[string]bool{}
	if o != nil {
		for _, k := range o.keys {
			ok[k] = true
		}
	}
	var keys []string
	if n != nil {
		keys = append(keys, n.keys...)
	}
	sort.Strings(keys)
	for _, k := range keys {
		nv := n.sub(k)
		if !ok[k] {
			fmt.Fprintf(sb, "+ %s %s (default %q, required %q)\n", what, k, nv.str("default"), nv.str("required"))
			continue
		}
		ov := o.sub(k)
		if ov.str("default") != nv.str("default") {
			fmt.Fprintf(sb, "~ %s %s default %q -> %q\n", what, k, ov.str("default"), nv.str("default"))
		}
		if ov.str("value") != nv.str("value") {
			fmt.Fprintf(sb, "~ %s %s value %q -> %q\n", what, k, ov.str("value"), nv.str("value"))
		}
	}
	if o != nil {
		nk := map[string]bool{}
		if n != nil {
			for _, k := range n.keys {
				nk[k] = true
			}
		}
		for _, k := range o.keys {
			if !nk[k] {
				fmt.Fprintf(sb, "- %s %s\n", what, k)
			}
		}
	}
}

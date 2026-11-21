package uv

import (
	"bufio"
	"bytes"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
	"github.com/sadbox/dep-review/internal/model"
)

// checkPackage runs the Python hard stops on the new version against the
// old one (zero sideTrees for a new package). Every finding forces
// RouteHuman.
func checkPackage(old, cur sideTrees) []model.Finding {
	var out []model.Finding
	add := func(code, format string, args ...any) {
		out = append(out, model.Finding{Code: code, Route: model.RouteHuman, Detail: fmt.Sprintf(format, args...)})
	}
	for _, t := range []struct {
		kind     string
		old, cur *ecoutil.Tree
	}{{"wheel", old.wheel, cur.wheel}, {"sdist", old.sdist, cur.sdist}} {
		if t.cur == nil {
			continue
		}
		var pth, native []string
		for _, f := range t.cur.Files {
			switch ext := path.Ext(f); ext {
			case ".pth":
				// Run by the interpreter at every start-up once installed.
				if t.kind == "wheel" || !t.old.Has(f) {
					pth = append(pth, f)
				}
			case ".so", ".pyd", ".dylib", ".dll":
				native = append(native, f)
			}
		}
		if len(pth) > 0 {
			add("uv.pth-file", "%s contains .pth files (code run at interpreter start-up): %s", t.kind, ecoutil.List(pth, 10))
		}
		if len(native) > 0 {
			add("uv.native-extension", "%s contains native extensions nobody can review as source: %s", t.kind, ecoutil.List(native, 10))
		}
		if t.kind == "wheel" {
			if hooks := installHookFiles(t.old, t.cur); len(hooks) > 0 {
				add("uv.install-hook-file", "wheel installs new or changed files under .data/ (scripts, purelib, platlib, data or headers): %s", ecoutil.List(hooks, 10))
			}
			if s := startupModules(t.cur); len(s) > 0 {
				add("uv.install-hook-file", "wheel installs a sitecustomize/usercustomize module (run at every interpreter start): %s", ecoutil.List(s, 10))
			}
			// A new import name can shadow another distribution's
			// ("requests/", "yaml.py"). For a new package (no old wheel)
			// Fetch compares names across the downloaded wheels instead.
			if t.old != nil {
				if added := newKeys(topLevel(t.old), topLevel(t.cur)); len(added) > 0 {
					add("uv.new-top-level", "wheel adds top-level import names: %s", ecoutil.List(added, 10))
				}
			}
		}
		pyc, unchecked, opaque := compiledFiles(t.old, t.cur)
		if len(pyc) > 0 {
			detail := ""
			if len(unchecked) > 0 {
				detail = fmt.Sprintf("; unchecked-hash .pyc (run without looking at the source): %s", ecoutil.List(unchecked, 10))
			}
			add("uv.compiled-bytecode", "%s contains Python bytecode nobody can review as source: %s%s", t.kind, ecoutil.List(pyc, 10), detail)
		}
		if len(opaque) > 0 {
			add("uv.binary-file", "%s has binary files added or changed (not reviewable as text): %s", t.kind, ecoutil.List(opaque, 10))
		}
	}

	// Entry points and dependencies, from the wheel's metadata (or the
	// sdist's when there is no wheel).
	oldMeta, curMeta := metadata(old), metadata(cur)
	if newReqs := newKeys(requiresDist(oldMeta.requires), requiresDist(curMeta.requires)); len(newReqs) > 0 {
		add("uv.new-requires-dist", "new Requires-Dist entries: %s", strings.Join(newReqs, ", "))
	}
	oe, ce := oldMeta.entryPoints, curMeta.entryPoints
	var eps []string
	for k, v := range ce {
		if ov, ok := oe[k]; !ok || ov != v {
			eps = append(eps, k+" = "+v)
		}
	}
	if len(eps) > 0 {
		slices.Sort(eps)
		add("uv.new-entry-point", "new or changed entry points / console scripts: %s", ecoutil.List(eps, 10))
	}

	// Build changes in the sdist, which uv builds when no wheel fits.
	if cur.sdist != nil {
		if s := cur.sdist.ReadFile("setup.py"); s != nil && !bytes.Equal(s, old.sdist.ReadFile("setup.py")) {
			add("uv.setup-py-changed", "sdist setup.py added or changed (runs at build time)")
		}
		if files := sdistDiff(old.sdist, cur.sdist); len(files) > 0 {
			add("uv.sdist-changed", "the sdist (which uv builds wherever no wheel fits) differs from the previous version's outside PKG-INFO: %s", ecoutil.List(files, 10))
		}
		ob, err1 := buildSystem(old.sdist.ReadFile("pyproject.toml"))
		cb, err2 := buildSystem(cur.sdist.ReadFile("pyproject.toml"))
		switch {
		case err1 != nil || err2 != nil:
			add("uv.pyproject-unparseable", "sdist pyproject.toml could not be parsed: %v", firstErr(err1, err2))
		case ob != cb:
			add("uv.build-backend-changed", "sdist [build-system] changed from %s to %s", orNone(ob), orNone(cb))
		}
	}
	return out
}

type meta struct {
	requires    []string          // Requires-Dist values
	entryPoints map[string]string // "section:name" -> object reference
}

// metadata reads METADATA and entry_points.txt from the wheel's
// .dist-info, or PKG-INFO and pyproject.toml from an sdist.
func metadata(s sideTrees) meta {
	m := meta{entryPoints: map[string]string{}}
	if t := s.wheel; t != nil {
		for _, f := range t.Files {
			dir, base := path.Split(f)
			if strings.Count(f, "/") != 1 || !strings.HasSuffix(dir, ".dist-info/") {
				continue
			}
			switch base {
			case "METADATA":
				m.requires = headerValues(t.ReadFile(f), "Requires-Dist")
			case "entry_points.txt":
				m.entryPoints = parseEntryPoints(t.ReadFile(f))
			}
		}
		return m
	}
	if t := s.sdist; t != nil {
		m.requires = headerValues(t.ReadFile("PKG-INFO"), "Requires-Dist")
		if doc, err := ParseTOML(string(t.ReadFile("pyproject.toml"))); err == nil {
			proj, _ := doc["project"].(map[string]any)
			if deps, ok := proj["dependencies"].([]any); ok {
				for _, d := range deps {
					m.requires = append(m.requires, fmt.Sprint(d))
				}
			}
			if opt, ok := proj["optional-dependencies"].(map[string]any); ok {
				for _, group := range opt {
					list, _ := group.([]any)
					for _, d := range list {
						m.requires = append(m.requires, fmt.Sprint(d))
					}
				}
			}
			// Named as the wheel's entry_points.txt names them.
			for sec, group := range map[string]string{"scripts": "console_scripts", "gui-scripts": "gui_scripts"} {
				if tbl, ok := proj[sec].(map[string]any); ok {
					for k, v := range tbl {
						m.entryPoints[group+":"+k] = fmt.Sprint(v)
					}
				}
			}
			if eps, ok := proj["entry-points"].(map[string]any); ok {
				for group, tbl := range eps {
					if t, ok := tbl.(map[string]any); ok {
						for k, v := range t {
							m.entryPoints[group+":"+k] = fmt.Sprint(v)
						}
					}
				}
			}
		}
	}
	return m
}

// headerValues returns the values of an RFC 822 style header in a
// METADATA/PKG-INFO file (up to the blank line before the description).
func headerValues(b []byte, header string) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(k, header) {
			out = append(out, strings.TrimSpace(v))
		}
	}
	return out
}

var reqNameRE = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)`)

// requiresDist maps requirement strings to normalized project names (an
// extra-only requirement is still something that can get installed).
func requiresDist(reqs []string) map[string]bool {
	out := map[string]bool{}
	for _, r := range reqs {
		if m := reqNameRE.FindStringSubmatch(r); m != nil {
			out[Normalize(m[1])] = true
		}
	}
	return out
}

func newKeys(old, cur map[string]bool) []string {
	var out []string
	for k := range cur {
		if !old[k] {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// parseEntryPoints reads entry_points.txt (INI): "section:name" -> value.
func parseEntryPoints(b []byte) map[string]string {
	out := map[string]string{}
	section := ""
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";"):
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			section = strings.TrimSpace(line[1 : len(line)-1])
		default:
			if k, v, ok := strings.Cut(line, "="); ok {
				out[section+":"+strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	}
	return out
}

// buildSystem is a canonical text of pyproject.toml's [build-system], ""
// if there is none.
func buildSystem(b []byte) (string, error) {
	if b == nil {
		return "", nil
	}
	doc, err := ParseTOML(string(b))
	if err != nil {
		return "", err
	}
	bs, ok := doc["build-system"].(map[string]any)
	if !ok {
		return "", nil
	}
	return fmt.Sprint(bs), nil // fmt sorts map keys
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

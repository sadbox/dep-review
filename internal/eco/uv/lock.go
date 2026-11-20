package uv

import (
	"fmt"

	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/model"
)

// Artifact is one sdist or wheel pinned in uv.lock.
type Artifact struct {
	URL  string
	Hash string // "sha256:<hex>"
	Size int64
}

// Package is one [[package]] of uv.lock.
type Package struct {
	Name    string
	Version string
	Source  map[string]string // {registry = "..."} | {virtual = "."} | {git = ...} | ...
	Sdist   *Artifact
	Wheels  []Artifact
	Deps    []string // names in dependencies, optional-dependencies, dev-dependencies
}

// IsProject reports whether the package is the workspace itself (never
// downloaded).
func (p Package) IsProject() bool {
	_, v := p.Source["virtual"]
	_, e := p.Source["editable"]
	return v || e
}

// Registry returns the registry URL, or "" for a non-registry source.
func (p Package) Registry() string { return p.Source["registry"] }

// Artifacts is the sdist (if any) and every wheel.
func (p Package) Artifacts() []Artifact {
	var out []Artifact
	if p.Sdist != nil {
		out = append(out, *p.Sdist)
	}
	return append(out, p.Wheels...)
}

// Lock is the part of uv.lock the gate uses.
type Lock struct {
	Packages []Package
}

// ParseLock parses uv.lock text.
func ParseLock(data string) (*Lock, error) {
	doc, err := ParseTOML(data)
	if err != nil {
		return nil, fmt.Errorf("uv.lock: %w", err)
	}
	if v, ok := doc["version"].(int64); !ok || v != 1 {
		return nil, fmt.Errorf("uv.lock: version %v is not supported (need 1)", doc["version"])
	}
	raw, _ := doc["package"].([]any)
	l := &Lock{}
	for i, r := range raw {
		t, ok := r.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("uv.lock: package %d is not a table", i)
		}
		p := Package{Source: map[string]string{}}
		p.Name, _ = t["name"].(string)
		p.Version, _ = t["version"].(string)
		if p.Name == "" {
			return nil, fmt.Errorf("uv.lock: package %d has no name", i)
		}
		if src, ok := t["source"].(map[string]any); ok {
			for k, v := range src {
				p.Source[k] = fmt.Sprint(v)
			}
		}
		if sd, ok := t["sdist"].(map[string]any); ok {
			a := artifact(sd)
			p.Sdist = &a
		}
		if ws, ok := t["wheels"].([]any); ok {
			for _, w := range ws {
				if m, ok := w.(map[string]any); ok {
					p.Wheels = append(p.Wheels, artifact(m))
				}
			}
		}
		p.Deps = append(p.Deps, depNames(t["dependencies"])...)
		for _, key := range []string{"optional-dependencies", "dev-dependencies"} {
			if groups, ok := t[key].(map[string]any); ok {
				for _, g := range groups {
					p.Deps = append(p.Deps, depNames(g)...)
				}
			}
		}
		l.Packages = append(l.Packages, p)
	}
	return l, nil
}

func artifact(m map[string]any) Artifact {
	a := Artifact{}
	a.URL, _ = m["url"].(string)
	a.Hash, _ = m["hash"].(string)
	a.Size, _ = m["size"].(int64)
	return a
}

func depNames(v any) []string {
	list, _ := v.([]any)
	var out []string
	for _, d := range list {
		if m, ok := d.(map[string]any); ok {
			if n, ok := m["name"].(string); ok {
				out = append(out, Normalize(n))
			}
		}
	}
	return out
}

// Normalize is the PEP 503 project name normalization (fetch.NormalizeName).
func Normalize(name string) string { return fetch.NormalizeName(model.UV, name) }

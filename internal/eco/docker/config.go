package docker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// imageConfig is the part of an OCI image config the gate reads.
type imageConfig struct {
	Architecture string                     `json:"architecture"`
	OS           string                     `json:"os"`
	Variant      string                     `json:"variant,omitempty"`
	Config       map[string]json.RawMessage `json:"config"`
	RootFS       struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
	History []struct {
		Created    string `json:"created"`
		CreatedBy  string `json:"created_by"`
		EmptyLayer bool   `json:"empty_layer"`
	} `json:"history"`
}

func (c *imageConfig) env() map[string]string {
	m, _ := c.envDups()
	return m
}

// envDups is env plus the variables set more than once. Which of the
// values a container sees is up to the runtime, so a duplicate is never
// "unchanged".
func (c *imageConfig) envDups() (map[string]string, []string) {
	var list []string
	json.Unmarshal(c.Config["Env"], &list)
	m := map[string]string{}
	var dups []string
	for _, kv := range list {
		k, v, _ := strings.Cut(kv, "=")
		if _, ok := m[k]; ok && !slices.Contains(dups, k) {
			dups = append(dups, k)
		}
		m[k] = v
	}
	return m, dups
}

func (c *imageConfig) labels() map[string]string {
	m := map[string]string{}
	json.Unmarshal(c.Config["Labels"], &m)
	return m
}

var (
	versionVarRe   = regexp.MustCompile(`^[A-Z][A-Z0-9_]*_VERSION$`)
	versionValueRe = regexp.MustCompile(`^v?[0-9][0-9A-Za-z.+~_-]{0,63}$`)
)

// Labels that change on every rebuild of the same software.
var rebuildLabels = map[string]bool{
	"org.opencontainers.image.created":  true,
	"org.opencontainers.image.revision": true,
	"org.opencontainers.image.version":  true,
}

// configDiff is the difference between two image configs.
type configDiff struct {
	// Versions are *_VERSION environment constants that moved, e.g.
	// GOLANG_VERSION 1.27.3 -> 1.27.4. They are expected.
	Versions map[string][2]string
	// Benign are other expected changes (rebuild labels).
	Benign []string
	// Other is everything else; any entry sends the PR to a human.
	Other []string
}

func diffConfig(a, b *imageConfig) configDiff {
	d := configDiff{Versions: map[string][2]string{}}
	for _, f := range [][3]string{{"architecture", a.Architecture, b.Architecture}, {"os", a.OS, b.OS}, {"variant", a.Variant, b.Variant}} {
		if f[1] != f[2] {
			d.Other = append(d.Other, fmt.Sprintf("%s: %q -> %q", f[0], f[1], f[2]))
		}
	}
	keys := map[string]bool{}
	for k := range a.Config {
		keys[k] = true
	}
	for k := range b.Config {
		keys[k] = true
	}
	for _, k := range sortedKeys(keys) {
		av, bv := a.Config[k], b.Config[k]
		if jsonEqual(av, bv) {
			continue
		}
		switch k {
		case "Env":
			ea, eb := a.env(), b.env()
			if _, dups := b.envDups(); len(dups) > 0 {
				d.Other = append(d.Other, "Env sets "+strings.Join(dups, ", ")+" more than once")
			}
			for _, v := range sortedKeys(union(ea, eb)) {
				x, xok := ea[v]
				y, yok := eb[v]
				switch {
				case xok && yok && x == y:
				case xok && yok && versionVarRe.MatchString(v) && versionValueRe.MatchString(x) && versionValueRe.MatchString(y):
					d.Versions[v] = [2]string{x, y}
				case !xok:
					d.Other = append(d.Other, fmt.Sprintf("Env %s added: %q", v, y))
				case !yok:
					d.Other = append(d.Other, fmt.Sprintf("Env %s removed (was %q)", v, x))
				default:
					d.Other = append(d.Other, fmt.Sprintf("Env %s: %q -> %q", v, x, y))
				}
			}
		case "Labels":
			la, lb := a.labels(), b.labels()
			for _, l := range sortedKeys(union(la, lb)) {
				x, xok := la[l]
				y, yok := lb[l]
				switch {
				case xok && yok && x == y:
				case xok && yok && rebuildLabels[l]:
					d.Benign = append(d.Benign, fmt.Sprintf("Label %s: %q -> %q", l, x, y))
				default:
					d.Other = append(d.Other, fmt.Sprintf("Label %s: %q -> %q", l, x, y))
				}
			}
		default:
			d.Other = append(d.Other, fmt.Sprintf("%s: %s -> %s", k, compact(av), compact(bv)))
		}
	}
	return d
}

func union[V any](a, b map[string]V) map[string]bool {
	m := map[string]bool{}
	for k := range a {
		m[k] = true
	}
	for k := range b {
		m[k] = true
	}
	return m
}

func jsonEqual(a, b json.RawMessage) bool {
	if len(a) == 0 || string(a) == "null" {
		a = nil
	}
	if len(b) == 0 || string(b) == "null" {
		b = nil
	}
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return bytes.Equal(a, b)
	}
	return deepEqualJSON(x, y)
}

func deepEqualJSON(x, y any) bool {
	switch xv := x.(type) {
	case map[string]any:
		yv, ok := y.(map[string]any)
		if !ok || len(xv) != len(yv) {
			return false
		}
		for k, v := range xv {
			if w, ok := yv[k]; !ok || !deepEqualJSON(v, w) {
				return false
			}
		}
		return true
	case []any:
		yv, ok := y.([]any)
		return ok && slices.EqualFunc(xv, yv, deepEqualJSON)
	default:
		return x == y
	}
}

func compact(m json.RawMessage) string {
	if len(m) == 0 {
		return "(unset)"
	}
	var b bytes.Buffer
	if json.Compact(&b, m) != nil {
		return string(m)
	}
	return b.String()
}

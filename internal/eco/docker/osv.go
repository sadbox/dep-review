package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
)

// OSV delta: which known vulnerabilities the changed packages' old versions
// have that the new versions do not (fixed), and the reverse (introduced).
// Only public distro package names and versions are sent; no auth.

const osvBatchURL = "https://api.osv.dev/v1/querybatch"

type osvClient struct {
	http *http.Client
	url  string
}

type osvQuery struct {
	Ecosystem, Name, Version string
}

type osvDelta struct {
	Ecosystem  string
	Fixed      map[string][]string // vuln id -> source packages
	Introduced map[string][]string
	Err        string
}

func (o *osvClient) query(ctx context.Context, qs []osvQuery) ([][]string, error) {
	type pkgQ struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Version string `json:"version"`
	}
	var body struct {
		Queries []pkgQ `json:"queries"`
	}
	for _, q := range qs {
		var p pkgQ
		p.Package.Name, p.Package.Ecosystem, p.Version = q.Name, q.Ecosystem, q.Version
		body.Queries = append(body.Queries, p)
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := o.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &statusError{Code: resp.StatusCode, What: "osv querybatch"}
	}
	var r struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&r); err != nil {
		return nil, err
	}
	if len(r.Results) != len(qs) {
		return nil, fmt.Errorf("osv: %d results for %d queries", len(r.Results), len(qs))
	}
	out := make([][]string, len(qs))
	for i, x := range r.Results {
		for _, v := range x.Vulns {
			out[i] = append(out[i], v.ID)
		}
	}
	return out, nil
}

// delta queries the old and new versions of every changed package.
func (o *osvClient) delta(ctx context.Context, eco string, changes []pkgChange) osvDelta {
	d := osvDelta{Ecosystem: eco, Fixed: map[string][]string{}, Introduced: map[string][]string{}}
	if o == nil || eco == "" || len(changes) == 0 {
		return d
	}
	type key struct{ src, ver string }
	var qs []osvQuery
	seen := map[key]int{}
	add := func(src, ver string) int {
		k := key{src, ver}
		if i, ok := seen[k]; ok {
			return i
		}
		seen[k] = len(qs)
		qs = append(qs, osvQuery{Ecosystem: eco, Name: src, Version: ver})
		return len(qs) - 1
	}
	type pair struct {
		src  string
		a, b int
	}
	var pairs []pair
	for _, c := range changes {
		if c.From == "" || c.To == "" || c.Rebuilt {
			continue
		}
		pairs = append(pairs, pair{c.Source, add(c.Source, c.From), add(c.Source, c.To)})
	}
	if len(qs) == 0 {
		return d
	}
	res, err := o.query(ctx, qs)
	if err != nil {
		d.Err = err.Error()
		return d
	}
	for _, p := range pairs {
		a, b := res[p.a], res[p.b]
		for _, id := range a {
			if !slices.Contains(b, id) && !slices.Contains(d.Fixed[id], p.src) {
				d.Fixed[id] = append(d.Fixed[id], p.src)
			}
		}
		for _, id := range b {
			if !slices.Contains(a, id) && !slices.Contains(d.Introduced[id], p.src) {
				d.Introduced[id] = append(d.Introduced[id], p.src)
			}
		}
	}
	return d
}

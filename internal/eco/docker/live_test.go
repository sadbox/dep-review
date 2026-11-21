package docker

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/policy"
)

// The five real base-image bumps the design was measured on. These tests
// download full images from Docker Hub (the golang image is ~320 MB
// compressed per platform), clone docker-library/repo-info and query
// OSV.dev, so they are skipped with -short.
//
// DOCKER_LIVE_CASES=<dir> runs every case directory under <dir> instead
// (same layout as testdata/cases); DOCKER_LIVE_OUT=<dir> writes the
// evidence files there.
var liveWant = map[string]model.Route{
	"golang-digest-noop":  model.RouteReview, // only riscv64/windows changed in the index: not a proven no-op
	"caddy-digest-noop":   model.RouteReview, // likewise (riscv64 added, windows rebuilt)
	"ubuntu-refresh":      model.RouteHuman,  // arm64: apt sources file not owned by a package
	"node-alpine-refresh": model.RouteHuman,  // see TestLive's log for the platform
	"golang-patch":        model.RouteReview, // every file attributed; archive verification is v2
}

func TestLive(t *testing.T) {
	if testing.Short() {
		t.Skip("downloads full images; skipped with -short")
	}
	root := os.Getenv("DOCKER_LIVE_CASES")
	strict := root == ""
	if root == "" {
		root = "testdata/cases"
	}
	ents, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	hist := newRepoInfo(t.TempDir())
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			cl, src := loadCase(t, filepath.Join(root, name))
			reg := newRegistry(&http.Client{Timeout: 10 * time.Minute}, maxDownload)
			a := &analyzer{reg: reg, hist: hist, osv: &osvClient{http: reg.client, url: osvBatchURL}, maxParallel: 2}
			w := newMemWriter()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
			defer cancel()
			start := time.Now()
			res, err := run(ctx, fetch.Env{Class: cl, Evidence: w}, src, a)
			if err != nil {
				if errors.Is(err, errRateLimited) {
					t.Skipf("skipped: the registry is still rate-limiting this IP after %d tries (Docker Hub allows 100 anonymous manifest pulls per hour); re-run later: %v", maxTries, err)
				}
				t.Fatal(err)
			}
			route := policy.Combine(res.Updates, res.Findings, false)
			t.Logf("%s: route=%s in %s", name, route, time.Since(start).Round(time.Second))
			for _, u := range res.Updates {
				t.Logf("  update %s %s->%s %s no_op=%v", u.Name, u.From, u.To, u.Type, u.NoOp)
			}
			for _, f := range res.Findings {
				t.Logf("  finding %s [%s] %.600s", f.Code, f.Route, f.Detail)
			}
			if out := os.Getenv("DOCKER_LIVE_OUT"); out != "" {
				names := make([]string, 0, len(w.files))
				for n := range w.files {
					names = append(names, n)
				}
				sort.Strings(names)
				for _, n := range names {
					p := filepath.Join(out, name, filepath.FromSlash(n))
					os.MkdirAll(filepath.Dir(p), 0o755)
					if err := os.WriteFile(p, []byte(w.files[n]), 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			for n := range w.files {
				if strings.HasSuffix(n, "-details.md") && !w.untrusted[n] {
					t.Errorf("%s must be written as untrusted", n)
				}
			}
			if want, ok := liveWant[name]; ok && strict && route != want {
				t.Errorf("%s: route %s, want %s", name, route, want)
			}
		})
	}
}

// TestLiveRepoInfo checks the tag-history source against digests these
// tags are known to have had.
func TestLiveRepoInfo(t *testing.T) {
	if testing.Short() {
		t.Skip("clones docker-library/repo-info; skipped with -short")
	}
	ri := newRepoInfo(t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	start := time.Now()
	for _, tc := range []struct{ image, tag, digest string }{
		{"golang", "1.27", "sha256:01aa404fa56b604b6f48e90c1d6e2c79fe5cd78f9592f78d80303fbe171cdcc0"},
		{"golang", "1.27", "sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf"},
		{"golang", "1.27.3", "sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e"},
	} {
		d, ok, err := ri.indexDigests(ctx, tc.image, tc.tag)
		if err != nil || !ok || !d[tc.digest] {
			t.Errorf("%s:%s: %d digests, has %s: %v (err %v)", tc.image, tc.tag, len(d), tc.digest, d[tc.digest], err)
		}
	}
	if _, ok, err := ri.indexDigests(ctx, "golang", "no-such-tag"); ok || err != nil {
		t.Errorf("missing tag: ok %v err %v", ok, err)
	}
	t.Logf("repo-info clone + 4 lookups: %s", time.Since(start).Round(time.Millisecond))
}

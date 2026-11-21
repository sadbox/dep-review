package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/policy"
)

func TestRegistryTokenFlowAndVerification(t *testing.T) {
	f := newFakeRegistry(t)
	a := f.analyzer(nil)
	ctx := context.Background()
	golang := imageRef{Registry: "docker.io", Repo: "library/golang"}
	body, doc, dg, err := a.reg.manifest(ctx, golang, dgB)
	if err != nil {
		t.Fatal(err)
	}
	if dg != dgB || !doc.isIndex() || len(body) == 0 {
		t.Fatalf("index %s %v", dg, doc.isIndex())
	}
	if f.hits["GET /token"] != 1 {
		t.Errorf("token fetched %d times", f.hits["GET /token"])
	}
	// Second request reuses the token.
	if _, _, _, err := a.reg.manifest(ctx, golang, dgB); err != nil {
		t.Fatal(err)
	}
	if f.hits["GET /token"] != 1 {
		t.Errorf("token refetched")
	}

	// A registry that serves different bytes for a digest is caught.
	f.tamper = func(p string, b []byte) []byte {
		if strings.HasSuffix(p, dgB) {
			return bytes.Replace(b, []byte("amd64"), []byte("amd65"), 1)
		}
		return b
	}
	if _, _, _, err := a.reg.manifest(ctx, golang, dgB); !errors.Is(err, errDigestMismatch) {
		t.Errorf("tampered manifest: %v", err)
	}
	f.tamper = nil

	// Blobs: hash and length are checked at EOF.
	good := f.put("library/golang", []byte("hello"))
	for _, tc := range []struct {
		name string
		d    descriptor
		max  int64
		want error
	}{
		{"ok", descriptor{Digest: good, Size: 5}, 10, nil},
		{"short descriptor", descriptor{Digest: good, Size: 4}, 10, errDigestMismatch},
		{"long descriptor", descriptor{Digest: good, Size: 6}, 10, errDigestMismatch},
		{"limit", descriptor{Digest: good, Size: 5}, 4, errTooLarge},
	} {
		b, err := a.reg.readBlob(ctx, golang, tc.d, tc.max)
		if !errors.Is(err, tc.want) || (tc.want == nil && string(b) != "hello") {
			t.Errorf("%s: %q %v", tc.name, b, err)
		}
	}
	f.tamper = func(p string, b []byte) []byte { return []byte("jello") }
	if _, err := a.reg.readBlob(ctx, golang, descriptor{Digest: good, Size: 5}, 10); !errors.Is(err, errDigestMismatch) {
		t.Errorf("tampered blob: %v", err)
	}
	f.tamper = nil

	// Token realms outside the allowlist are never contacted.
	reg := newRegistry(f.srv.Client(), 0)
	reg.endpoint = func(string) string { return f.srv.URL }
	if _, _, _, err := reg.manifest(ctx, golang, dgB); err == nil || !strings.Contains(err.Error(), "realm") {
		t.Errorf("default realm allowlist: %v", err)
	}
}

func TestStatusErrorNotFound(t *testing.T) {
	for code, want := range map[int]bool{404: true, 401: false, 500: false} {
		err := fmt.Errorf("manifest: %w", &statusError{Code: code, What: "GET x"})
		if got := errors.Is(err, gh.ErrNotFound); got != want {
			t.Errorf("HTTP %d: errors.Is(gh.ErrNotFound) = %v, want %v", code, got, want)
		}
	}
}

func TestSelectPlatform(t *testing.T) {
	b, ok := (&fakeRegistry{}).get("library/golang", dgB)
	if !ok {
		t.Fatal("fixture missing")
	}
	var idx manifestDoc
	if err := json.Unmarshal(b, &idx); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{
		"linux/amd64":    "sha256:2cd7e1ebf475c6208122d2b9cefc638d98fcc8dfd8554c8872c9dd0c21f4ac61",
		"linux/arm64":    "sha256:96335ac31f35abde9f40cbb1032e06d8571fc43c51230e9a90e14145debc6199",
		"linux/arm64/v8": "sha256:96335ac31f35abde9f40cbb1032e06d8571fc43c51230e9a90e14145debc6199",
		"linux/mips":     "",
	} {
		d, ok := selectPlatform(&idx, normPlatform(p))
		if d.Digest != want || ok != (want != "") {
			t.Errorf("%s: %s", p, d.Digest)
		}
	}
}

// The five recorded bumps, offline: index, platform manifests and configs
// as the registries served them. The two digest refreshes are identical
// for every platform the repository builds but changed riscv64 and the
// Windows images, so they are not proven no-ops (review), decided from the
// indexes alone; the others' config diffs are checked from the
// recorded configs (their layers are only fetched by TestLive).
func TestRecordedCases(t *testing.T) {
	for _, tc := range []struct {
		name  string
		route model.Route
		noop  bool
		tag   tagState
	}{
		{"golang-digest-noop", model.RouteReview, false, tagCurrent},
		{"caddy-digest-noop", model.RouteReview, false, tagEquivalent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRegistry(t)
			cl, src := loadCase(t, filepath.Join("testdata/cases", tc.name))
			w := newMemWriter()
			res, err := run(context.Background(), fetch.Env{Class: cl, Evidence: w}, src, f.analyzer(nil))
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Updates) != 1 || res.Updates[0].NoOp != tc.noop || res.Updates[0].Type != model.Digest {
				t.Fatalf("updates %+v", res.Updates)
			}
			if r := policy.Combine(res.Updates, res.Findings, false); r != tc.route || !strings.Contains(codes(res.Findings), codeOtherPlatforms+"=review") {
				t.Errorf("route %s, want %s (%s)", r, tc.route, codes(res.Findings))
			}
			var summary string
			for n, b := range w.files {
				if !strings.HasSuffix(n, "-details.md") {
					summary = b
				}
			}
			if !strings.Contains(summary, "**"+string(tc.tag)+"**") || !strings.Contains(summary, fmt.Sprintf("no-op proven: %v", tc.noop)) {
				t.Errorf("summary:\n%s", summary)
			}
			for _, n := range []string{"docker/01-golang-details.md", "docker/01-caddy-details.md"} {
				if _, ok := w.files[n]; ok && !w.untrusted[n] {
					t.Errorf("%s not untrusted", n)
				}
			}
		})
	}

	// Tag states when the tag has moved on.
	t.Run("tag states", func(t *testing.T) {
		cl, src := loadCase(t, "testdata/cases/golang-digest-noop")
		other := "sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e" // golang:1.27.3, different amd64/arm64 manifests
		for _, h := range []struct {
			name  string
			hist  tagHistory
			code  string
			route model.Route
		}{
			{"superseded", fakeHistory{dgB: true, other: true}, "", model.RouteReview},
			{"never", fakeHistory{other: true}, codeTagUnattributable, model.RouteRefuse},
			{"no history", nil, codeTagHistoryUnavailable, model.RouteHuman},
		} {
			f := newFakeRegistry(t)
			f.tags["library/golang:1.27"] = other
			res, err := run(context.Background(), fetch.Env{Class: cl}, src, f.analyzer(h.hist))
			if err != nil {
				t.Fatal(err)
			}
			if r := policy.Combine(res.Updates, res.Findings, false); r != h.route || (h.code != "" && !strings.Contains(codes(res.Findings), h.code)) {
				t.Errorf("%s: route %s findings %s", h.name, r, codes(res.Findings))
			}
		}
	})

	// Missing platform: a repo building linux/s390x against an index without it.
	t.Run("platform missing", func(t *testing.T) {
		f := newFakeRegistry(t)
		ch := fromChange{Path: "Dockerfile", Old: mustRef(t, "golang:1.27@"+dgA), New: mustRef(t, "golang:1.27@"+dgB)}
		u, err := f.analyzer(nil).analyze(context.Background(), ch, []string{"linux/amd64", "linux/mips64"}, "example")
		if err != nil {
			t.Fatal(err)
		}
		if u.Update.NoOp || !strings.Contains(codes(u.Findings), codePlatformMissing+"=human") {
			t.Errorf("noop %v findings %s", u.Update.NoOp, codes(u.Findings))
		}
	})

	t.Run("not allowlisted", func(t *testing.T) {
		f := newFakeRegistry(t)
		ch := fromChange{Path: "Dockerfile", Old: mustRef(t, "someone/golang:1.27@"+dgA), New: mustRef(t, "someone/golang:1.27@"+dgB)}
		u, err := f.analyzer(nil).analyze(context.Background(), ch, defaultPlatforms, "example")
		if err != nil {
			t.Fatal(err)
		}
		if codes(u.Findings) != codeNotAllowlisted+"=human" || len(f.hits) != 0 {
			t.Errorf("findings %s, registry hits %v", codes(u.Findings), f.hits)
		}
	})
}

func mustRef(t *testing.T, s string) imageRef {
	t.Helper()
	r, err := parseRef(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRecordedConfigDiffs(t *testing.T) {
	f := newFakeRegistry(t)
	a := f.analyzer(nil)
	ctx := context.Background()
	for _, tc := range []struct {
		image, old, new, plat string
		versions              map[string][2]string
		benign                int
	}{
		{"golang", "sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e", dgB, "linux/amd64",
			map[string][2]string{"GOLANG_VERSION": {"1.27.3", "1.27.4"}}, 0},
		{"node", "sha256:8996bb5821d62a8fd9bb27c1cb07462f3fdce6e47d640c6a881ead0b064ce216", "sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5", "linux/arm64",
			map[string][2]string{"NODE_VERSION": {"26.13.0", "26.13.1"}}, 0},
		{"ubuntu", "sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c", "sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db", "linux/arm64",
			map[string][2]string{}, 1},
	} {
		ref := imageRef{Registry: "docker.io", Repo: "library/" + tc.image}
		var cfgs []*imageConfig
		for _, dg := range []string{tc.old, tc.new} {
			_, idx, _, err := a.reg.manifest(ctx, ref, dg)
			if err != nil {
				t.Fatal(err)
			}
			d, ok := platformDesc(idx, dg, tc.plat)
			if !ok {
				t.Fatalf("%s: no %s", tc.image, tc.plat)
			}
			_, c, err := a.image(ctx, ref, d)
			if err != nil {
				t.Fatal(err)
			}
			cfgs = append(cfgs, c)
		}
		d := diffConfig(cfgs[0], cfgs[1])
		if len(d.Other) != 0 || len(d.Benign) != tc.benign || len(d.Versions) != len(tc.versions) {
			t.Errorf("%s: %+v", tc.image, d)
		}
		for k, v := range tc.versions {
			if d.Versions[k] != v {
				t.Errorf("%s: %s = %v", tc.image, k, d.Versions[k])
			}
		}
	}
}

func TestDiffConfig(t *testing.T) {
	mk := func(env []string, extra map[string]any) *imageConfig {
		c := map[string]any{"Env": env, "Cmd": []string{"bash"}}
		for k, v := range extra {
			c[k] = v
		}
		b, _ := json.Marshal(map[string]any{"architecture": "amd64", "os": "linux", "config": c})
		var ic imageConfig
		json.Unmarshal(b, &ic)
		return &ic
	}
	base := []string{"PATH=/usr/bin", "GOLANG_VERSION=1.27.3"}
	for _, tc := range []struct {
		name  string
		b     *imageConfig
		other int
	}{
		{"same", mk(base, nil), 0},
		{"version", mk([]string{"PATH=/usr/bin", "GOLANG_VERSION=1.27.4"}, nil), 0},
		{"path", mk([]string{"PATH=/evil:/usr/bin", "GOLANG_VERSION=1.27.3"}, nil), 1},
		{"env added", mk(append(base, "LD_PRELOAD=/x.so"), nil), 1},
		{"version not a version", mk([]string{"PATH=/usr/bin", "GOLANG_VERSION=$(curl x)"}, nil), 1},
		{"entrypoint", mk(base, map[string]any{"Entrypoint": []string{"/x"}}), 1},
		{"user", mk(base, map[string]any{"User": "root"}), 1},
		{"created label", mk(base, map[string]any{"Labels": map[string]string{}}), 0},
		{"label", mk(base, map[string]any{"Labels": map[string]string{"evil": "1"}}), 1},
	} {
		d := diffConfig(mk(base, nil), tc.b)
		if len(d.Other) != tc.other {
			t.Errorf("%s: %+v", tc.name, d)
		}
	}
}

func TestVerifyingReaderMustReachEOF(t *testing.T) {
	v := &verifyingReader{rc: io.NopCloser(strings.NewReader("abc")), h: newSHA256(), want: sha256Digest([]byte("abd")), size: 3}
	if _, err := io.ReadAll(v); !errors.Is(err, errDigestMismatch) {
		t.Errorf("got %v", err)
	}
}

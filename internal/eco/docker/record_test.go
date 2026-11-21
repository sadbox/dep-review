package docker

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRecordFixtures refreshes testdata/registry from the live registries:
// for every case, the old and new index, the platform manifests and
// configs for the platforms the case builds, and the tag's current index.
// Run with DOCKER_RECORD=1. Layers are not recorded.
func TestRecordFixtures(t *testing.T) {
	if os.Getenv("DOCKER_RECORD") == "" {
		t.Skip("set DOCKER_RECORD=1 to re-record registry fixtures")
	}
	reg := newRegistry(&http.Client{Timeout: time.Minute}, 0)
	ctx := context.Background()
	ents, err := os.ReadDir("testdata/cases")
	if err != nil {
		t.Fatal(err)
	}
	save := func(r imageRef, name string, b []byte) {
		p := filepath.Join("testdata/registry", r.Registry, filepath.FromSlash(r.Repo), name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	saveImage := func(r imageRef, dg string, plats []string) {
		body, doc, _, err := reg.manifest(ctx, r, dg)
		if err != nil {
			t.Fatal(err)
		}
		save(r, strings.TrimPrefix(dg, "sha256:"), body)
		for _, p := range plats {
			d, n := platformDesc(doc, dg, p)
			if n != 1 {
				continue
			}
			mb, m, _, err := reg.manifest(ctx, r, d.Digest)
			if err != nil {
				t.Fatal(err)
			}
			save(r, strings.TrimPrefix(d.Digest, "sha256:"), mb)
			cb, err := reg.readBlob(ctx, r, *m.Config, maxConfigBytes)
			if err != nil {
				t.Fatal(err)
			}
			save(r, strings.TrimPrefix(m.Config.Digest, "sha256:"), cb)
		}
	}
	for _, e := range ents {
		cl, src := loadCase(t, filepath.Join("testdata/cases", e.Name()))
		for _, f := range cl.Files {
			ob, _, _ := src.show(ctx, cl.BaseSHA, f)
			nb, _, _ := src.show(ctx, cl.HeadSHA, f)
			chs, _, err := diffDockerfile(f, ob, nb)
			if err != nil {
				t.Fatal(err)
			}
			wf := map[string]string{}
			names, _ := src.list(ctx, cl.HeadSHA, ".github/workflows")
			for _, n := range names {
				wf[n], _, _ = src.show(ctx, cl.HeadSHA, n)
			}
			pi := detectPlatforms(wf, f)
			for _, ch := range chs {
				plats := pi.stagePlatforms(ch.Stage.Platform)
				saveImage(ch.Old, ch.Old.Digest, plats)
				saveImage(ch.New, ch.New.Digest, plats)
				cur, err := reg.tagDigest(ctx, ch.New, ch.New.Tag)
				if err != nil {
					t.Fatal(err)
				}
				save(ch.New, "tags/"+ch.New.Tag, []byte(cur+"\n"))
				saveImage(ch.New, cur, plats)
			}
		}
	}
}

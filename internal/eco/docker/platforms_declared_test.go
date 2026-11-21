package docker

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/policy"
)

func TestParsePlatforms(t *testing.T) {
	got, err := ParsePlatforms(" linux/arm64/v8, linux/amd64 ,linux/arm64,")
	if err != nil || !slices.Equal(got, []string{"linux/amd64", "linux/arm64"}) {
		t.Errorf("%v %v", got, err)
	}
	if got, err := ParsePlatforms(""); err != nil || got != nil {
		t.Errorf("empty: %v %v", got, err)
	}
	for _, bad := range []string{"linux", "linux/amd64;id", "Linux/AMD64", "linux/amd64/v8/x", "../x", strings.Repeat("linux/a,", 1) + strings.Repeat("x", 40) + "/y"} {
		if _, err := ParsePlatforms(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	many := make([]string, 17)
	for i := range many {
		many[i] = "linux/a" + string(rune('a'+i))
	}
	if _, err := ParsePlatforms(strings.Join(many, ",")); err == nil {
		t.Error("accepted 17 platforms")
	}
}

func TestSamePlatforms(t *testing.T) {
	plat := func(os, arch, variant, osVersion string) *ociPlatform {
		return &ociPlatform{OS: os, Architecture: arch, Variant: variant, OSVersion: osVersion}
	}
	img := func(dg string, p *ociPlatform) descriptor {
		return descriptor{MediaType: mtOCIManifest, Digest: "sha256:" + strings.Repeat(dg, 64)[:64], Platform: p}
	}
	idx := func(ms ...descriptor) *manifestDoc { return &manifestDoc{MediaType: mtOCIIndex, Manifests: ms} }
	single := &manifestDoc{MediaType: mtOCIManifest, Config: &descriptor{}}
	amd, arm := img("a", plat("linux", "amd64", "", "")), img("b", plat("linux", "arm64", "v8", ""))
	rv1, rv2 := img("c", plat("linux", "riscv64", "", "")), img("d", plat("linux", "riscv64", "", ""))
	win1, win2 := img("e", plat("windows", "amd64", "", "10.0.1")), img("f", plat("windows", "amd64", "", "10.0.2"))
	both := []string{"linux/amd64", "linux/arm64"}
	tests := []struct {
		name     string
		old, new *manifestDoc
		od, nd   string
		plats    []string
		same     bool
	}{
		{"other platform changed", idx(amd, arm, rv1), idx(amd, arm, rv2), "x", "y", both, true},
		{"declared platform changed", idx(amd, arm), idx(amd, img("g", arm.Platform)), "x", "y", both, false},
		{"declared platform missing in new", idx(amd, arm), idx(amd), "x", "y", both, false},
		{"declared platform missing in old", idx(amd), idx(amd, arm), "x", "y", both, false},
		{"declared platform listed twice", idx(amd, win1, win2), idx(amd, win1, win2), "x", "y", []string{"windows/amd64"}, false},
		{"no platforms", idx(amd), idx(amd), "x", "y", nil, false},
		{"single manifests, same digest", single, single, "x", "x", both, true},
		{"single manifests, new digest", single, single, "x", "y", both, false},
		{"index to single manifest", idx(amd, arm), single, "x", "y", both, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := samePlatforms(tt.old, tt.od, tt.new, tt.nd, tt.plats); got != tt.same {
				t.Errorf("same = %v, want %v", got, tt.same)
			}
		})
	}
}

// With docker_platforms the declared set is compared, and detection can
// only add to it.
func TestDeclaredPlatforms(t *testing.T) {
	a := &analyzer{platforms: []string{"linux/amd64", "linux/arm64"}}
	if got := a.platformsFor([]string{"linux/riscv64", "linux/arm64/v8"}); !slices.Equal(got, []string{"linux/amd64", "linux/arm64", "linux/riscv64"}) {
		t.Errorf("platformsFor = %v", got)
	}
	if got := (&analyzer{}).platformsFor([]string{"linux/s390x"}); !slices.Equal(got, []string{"linux/s390x"}) {
		t.Errorf("default platformsFor = %v", got)
	}

	f := newFakeRegistry(t)
	repo := "library/golang"
	same := []tfile{{path: "bin/x", body: "same"}}
	amd := f.image(repo, "linux/amd64", []string{"V=1"}, same)
	armOld := f.image(repo, "linux/arm64", []string{"V=1"}, same)
	armNew := f.image(repo, "linux/arm64", []string{"V=1", "LD_PRELOAD=/evil.so"}, []tfile{{path: "evil.so", body: "x"}})
	rvOld := f.image(repo, "linux/riscv64", []string{"V=1"}, same)
	rvNew := f.image(repo, "linux/riscv64", []string{"V=2"}, same)
	run := func(oldIdx, newIdx string, declared []string) (*updateResult, model.Route) {
		t.Helper()
		f.tags[repo+":1.27"] = newIdx
		ch := fromChange{Path: "Dockerfile", Old: mustRef(t, "golang:1.27@"+oldIdx), New: mustRef(t, "golang:1.27@"+newIdx)}
		an := f.analyzer(nil)
		an.platforms = declared
		u, err := an.analyze(context.Background(), ch, an.platformsFor([]string{"linux/amd64"}), "example")
		if err != nil {
			t.Fatal(err)
		}
		return u, policy.Combine([]model.Update{u.Update}, u.Findings, false)
	}
	declared := []string{"linux/amd64", "linux/arm64"}
	// Only an undeclared platform changed: a no-op for this repository.
	if u, r := run(f.index(repo, amd, armOld, rvOld), f.index(repo, amd, armOld, rvNew), declared); !u.Update.NoOp || r != model.RouteAuto {
		t.Errorf("riscv64 only: NoOp=%v route=%s %s", u.Update.NoOp, r, codes(u.Findings))
	}
	// A declared platform changed: analysed, never a no-op, even though
	// detection only saw amd64.
	if u, r := run(f.index(repo, amd, armOld), f.index(repo, amd, armNew), declared); u.Update.NoOp || r == model.RouteAuto {
		t.Errorf("arm64 swapped: NoOp=%v route=%s %s", u.Update.NoOp, r, codes(u.Findings))
	}
	// A declared platform the index lacks needs a person.
	if u, r := run(f.index(repo, amd), f.index(repo, amd), declared); u.Update.NoOp || r != model.RouteHuman || !strings.Contains(codes(u.Findings), codePlatformMissing) {
		t.Errorf("arm64 missing: NoOp=%v route=%s %s", u.Update.NoOp, r, codes(u.Findings))
	}
}

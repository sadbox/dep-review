package docker

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/policy"
)

func TestMatcherNormalizes(t *testing.T) {
	for _, tc := range []struct {
		want string
		p    ociPlatform
		ok   bool
	}{
		{"linux/amd64", ociPlatform{OS: "linux", Architecture: "x86_64"}, true},
		{"linux/amd64", ociPlatform{OS: "Linux", Architecture: "AMD64"}, true},
		{"linux/amd64", ociPlatform{OS: "linux", Architecture: "amd64", Variant: "v1"}, true},
		{"linux/amd64", ociPlatform{OS: "", Architecture: "amd64"}, true},
		{"linux/amd64", ociPlatform{OS: "linux", Architecture: "amd64", OSFeatures: []string{"x"}}, true},
		{"linux/amd64", ociPlatform{OS: "linux", Architecture: "amd64", Variant: "v3"}, false},
		{"linux/amd64", ociPlatform{OS: "linux", Architecture: "386"}, false},
		{"linux/arm64", ociPlatform{OS: "linux", Architecture: "aarch64"}, true},
		{"linux/arm64", ociPlatform{OS: "linux", Architecture: "arm64", Variant: "v8"}, true},
		{"linux/arm64", ociPlatform{OS: "linux", Architecture: "arm", Variant: "v7"}, false},
		{"linux/arm/v7", ociPlatform{OS: "linux", Architecture: "arm"}, true},
		{"linux/arm/v7", ociPlatform{OS: "linux", Architecture: "armhf"}, true},
		{"linux/arm/v6", ociPlatform{OS: "linux", Architecture: "armel"}, true},
		{"linux/amd64", ociPlatform{OS: "unknown", Architecture: "unknown"}, false},
		{"windows/amd64", ociPlatform{OS: "windows", Architecture: "amd64", OSVersion: "10.0.1"}, true},
	} {
		p := tc.p
		if got := newMatcher(tc.want).match(&p); got != tc.ok {
			t.Errorf("%s matches %+v = %v, want %v", tc.want, tc.p, got, tc.ok)
		}
	}
	if !newMatcher("linux/amd64").match(nil) {
		t.Error("an entry without a platform must count as a candidate")
	}
	for in, want := range map[string]string{"linux/arm64/v8": "linux/arm64", "LINUX/X86_64": "linux/amd64", "linux/arm": "linux/arm/v7", "arm64": "linux/arm64"} {
		if got := normPlatform(in); got != want {
			t.Errorf("normPlatform(%q) = %q, want %q", in, got, want)
		}
	}
}

func analyzeIdx(t *testing.T, f *fakeRegistry, repo, oldIdx, newIdx string, declared, detected []string) (*updateResult, model.Route) {
	t.Helper()
	f.tags[repo+":1.27"] = newIdx
	ch := fromChange{Path: "Dockerfile", Old: mustRef(t, "golang:1.27@"+oldIdx), New: mustRef(t, "golang:1.27@"+newIdx)}
	an := f.analyzer(nil)
	an.platforms = declared
	u, err := an.analyze(context.Background(), ch, an.platformsFor(detected), "example")
	if err != nil {
		t.Fatal(err)
	}
	return u, policy.Combine([]model.Update{u.Update}, u.Findings, false)
}

// Regressions for the re-review's N1 PoCs (TestReproDeclaredAlias,
// TestReproAnnotatedDecoy, TestReproReorder): an index entry the pulling
// tools would pick but the gate's matcher skipped (an alias spelling, an
// annotation) or picked second (index order) reached auto.
func TestPlatformDecoys(t *testing.T) {
	f := newFakeRegistry(t)
	repo := "library/golang"
	same := []tfile{{path: "bin/x", body: "same"}}
	amd := f.image(repo, "linux/amd64", []string{"V=1"}, same)
	arm := f.image(repo, "linux/arm64", []string{"V=1"}, same)
	n := 0
	evil := func(p ociPlatform, annotations map[string]string) descriptor {
		n++
		d := f.image(repo, "linux/amd64", []string{"V=1", "LD_PRELOAD=/evil.so"}, []tfile{{path: "evil.so", body: fmt.Sprint("payload", n)}})
		d.Platform = &p
		d.Annotations = annotations
		return d
	}
	both := []string{"linux/amd64", "linux/arm64"}
	amdOnly := []string{"linux/amd64"}

	// Benign controls: an unchanged index is a no-op in both modes.
	idx := f.index(repo, amd, arm)
	for _, declared := range [][]string{nil, both} {
		if u, r := analyzeIdx(t, f, repo, idx, idx, declared, amdOnly); !u.Update.NoOp || r != model.RouteAuto {
			t.Fatalf("control (declared %v): NoOp=%v route %s %s", declared, u.Update.NoOp, r, codes(u.Findings))
		}
	}

	type tc struct {
		name           string
		oldIdx, newIdx string
		declared       []string
	}
	var cases []tc
	for _, p := range []ociPlatform{
		{OS: "linux", Architecture: "x86_64"},
		{OS: "Linux", Architecture: "amd64"},
		{OS: "linux", Architecture: "amd64", Variant: "v1"},
	} {
		e := evil(p, nil)
		for _, declared := range [][]string{both, nil} {
			cases = append(cases, tc{fmt.Sprintf("alias %s first, declared %v", p, declared), f.index(repo, amd, arm), f.index(repo, e, amd, arm), declared})
		}
	}
	a7 := f.image(repo, "linux/arm", []string{"V=1"}, same)
	a7.Platform = &ociPlatform{OS: "linux", Architecture: "arm", Variant: "v7"}
	cases = append(cases,
		tc{"linux/arm before linux/arm/v7", f.index(repo, amd, a7), f.index(repo, amd, evil(ociPlatform{OS: "linux", Architecture: "arm"}, nil), a7), []string{"linux/amd64", "linux/arm/v7"}},
		tc{"linux/aarch64 before linux/arm64", f.index(repo, amd, arm), f.index(repo, amd, evil(ociPlatform{OS: "linux", Architecture: "aarch64"}, nil), arm), both},
		tc{"annotated decoy first", f.index(repo, amd), f.index(repo, evil(ociPlatform{OS: "linux", Architecture: "amd64"}, map[string]string{"vnd.docker.reference.type": "x"}), amd), nil},
	)
	for name, mod := range map[string]func() descriptor{
		"exact dup": func() descriptor { return evil(ociPlatform{OS: "linux", Architecture: "amd64"}, nil) },
		"x86_64":    func() descriptor { return evil(ociPlatform{OS: "linux", Architecture: "x86_64"}, nil) },
		"annotated": func() descriptor {
			return evil(ociPlatform{OS: "linux", Architecture: "amd64"}, map[string]string{"vnd.docker.reference.type": "x"})
		},
	} {
		e := mod()
		cases = append(cases,
			tc{name + ": inert entry appended", f.index(repo, amd), f.index(repo, amd, e), nil},
			tc{name + ": reordered first", f.index(repo, amd, e), f.index(repo, e, amd), nil},
			tc{name + ": reordered first, declared", f.index(repo, amd, e), f.index(repo, e, amd), amdOnly},
			tc{name + ": one step, declared", f.index(repo, amd), f.index(repo, e, amd), amdOnly},
		)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, r := analyzeIdx(t, f, repo, c.oldIdx, c.newIdx, c.declared, amdOnly)
			if u.Update.NoOp || r != model.RouteHuman {
				t.Errorf("NoOp=%v route %s %s, want human", u.Update.NoOp, r, codes(u.Findings))
			}
		})
	}
}

// The default proof is order-sensitive: the same entries in another order
// are not the same image, because the tools take the first match.
func TestSameManifestsOrder(t *testing.T) {
	amd := descriptor{MediaType: mtOCIManifest, Digest: "sha256:" + strings.Repeat("a", 64), Platform: &ociPlatform{OS: "linux", Architecture: "amd64"}}
	arm := descriptor{MediaType: mtOCIManifest, Digest: "sha256:" + strings.Repeat("b", 64), Platform: &ociPlatform{OS: "linux", Architecture: "arm64"}}
	att := descriptor{MediaType: mtOCIManifest, Digest: "sha256:" + strings.Repeat("c", 64), Platform: &ociPlatform{OS: "unknown", Architecture: "unknown"},
		Annotations: map[string]string{"vnd.docker.reference.type": "attestation-manifest"}}
	att2 := att
	att2.Digest = "sha256:" + strings.Repeat("d", 64)
	idx := func(ms ...descriptor) *manifestDoc { return &manifestDoc{MediaType: mtOCIIndex, Manifests: ms} }
	annotated := amd
	annotated.Annotations = map[string]string{"org.opencontainers.image.revision": "x"}
	for _, tc := range []struct {
		name     string
		old, new *manifestDoc
		plats    []string
		same     bool
	}{
		{"identical", idx(amd, att, arm), idx(amd, att, arm), []string{"linux/amd64"}, true},
		{"attestation changed", idx(amd, att, arm), idx(amd, att2, arm), []string{"linux/amd64"}, true},
		{"reordered", idx(amd, arm), idx(arm, amd), []string{"linux/amd64"}, false},
		{"annotation changed", idx(amd, arm), idx(annotated, arm), []string{"linux/amd64"}, false},
		{"attestation a compared platform could pull", idx(amd, att), idx(amd, att2), []string{"unknown/unknown"}, false},
	} {
		if same, _ := sameManifests(tc.old, "x", tc.new, "y", tc.plats); same != tc.same {
			t.Errorf("%s: same = %v, want %v", tc.name, same, tc.same)
		}
	}
}

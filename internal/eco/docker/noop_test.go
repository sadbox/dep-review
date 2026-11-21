package docker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/policy"
)

// Regression for the review's TestReproNoOpArm64Unchecked: the old no-op
// proof compared only the platforms detected from the workflows, so an
// index that kept amd64 and swapped arm64 was auto-merged whenever
// detection missed the arm64 build (a multi-line buildx, a bake file, ...).
func TestNoOpNeedsEveryManifest(t *testing.T) {
	const native = "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: docker build .\n"
	const tagged = "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@x\n      - run: docker build -t app:test .\n"
	const multiline = "on: push\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          docker buildx build \\\n            --platform linux/amd64,linux/arm64 \\\n            -t ghcr.io/o/app --push .\n"
	const bake = "on: push\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: docker/bake-action@x\n        with:\n          targets: app\n"

	f := newFakeRegistry(t)
	repo := "library/golang"
	same := []tfile{{path: "bin/x", body: "same"}}
	amd := f.image(repo, "linux/amd64", []string{"GOLANG_VERSION=1.27.3"}, same)
	armOld := f.image(repo, "linux/arm64", []string{"GOLANG_VERSION=1.27.3"}, same)
	armNew := f.image(repo, "linux/arm64", []string{"GOLANG_VERSION=1.27.3", "LD_PRELOAD=/evil.so"}, []tfile{{path: "evil.so", body: "payload"}})
	oldIdx, newIdx := f.index(repo, amd, armOld), f.index(repo, amd, armNew)
	f.tags[repo+":1.27"] = newIdx
	ch := fromChange{Path: "Dockerfile", Old: mustRef(t, "golang:1.27@"+oldIdx), New: mustRef(t, "golang:1.27@"+newIdx)}

	for name, wf := range map[string]map[string]string{
		"release only (multi-line buildx)": {"release.yml": multiline},
		"ci native + release multi-line":   {"ci.yml": native, "release.yml": multiline},
		"ci native + bake":                 {"ci.yml": native, "release.yml": bake},
		"ci tagged build + release":        {"ci.yml": tagged, "release.yml": multiline},
		"amd64 only, explicitly":           nil,
	} {
		t.Run(name, func(t *testing.T) {
			plats := []string{"linux/amd64"}
			if wf != nil {
				plats = detectPlatforms(wf, "Dockerfile").stagePlatforms("")
			}
			u, err := f.analyzer(nil).analyze(context.Background(), ch, plats, "example")
			if err != nil {
				t.Fatal(err)
			}
			r := policy.Combine([]model.Update{u.Update}, u.Findings, false)
			if u.Update.NoOp || r == model.RouteAuto {
				t.Fatalf("platforms %v: NoOp=%v route=%s findings %s", plats, u.Update.NoOp, r, codes(u.Findings))
			}
			// When arm64 was not analysed, the evidence names it.
			analysedArm := false
			for _, p := range plats {
				analysedArm = analysedArm || normPlatform(p) == "linux/arm64"
			}
			if !analysedArm && !strings.Contains(codes(u.Findings), codeOtherPlatforms) {
				t.Errorf("platforms %v: findings %s lack %s", plats, codes(u.Findings), codeOtherPlatforms)
			}
		})
	}
}

func TestSameManifests(t *testing.T) {
	plat := func(os, arch, variant, osVersion string) *ociPlatform {
		return &ociPlatform{OS: os, Architecture: arch, Variant: variant, OSVersion: osVersion}
	}
	img := func(dg string, p *ociPlatform) descriptor {
		return descriptor{MediaType: mtOCIManifest, Digest: "sha256:" + strings.Repeat(dg, 64)[:64], Platform: p}
	}
	att := func(dg, ref string) descriptor {
		d := img(dg, plat("unknown", "unknown", "", ""))
		d.Annotations = map[string]string{"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": ref}
		return d
	}
	idx := func(ms ...descriptor) *manifestDoc { return &manifestDoc{MediaType: mtOCIIndex, Manifests: ms} }
	single := &manifestDoc{MediaType: mtOCIManifest, Config: &descriptor{}}
	amd, arm := img("a", plat("linux", "amd64", "", "")), img("b", plat("linux", "arm64", "v8", ""))
	win1 := img("c", plat("windows", "amd64", "", "10.0.26100.1"))
	win2 := img("d", plat("windows", "amd64", "", "10.0.20348.1"))
	built := []string{"linux/amd64", "linux/arm64"}

	tests := []struct {
		name     string
		old, new *manifestDoc
		od, nd   string
		same     bool
		unbuilt  string
	}{
		{"identical", idx(amd, arm, win1), idx(amd, arm, win1), "x", "y", true, ""},
		{"only attestations differ", idx(amd, att("1", "a"), arm), idx(amd, att("2", "a"), arm), "x", "y", true, ""},
		{"built platform changed", idx(amd, arm), idx(amd, img("e", arm.Platform)), "x", "y", false, ""},
		{"unbuilt platform changed", idx(amd, arm, img("f", plat("linux", "riscv64", "", ""))), idx(amd, arm, img("g", plat("linux", "riscv64", "", ""))), "x", "y", false, "linux/riscv64"},
		{"platform added", idx(amd, arm), idx(amd, arm, img("f", plat("linux", "s390x", "", ""))), "x", "y", false, "linux/s390x"},
		{"platform removed", idx(amd, arm, win1), idx(amd, arm), "x", "y", false, "windows/amd64 10.0.26100.1"},
		{"windows told apart by os.version", idx(amd, win1, win2), idx(amd, win1, img("d", plat("windows", "amd64", "", "10.0.20348.2"))), "x", "y", false, "windows/amd64 10.0.20348.1, windows/amd64 10.0.20348.2"},
		{"duplicate entry", idx(amd, arm), idx(amd, arm, arm), "x", "y", false, ""},
		{
			// An annotation alone does not make a real platform's manifest
			// an attestation.
			"annotated image manifest still compared",
			idx(amd, arm),
			idx(amd, func() descriptor {
				d := img("h", arm.Platform)
				d.Annotations = map[string]string{"vnd.docker.reference.type": "attestation-manifest"}
				return d
			}()),
			"x", "y", false, "",
		},
		{"unknown platform without annotation compared", idx(amd, img("i", plat("unknown", "unknown", "", ""))), idx(amd, img("j", plat("unknown", "unknown", "", ""))), "x", "y", false, "unknown/unknown"},
		{"empty indexes", idx(), idx(), "x", "y", false, ""},
		{"single manifests, same digest", single, single, "x", "x", true, ""},
		{"single manifests, new digest", single, single, "x", "y", false, ""},
		{"index to single manifest", idx(amd), single, "x", "y", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			same, unbuilt := sameManifests(tt.old, tt.od, tt.new, tt.nd, built)
			if same != tt.same || strings.Join(unbuilt, ", ") != tt.unbuilt {
				t.Errorf("same=%v unbuilt=%q, want %v %q", same, unbuilt, tt.same, tt.unbuilt)
			}
		})
	}
}

// An OSV.dev failure is not "no vulnerabilities": it needs a person.
func TestOSVUnavailableRoutesHuman(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	osv := &osvClient{http: srv.Client(), url: srv.URL}
	old := [][]tfile{debImage("1.0", "foo1", "foo1", "20000")}
	u, r := runSynthetic(t, "debian", nil, nil, old, [][]tfile{debImage("1.1", "foo2", "foo2", "20000")}, osv)
	if r != model.RouteHuman || !strings.Contains(codes(u.Findings), codeOSVUnavailable+"=human") {
		t.Errorf("route %s %s", r, codes(u.Findings))
	}
}

// A distribution OSV.dev is not queried for leaves the changed packages
// unchecked, which is not the same as clean.
func TestOSVUnknownDistroRoutesHuman(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	osv := &osvClient{http: srv.Client(), url: srv.URL}
	unknown := func(img []tfile) []tfile {
		img[0] = osRel("someos", "1")
		return img
	}
	old := [][]tfile{unknown(debImage("1.0", "foo1", "foo1", "20000"))}
	u, r := runSynthetic(t, "debian", nil, nil, old, [][]tfile{unknown(debImage("1.1", "foo2", "foo2", "20000"))}, osv)
	if r != model.RouteHuman || !strings.Contains(codes(u.Findings), codeOSVUnavailable+"=human") || calls != 0 {
		t.Errorf("route %s %s, %d OSV calls", r, codes(u.Findings), calls)
	}
}

// The real git source refuses anything that could reach git as an option
// or a revision expression.
func TestGitSourceArgs(t *testing.T) {
	g := gitSource{dir: t.TempDir()}
	ctx := context.Background()
	sha := strings.Repeat("a", 40)
	for _, rev := range []string{"HEAD", "--output=/tmp/x", "main", sha[:12], sha + "^"} {
		if _, _, err := g.show(ctx, rev, "Dockerfile"); err == nil {
			t.Errorf("show accepted rev %q", rev)
		}
		if _, err := g.list(ctx, rev, ".github/workflows"); err == nil {
			t.Errorf("list accepted rev %q", rev)
		}
		if _, err := g.changed(ctx, rev, sha); err == nil {
			t.Errorf("changed accepted rev %q", rev)
		}
	}
	for _, p := range []string{"", "-x", "a/--output=x", "/etc/passwd", "../x", "a/../b", "a//b", "a\nb", "a\\b", "."} {
		if _, _, err := g.show(ctx, sha, p); err == nil {
			t.Errorf("show accepted path %q", p)
		}
	}
	if err := gitArgs([]string{sha, strings.Repeat("b", 64)}, "proxy/Dockerfile", ".github/workflows"); err != nil {
		t.Errorf("valid arguments refused: %v", err)
	}
}

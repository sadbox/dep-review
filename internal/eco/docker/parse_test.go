package docker

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/model"
)

const (
	dgA = "sha256:01aa404fa56b604b6f48e90c1d6e2c79fe5cd78f9592f78d80303fbe171cdcc0"
	dgB = "sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf"
)

func TestParseRef(t *testing.T) {
	for _, tc := range []struct {
		in                     string
		reg, repo, tag, digest string
		name                   string
		err                    bool
		allowed                bool
	}{
		{in: "golang:1.27@" + dgA, reg: "docker.io", repo: "library/golang", tag: "1.27", digest: dgA, name: "golang", allowed: true},
		{in: "docker.io/library/node:26-alpine", reg: "docker.io", repo: "library/node", tag: "26-alpine", name: "node", allowed: true},
		{in: "gcr.io/distroless/static-debian12:nonroot@" + dgA, reg: "gcr.io", repo: "distroless/static-debian12", tag: "nonroot", digest: dgA, name: "gcr.io/distroless/static-debian12", allowed: true},
		{in: "ghcr.io/example/tool:1", reg: "ghcr.io", repo: "example/tool", tag: "1", name: "ghcr.io/example/tool", allowed: true},
		{in: "ghcr.io/other/tool:1", reg: "ghcr.io", repo: "other/tool", tag: "1", name: "ghcr.io/other/tool"},
		{in: "someone/image:1", reg: "docker.io", repo: "someone/image", tag: "1", name: "someone/image"},
		{in: "localhost:5000/x:1", reg: "localhost:5000", repo: "x", tag: "1", name: "localhost:5000/x"},
		{in: "quay.io/a/b@" + dgB, reg: "quay.io", repo: "a/b", digest: dgB, name: "quay.io/a/b"},
		{in: "golang:${GO}", err: true},
		{in: "golang@sha512:abc", err: true},
		{in: "golang@sha256:ABC", err: true},
		{in: "Golang:1", err: true},
	} {
		r, err := parseRef(tc.in)
		if (err != nil) != tc.err {
			t.Errorf("%s: err %v", tc.in, err)
			continue
		}
		if tc.err {
			continue
		}
		if r.Registry != tc.reg || r.Repo != tc.repo || r.Tag != tc.tag || r.Digest != tc.digest || r.Name() != tc.name {
			t.Errorf("%s: got %+v name %s", tc.in, r, r.Name())
		}
		if got := r.allowed("Example"); got != tc.allowed {
			t.Errorf("%s: allowed %v", tc.in, got)
		}
	}
}

func TestDiffDockerfile(t *testing.T) {
	base := "FROM golang:1.27@" + dgA + " AS build\nRUN go build\nFROM gcr.io/distroless/static:nonroot@" + dgA + "\nCOPY --from=build /x /x\n"
	for _, tc := range []struct {
		name, head string
		code       string // "" = ok
		n          int
	}{
		{name: "digest", head: strings.Replace(base, "golang:1.27@"+dgA, "golang:1.27@"+dgB, 1), n: 1},
		{name: "tag and digest", head: strings.Replace(base, "golang:1.27@"+dgA, "golang:1.28@"+dgB, 1), n: 1},
		{name: "two FROMs", head: strings.ReplaceAll(base, dgA, dgB), n: 2},
		{name: "case-insensitive", head: strings.Replace(strings.Replace(base, "FROM golang", "from golang", 1), dgA, dgB, 1), n: 1},
		{name: "run changed", head: strings.Replace(base, "go build", "go build -v", 1), code: codeDockerfileOther},
		{name: "line added", head: base + "USER root\n", code: codeDockerfileOther},
		{name: "digest dropped", head: strings.Replace(base, "golang:1.27@"+dgA, "golang:1.27", 1), code: codeFromUnpinned},
		{name: "stage renamed", head: strings.Replace(strings.Replace(base, "AS build", "AS b", 1), dgA, dgB, 1), code: codeDockerfileOther},
		{name: "platform added", head: strings.Replace(strings.Replace(base, "FROM golang", "FROM --platform=linux/amd64 golang", 1), dgA, dgB, 1), code: codeDockerfileOther},
		{name: "image swapped", head: strings.Replace(base, "golang:1.27@"+dgA, "evil/golang:1.27@"+dgB, 1), code: codeDockerfileOther},
		{name: "variable", head: strings.Replace(base, "golang:1.27@"+dgA, "golang:${V}@"+dgB, 1), code: codeFromUnparseable},
		{name: "whitespace", head: strings.Replace(base, "FROM golang", "FROM  golang", 1), code: codeDockerfileOther},
	} {
		got, _, err := diffDockerfile("Dockerfile", base, tc.head)
		var ce *changeError
		switch {
		case tc.code == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.code != "" && (!errors.As(err, &ce) || ce.Code != tc.code):
			t.Errorf("%s: err %v, want %s", tc.name, err, tc.code)
		case tc.code == "" && len(got) != tc.n:
			t.Errorf("%s: %d changes, want %d", tc.name, len(got), tc.n)
		}
	}
}

func TestParseStages(t *testing.T) {
	df := "FROM node:26@" + dgA + " AS assets\nRUN x\nFROM golang:1.27@" + dgA + " AS build\nCOPY --from=assets /a /a\nFROM build AS test\nFROM scratch\nCOPY --from=build /b /b\n"
	st, err := parseStages(df)
	if err != nil {
		t.Fatal(err)
	}
	if len(st) != 4 || !st[3].Final || st[0].Final || st[1].Stage != "build" || st[2].Image != "build" {
		t.Fatalf("stages %+v", st)
	}
	if len(st[0].Used) != 1 || len(st[1].Used) != 2 {
		t.Errorf("used: assets %v build %v", st[0].Used, st[1].Used)
	}
}

func TestIsDockerfile(t *testing.T) {
	for p, want := range map[string]bool{"Dockerfile": true, "a/Dockerfile.prod": true, "x.dockerfile": true, "Containerfile": true, "go.mod": false, ".github/dependabot.yml": false, "docker-compose.yml": false} {
		if isDockerfile(p) != want {
			t.Errorf("%s", p)
		}
	}
}

func TestTagUpdateType(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want model.UpdateType
	}{
		{"1.27", "1.27", model.Digest},
		{"1.27.3", "1.27.4", model.Patch},
		{"1.27", "1.28", model.Minor},
		{"26-alpine", "27-alpine", model.Major},
		{"2.11.9-alpine", "2.11.10-alpine", model.Patch},
		{"1.27", "1.27.4", model.Unknown},
		{"1.27-trixie", "1.27-bookworm", model.Unknown},
		{"1.28", "1.27", model.Unknown},
		{"latest", "stable", model.Unknown},
		{"nonroot", "nonroot", model.Digest},
	} {
		if got := tagUpdateType(tc.a, tc.b); got != tc.want {
			t.Errorf("%s -> %s: %s, want %s", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestDetectPlatforms(t *testing.T) {
	bpa := func(with string) string {
		return "jobs:\n  b:\n    runs-on: ubuntu-26.04\n    steps:\n      - uses: docker/build-push-action@x # v7\n        with:\n" + with
	}
	for _, tc := range []struct {
		name      string
		wf        map[string]string
		df        string
		targets   []string
		build     []string
		defaulted bool
	}{
		{name: "qemu", df: "Dockerfile",
			wf:      map[string]string{"w.yaml": bpa("          context: .\n          platforms: linux/amd64,linux/arm64\n")},
			targets: []string{"linux/amd64", "linux/arm64"}, build: []string{"linux/amd64"}},
		{name: "amd64 only", df: "Dockerfile",
			wf:      map[string]string{"w.yaml": bpa("          context: .\n          platforms: linux/amd64 # prod host\n")},
			targets: []string{"linux/amd64"}, build: []string{"linux/amd64"}},
		{name: "other context", df: "Dockerfile",
			wf:      map[string]string{"w.yaml": bpa("          context: tools\n          platforms: linux/amd64\n")},
			targets: defaultPlatforms, build: defaultPlatforms, defaulted: true},
		{name: "subdir", df: "proxy/Dockerfile",
			wf:      map[string]string{"w.yaml": bpa("          context: ./proxy\n          platforms: linux/arm64/v8\n")},
			targets: []string{"linux/arm64"}, build: []string{"linux/amd64"}},
		{name: "file", df: "build/app.Dockerfile",
			wf:      map[string]string{"w.yaml": bpa("          context: .\n          file: build/app.Dockerfile\n          platforms: linux/riscv64\n")},
			targets: []string{"linux/riscv64"}, build: []string{"linux/amd64"}},
		{name: "native matrix", df: "Dockerfile",
			wf:      map[string]string{"w.yaml": "jobs:\n  b:\n    strategy:\n      matrix:\n        include:\n          - platform: linux/amd64\n            runner: ubuntu-26.04\n          - platform: linux/arm64\n            runner: ubuntu-26.04-arm\n    runs-on: ${{ matrix.runner }}\n    steps:\n      - uses: docker/build-push-action@x\n        with:\n          context: .\n          platforms: ${{ matrix.platform }}\n"},
			targets: []string{"linux/amd64", "linux/arm64"}, build: []string{"linux/amd64", "linux/arm64"}},
		{name: "list matrix", df: "Dockerfile",
			wf:      map[string]string{"w.yaml": "jobs:\n  b:\n    strategy:\n      matrix:\n        arch: [amd64, arm64]\n    runs-on: ubuntu-26.04\n    steps:\n      - uses: docker/build-push-action@x\n        with:\n          platforms: linux/${{ matrix.arch }}\n"},
			targets: []string{"linux/amd64", "linux/arm64"}, build: []string{"linux/amd64"}},
		{name: "buildx cli", df: "Dockerfile",
			wf:      map[string]string{"w.yml": "jobs:\n  b:\n    runs-on: ubuntu-26.04-arm\n    steps:\n      - run: docker buildx build --platform linux/arm64 -t x .\n"},
			targets: []string{"linux/arm64"}, build: []string{"linux/arm64"}},
		{name: "native docker build", df: "Dockerfile",
			wf:      map[string]string{"w.yml": "jobs:\n  b:\n    runs-on: ubuntu-26.04\n    steps:\n      - run: docker build -t x .\n"},
			targets: []string{"linux/amd64"}, build: []string{"linux/amd64"}},
		{name: "unresolved expression", df: "Dockerfile",
			wf:      map[string]string{"w.yaml": bpa("          context: .\n          platforms: ${{ inputs.platforms }}\n")},
			targets: defaultPlatforms, build: []string{"linux/amd64", "linux/arm64"}, defaulted: true},
		{name: "no workflows", df: "Dockerfile", wf: map[string]string{},
			targets: defaultPlatforms, build: defaultPlatforms, defaulted: true},
	} {
		pi := detectPlatforms(tc.wf, tc.df)
		if !slices.Equal(pi.Targets, tc.targets) || !slices.Equal(pi.Build, tc.build) || pi.Defaulted != tc.defaulted {
			t.Errorf("%s: targets %v build %v defaulted %v (notes %v)", tc.name, pi.Targets, pi.Build, pi.Defaulted, pi.Notes)
		}
	}
	pi := platformInfo{Targets: []string{"linux/amd64", "linux/arm64"}, Build: []string{"linux/amd64"}}
	for flag, want := range map[string][]string{"": pi.Targets, "$BUILDPLATFORM": pi.Build, "${TARGETPLATFORM}": pi.Targets, "linux/arm64": {"linux/arm64"}} {
		if got := pi.stagePlatforms(flag); !slices.Equal(got, want) {
			t.Errorf("stage --platform=%q: %v", flag, got)
		}
	}
}

func TestParseRepoInfoLog(t *testing.T) {
	log := `commit 3333
diff --git a/repos/golang/remote/1.27.md b/repos/golang/remote/1.27.md
index 1..2 100644
--- a/repos/golang/remote/1.27.md
+++ b/repos/golang/remote/1.27.md
@@ -1,7 +1,7 @@
 ## ` + "`golang:1.27`" + `

 ` + "```console" + `
-$ docker pull golang@` + dgA + `
+$ docker pull golang@` + dgB + `
 ` + "```" + `

@@ -20,7 +20,7 @@
 ### ` + "`golang:1.27` - linux; amd64" + `

 ` + "```console" + `
-$ docker pull golang@sha256:1111111111111111111111111111111111111111111111111111111111111111
+$ docker pull golang@sha256:2222222222222222222222222222222222222222222222222222222222222222
commit 1111
diff --git a/repos/golang/remote/1.27.md b/repos/golang/remote/1.27.md
new file mode 100644
--- /dev/null
+++ b/repos/golang/remote/1.27.md
@@ -0,0 +1,9 @@
+## ` + "`golang:1.27`" + `
+
+` + "```console" + `
+$ docker pull golang@sha256:3333333333333333333333333333333333333333333333333333333333333333
+` + "```" + `
+### ` + "`golang:1.27` - linux; amd64" + `
+` + "```console" + `
+$ docker pull golang@sha256:4444444444444444444444444444444444444444444444444444444444444444
+` + "```" + `
`
	got := parseRepoInfoLog([]byte(log), "golang")
	want := []string{dgA, dgB, "sha256:" + strings.Repeat("3", 64)}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing %s in %v", w, got)
		}
	}
}

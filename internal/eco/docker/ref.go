package docker

import (
	"fmt"
	"regexp"
	"strings"
)

// imageRef is a parsed image reference as written in a FROM line.
type imageRef struct {
	Registry string // canonical: "docker.io", "gcr.io", "ghcr.io", ...
	Repo     string // repository path, "library/golang" for Docker Official Images
	Tag      string // may be empty
	Digest   string // "sha256:<64 hex>", may be empty
}

var (
	repoRe   = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)
	tagRe    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// parseRef parses "[host/]repo[:tag][@sha256:...]". It rejects variables,
// unknown digest algorithms and anything that is not a plain reference.
func parseRef(s string) (imageRef, error) {
	var r imageRef
	if strings.ContainsAny(s, "${}") {
		return r, fmt.Errorf("reference %q uses a build variable", s)
	}
	name := s
	if i := strings.IndexByte(name, '@'); i >= 0 {
		r.Digest = name[i+1:]
		name = name[:i]
		if !digestRe.MatchString(r.Digest) {
			return r, fmt.Errorf("reference %q: digest is not sha256:<64 hex>", s)
		}
	}
	last := name[strings.LastIndexByte(name, '/')+1:]
	if i := strings.LastIndexByte(last, ':'); i >= 0 {
		r.Tag = last[i+1:]
		name = name[:len(name)-len(last)+i]
		if !tagRe.MatchString(r.Tag) {
			return r, fmt.Errorf("reference %q: bad tag", s)
		}
	}
	host, rest, found := strings.Cut(name, "/")
	if found && (strings.ContainsAny(host, ".:") || host == "localhost") {
		r.Registry, r.Repo = host, rest
	} else {
		r.Registry, r.Repo = "docker.io", name
	}
	if r.Registry == "index.docker.io" || r.Registry == "registry-1.docker.io" {
		r.Registry = "docker.io"
	}
	if r.Registry == "docker.io" && !strings.Contains(r.Repo, "/") {
		r.Repo = "library/" + r.Repo
	}
	if !repoRe.MatchString(r.Repo) {
		return r, fmt.Errorf("reference %q: bad repository name", s)
	}
	return r, nil
}

// Name is the image name without tag or digest, in the short form people
// write ("golang", "gcr.io/distroless/static-debian12").
func (r imageRef) Name() string {
	if r.Registry == "docker.io" {
		return strings.TrimPrefix(r.Repo, "library/")
	}
	return r.Registry + "/" + r.Repo
}

func (r imageRef) String() string {
	s := r.Name()
	if r.Tag != "" {
		s += ":" + r.Tag
	}
	if r.Digest != "" {
		s += "@" + r.Digest
	}
	return s
}

// officialImage reports whether r is a Docker Official Image
// (docker.io/library/<name>), and returns <name>.
func (r imageRef) officialImage() (string, bool) {
	if r.Registry != "docker.io" {
		return "", false
	}
	n, ok := strings.CutPrefix(r.Repo, "library/")
	return n, ok && !strings.Contains(n, "/")
}

// allowed reports whether the gate may fetch and analyse r: Docker Official
// Images, distroless, and the repository owner's own GHCR packages.
func (r imageRef) allowed(owner string) bool {
	if _, ok := r.officialImage(); ok {
		return true
	}
	switch r.Registry {
	case "gcr.io":
		return strings.HasPrefix(r.Repo, "distroless/")
	case "ghcr.io":
		return owner != "" && strings.HasPrefix(r.Repo, strings.ToLower(owner)+"/")
	}
	return false
}

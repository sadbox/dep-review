// Package docker is the fetcher for Dependabot's docker ecosystem: base
// image digest and tag bumps in Dockerfiles.
//
// For every changed FROM it proves, from the registry and without running
// anything from the image:
//
//   - the change set: only FROM image references changed, every one pinned
//     by digest, to an allowlisted registry/repository;
//   - which platforms the repository builds (from its workflows) and which
//     stage the image is used in;
//   - tag attribution: the pinned index is the tag's current value, is
//     the same image (see below), or is a former value in
//     docker-library/repo-info's history;
//   - a no-op, the only route to auto-merge: the old and new index are the
//     same image. By default that means every non-attestation manifest is
//     identical; with WithPlatforms (gate input docker_platforms) it means
//     identical manifests for exactly the declared platforms, each present
//     in both indexes. Detected platforms only add to that set;
//   - otherwise, per built platform: the config diff, the file-level layer
//     diff, and attribution of every changed file to a changed distro
//     package, an upstream payload or known build noise.
//
// Registry access is a small OCI distribution client (registry.go) with
// anonymous tokens, size limits and digest verification of every byte.
package docker

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
)

// Finding codes.
const (
	codeNonDockerfile         = "docker.non-dockerfile-change"
	codeDockerfileOther       = "docker.dockerfile-other-change"
	codeFromUnpinned          = "docker.from-unpinned"
	codeFromUnparseable       = "docker.from-unparseable"
	codeNoChanges             = "docker.no-from-change"
	codeNotAllowlisted        = "docker.registry-not-allowlisted"
	codePlatformMissing       = "docker.platform-missing"
	codeTagUnattributable     = "docker.tag-unattributable"
	codeTagHistoryUnavailable = "docker.tag-history-unavailable"
	codeDigestMismatch        = "docker.digest-mismatch"
	codeDownloadLimit         = "docker.download-limit"
	codeZstdLayer             = "docker.zstd-layer"
	codeLayerUnsupported      = "docker.layer-unsupported"
	codeNotFound              = "docker.manifest-not-found"
	codeConfigChanged         = "docker.config-changed"
	codePackageAdded          = "docker.package-added"
	codePackageRemoved        = "docker.package-removed"
	codeReleaseChanged        = "docker.distro-release-changed"
	codeLayerAnomaly          = "docker.layer-anomaly"
	codeUnexplainedFiles      = "docker.unexplained-files"
	codeOSVIntroduced         = "docker.osv-introduced"
	codeArchiveNotVerified    = "docker.archive-verification-not-run"
	codeOtherPlatforms        = "docker.unbuilt-platforms-changed"
	codeOSVUnavailable        = "docker.osv-unavailable"
	codePlatformAmbiguous     = "docker.platform-ambiguous"
	codeStagePlatformArg      = "docker.stage-platform-arg"
)

// maxDownload bounds the bytes one Fetch pulls from registries.
const maxDownload = 8 << 30

type options struct {
	noHistory   bool
	platforms   []string
	noOSV       bool
	maxParallel int
}

// Option configures the fetcher; the zero set is the production setup.
type Option func(*options)

// WithoutTagHistory skips docker-library/repo-info (tag history then
// counts as unavailable: a review finding, never a refusal).
func WithoutTagHistory() Option { return func(o *options) { o.noHistory = true } }

// WithoutOSV skips the OSV.dev vulnerability delta.
func WithoutOSV() Option { return func(o *options) { o.noOSV = true } }

// WithPlatforms declares the platforms the repository builds (gate input
// docker_platforms, already checked by ParsePlatforms). The no-op proof
// and tag equivalence then need identity on exactly those platforms (plus
// any a stage names), each present in both indexes; manifests for other
// platforms may differ. Without it every manifest must be identical.
func WithPlatforms(platforms []string) Option {
	return func(o *options) { o.platforms = append([]string(nil), platforms...) }
}

// New returns the docker ecosystem fetcher.
func New(opts ...Option) fetch.Ecosystem {
	o := options{maxParallel: 2}
	for _, f := range opts {
		f(&o)
	}
	return &ecosystem{opts: o}
}

type ecosystem struct{ opts options }

// source is how the fetcher reads the repository: files at a commit.
type source interface {
	show(ctx context.Context, rev, p string) (string, bool, error)
	list(ctx context.Context, rev, dir string) ([]string, error)
	changed(ctx context.Context, base, head string) ([]string, error)
}

type gitSource struct{ dir string }

// gitArgs checks what reaches a git command line: revisions must be full
// commit IDs and paths clean repository-relative paths, so nothing can be
// read as an option or a revision expression.
func gitArgs(revs []string, paths ...string) error {
	for _, r := range revs {
		if !gh.ValidSHA(r) {
			return fmt.Errorf("git: %.80q is not a full commit ID", r)
		}
	}
	for _, p := range paths {
		if !safeRepoPath(p) {
			return fmt.Errorf("git: %.200q is not a safe repository path", p)
		}
	}
	return nil
}

func safeRepoPath(p string) bool {
	if p == "" || len(p) > 4096 || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "-") || path.Clean(p) != p || p == "." {
		return false
	}
	for _, el := range strings.Split(p, "/") {
		if el == ".." || strings.HasPrefix(el, "-") {
			return false
		}
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError || r == '\\' {
			return false
		}
	}
	return true
}

func (g gitSource) show(ctx context.Context, rev, p string) (string, bool, error) {
	if err := gitArgs([]string{rev}, p); err != nil {
		return "", false, err
	}
	cmd := gitCmd(ctx, g.dir, "cat-file", "-e", rev+":"+p)
	if cmd.Run() != nil {
		return "", false, nil
	}
	var stderr bytes.Buffer
	cmd = gitCmd(ctx, g.dir, "show", "--no-textconv", rev+":"+p)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", false, fmt.Errorf("git show %s:%s: %v: %s", rev, p, err, strings.TrimSpace(stderr.String()))
	}
	return string(out), true, nil
}

func (g gitSource) list(ctx context.Context, rev, dir string) ([]string, error) {
	if err := gitArgs([]string{rev}, dir); err != nil {
		return nil, err
	}
	out, err := gitCmd(ctx, g.dir, "ls-tree", "--name-only", rev, "--", dir+"/").Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return nil, nil
		}
		return nil, err
	}
	return strings.Fields(string(out)), nil
}

func (g gitSource) changed(ctx context.Context, base, head string) ([]string, error) {
	if err := gitArgs([]string{base, head}); err != nil {
		return nil, err
	}
	out, err := gitCmd(ctx, g.dir, "diff", "--no-ext-diff", "--name-only", "--no-renames", base, head, "--").Output()
	if err != nil {
		return nil, fmt.Errorf("git diff %s %s: %w", base, head, err)
	}
	return strings.Fields(string(out)), nil
}

func (e *ecosystem) Fetch(ctx context.Context, env fetch.Env) (fetch.Result, error) {
	reg := newRegistry(env.HTTP, maxDownload)
	a := &analyzer{reg: reg, maxParallel: e.opts.maxParallel, platforms: e.opts.platforms}
	if !e.opts.noHistory && env.Scratch != "" {
		a.hist = newRepoInfo(env.Scratch)
	}
	if !e.opts.noOSV {
		a.osv = &osvClient{http: reg.client, url: osvBatchURL}
	}
	return run(ctx, env, gitSource{env.RepoDir}, a)
}

func run(ctx context.Context, env fetch.Env, src source, a *analyzer) (fetch.Result, error) {
	var res fetch.Result
	c := env.Class
	files := c.Files
	if len(files) == 0 {
		var err error
		if files, err = src.changed(ctx, c.BaseSHA, c.HeadSHA); err != nil {
			return res, err
		}
	}
	owner, _, _ := strings.Cut(c.Repo, "/")
	refuse := func(code, format string, args ...any) {
		res.Findings = append(res.Findings, model.Finding{Code: code, Route: model.RouteRefuse, Detail: sanitize(fmt.Sprintf(format, args...))})
	}
	workflows := map[string]string{}
	if names, err := src.list(ctx, c.HeadSHA, ".github/workflows"); err != nil {
		return res, err
	} else {
		for _, n := range names {
			if ext := path.Ext(n); ext != ".yml" && ext != ".yaml" {
				continue
			}
			body, ok, err := src.show(ctx, c.HeadSHA, n)
			if err != nil {
				return res, err
			}
			if ok {
				workflows[n] = body
			}
		}
	}
	var results []*updateResult
	seen := map[string]*updateResult{}
	ew := evidenceWriter{w: env.Evidence}
	for _, f := range files {
		if !isDockerfile(f) {
			refuse(codeNonDockerfile, "%s changed in a docker update; only Dockerfiles are expected", f)
			continue
		}
		oldBody, oldOK, err := src.show(ctx, c.BaseSHA, f)
		if err != nil {
			return res, err
		}
		newBody, newOK, err := src.show(ctx, c.HeadSHA, f)
		if err != nil {
			return res, err
		}
		if !oldOK || !newOK {
			refuse(codeDockerfileOther, "%s was added or deleted", f)
			continue
		}
		changes, stages, err := diffDockerfile(f, oldBody, newBody)
		if err != nil {
			if ce, ok := err.(*changeError); ok {
				refuse(ce.Code, "%s", ce.Detail)
				continue
			}
			return res, err
		}
		if len(changes) == 0 {
			refuse(codeNoChanges, "%s changed but no FROM reference did", f)
			continue
		}
		pi := detectPlatforms(workflows, f)
		for _, ch := range changes {
			plats := a.platformsFor(pi.stagePlatforms(ch.Stage.Platform))
			key := f + " " + ch.Old.String() + " " + ch.New.String() + " " + strings.Join(plats, ",")
			if first, ok := seen[key]; ok {
				first.Notes = append(first.Notes, fmt.Sprintf("the same change is also on line %d", ch.Line))
				continue
			}
			u, err := a.analyze(ctx, ch, plats, owner)
			if err != nil {
				return res, fmt.Errorf("%s:%d %s: %w", f, ch.Line, ch.New, err)
			}
			u.Notes = append(u.Notes, platformNotes(pi, ch.Stage)...)
			if len(a.platforms) > 0 && platformFromArg(ch.Stage.Platform) {
				// The declared set only covers what the build pulls if
				// the stage's platform is one of them; an ARG can name any.
				u.find(model.RouteHuman, codeStagePlatformArg, "%s:%d: FROM --platform=%s comes from a build argument, so docker_platforms does not say which platform this stage pulls", f, ch.Line, sanitize(ch.Stage.Platform))
			}
			results = append(results, u)
			seen[key] = u
			if err := ew.write(len(results), u, stages, newBody); err != nil {
				return res, err
			}
		}
	}
	for _, u := range results {
		res.Updates = append(res.Updates, u.Update)
		res.Findings = append(res.Findings, u.Findings...)
	}
	sort.SliceStable(res.Findings, func(i, j int) bool { return res.Findings[i].Code < res.Findings[j].Code })
	return res, nil
}

// platformFromArg reports a FROM --platform value that uses a variable
// other than BuildKit's own $BUILDPLATFORM / $TARGETPLATFORM.
func platformFromArg(flag string) bool {
	if !strings.Contains(flag, "$") {
		return false
	}
	switch strings.TrimSpace(flag) {
	case "$BUILDPLATFORM", "${BUILDPLATFORM}", "$TARGETPLATFORM", "${TARGETPLATFORM}":
		return false
	}
	return true
}

func platformNotes(pi platformInfo, st stage) []string {
	var n []string
	src := "workflows: " + strings.Join(pi.Sources, ", ")
	if len(pi.Sources) == 0 {
		src = "no workflow builds this Dockerfile"
	}
	n = append(n, fmt.Sprintf("built platforms %s (%s); runner platforms %s", strings.Join(pi.Targets, ", "), src, strings.Join(pi.Build, ", ")))
	if pi.Defaulted {
		n = append(n, "platform detection fell back to the default linux/amd64 + linux/arm64: "+strings.Join(pi.Notes, "; "))
	}
	if st.Platform != "" {
		n = append(n, "stage uses --platform="+st.Platform)
	}
	return n
}

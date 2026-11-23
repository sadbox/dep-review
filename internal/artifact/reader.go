package artifact

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"golang.org/x/mod/module"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/gh"
)

func badRef(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBadRef, fmt.Sprintf(format, args...))
}

// Options configures the Preparer that New returns.
type Options struct {
	// Scratch is a directory to work in. Every Prepare makes its own
	// directory under it and removes it again. Empty means the system's
	// temporary directory.
	Scratch string
	// HTTP is used for every download. Only its Transport and Timeout are
	// used: the redirect policy is this package's own. Nil means
	// http.DefaultTransport and no timeout beyond each download's.
	HTTP *http.Client
	// GitHub supplies the job's read-only token for action tarballs; none
	// of its methods is called, and its API root must be github.com's.
	// Nil means no token, which is enough for public actions at the
	// unauthenticated rate limit.
	GitHub *gh.Client
	// Inspect holds, by Kind, the function whose answer about the
	// extracted artifacts is Prepared.Inspected.
	Inspect map[Kind]Inspect
}

// New returns the Preparer that downloads from the module proxy, the npm
// registry and GitHub. It needs git on PATH. The Preparer keeps no state
// between calls and may be used from several goroutines.
func New(o Options) (Preparer, error) {
	git, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("artifact: git is not installed: %w", err)
	}
	f := &netFetcher{retryDelay: time.Second}
	if o.GitHub != nil {
		// The token is sent to the API root, and tarballs are followed to
		// github.com's download host only.
		if o.GitHub.BaseURL != gh.DefaultBaseURL {
			return nil, fmt.Errorf("artifact: GitHub API root %q: action tarballs are read from %s only", o.GitHub.BaseURL, gh.DefaultBaseURL)
		}
		f.githubToken = o.GitHub.Token
	}
	var base http.Client
	if o.HTTP != nil {
		base.Transport, base.Timeout = o.HTTP.Transport, o.HTTP.Timeout
	}
	registry, proxy, github := base, base, base
	registry.CheckRedirect = redirects()
	proxy.CheckRedirect = redirects(goProxyStorageHost)
	// GitHub redirects a tarball request to its download host, and the
	// request for a renamed repository to another path of the API first.
	github.CheckRedirect = redirects(codeloadHost, githubAPIHost)
	f.registry, f.proxy, f.github = &registry, &proxy, &github

	return &reader{scratch: o.Scratch, git: git, fetch: f, limits: defaultExtractLimits, maxFile: maxFileBytes, maxText: maxBudgetBytes, inspect: o.Inspect}, nil
}

// reader is the Preparer.
type reader struct {
	scratch string
	git     string
	fetch   fetcher
	limits  extractLimits
	// maxFile is the largest file read in to be diffed; a larger changed
	// file is listed as unread. maxText is the most diff text held; once
	// there is more, the changed files left are listed as unread without
	// being diffed. Both are constants outside tests.
	maxFile int64
	maxText int
	inspect map[Kind]Inspect
}

// Shapes of npm names and versions. The registry URL is built from them,
// so they are matched exactly; a name the pattern does not cover is not
// fetched. The npm gatherer asks the registry about these shapes and no
// others, so a name the facts were gathered for is one the reader fetches.
var (
	npmNameRE    = regexp.MustCompile(`^(@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*$`)
	npmVersionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
)

// ValidNPMName reports whether name is a package name the gate puts in a
// registry URL. 214 bytes is npm's own limit.
func ValidNPMName(name string) bool { return len(name) <= 214 && npmNameRE.MatchString(name) }

// ValidNPMVersion reports whether version is a version the gate puts in a
// registry URL.
func ValidNPMVersion(version string) bool {
	return len(version) <= 256 && npmVersionRE.MatchString(version)
}

// actionTagRE is the shape of an action's tag: what version tags and
// release branches look like ("v4", "v4.1.0", "v3.1.0-node20",
// "releases/v1"), in plain characters and of a bounded length.
var actionTagRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/+-]{0,127}$`)

// kinds maps each ecosystem that has something to read to its artifact.
var kinds = map[string]Kind{
	allow.GoModules:     GoModuleZip,
	allow.NPM:           NPMTarball,
	allow.GitHubActions: ActionTarball,
}

// checkRef refuses a Ref whose fields are not in their kind's shape.
func checkRef(ref Ref) error {
	switch ref.Kind {
	case GoModuleZip:
		if err := module.Check(ref.Name, ref.Version); err != nil {
			return badRef("%v", err)
		}
		// module.Check takes "v1.2"; go.mod and go.sum never hold it.
		if module.CanonicalVersion(ref.Version) != ref.Version {
			return badRef("%s: version %q is not canonical", ref.Name, ref.Version)
		}
		if !moduleHashRE.MatchString(ref.Hash) {
			return badRef("%s@%s: %q is not an h1: hash", ref.Name, ref.Version, ref.Hash)
		}
	case NPMTarball:
		if !ValidNPMName(ref.Name) {
			return badRef("%q is not an npm package name the gate fetches", ref.Name)
		}
		if !ValidNPMVersion(ref.Version) {
			return badRef("%s: %q is not a version", ref.Name, ref.Version)
		}
		if _, ok := NPMIntegrity(ref.Hash); !ok {
			return badRef("%s@%s: %q is not exactly one sha512 integrity", ref.Name, ref.Version, ref.Hash)
		}
	case ActionTarball:
		if !gh.ValidRepo(ref.Name) {
			return badRef("%q is not owner/repo", ref.Name)
		}
		// The tag is not part of the download, but the model is told
		// it and it is in the content key.
		if !actionTagRE.MatchString(ref.Version) {
			return badRef("%s: %q is not a tag the gate takes", ref.Name, ref.Version)
		}
		if len(ref.Hash) != 40 || !gh.ValidSHA(ref.Hash) {
			return badRef("%s@%s: %q is not a full commit ID", ref.Name, ref.Version, ref.Hash)
		}
	default:
		return badRef("kind %q", ref.Kind)
	}
	return nil
}

// checkPair refuses a Pair whose parts do not describe one update.
func checkPair(p Pair) error {
	if err := checkRef(p.New); err != nil {
		return err
	}
	if kind, ok := kinds[p.Ecosystem]; !ok || kind != p.New.Kind {
		return badRef("ecosystem %q does not go with a %s", p.Ecosystem, p.New.Kind)
	}
	if p.New.Name != p.Name || p.New.Version != p.To {
		return badRef("the new artifact is %s@%s, the update is %q to %q", p.New.Name, p.New.Version, p.Name, p.To)
	}
	if p.Old == (Ref{}) {
		if p.From != "" {
			return badRef("%s: an update from %q with no old artifact", p.Name, p.From)
		}
		return nil
	}
	if err := checkRef(p.Old); err != nil {
		return err
	}
	if p.Old.Kind != p.New.Kind {
		return badRef("%s: old artifact is a %s, new is a %s", p.Name, p.Old.Kind, p.New.Kind)
	}
	if p.Old.Name != p.Name || p.Old.Version != p.From {
		return badRef("the old artifact is %s@%s, the update is %s from %q", p.Old.Name, p.Old.Version, p.Name, p.From)
	}
	return nil
}

// Prepare implements Preparer.
func (r *reader) Prepare(ctx context.Context, p Pair, lim Limits) (Prepared, error) {
	if lim.ChunkBytes < MinChunkBytes || lim.MaxChunks < 1 ||
		lim.ChunkBytes > maxBudgetBytes || lim.MaxChunks > maxBudgetBytes/lim.ChunkBytes {
		return Prepared{}, badRef("limits %+v: want at least %d bytes per chunk, at least 1 chunk, and at most %d bytes in all",
			lim, MinChunkBytes, maxBudgetBytes)
	}
	if err := checkPair(p); err != nil {
		return Prepared{}, err
	}
	if err := ctx.Err(); err != nil {
		return Prepared{}, err
	}

	work, err := os.MkdirTemp(r.scratch, "dep-review-read-")
	if err != nil {
		return Prepared{}, err
	}
	defer os.RemoveAll(work)
	// git compares GIT_CEILING_DIRECTORIES with real paths, and the
	// system's temporary directory can be a symbolic link.
	if work, err = filepath.EvalSymlinks(work); err != nil {
		return Prepared{}, err
	}

	oldTree, err := r.extract(ctx, p.Old, work, "old")
	if err != nil {
		return Prepared{}, err
	}
	defer oldTree.close()
	newTree, err := r.extract(ctx, p.New, work, "new")
	if err != nil {
		return Prepared{}, err
	}
	defer newTree.close()

	d, err := newDiffer(r.git, work)
	if err != nil {
		return Prepared{}, err
	}
	changed, removed := compare(oldTree, newTree)
	sections, unread, err := readChanged(ctx, p.New.Kind, oldTree, newTree, changed, d, r.maxFile, r.maxText)
	if err != nil {
		return Prepared{}, err
	}
	out := assemble(p, sections, unread, removed, lim)
	// After the content key is settled: the answer is about the
	// artifacts, not about what the model reads.
	if inspect := r.inspect[p.New.Kind]; inspect != nil {
		out.Inspected = inspect(oldTree.fs(), newTree.fs())
	}
	return out, nil
}

// extract downloads one side's artifact, verifies it and extracts it
// into work/side. The zero Ref is "no artifact" and gives an empty tree.
// Verification comes first: an archive that is not the one the pull
// request is bound to is never opened by an extractor.
func (r *reader) extract(ctx context.Context, ref Ref, work, side string) (*tree, error) {
	if ref == (Ref{}) {
		return &tree{}, nil
	}
	archive, err := r.fetch.fetch(ctx, ref, work)
	if err != nil {
		return nil, fmt.Errorf("artifact: fetching %s %s@%s: %w", ref.Kind, ref.Name, ref.Version, err)
	}
	if err := verify(archive, ref); err != nil {
		return nil, err
	}
	dir := filepath.Join(work, side)
	var t *tree
	if ref.Kind == GoModuleZip {
		t, err = unzipModule(archive, dir, module.Version{Path: ref.Name, Version: ref.Version}, r.limits)
	} else {
		t, err = extractTarGz(archive, dir, r.limits)
	}
	if err != nil {
		return nil, fmt.Errorf("%s %s@%s: %w", ref.Kind, ref.Name, ref.Version, err)
	}
	return t, nil
}

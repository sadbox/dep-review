package artifact

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/mod/module"

	"github.com/sadbox/dep-review/internal/gh"
)

// Where artifacts come from. A Ref carries no URL: these constants and
// the Ref's kind, name and version (for an action, its commit) are all
// that decide what is downloaded.
const (
	npmRegistry = "https://registry.npmjs.org/"
	// The module proxy only: a module path never names the host that is
	// asked.
	goProxy = "https://proxy.golang.org/"
	// The module proxy answers the request for a large zip with a redirect
	// to this host (seen 2026-11-23 for zips of some tens of megabytes).
	goProxyStorageHost = "storage.googleapis.com"
	// GitHub answers a tarball request with a redirect to this host.
	codeloadHost  = "codeload.github.com"
	githubAPIHost = "api.github.com"

	// maxDownloadBytes bounds one download.
	maxDownloadBytes = 512 << 20
	downloadTimeout  = 5 * time.Minute
	downloadAttempts = 3
)

// fetcher downloads an artifact's archive. It is the package's only use
// of the network; tests replace it or the transport under it.
type fetcher interface {
	// fetch downloads the archive ref names into dir, which belongs to
	// one Prepare call, and returns the file's path. The caller verifies
	// the archive: a fetcher is not trusted to have fetched the right one.
	fetch(ctx context.Context, ref Ref, dir string) (string, error)
}

// netFetcher is the real fetcher.
type netFetcher struct {
	// registry downloads npm tarballs and follows no redirect.
	registry *http.Client
	// proxy downloads module zips and follows a redirect only to the
	// module proxy's storage host.
	proxy *http.Client
	// github downloads repository tarballs from github.com's API and
	// follows a redirect only within it or to its download host.
	github *http.Client
	// githubToken is sent to the API only, and may be empty.
	githubToken string
	// retryDelay is the wait before the first retry; it doubles.
	retryDelay time.Duration
}

// fetch implements fetcher. Of its errors only those that mean "the
// registry was asked and did not deliver" are ErrUnavailable: a failure
// that was retried to the last attempt, and the download's own time
// running out. The caller's context ending is the caller's error.
func (f *netFetcher) fetch(ctx context.Context, ref Ref, dir string) (string, error) {
	caller := ctx
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	var archive string
	var err error
	switch ref.Kind {
	case GoModuleZip:
		var rawURL string
		if rawURL, err = moduleZipURL(ref.Name, ref.Version); err == nil {
			archive, err = f.download(ctx, f.proxy, rawURL, nil, dir)
		}
	case NPMTarball:
		archive, err = f.download(ctx, f.registry, NPMTarballURL(ref.Name, ref.Version), nil, dir)
	case ActionTarball:
		header := http.Header{}
		header.Set("Accept", "application/vnd.github+json")
		header.Set("X-GitHub-Api-Version", "2022-11-28")
		if f.githubToken != "" {
			// net/http drops this header when it follows the redirect
			// to another host, so the token stays with the API.
			header.Set("Authorization", "Bearer "+f.githubToken)
		}
		archive, err = f.download(ctx, f.github, gh.DefaultBaseURL+actionTarballPath(ref.Name, ref.Hash), header, dir)
	default:
		return "", fmt.Errorf("%w: kind %q", ErrBadRef, ref.Kind)
	}
	if err != nil {
		return "", fetchError(err, caller.Err(), ctx.Err() != nil)
	}
	return archive, nil
}

// fetchError settles which class a failed fetch is in. callerErr is the
// caller's context error, if it has ended; timedOut says the download's
// own time ran out.
func fetchError(err, callerErr error, timedOut bool) error {
	switch {
	case callerErr != nil:
		// The caller giving up says nothing about the registry.
		return callerErr
	case errors.Is(err, ErrHashMismatch), errors.Is(err, ErrUnsafeArchive), errors.Is(err, ErrBadRef), errors.Is(err, ErrUnavailable):
		// Already in a class. A refusal in particular is never turned
		// into a wait, however late it arrived.
		return err
	case timedOut:
		return fmt.Errorf("%w: no complete download within %s: %v", ErrUnavailable, downloadTimeout, err)
	}
	return err
}

// NPMTarballURL is where registry.npmjs.org serves name@version: the
// "dist.tarball" of every package on the public registry has this form,
// and it is the only "resolved" a lock entry for it may have.
func NPMTarballURL(name, version string) string {
	base := name[strings.LastIndex(name, "/")+1:]
	return npmRegistry + name + "/-/" + base + "-" + version + ".tgz"
}

// moduleZipURL is where the module proxy serves a module's zip: the URL
// the go command downloads (go help goproxy), with x/mod's own escaping
// of upper-case letters.
func moduleZipURL(path, version string) (string, error) {
	escapedPath, err := module.EscapePath(path)
	if err != nil {
		return "", badRef("%v", err)
	}
	escapedVersion, err := module.EscapeVersion(version)
	if err != nil {
		return "", badRef("%v", err)
	}
	return goProxy + escapedPath + "/@v/" + escapedVersion + ".zip", nil
}

// actionTarballPath is the API path of a repository's tarball at one
// commit, the request the Actions runner makes for a pinned action.
func actionTarballPath(repo, commit string) string {
	return "repos/" + repo + "/tarball/" + commit
}

// errRedirect is a redirect the policy refused. It is final: asking again
// gets the same redirect.
var errRedirect = errors.New("refusing a redirect")

// redirects is a redirect policy: https only, to the listed hosts only.
func redirects(hosts ...string) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return fmt.Errorf("%w: more than 3 in a row", errRedirect)
		}
		if req.URL.Scheme == "https" {
			for _, h := range hosts {
				if req.URL.Host == h {
					return nil
				}
			}
		}
		return fmt.Errorf("%w to %s://%s", errRedirect, req.URL.Scheme, req.URL.Host)
	}
}

// download GETs rawURL into a new file under dir. Network errors, 429 and
// 5xx are retried, and when the last attempt ends in one of them the
// error is ErrUnavailable. Any other answer is final and is not: a 404 or
// a 403 arrived, and says something.
func (f *netFetcher) download(ctx context.Context, client *http.Client, rawURL string, header http.Header, dir string) (string, error) {
	out, err := os.CreateTemp(dir, "download-*")
	if err != nil {
		return "", err
	}
	defer out.Close()
	delay := f.retryDelay
	for attempt := 1; ; attempt++ {
		retry, err := downloadOnce(ctx, client, rawURL, header, out)
		if err == nil {
			return out.Name(), out.Close()
		}
		if !retry {
			return "", err
		}
		if attempt == downloadAttempts || ctx.Err() != nil {
			return "", fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		select {
		case <-ctx.Done():
			return "", err
		case <-time.After(delay):
		}
		delay *= 2
		// Start the file over: a failed attempt may have written part.
		if _, err := out.Seek(0, io.SeekStart); err != nil {
			return "", err
		}
		if err := out.Truncate(0); err != nil {
			return "", err
		}
	}
}

func downloadOnce(ctx context.Context, client *http.Client, rawURL string, header http.Header, out io.Writer) (retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("User-Agent", "dep-review")
	resp, err := client.Do(req)
	if err != nil {
		return !errors.Is(err, errRedirect), err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return true, fmt.Errorf("GET %s: HTTP %d", rawURL, resp.StatusCode)
	default:
		return false, fmt.Errorf("GET %s: HTTP %d", rawURL, resp.StatusCode)
	}
	if resp.ContentLength > maxDownloadBytes {
		return false, fmt.Errorf("GET %s: %d bytes, more than %d", rawURL, resp.ContentLength, maxDownloadBytes)
	}
	n, err := io.Copy(out, io.LimitReader(resp.Body, maxDownloadBytes+1))
	if err != nil {
		return true, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	if n > maxDownloadBytes {
		return false, fmt.Errorf("GET %s: more than %d bytes", rawURL, maxDownloadBytes)
	}
	return false, nil
}

// clip shortens tool output for an error message and escapes it.
func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 400 {
		s = strings.ToValidUTF8(s[:400], "") + "..."
	}
	return escapeLine(s)
}

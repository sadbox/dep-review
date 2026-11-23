package artifact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Where artifacts come from. A Ref carries no URL: these constants and
// the Ref's kind, name and version (for an action, its commit) are all
// that decide what is downloaded.
const (
	npmRegistry = "https://registry.npmjs.org/"
	// The module proxy only: "direct" would run git or hg against
	// whatever host a module path names.
	goProxy = "https://proxy.golang.org"
	goSumDB = "sum.golang.org"
	// GitHub answers a tarball request with a redirect to this host.
	codeloadHost = "codeload.github.com"

	// maxDownloadBytes bounds one tarball download. The go command has
	// its own limit for a module zip (500 MiB).
	maxDownloadBytes = 512 << 20
	downloadTimeout  = 5 * time.Minute
	downloadAttempts = 3
)

// fetcher downloads an artifact's archive. It is the package's only use
// of the network; tests replace it or the transport under it.
type fetcher interface {
	// fetch downloads the archive ref names and returns the path of the
	// file. dir exists and belongs to one Prepare call; the fetcher may
	// keep whatever it likes in it. The caller verifies the archive, so a
	// fetcher is not trusted to have fetched the right thing.
	fetch(ctx context.Context, ref Ref, dir string) (string, error)
}

// netFetcher is the real fetcher.
type netFetcher struct {
	// registry downloads npm tarballs and follows no redirect.
	registry *http.Client
	// github downloads repository tarballs and follows a redirect only
	// to GitHub's download host.
	github *http.Client
	// githubAPI is the API root, with a trailing slash.
	githubAPI string
	// githubToken is sent to githubAPI only. Empty is fine for public
	// repositories, at the unauthenticated rate limit.
	githubToken string
	// goBin is the go command; empty when there is none installed.
	goBin string
	// goProxy and goSumDB are the constants above, except in the test
	// that runs the go command against a directory.
	goProxy string
	goSumDB string
	// retryDelay is the wait before the first retry; it doubles.
	retryDelay time.Duration
}

// fetch implements fetcher. Of its errors only those that mean "the
// registry was asked and did not deliver" are ErrUnavailable: a failure
// that was retried to the last attempt, the download's own time running
// out, and the one go command error that is recognisably the module
// proxy's outage. The caller's context ending is the caller's error.
func (f *netFetcher) fetch(ctx context.Context, ref Ref, dir string) (string, error) {
	caller := ctx
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	var archive string
	var err error
	switch ref.Kind {
	case GoModuleZip:
		archive, err = f.moduleZip(ctx, ref, dir)
	case NPMTarball:
		archive, err = f.download(ctx, f.registry, npmTarballURL(ref.Name, ref.Version), nil, dir)
	case ActionTarball:
		header := http.Header{}
		header.Set("Accept", "application/vnd.github+json")
		header.Set("X-GitHub-Api-Version", "2022-11-28")
		if f.githubToken != "" {
			// net/http drops this header when it follows the redirect
			// to another host, so the token stays with the API.
			header.Set("Authorization", "Bearer "+f.githubToken)
		}
		archive, err = f.download(ctx, f.github, f.githubAPI+actionTarballPath(ref.Name, ref.Hash), header, dir)
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
		// Whatever the download made of it, this is the caller giving up,
		// which says nothing about the registry.
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

// npmTarballURL is where registry.npmjs.org serves name@version: the
// "dist.tarball" of every package on the public registry has this form.
func npmTarballURL(name, version string) string {
	base := name[strings.LastIndex(name, "/")+1:]
	return npmRegistry + name + "/-/" + base + "-" + version + ".tgz"
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
// error is ErrUnavailable. Any other answer is final, and is not: a 404
// or a 403 arrived, and says something.
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

// moduleZip has the go command download a module and returns the zip in
// its module cache. The go command checks the module against the
// checksum database itself; the hash it reports must be the one the pull
// request is bound to, and the caller hashes the zip once more.
func (f *netFetcher) moduleZip(ctx context.Context, ref Ref, dir string) (string, error) {
	if f.goBin == "" {
		return "", errors.New("artifact: the go command is not installed")
	}
	// One module cache per Prepare, shared by the old and the new
	// module, in a directory nothing else uses.
	scratch := filepath.Join(dir, "go")
	work := filepath.Join(scratch, "work")
	home := filepath.Join(scratch, "home")
	if err := os.MkdirAll(work, 0o700); err != nil {
		return "", err
	}
	if err := goTelemetryOff(home); err != nil {
		return "", err
	}

	cmd := exec.CommandContext(ctx, f.goBin, "mod", "download", "-json", "--", ref.Name+"@"+ref.Version)
	// An empty directory: no go.mod, go.work or vendor directory of the
	// pull request's repository, or of anything else, is in reach.
	cmd.Dir = work
	cmd.Env = f.goEnv(scratch, home)
	cmd.WaitDelay = 10 * time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()

	// On failure the go command still prints the JSON, with Error set.
	var m struct {
		Path    string
		Version string
		Error   string
		Zip     string
		Sum     string
	}
	if err := json.Unmarshal(stdout.Bytes(), &m); err != nil {
		if runErr == nil {
			runErr = err
		}
		return "", fmt.Errorf("go mod download %s@%s: %v: %s", ref.Name, ref.Version, runErr, clip(stderr.String()))
	}
	switch {
	case goProxyOutageRE.MatchString(m.Error):
		return "", fmt.Errorf("%w: go mod download %s@%s: %s", ErrUnavailable, ref.Name, ref.Version, clip(m.Error))
	case m.Error != "":
		// Everything else the go command says stays unclassified, a
		// checksum mismatch it found itself included: its text is not
		// taken apart any further than the one shape above.
		return "", fmt.Errorf("go mod download %s@%s: %s", ref.Name, ref.Version, clip(m.Error))
	case runErr != nil:
		return "", fmt.Errorf("go mod download %s@%s: %v: %s", ref.Name, ref.Version, runErr, clip(stderr.String()))
	case m.Path != ref.Name || m.Version != ref.Version || m.Zip == "":
		return "", fmt.Errorf("go mod download %s@%s: answered for %s@%s", ref.Name, ref.Version, clip(m.Path), clip(m.Version))
	case m.Sum != ref.Hash:
		return "", hashMismatch(ref, "the go command reports %s, the pull request is bound to %s", clip(m.Sum), ref.Hash)
	}
	return m.Zip, nil
}

// goProxyOutageRE is the one shape of go command error that is read as
// "the module proxy was asked and did not answer": the error for the
// module itself (not one nested in another), about a URL of the proxy,
// and either a 429 or 5xx status or no response at all. The two forms are
// cmd/go/internal/web's: an HTTPError is "reading URL: STATUS" (for some
// answers with the server's text after it), and a request that got no
// response is net/http's own error, `Get "URL": ...`, passed on as it is.
// Both stand behind the module the go command was asked for; a 404 in the
// first form is in internal/facts/gomod's recorded output. Nothing else
// in the go command's text is interpreted: an error that does not start
// exactly like this is not an outage. internal/facts/gomod has the same
// shape for the same reason.
var goProxyOutageRE = regexp.MustCompile(`^[^ \n]+@[^ \n]+: (?:` +
	`reading ` + regexp.QuoteMeta(goProxy) + `/[^ \n]+: (?:429|5[0-9][0-9]) ` +
	`|Get "` + regexp.QuoteMeta(goProxy) + `/[^" \n]+": )`)

// goEnv is the whole environment of the go command. Nothing is inherited
// but PATH, so no GOFLAGS, GOPROXY or GONOSUMDB of the job can redirect
// the download or switch the checksum database off.
func (f *netFetcher) goEnv(scratch, home string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"GOPATH=" + filepath.Join(scratch, "gopath"),
		"GOMODCACHE=" + filepath.Join(scratch, "gopath", "pkg", "mod"),
		"GOCACHE=" + filepath.Join(scratch, "gocache"),
		"GOENV=off",
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		// -modcacherw: the cache can be removed again afterwards.
		"GOFLAGS=-mod=mod -modcacherw",
		"GOPROXY=" + f.goProxy,
		"GOSUMDB=" + f.goSumDB,
		"GONOSUMDB=",
		"GONOSUMCHECK=",
		"GONOPROXY=",
		"GOPRIVATE=",
		"GOINSECURE=",
		"GOVCS=*:off",
		"CGO_ENABLED=0",
		"GIT_TERMINAL_PROMPT=0",
	}
}

// goTelemetryOff prepares home as the HOME of a go command with Go
// telemetry off. Without the mode file the mode is "local", and the go
// command starts a sidecar process that writes counters under home after
// the command has returned, into a directory this package is about to
// remove. The file is where os.UserConfigDir puts it on Linux and on
// macOS; "off" is what "go telemetry off" writes.
func goTelemetryOff(home string) error {
	for _, config := range []string{".config", filepath.Join("Library", "Application Support")} {
		dir := filepath.Join(home, config, "go", "telemetry")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "mode"), []byte("off"), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// clip shortens tool output for an error message and escapes it: a
// registry or a module proxy can put anything there.
func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 400 {
		s = strings.ToValidUTF8(s[:400], "") + "..."
	}
	return escapeLine(s)
}

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

func (f *netFetcher) fetch(ctx context.Context, ref Ref, dir string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	switch ref.Kind {
	case GoModuleZip:
		return f.moduleZip(ctx, ref, dir)
	case NPMTarball:
		return f.download(ctx, f.registry, npmTarballURL(ref.Name, ref.Version), nil, dir)
	case ActionTarball:
		header := http.Header{}
		header.Set("Accept", "application/vnd.github+json")
		header.Set("X-GitHub-Api-Version", "2022-11-28")
		if f.githubToken != "" {
			// net/http drops this header when it follows the redirect
			// to another host, so the token stays with the API.
			header.Set("Authorization", "Bearer "+f.githubToken)
		}
		return f.download(ctx, f.github, f.githubAPI+actionTarballPath(ref.Name, ref.Hash), header, dir)
	}
	return "", fmt.Errorf("%w: kind %q", ErrBadRef, ref.Kind)
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
// 5xx are retried; anything else is final.
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
		if !retry || attempt == downloadAttempts || ctx.Err() != nil {
			return "", err
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
	case m.Error != "":
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

package gomod

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Downloaded is one module version from `go mod download -json`.
type Downloaded struct {
	Path     string
	Version  string
	Error    string
	Dir      string
	Sum      string
	GoModSum string
}

// Downloader runs `go mod download` in an empty directory with a module
// cache of its own, so nothing from the PR's repository (go.mod, go.work,
// toolchain lines, GOFLAGS from the environment) is consulted, and every
// module is checked against sum.golang.org.
type Downloader struct {
	Scratch string // GOPATH, GOMODCACHE, GOCACHE and the work dir live here
	GoBin   string // the go command; "go" from PATH if empty
}

// Env is the complete environment of the go command. Nothing is inherited
// except PATH.
func (d Downloader) Env() []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + filepath.Join(d.Scratch, "home"),
		"GOPATH=" + filepath.Join(d.Scratch, "gopath"),
		"GOMODCACHE=" + filepath.Join(d.Scratch, "gopath", "pkg", "mod"),
		"GOCACHE=" + filepath.Join(d.Scratch, "gocache"),
		"GOENV=off",
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		// -modcacherw: the cache stays removable; -mod=mod: never read a vendor dir.
		"GOFLAGS=-mod=mod -modcacherw",
		// The proxy only: "direct" would run git/hg/svn against arbitrary hosts.
		"GOPROXY=https://proxy.golang.org",
		"GOSUMDB=sum.golang.org",
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

// Download fetches every module@version in one go command. Per-module
// failures come back in Downloaded.Error; the error return is for the
// command itself failing to run or produce JSON.
func (d Downloader) Download(ctx context.Context, mods []string) (map[string]Downloaded, error) {
	work := filepath.Join(d.Scratch, "work")
	for _, dir := range []string{work, filepath.Join(d.Scratch, "home")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	ents, err := os.ReadDir(work)
	if err != nil {
		return nil, err
	}
	if len(ents) > 0 {
		return nil, fmt.Errorf("go work directory %s is not empty", work)
	}
	for _, m := range mods {
		if strings.HasPrefix(m, "-") || strings.ContainsAny(m, " \t\n") || !strings.Contains(m, "@") {
			return nil, fmt.Errorf("refusing module argument %q", m)
		}
	}
	bin := d.GoBin
	if bin == "" {
		bin = "go"
	}
	cmd := exec.CommandContext(ctx, bin, append([]string{"mod", "download", "-json", "--"}, mods...)...)
	cmd.Dir = work
	cmd.Env = d.Env()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()

	out := map[string]Downloaded{}
	dec := json.NewDecoder(&stdout)
	for {
		var m Downloaded
		if err := dec.Decode(&m); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("go mod download: bad JSON: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
		}
		out[m.Path+"@"+m.Version] = m
	}
	if runErr != nil && len(out) == 0 {
		return nil, fmt.Errorf("go mod download: %w: %s", runErr, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// errorClass sorts a per-module go error: a checksum/sumdb failure means the
// bytes are not what the world agrees on (refuse); a missing module or
// version is something a person must look at; anything else is
// infrastructure (retry later).
func errorClass(msg string) string {
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "security error"), strings.Contains(m, "checksum mismatch"),
		strings.Contains(m, "verifying module"), strings.Contains(m, "verifying go.mod"):
		return "refuse"
	case strings.Contains(m, "not found"), strings.Contains(m, "404"), strings.Contains(m, "410"),
		strings.Contains(m, "unknown revision"), strings.Contains(m, "invalid version"),
		strings.Contains(m, "malformed module path"), strings.Contains(m, "disabled by govcs"):
		return "human"
	}
	return "infra"
}

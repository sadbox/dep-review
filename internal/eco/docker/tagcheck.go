package docker

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Tag attribution: the pinned index digest must be one the tag has pointed
// at. Tags churn (golang:1.27 changed 19 times in 31 days), so a pin that
// lags its tag is normal.
type tagState string

const (
	tagCurrent     tagState = "current"     // the tag resolves to the pinned digest now
	tagEquivalent  tagState = "equivalent"  // the tag's current manifests for every built platform equal the pin's
	tagSuperseded  tagState = "superseded"  // the pin is in the tag's published history
	tagUnavailable tagState = "unavailable" // no history source for this image; not proven either way
	tagNever       tagState = "unattributable"
)

// tagHistory lists every index digest a tag of a Docker Official Image has
// had. ok is false if no history is available for this image/tag.
type tagHistory interface {
	indexDigests(ctx context.Context, image, tag string) (digests map[string]bool, ok bool, err error)
}

// repoInfo reads docker-library/repo-info's per-tag files
// (repos/<image>/remote/<tag>.md): the first `docker pull <image>@sha256:`
// line of the file is the tag's index digest. `git log -p` over a blobless,
// shallow clone yields every value that line has had.
type repoInfo struct {
	dir   string        // clone destination
	url   string        // https://github.com/docker-library/repo-info.git
	since time.Duration // shallow history depth

	once     sync.Once
	cloneErr error
}

func newRepoInfo(scratch string) *repoInfo {
	return &repoInfo{
		dir:   filepath.Join(scratch, "repo-info"),
		url:   "https://github.com/docker-library/repo-info.git",
		since: 180 * 24 * time.Hour,
	}
}

func gitCmd(ctx context.Context, dir string, args ...string) *exec.Cmd {
	base := []string{"-c", "core.fsmonitor=false", "-c", "credential.helper=", "-c", "protocol.file.allow=never"}
	if dir != "" {
		base = append(base, "-C", dir)
	}
	cmd := exec.CommandContext(ctx, "git", append(base, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/false")
	return cmd
}

func (ri *repoInfo) clone(ctx context.Context) error {
	ri.once.Do(func() {
		since := time.Now().Add(-ri.since).UTC().Format("2006-01-02")
		cmd := gitCmd(ctx, "", "clone", "--quiet", "--filter=blob:none", "--no-checkout", "--single-branch",
			"--shallow-since="+since, ri.url, ri.dir)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			ri.cloneErr = fmt.Errorf("clone repo-info: %v: %s", err, strings.TrimSpace(stderr.String()))
		}
	})
	return ri.cloneErr
}

var safeName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

func (ri *repoInfo) indexDigests(ctx context.Context, image, tag string) (map[string]bool, bool, error) {
	if !safeName.MatchString(image) || !tagRe.MatchString(tag) {
		return nil, false, nil
	}
	if err := ri.clone(ctx); err != nil {
		return nil, false, err
	}
	file := "repos/" + image + "/remote/" + tag + ".md"
	cmd := gitCmd(ctx, ri.dir, "log", "-p", "--no-color", "--no-ext-diff", "--no-textconv", "--format=commit %H", "HEAD", "--", file)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, false, fmt.Errorf("git log %s: %v: %s", file, err, strings.TrimSpace(stderr.String()))
	}
	d := parseRepoInfoLog(out, image)
	return d, len(d) > 0, nil
}

var hunkRe = regexp.MustCompile(`^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@`)

// parseRepoInfoLog extracts index digests from `git log -p` of one
// repo-info tag file. The index digest is the first `docker pull` line,
// which precedes the first "### " (per-platform) heading. A hunk can only
// show it if it starts before that heading, so we track, per side, whether
// a "### " line has been seen in the hunk and the hunk starts at line 1.
func parseRepoInfoLog(out []byte, image string) map[string]bool {
	digests := map[string]bool{}
	prefix := "$ docker pull " + image + "@"
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	inHunk := false
	var oldTop, newTop bool // still above the first "### " on that side, in a hunk that started at line 1
	for sc.Scan() {
		l := sc.Text()
		if m := hunkRe.FindStringSubmatch(l); m != nil {
			inHunk = true
			o, _ := strconv.Atoi(m[1])
			n, _ := strconv.Atoi(m[2])
			oldTop, newTop = o <= 1, n <= 1
			continue
		}
		if strings.HasPrefix(l, "commit ") || strings.HasPrefix(l, "diff --git") {
			inHunk = false
			continue
		}
		if !inHunk || l == "" {
			continue
		}
		side, body := l[0], l[1:]
		if strings.HasPrefix(body, "### ") {
			switch side {
			case ' ':
				oldTop, newTop = false, false
			case '-':
				oldTop = false
			case '+':
				newTop = false
			}
			continue
		}
		v, ok := strings.CutPrefix(body, prefix)
		if !ok || !digestRe.MatchString(v) {
			continue
		}
		if (side == '+' || side == ' ') && newTop || (side == '-' || side == ' ') && oldTop {
			digests[v] = true
		}
	}
	return digests
}

// tagResult is the outcome of the tag check.
type tagResult struct {
	State   tagState
	Current string // digest the tag resolves to now
	Detail  string
}

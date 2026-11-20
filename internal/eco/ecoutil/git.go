// Package ecoutil holds what the gomod, npm and uv fetchers share: reading
// files at a commit with git, bounded HTTP downloads, safe archive
// extraction, tree diffs and version arithmetic. Nothing here executes
// code from the repository or from a dependency.
package ecoutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var shaRE = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// gitEnv isolates git from the runner's and the user's configuration, so no
// configured diff driver, textconv, pager or hook can run.
func gitEnv(home string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_PAGER=cat",
		"LC_ALL=C",
	}
}

// Git reads files from the PR's checkout at fixed commits. It runs only
// read-only plumbing (merge-base, diff --name-only, show).
type Git struct {
	Repo string
	Home string // an empty directory to use as $HOME
}

func (g Git) run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", g.Repo, "-c", "core.quotePath=false"}, args...)...)
	cmd.Env = gitEnv(g.Home)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// MergeBase returns the merge base of base and head: the commit the PR's
// changes are relative to. Comparing against it (not the base branch tip)
// keeps unrelated changes that landed on the base branch out of the change set.
func (g Git) MergeBase(ctx context.Context, base, head string) (string, error) {
	if !shaRE.MatchString(base) || !shaRE.MatchString(head) {
		return "", fmt.Errorf("base %q / head %q are not commit SHAs", base, head)
	}
	out, err := g.run(ctx, "merge-base", base, head)
	if err != nil {
		return "", err
	}
	mb := strings.TrimSpace(string(out))
	if !shaRE.MatchString(mb) {
		return "", fmt.Errorf("git merge-base: unexpected output %q", mb)
	}
	return mb, nil
}

// ChangedFiles lists paths that differ between two commits.
func (g Git) ChangedFiles(ctx context.Context, from, to string) ([]string, error) {
	out, err := g.run(ctx, "diff", "--no-renames", "--no-ext-diff", "--name-only", "-z", from, to, "--")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	return files, nil
}

// ErrNotExist is returned by Show for a path absent at that commit.
var ErrNotExist = errors.New("path does not exist at commit")

// Show returns the blob at sha:path, or ErrNotExist. Symlinks and
// submodules are refused: only regular blobs are read.
func (g Git) Show(ctx context.Context, sha, path string) ([]byte, error) {
	if !shaRE.MatchString(sha) {
		return nil, fmt.Errorf("%q is not a commit SHA", sha)
	}
	if strings.HasPrefix(path, "/") || strings.Contains("/"+path+"/", "/../") {
		return nil, fmt.Errorf("unsafe path %q", path)
	}
	ls, err := g.run(ctx, "ls-tree", "-z", sha, "--", path)
	if err != nil {
		return nil, err
	}
	if len(ls) == 0 {
		return nil, ErrNotExist
	}
	// "<mode> <type> <object>\t<path>\x00"
	if !bytes.HasPrefix(ls, []byte("100644 blob ")) && !bytes.HasPrefix(ls, []byte("100755 blob ")) {
		return nil, fmt.Errorf("%s at %s is not a regular file: %q", path, sha, strings.TrimRight(string(ls), "\x00"))
	}
	return g.run(ctx, "show", sha+":"+path)
}

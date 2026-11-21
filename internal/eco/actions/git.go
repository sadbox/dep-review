package actions

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// git runs read-only git commands. Every invocation disables hooks and
// credential helpers and never prompts; nothing in a repository is executed.
type git struct {
	bin string
	dir string
}

var errMissing = errors.New("object not found")

func (g git) run(ctx context.Context, args ...string) ([]byte, error) {
	return g.runStdin(ctx, nil, args...)
}

// runStdin is run with stdin (nil for none).
func (g git) runStdin(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	full := []string{
		"-c", "core.hooksPath=/dev/null",
		"-c", "credential.helper=",
		"-c", "core.fsmonitor=false",
		"-c", "diff.external=",
	}
	if g.dir != "" {
		full = append([]string{"-C", g.dir}, full...)
	}
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, g.bin, full...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "SSH_ASKPASS=", "GIT_PAGER=cat", "GIT_EXTERNAL_DIFF=")
	var out, stderr bytes.Buffer
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 400 {
			msg = msg[:400]
		}
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, msg)
	}
	return out.Bytes(), nil
}

// show returns the content of path at rev, or errMissing when the path
// does not exist there.
func (g git) show(ctx context.Context, rev, path string) ([]byte, error) {
	spec := rev + ":" + path
	if _, err := g.run(ctx, "cat-file", "-e", spec); err != nil {
		return nil, errMissing
	}
	return g.run(ctx, "cat-file", "blob", spec)
}

// hasCommit reports whether rev names a commit object present locally.
func (g git) hasCommit(ctx context.Context, rev string) bool {
	out, err := g.run(ctx, "cat-file", "-t", rev)
	return err == nil && strings.TrimSpace(string(out)) == "commit"
}

type fileChange struct {
	status           byte // A, M, D, T (renames are disabled)
	path             string
	oldMode, newMode string
	newSHA           string // blob on the new side; all zeros when deleted
}

// changedFiles lists files that differ between two commits.
func (g git) changedFiles(ctx context.Context, from, to string) ([]fileChange, error) {
	out, err := g.run(ctx, "diff", "--raw", "--no-abbrev", "--no-renames", "--no-ext-diff", "--no-textconv", "-z", from, to, "--")
	if err != nil {
		return nil, err
	}
	return parseRawDiff(out)
}

// parseRawDiff parses `git diff --raw -z` output:
// ":oldmode newmode oldsha newsha status\0path\0".
func parseRawDiff(out []byte) ([]fileChange, error) {
	var res []fileChange
	fields := bytes.Split(out, []byte{0})
	for i := 0; i < len(fields); i++ {
		f := string(fields[i])
		if f == "" {
			continue
		}
		if !strings.HasPrefix(f, ":") || i+1 >= len(fields) {
			return nil, fmt.Errorf("unexpected git diff --raw output %q", f)
		}
		meta := strings.Fields(f[1:])
		if len(meta) < 5 || meta[4] == "" {
			return nil, fmt.Errorf("unexpected git diff --raw header %q", f)
		}
		i++
		res = append(res, fileChange{status: meta[4][0], path: string(fields[i]), oldMode: meta[0], newMode: meta[1], newSHA: meta[3]})
	}
	return res, nil
}

// diff returns `git diff` between two commits restricted by pathspecs.
func (g git) diff(ctx context.Context, from, to string, pathspecs ...string) (string, error) {
	args := []string{"diff", "--no-color", "--no-renames", "--no-ext-diff", "--no-textconv", from, to, "--"}
	args = append(args, pathspecs...)
	out, err := g.run(ctx, args...)
	return string(out), err
}

// blobPrefixes returns up to n leading bytes of each blob, by SHA, in one
// `git cat-file --batch`. In a blobless clone the blobs must be present
// first (see lfsPointers).
func (g git) blobPrefixes(ctx context.Context, shas []string, n int) (map[string][]byte, error) {
	out := map[string][]byte{}
	if len(shas) == 0 {
		return out, nil
	}
	raw, err := g.runStdin(ctx, []byte(strings.Join(shas, "\n")+"\n"), "cat-file", "--batch")
	if err != nil {
		return nil, err
	}
	for len(raw) > 0 {
		hdr, rest, ok := bytes.Cut(raw, []byte("\n"))
		if !ok {
			return nil, fmt.Errorf("truncated cat-file --batch output")
		}
		f := strings.Fields(string(hdr))
		if len(f) == 2 && f[1] == "missing" {
			raw = rest
			continue
		}
		if len(f) != 3 {
			return nil, fmt.Errorf("unexpected cat-file --batch header %q", hdr)
		}
		size, err := strconv.Atoi(f[2])
		if err != nil || size < 0 || size+1 > len(rest) {
			return nil, fmt.Errorf("unexpected cat-file --batch header %q", hdr)
		}
		out[f[0]] = rest[:min(size, n)]
		raw = rest[size+1:]
	}
	return out, nil
}

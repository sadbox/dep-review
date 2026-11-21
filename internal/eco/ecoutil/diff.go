package ecoutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// maxRawDiff bounds what is read from git; the evidence writer cuts far
// earlier (and records truncation).
const maxRawDiff = 64 << 20

// FileDiff is one file's part of a tree diff.
type FileDiff struct {
	Path string // relative to the tree root
	Body []byte // from the "diff --git" line on
}

// DiffTrees diffs parent/oldRel against parent/newRel with
// `git diff --no-index`, outside any repository and with no user or system
// git configuration, so no diff driver or textconv can run. Either side may
// be "" for an absent tree (a new or removed dependency): an empty
// directory is used. Binary files appear as "Binary files ... differ".
// Renames are not detected (--no-renames): a file moved with identical
// bytes, say an inert testdata/x.txt that becomes a compiled evil.c, must
// show as the removal and the full addition it is, not as a one-line
// rename.
func DiffTrees(ctx context.Context, home, parent, oldRel, newRel string) ([]FileDiff, bool, error) {
	empty := ""
	for _, side := range []*string{&oldRel, &newRel} {
		if *side != "" {
			continue
		}
		if empty == "" {
			d, err := os.MkdirTemp(parent, "empty-")
			if err != nil {
				return nil, false, err
			}
			empty = d[len(parent)+1:]
		}
		*side = empty
	}
	cmd := exec.CommandContext(ctx, "git", "-c", "core.quotePath=false",
		"diff", "--no-index", "--no-color", "--no-ext-diff", "--no-textconv",
		"--no-renames", "--src-prefix=", "--dst-prefix=", "--", oldRel, newRel)
	cmd.Dir = parent
	cmd.Env = append(gitEnv(home), "GIT_CEILING_DIRECTORIES="+parent)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, false, err
	}
	if err := cmd.Start(); err != nil {
		return nil, false, err
	}
	raw, rerr := io.ReadAll(io.LimitReader(stdout, maxRawDiff+1))
	truncated := len(raw) > maxRawDiff
	if truncated {
		raw = raw[:maxRawDiff]
		_, _ = io.Copy(io.Discard, stdout)
	}
	werr := cmd.Wait()
	if rerr != nil {
		return nil, false, rerr
	}
	var ee *exec.ExitError
	if werr != nil && !(errors.As(werr, &ee) && ee.ExitCode() == 1) {
		return nil, false, fmt.Errorf("git diff --no-index: %w: %s", werr, strings.TrimSpace(stderr.String()))
	}
	return splitDiff(raw, oldRel+"/", newRel+"/"), truncated, nil
}

func splitDiff(raw []byte, oldPrefix, newPrefix string) []FileDiff {
	var out []FileDiff
	const hdr = "diff --git "
	for len(raw) > 0 {
		next := bytes.Index(raw[1:], []byte("\n"+hdr))
		var chunk []byte
		if next < 0 {
			chunk, raw = raw, nil
		} else {
			chunk, raw = raw[:next+2], raw[next+2:]
		}
		line, _, _ := bytes.Cut(chunk, []byte("\n"))
		p := strings.TrimPrefix(string(line), hdr)
		// "<old>/<path> <new>/<path>"; take the side that starts the line.
		switch {
		case strings.HasPrefix(p, oldPrefix):
			p = p[len(oldPrefix):]
		case strings.HasPrefix(p, newPrefix):
			p = p[len(newPrefix):]
		}
		if i := strings.Index(p, " "+newPrefix); i >= 0 {
			p = p[:i]
		} else if i := strings.Index(p, " "+oldPrefix); i >= 0 {
			p = p[:i]
		}
		out = append(out, FileDiff{Path: p, Body: chunk})
	}
	return out
}

// JoinDiffs concatenates file diffs, dropping those skip rejects, and
// returns the text plus the paths kept.
func JoinDiffs(diffs []FileDiff, skip func(path string) bool) ([]byte, []string) {
	var buf bytes.Buffer
	var kept []string
	for _, d := range diffs {
		if skip != nil && skip(d.Path) {
			continue
		}
		buf.Write(d.Body)
		if !bytes.HasSuffix(d.Body, []byte("\n")) {
			buf.WriteByte('\n')
		}
		kept = append(kept, d.Path)
	}
	return buf.Bytes(), kept
}

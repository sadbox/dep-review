package gather

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sadbox/dep-review/internal/facts"
	"github.com/sadbox/dep-review/internal/gh"
)

// Changes is what a pull request changes, read from git objects.
type Changes struct {
	// Base is the merge base of the pull request's base and head commits:
	// the commit its changes are relative to. Comparing against it, not
	// against the tip of the base branch, keeps what landed on the base
	// branch since out of the change set.
	Base string
	// Head is the pull request's head commit.
	Head string
	// Files is every path that differs between Base and Head, with its
	// mode and content at both.
	Files []facts.File
	// Refused says why the change set is more than the gate reads (too
	// many paths, a file too large) and is empty otherwise. Files is then
	// empty, and Fetch records a Shape that does not hold: no ecosystem's
	// manifest and lock files come near these limits.
	Refused string
}

// changeLimits bound what ReadChanges holds in memory.
type changeLimits struct {
	// files is the most paths a change set may have.
	files int
	// blob is the most bytes one file may have at either commit.
	blob int64
	// total is the most bytes all contents may have together.
	total int64
}

// defaultChangeLimits is far above a Dependabot pull request, which
// changes a handful of manifest and lock files; a large package-lock.json
// is a few megabytes.
var defaultChangeLimits = changeLimits{files: 1000, blob: 32 << 20, total: 128 << 20}

// ReadChanges reads the pull request's change set from the checkout in
// repoDir, which must hold both commits and their history (a full clone
// of the head). base is the base commit classify recorded and head the
// head commit.
//
// Only git objects are read: the merge base, the two trees and the blobs
// that differ. The working tree is never looked at and nothing from it is
// run. git is given the repository's own directory, so it searches for
// none, and an environment without system or user configuration.
//
// An error means the checkout could not be read (no git, a commit or an
// object that is not there, the context ended): there is nothing to
// gather from and the job fails. A change set that is too large is not an
// error; see Changes.Refused.
func ReadChanges(ctx context.Context, repoDir, base, head string) (Changes, error) {
	return readChanges(ctx, repoDir, base, head, defaultChangeLimits)
}

func readChanges(ctx context.Context, repoDir, base, head string, lim changeLimits) (Changes, error) {
	if !gh.ValidSHA(base) || !gh.ValidSHA(head) {
		return Changes{}, fmt.Errorf("gather: base %q and head %q must be full commit IDs", base, head)
	}
	g, err := newGit(repoDir)
	if err != nil {
		return Changes{}, err
	}

	out, err := g.run(ctx, 1<<10, "merge-base", base, head)
	if err != nil {
		return Changes{}, err
	}
	mergeBase := strings.TrimSpace(string(out))
	if !gh.ValidSHA(mergeBase) {
		return Changes{}, fmt.Errorf("gather: git merge-base printed %q, not a commit ID", mergeBase)
	}
	changes := Changes{Base: mergeBase, Head: head}

	// One record per path: the two modes, the two object IDs and a status
	// letter, then the path. No rename detection: a rename is a path that
	// went away and a path that appeared, which is what a gatherer checks.
	// The cap is every record at the longest path a tree can hold.
	raw, err := g.run(ctx, int64(lim.files)*(4096+256), "diff-tree", "-r", "-z", "--raw", "--no-renames", "--no-abbrev", mergeBase, head)
	if errors.Is(err, errTooMuch) {
		changes.Refused = fmt.Sprintf("the pull request changes more than %d paths", lim.files)
		return changes, nil
	}
	if err != nil {
		return Changes{}, err
	}
	records, err := parseRaw(raw)
	if err != nil {
		return Changes{}, err
	}
	if len(records) > lim.files {
		changes.Refused = fmt.Sprintf("the pull request changes %d paths, more than %d", len(records), lim.files)
		return changes, nil
	}

	// "git cat-file blob" prints an object as it is stored: no filter and
	// no conversion is applied, and an object that is not a blob is an
	// error.
	var files []facts.File
	var total int64
	for _, r := range records {
		f := facts.File{Path: r.path, BaseMode: r.baseMode, HeadMode: r.headMode}
		for _, side := range []struct {
			mode, object string
			content      *[]byte
		}{{r.baseMode, r.baseObject, &f.Base}, {r.headMode, r.headObject, &f.Head}} {
			// A path that is absent has nothing to read, and neither has a
			// submodule (160000), whose object is a commit of another
			// repository.
			if side.mode == "" || side.mode == "160000" {
				continue
			}
			content, err := g.run(ctx, lim.blob, "cat-file", "blob", side.object)
			if errors.Is(err, errTooMuch) {
				changes.Refused = fmt.Sprintf("a changed file is more than %d bytes", lim.blob)
				return changes, nil
			}
			if err != nil {
				return Changes{}, err
			}
			if total += int64(len(content)); total > lim.total {
				changes.Refused = fmt.Sprintf("the changed files are more than %d bytes together", lim.total)
				return changes, nil
			}
			*side.content = content
		}
		files = append(files, f)
	}
	changes.Files = files
	return changes, nil
}

// record is one changed path as git diff-tree prints it.
type record struct {
	path string
	// The modes are git's ("100644"), and empty for a path that is absent
	// at that commit.
	baseMode, headMode     string
	baseObject, headObject string
}

// rawRE is one record of "git diff-tree --raw --no-abbrev": the modes,
// the object IDs and the status. Without rename detection the status is
// A, M, D or T (a change of type) and carries no score.
var rawRE = regexp.MustCompile(`^:([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40}|[0-9a-f]{64}) ([0-9a-f]{40}|[0-9a-f]{64}) [AMDT]$`)

// parseRaw reads the NUL-separated output of git diff-tree -z --raw.
func parseRaw(raw []byte) ([]record, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	parts := strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00")
	if len(parts)%2 != 0 {
		return nil, errors.New("gather: git diff-tree printed a record without a path")
	}
	var out []record
	for i := 0; i < len(parts); i += 2 {
		m := rawRE.FindStringSubmatch(parts[i])
		if m == nil || parts[i+1] == "" {
			return nil, fmt.Errorf("gather: git diff-tree printed a record the gate does not know: %.120q", parts[i])
		}
		r := record{path: parts[i+1], baseMode: m[1], headMode: m[2], baseObject: m[3], headObject: m[4]}
		// git writes an absent side as mode 000000.
		if r.baseMode == "000000" {
			r.baseMode = ""
		}
		if r.headMode == "000000" {
			r.headMode = ""
		}
		out = append(out, r)
	}
	return out, nil
}

// git runs read-only git plumbing on one repository's objects.
type git struct {
	bin string
	// dir is the repository's own directory (.git), named to every
	// command so git never searches for one.
	dir string
	env []string
}

func newGit(repoDir string) (git, error) {
	bin, err := exec.LookPath("git")
	if err != nil {
		return git{}, fmt.Errorf("gather: git is not installed: %w", err)
	}
	abs, err := filepath.Abs(repoDir)
	if err != nil {
		return git{}, err
	}
	return git{
		bin: bin,
		dir: filepath.Join(abs, ".git"),
		// Written out in full: no system or user configuration and no
		// attributes, so no diff driver, filter, pager or helper of the
		// runner's or a user's is ever in play.
		env: []string{
			"PATH=" + os.Getenv("PATH"),
			"HOME=" + os.DevNull,
			"XDG_CONFIG_HOME=" + os.DevNull,
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=" + os.DevNull,
			"GIT_ATTR_NOSYSTEM=1",
			"GIT_TERMINAL_PROMPT=0",
			"GIT_OPTIONAL_LOCKS=0",
			// An object that is not there is an error, never a download
			// through whatever remote the repository's configuration names.
			"GIT_NO_LAZY_FETCH=1",
			"LC_ALL=C",
		},
	}, nil
}

// command is one git command on the repository. The repository's own
// configuration is still read, and it is the checkout step's, not the
// pull request's. All the same, the two settings that would have these
// commands run a program are switched off: git diff-tree reads the index,
// and with it runs a configured core.fsmonitor (seen with git 2.56.1; a
// test keeps it from coming back), and a hook is a program by definition.
func (g git) command(ctx context.Context, args ...string) *exec.Cmd {
	fixed := []string{"--git-dir=" + g.dir, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.DevNull}
	cmd := exec.CommandContext(ctx, g.bin, append(fixed, args...)...)
	cmd.Env = g.env
	return cmd
}

// errTooMuch is run's error for a command that printed more than its cap.
var errTooMuch = errors.New("gather: git printed more than the gate reads")

// run runs one git command and returns what it printed, at most max
// bytes.
func (g git) run(ctx context.Context, max int64, args ...string) ([]byte, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := g.command(ctx, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	out, readErr := io.ReadAll(io.LimitReader(stdout, max+1))
	if int64(len(out)) > max {
		// Stop git instead of reading the rest.
		cancel()
		_ = cmd.Wait()
		return nil, errTooMuch
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("gather: git %s: %w: %.300q", args[0], err, strings.TrimSpace(stderr.String()))
	}
	if readErr != nil {
		return nil, fmt.Errorf("gather: git %s: %w", args[0], readErr)
	}
	return out, nil
}

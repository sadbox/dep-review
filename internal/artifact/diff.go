package artifact

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	// bundleBytes is the size above which one file of an npm or Actions
	// artifact is shown as its new lines only (spec section 7). Such a
	// file is build output: a line-by-line diff of two builds is mostly
	// lines that moved.
	bundleBytes = 256 << 10
	// contextLines is how many unchanged lines are shown around a change.
	contextLines = 3
)

// readLimits bound what is held in memory while a read is prepared.
type readLimits struct {
	// file is the largest file read in to be diffed. A larger changed
	// file is listed as unread.
	file int64
	// text is the most diff text held. Once there is more, the changed
	// files that are left are listed as unread without being diffed.
	text int
}

// defaultReadLimits: no file the gate has met comes near the first, and
// the second is the largest budget Prepare accepts, so a read that could
// still be full is never cut short by it.
var defaultReadLimits = readLimits{file: 64 << 20, text: maxBudgetBytes}

// section is one changed or added text file, ready to be shown.
type section struct {
	// path is the file's path in the artifact, as it is (not escaped).
	path string
	// file is the new file's size and hash, for the unread list should
	// the budget leave the section out.
	file file
	// header is the gate's line that introduces the file, without its
	// newline.
	header string
	// hunks is the text, escaped. Each hunk is whole lines, starts with
	// an "@@" line and ends with a newline. A file with nothing to show
	// (it is now empty) has none.
	hunks []string
	// generated: the file carries a generated-code marker or is a
	// bundle. It only matters to the targeted read.
	generated bool
}

// isText is the gate's whole definition of text: valid UTF-8 with no NUL
// byte. There is no "mostly text": one NUL makes a file something the
// model is not shown, and it is then listed as unread, never left out
// silently.
func isText(b []byte) bool {
	return utf8.Valid(b) && bytes.IndexByte(b, 0) < 0
}

// compare lists the paths whose bytes differ between two trees or exist
// only in the new one, and the paths that exist only in the old one, both
// sorted. The gate decides what changed here, from the extracted bytes;
// git is only asked to format one file's change at a time, so nothing git
// decides not to print can drop a file from the list.
func compare(oldTree, newTree *tree) (changed, removed []string) {
	for p, nf := range newTree.files {
		if of, ok := oldTree.files[p]; !ok || of != nf {
			changed = append(changed, p)
		}
	}
	for p := range oldTree.files {
		if _, ok := newTree.files[p]; !ok {
			removed = append(removed, p)
		}
	}
	sort.Strings(changed)
	sort.Strings(removed)
	return changed, removed
}

// readChanged turns every changed or added file into a section, or into
// an unread entry when it is not text or is past what lim lets be held.
func readChanged(ctx context.Context, kind Kind, oldTree, newTree *tree, changed []string, d *differ, lim readLimits) ([]section, []unreadFile, error) {
	var sections []section
	var unread []unreadFile
	held := 0 // bytes of text in sections
	for _, p := range changed {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		nf := newTree.files[p]
		if nf.size > lim.file || held > lim.text {
			unread = append(unread, unreadFile{p, nf})
			continue
		}
		content, err := newTree.root.ReadFile(p)
		if err != nil {
			return nil, nil, err
		}
		if !isText(content) {
			unread = append(unread, unreadFile{p, nf})
			continue
		}

		status := "added"
		var before []byte
		if of, ok := oldTree.files[p]; ok {
			// When there is nothing readable to compare with, the
			// model is shown all of the new file.
			status = "changed"
			if of.size > lim.file {
				status = "changed; the old version is too large to compare with, so the whole file is shown as added"
			} else if before, err = oldTree.root.ReadFile(p); err != nil {
				return nil, nil, err
			} else if !isText(before) {
				before = nil
				status = "changed; the old version is not text, so the whole file is shown as added"
			}
		}

		s := section{path: p, file: nf, generated: generated(content)}
		var hunks []string
		switch {
		case (kind == NPMTarball || kind == ActionTarball) && len(content) > bundleBytes:
			hunks = newLines(before, content)
			status += fmt.Sprintf("; larger than %d KB, so only the lines that occur nowhere in the old version are shown, with %d lines around each",
				bundleBytes>>10, contextLines)
			if len(hunks) == 0 {
				status += "; there are none: lines were only removed or moved"
			}
			s.generated = true
		case len(content) == 0 && len(before) == 0:
			status += "; empty"
		default:
			if hunks, err = d.diff(ctx, before, content); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", escapeLine(p), err)
			}
		}
		for _, h := range hunks {
			h = escapeText(h)
			held += len(h)
			s.hunks = append(s.hunks, h)
		}
		s.header = "== file: " + escapeLine(p) + " (" + status + ")"
		sections = append(sections, s)
	}
	return sections, unread, nil
}

// unreadFile is a changed or added file the model is not shown.
type unreadFile struct {
	path string
	file file
}

// newLines is the bundle view: the lines of content that occur nowhere in
// before, each with contextLines lines around it. The hunks look like a
// unified diff's with nothing removed: "+" for a new line, a space for
// context.
func newLines(before, content []byte) []string {
	have := map[string]bool{}
	for _, l := range splitLines(before) {
		have[l] = true
	}
	lines := splitLines(content)
	var hunks []string
	for i := 0; i < len(lines); i++ {
		if have[lines[i]] {
			continue
		}
		// A hunk runs from contextLines before this new line to
		// contextLines after the last new line whose context touches.
		start := max(0, i-contextLines)
		last := i
		for j := i + 1; j < len(lines) && j <= last+2*contextLines+1; j++ {
			if !have[lines[j]] {
				last = j
			}
		}
		end := min(len(lines), last+contextLines+1)
		var b strings.Builder
		fmt.Fprintf(&b, "@@ +%d,%d @@\n", start+1, end-start)
		for j := start; j < end; j++ {
			if have[lines[j]] {
				b.WriteByte(' ')
			} else {
				b.WriteByte('+')
			}
			b.WriteString(lines[j])
			b.WriteByte('\n')
		}
		hunks = append(hunks, b.String())
		i = end - 1
	}
	return hunks
}

// splitLines splits at "\n" only, which is what git does too. A last line
// without a newline is a line.
func splitLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

// differ runs git diff for one Prepare.
type differ struct {
	git string
	// cwd is an empty directory, pair holds the two files being
	// compared, under fixed names.
	cwd, pair string
	env       []string
}

// newDiffer sets up the directories git runs in, under work, which must
// be an absolute path with its symbolic links resolved.
//
// What makes the diff safe is where and how git runs, not only "--text":
//
//   - The two files are copies under fixed names in a directory of their
//     own. No .gitattributes of the artifact is beside them or above
//     them, so none can mark a file binary, re-encode it or filter it.
//   - The working directory is empty and GIT_CEILING_DIRECTORIES stops
//     the search for a repository right above it. Inside a repository
//     git would read that repository's configuration and attributes,
//     and those do apply to "diff --no-index".
//   - The environment is written out here in full: no system or global
//     configuration, no system or global attributes, an empty HOME.
func newDiffer(git, work string) (*differ, error) {
	d := &differ{git: git, cwd: filepath.Join(work, "cwd"), pair: filepath.Join(work, "pair")}
	home := filepath.Join(work, "home")
	for _, dir := range []string{d.cwd, d.pair, home} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return nil, err
		}
	}
	d.env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		// Nothing is there: no git/config, no git/attributes.
		"XDG_CONFIG_HOME=" + filepath.Join(home, "xdg"),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_ATTR_NOSYSTEM=1",
		"GIT_CEILING_DIRECTORIES=" + work,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_OPTIONAL_LOCKS=0",
		"LC_ALL=C",
	}
	return d, nil
}

// diff returns the hunks of "git diff --no-index --text" between two
// texts that differ, not yet escaped. git's own header lines, which name
// the temporary files, are dropped; the caller writes the file's header.
func (d *differ) diff(ctx context.Context, before, after []byte) ([]string, error) {
	a, b := filepath.Join(d.pair, "old"), filepath.Join(d.pair, "new")
	if err := os.WriteFile(a, before, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(b, after, 0o600); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, d.git, "diff", "--no-index", "--text",
		"--no-color", "--no-ext-diff", "--no-textconv", "--no-renames",
		// Spelled out so the text, and with it the content key, does
		// not depend on a default.
		"--diff-algorithm=myers", fmt.Sprintf("--unified=%d", contextLines), "--inter-hunk-context=0",
		"--", a, b)
	cmd.Dir = d.cwd
	cmd.Env = d.env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	// git diff exits 1 when the files differ, which they do.
	var exit *exec.ExitError
	switch {
	case err == nil:
		return nil, errors.New("git diff reports no difference between two files that differ")
	case !errors.As(err, &exit) || exit.ExitCode() != 1:
		return nil, fmt.Errorf("git diff: %v: %s", err, clip(stderr.String()))
	}

	// Everything before the first hunk is git's header.
	out := stdout.String()
	if !strings.HasPrefix(out, "@@ ") {
		i := strings.Index(out, "\n@@ ")
		if i < 0 {
			return nil, errors.New("git diff printed no hunk for two files that differ")
		}
		out = out[i+1:]
	}
	return splitHunks(out), nil
}

// splitHunks cuts a diff body before every hunk header. Only a hunk
// header starts with "@@": every line of content starts with a space, "+",
// "-" or "\".
func splitHunks(body string) []string {
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	var hunks []string
	start := 0
	for i := 0; i < len(body); {
		if i > start && strings.HasPrefix(body[i:], "@@ ") {
			hunks = append(hunks, body[start:i])
			start = i
		}
		i += strings.IndexByte(body[i:], '\n') + 1
	}
	return append(hunks, body[start:])
}

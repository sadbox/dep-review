package artifact

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// What an action runs is not all in its repository. A JavaScript action
// and a composite action run files of the repository, which the tarball
// holds and the model reads. A container action runs an image: one named
// by reference, or built from a Dockerfile, whose base image and
// downloads are an image's as well. Nothing of an image is read (spec
// section 11, amendment 3), so a read of the repository would not be a
// read of what runs. This file tells the two apart, for the directories
// the pull request's workflows use the action from, and refuses whatever
// it does not recognise (ErrActionKind).
//
// There is no YAML parser here (spec section 6). The metadata file must
// be in the plain block form and say what runs on one line of one shape,
// as every action the gate has met writes it, and any other way of
// writing it is refused, not read.

// actionMetadata are the two names the runner looks for, in its order.
var actionMetadata = []string{"action.yml", "action.yaml"}

// maxMetadataBytes is the largest metadata file read. The largest the
// gate has met is a few kilobytes.
const maxMetadataBytes = 1 << 20

var (
	// plainKeyRE is a line, after its indent, that starts a key in the
	// one form the gate takes: ASCII letters, digits, '_' and '-',
	// starting with a letter, unquoted, then a colon and a blank or the
	// line's end. Quoted and explicit keys, merge keys, anchors, tags,
	// aliases, flow collections, directives and document markers do not
	// start that way.
	plainKeyRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*:(?:[ \t]|$)`)
	// runsLineRE is the one top-level runs line the gate takes: a block
	// under it, and at most a comment beside it.
	runsLineRE = regexp.MustCompile(`^runs:[ \t]*(?:#.*)?$`)
	// usingCodeRE is the one using line the gate takes, after its
	// indent: a runtime that executes the repository's own files, bare
	// or in quotes, and at most a comment after it.
	usingCodeRE = regexp.MustCompile(`^using:[ \t]+(?:node[0-9]{1,3}|'node[0-9]{1,3}'|"node[0-9]{1,3}"|composite|'composite'|"composite")(?:[ \t]+#.*)?[ \t]*$`)
	// firstMarkerRE is the one document marker a metadata file may have,
	// as its first line; docMarkerRE is any document marker.
	firstMarkerRE = regexp.MustCompile(`^---[ \t]*$`)
	docMarkerRE   = regexp.MustCompile(`^(?:---|\.\.\.)(?:[ \t]|$)`)
)

// yamlBreaks are the line breaks YAML knows besides LF and CR LF. A
// split on LF does not see them, so a file with one is not read.
var yamlBreaks = []struct{ text, name string }{
	{"\u0085", "U+0085"}, {"\u2028", "U+2028"}, {"\u2029", "U+2029"},
}

// actionProblem says why the action in t, used from dirs, is not shown to
// run only files of its own repository, or "". dirs are paths in the
// repository, "." for its root. With none, which directory is used is not
// known, and every directory that holds a metadata file counts.
func actionProblem(t *tree, dirs []string) string {
	if len(dirs) == 0 {
		seen := map[string]bool{}
		for p := range t.files {
			if base := path.Base(p); (base == actionMetadata[0] || base == actionMetadata[1]) && !seen[path.Dir(p)] {
				seen[path.Dir(p)] = true
				dirs = append(dirs, path.Dir(p))
			}
		}
		if len(dirs) == 0 {
			return "there is no action.yml or action.yaml anywhere in the repository"
		}
		sort.Strings(dirs)
	}
	for _, dir := range dirs {
		found := false
		for _, name := range actionMetadata {
			p := path.Join(dir, name)
			f, ok := t.files[p]
			if !ok {
				continue
			}
			found = true
			if f.size > maxMetadataBytes {
				return fmt.Sprintf("%s is %d bytes, more than the gate reads of a metadata file", escapeLine(p), f.size)
			}
			content, err := t.root.ReadFile(p)
			if err != nil {
				return fmt.Sprintf("%s could not be read: %v", escapeLine(p), err)
			}
			if why := metadataProblem(content); why != "" {
				return escapeLine(p) + " " + why
			}
		}
		if !found {
			// The runner would build a Dockerfile in that directory, or
			// fail. Neither is code the model was shown.
			return fmt.Sprintf("there is no action.yml or action.yaml in %s, where a workflow uses the action from", escapeLine(dir))
		}
	}
	return ""
}

// metadataProblem says why one metadata file does not show an action that
// runs only its repository's files, or "".
//
// The file counts only in the plain block form (spec section 11,
// amendment 68). In a YAML block mapping every key starts a line at the
// mapping's indent. So every line of the top level, and every line at the
// indent of the runs block, must start with a plain key, and exactly one
// of each says runs and using. The runner's own runs and using keys can
// then only be lines the gate counted: a decoy inside a block scalar or a
// flow collection makes a count two, or leaves the runner with no key.
func metadataProblem(content []byte) string {
	if !isText(content) {
		return "is not text"
	}
	text := string(content)
	// A composite action may run an image as a step, and a container
	// action names one here.
	if strings.Contains(text, "docker://") {
		return "names a docker:// image"
	}
	if strings.HasPrefix(text, "\uFEFF") {
		return "starts with a byte order mark"
	}
	if strings.Contains(strings.ReplaceAll(text, "\r\n", ""), "\r") {
		return "has a bare CR, a line break YAML knows and the gate does not read"
	}
	for _, b := range yamlBreaks {
		if strings.Contains(text, b.text) {
			return "has " + b.name + ", a line break YAML knows and the gate does not read"
		}
	}
	lines := strings.Split(text, "\n")
	skip := func(line string) bool {
		rest := strings.TrimLeft(line, " \t")
		return rest == "" || rest[0] == '#'
	}
	key := func(s string) string { return s[:strings.IndexByte(s, ':')] }

	// The top level.
	runs, runsAt := 0, -1
	first, marked := true, false
	for i := range lines {
		line := strings.TrimSuffix(lines[i], "\r")
		lines[i] = line
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if strings.ContainsRune(line[:indent], '\t') {
			return fmt.Sprintf("line %d has a tab in its indentation", i+1)
		}
		if skip(line) {
			continue
		}
		switch {
		case first && firstMarkerRE.MatchString(line):
			first, marked = false, true
			continue
		case first && indent > 0:
			return fmt.Sprintf("line %d is indented, and the first line that is not blank or a comment must start in column 0", i+1)
		case marked && indent > 0:
			return fmt.Sprintf("line %d is indented, and the first line after `---` must start in column 0", i+1)
		}
		first, marked = false, false
		switch {
		case indent > 0:
			continue
		case docMarkerRE.MatchString(line):
			return fmt.Sprintf("line %d is a document marker, and the gate takes one document with at most `---` alone on its first line", i+1)
		case !plainKeyRE.MatchString(line):
			return fmt.Sprintf("line %d starts in column 0 and is neither a comment nor a plain key", i+1)
		case strings.EqualFold(key(line), "runs"):
			runs, runsAt = runs+1, i
		}
	}
	if runs != 1 {
		return fmt.Sprintf("has %d top-level `runs` keys, and the gate takes exactly one", runs)
	}
	if !runsLineRE.MatchString(lines[runsAt]) {
		return fmt.Sprintf("line %d is not `runs:` alone, with the block of what runs under it", runsAt+1)
	}

	// The runs block: the lines up to the next one in column 0, which is
	// a key of the top level.
	using, n := 0, 0
	for i := runsAt + 1; i < len(lines); i++ {
		line := lines[i]
		if skip(line) {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 {
			break
		}
		switch {
		case n == 0:
			n = indent
		case indent < n:
			return fmt.Sprintf("line %d is indented less than the first line of the `runs` block", i+1)
		}
		body := line[n:]
		if indent > n || body == "-" || strings.HasPrefix(body, "- ") {
			continue
		}
		if !plainKeyRE.MatchString(body) {
			return fmt.Sprintf("line %d is in the `runs` block, at its indent, and is neither a plain key nor a sequence entry", i+1)
		}
		if strings.EqualFold(key(body), "using") {
			if !usingCodeRE.MatchString(body) {
				return "has a `using` line that is not `using: nodeNN` or `using: composite` in the usual form"
			}
			using++
		}
	}
	if using != 1 {
		return fmt.Sprintf("has %d `using` keys in the `runs` block, and the gate takes exactly one", using)
	}
	return ""
}

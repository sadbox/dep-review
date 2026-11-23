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
// say what runs on one line of one shape, as every action the gate has
// met writes it, and any other way of writing it is refused, not read.

// actionMetadata are the two names the runner looks for, in its order.
var actionMetadata = []string{"action.yml", "action.yaml"}

// maxMetadataBytes is the largest metadata file read. The largest the
// gate has met is a few kilobytes.
const maxMetadataBytes = 1 << 20

var (
	// usingKeyRE is a line that sets a key called using, however it is
	// quoted and wherever it stands.
	usingKeyRE = regexp.MustCompile(`^[ \t]*["']?using["']?[ \t]*:`)
	// usingCodeRE is the one such line the gate takes: indented under
	// runs, with a runtime that executes the repository's own files, bare
	// or in quotes, and at most a comment after it.
	usingCodeRE = regexp.MustCompile(`^[ \t]+using:[ \t]+(?:node[0-9]{1,3}|'node[0-9]{1,3}'|"node[0-9]{1,3}"|composite|'composite'|"composite")(?:[ \t]+#.*)?[ \t]*$`)
)

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
func metadataProblem(content []byte) string {
	if !isText(content) {
		return "is not text"
	}
	// A composite action may run an image as a step, and a container
	// action names one here.
	if strings.Contains(string(content), "docker://") {
		return "names a docker:// image"
	}
	code := 0
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if !usingKeyRE.MatchString(line) {
			continue
		}
		if !usingCodeRE.MatchString(line) {
			return "has a `using` line that is not `using: nodeNN` or `using: composite` in the usual form"
		}
		code++
	}
	if code != 1 {
		return fmt.Sprintf("has %d lines that say `using: nodeNN` or `using: composite`, and the gate takes exactly one", code)
	}
	return ""
}

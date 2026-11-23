package gomod

import (
	"bytes"
	"path"
	"strings"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"

	"golang.org/x/mod/module"
)

// Leniency for well-known modules. For the Go project's and Google's own
// module paths, and only when the update's upstream history was verified
// (upstream.go: both zips rebuilt from the repository at the proxy's
// commits match go.sum), some items that otherwise go to a person are
// reviewed instead, with the same per-item accounting and citations:
//   - cgo, C and assembly source (text, quoted in full);
//   - binaries under testdata/ that nothing embeds and only the module's
//     link lines could reach, that the linker cannot take by name (not a
//     .syso, .a, .o, .so, .dylib, .lib or .dll), whose bytes are a known
//     data format (an image, a document, a compressed stream: never a
//     linker input), in a module with no cgo, C or preprocessed assembly
//     (Go assembly includes only literal paths), and whose name no text
//     file of the module holds;
//   - embeds the gate could not resolve.
//
// Leniency never skips the review or the accounting, and nothing else
// changes: every other binary, a decoded blob that is not text, an
// unparseable file and a module the gate could not analyze still go to a
// person. The list is the gate's, with no per-repository input.

// lenientNote marks a finding leniency put on review.
const lenientNote = "reviewed, not sent to a person (well-known module with verified upstream history) despite this check's route: "

// wellKnownModule: a module under a path only Google publishes. Not
// github.com/google/*, which holds many small projects reviewed unevenly.
func wellKnownModule(path string) bool {
	if module.CheckPath(path) != nil {
		return false
	}
	return strings.HasPrefix(path, "golang.org/x/") ||
		strings.HasPrefix(path, "google.golang.org/") ||
		path == "cloud.google.com/go" || strings.HasPrefix(path, "cloud.google.com/go/")
}

// lenientCodes are the person-routed codes leniency puts on review.
var lenientCodes = map[string]bool{codeCgo: true, codeCSource: true, codeAsm: true, codeIncludable: true}

// lenientCode reports that leniency puts code's finding on review: one of
// lenientCodes, or codeIncomplete when every item not shown in full is a
// binary eligible for it (report.eligible) or an unresolved embed.
func (r *report) lenientCode(code string) bool {
	if !r.lenient {
		return false
	}
	if lenientCodes[code] {
		return true
	}
	if code != codeIncomplete {
		return false
	}
	for k := range r.keys {
		if r.shown[k] {
			continue
		}
		if k[0] != codeEmbed && !r.eligible[k] {
			return false
		}
	}
	return true
}

// cgoText reports that the module has text the C toolchain compiles or
// preprocesses (cgo, C, C++, preprocessed assembly and the other cgo
// sources): its includes and .incbin can name a file through macros and
// concatenation, so no name search rules a fixture out. Over-approximated:
// any .go file holding "C" in quotes counts.
func cgoText(t *ecoutil.Tree) bool {
	for _, f := range t.Files {
		switch ext := path.Ext(f); {
		case cgoSourceExts[ext], ext == ".S", ext == ".sx":
			return true
		case ext == ".go" && bytes.Contains(t.ReadFile(f), []byte(`"C"`)):
			return true
		}
	}
	return false
}

// textNames reports that some text file of the module may name rel: its
// base name, or without its extension when that is 3 bytes or more, in
// any non-binary file, compared case-folded. Over-approximated: any occurrence counts, so no
// cgo line, include, linker script or response file can name it unseen.
func textNames(t *ecoutil.Tree, rel string) bool {
	base := fold(path.Base(rel))
	stem := strings.TrimSuffix(base, path.Ext(base))
	for _, f := range t.Files {
		text := t.ReadFile(f)
		if f == rel || isBinaryFile(f, text) {
			continue
		}
		low := []byte(fold(string(text)))
		if bytes.Contains(low, []byte(base)) || len(stem) >= 3 && bytes.Contains(low, []byte(stem)) {
			return true
		}
	}
	return false
}

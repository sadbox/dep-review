package gomod

import (
	"strings"

	"golang.org/x/mod/module"
)

// Leniency for well-known modules. For the Go project's and Google's own
// module paths, and only when the update's upstream history was verified
// (upstream.go: both zips rebuilt from the repository at the proxy's
// commits match go.sum), some items that otherwise go to a person are
// reviewed instead, with the same per-item accounting and citations:
//   - cgo, C and assembly source (text, quoted in full);
//   - binaries under testdata/ that nothing embeds and only the module's
//     link lines could reach, and that the linker cannot take by name
//     (not a .syso, .a, .o, .so, .dylib, .lib or .dll);
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
var lenientCodes = map[string]bool{codeCgo: true, codeCSource: true, codeAsm: true}

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

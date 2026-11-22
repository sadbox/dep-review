package gomod

import (
	"path"
	"slices"
	"strings"

	"github.com/sadbox/dep-review/internal/evidence"
)

// Which binaries are flagged. Every flagged binary goes to a person; this
// only decides what is flagged:
//   - a binary added or changed outside testdata/ (as on main);
//   - a changed testdata binary the new tree embeds, or any changed binary
//     when the module has cgo, C or assembly sources or a .syso (links:
//     they can link or include any file without naming it);
//   - an unchanged binary the new tree newly embeds (exact //go:embed
//     resolution, embed.go), or every unchanged binary when the module
//     newly has links.

// linkReason is why, under the module's links, every binary is reachable.
func linkReason(links string) string {
	return "the module has " + links + ", which can link or include any file without naming it"
}

func inTestdata(rel string) bool {
	return slices.Contains(strings.Split(path.Dir(rel), "/"), "testdata")
}

// isBinaryFile is how CheckTrees decides a file is a binary to flag:
// a .syso or library/object file by name, a .go test file or any file the
// toolchain does not compile as source by its bytes.
func isBinaryFile(rel string, data []byte) bool {
	switch ext := path.Ext(rel); {
	case ext == ".syso" || linkExts[ext]:
		return true
	case ext == ".go":
		return strings.HasSuffix(rel, "_test.go") && evidence.IsBinary(data)
	case ext == ".s" || ext == ".S" || ext == ".sx" || cgoSourceExts[ext]:
		return false
	}
	return evidence.IsBinary(data)
}

// ascii reports a string of ASCII bytes only.
func ascii(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// fold is the ASCII case folding of a case-insensitive file system for
// literal names (macOS, Windows). Over-matching is the safe side.
func fold(s string) string { return strings.ToLower(s) }

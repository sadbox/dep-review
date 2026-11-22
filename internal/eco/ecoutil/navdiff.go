package ecoutil

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/sadbox/dep-review/internal/evidence"
	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/model"
)

// Navigable diffs: a package's diff written one part per changed file
// (evidence.Dir.AddPart, under the part caps) with a gate-written index
// (diffs.md) listing each with an ID. Every file is required reading
// unless Optional says why no consumer reads it; the verdict's examined
// must list every required ID (publish's accounting).

// NavDiffs is one update's diff to write.
type NavDiffs struct {
	Eco    string // finding code prefix: "gomod", "npm", "uv"
	Key    string // the update as flagged items name it
	Update string // the sanitized package name, for findings
	// Name is the evidence name for a suffix: "diff/<ID>.diff" for a
	// part, "diffs.md" for the index.
	Name  func(suffix string) string
	What  string // "module", "package"
	Desc  string // the index's description
	Diffs []FileDiff
	Cut   bool // git stopped reading the diff
	// Old and Cur are the two trees (Cur nil: the paths are not checked).
	Old, Cur *Tree
	// Optional is why no consumer reads path ("": required). Nil: every
	// file is required.
	Optional func(path string) string
	// SafePath sanitizes a path for the index (nil: evidence.SanitizeName).
	SafePath func(string) string
}

// Write writes the parts and the index; n numbers the IDs after the
// fetch's earlier ones.
func (nd NavDiffs) Write(env fetch.Env, n int) ([]model.DiffFile, []model.Finding, error) {
	safe := nd.SafePath
	if safe == nil {
		safe = evidence.SanitizeName
	}
	var findings []model.Finding
	if nd.Cut {
		findings = append(findings, model.Finding{Code: nd.Eco + ".diff-cut", Route: model.RouteHuman, Update: nd.Update,
			Detail: fmt.Sprintf("the diff of %s exceeded the gate's read limit, so some changes were never shown", nd.Key)})
	}
	// git's "diff --git a/x b/y" header is ambiguous for a path with a
	// space, so a file's path is believed only when the diffs' paths are
	// exactly the files that changed between the trees, each once.
	// Otherwise nothing is optional, and a person decides.
	trusted := true
	if nd.Cur != nil {
		want := map[string]bool{}
		for _, f := range ChangedFiles(nd.Old, nd.Cur) {
			want[f] = true
		}
		got := map[string]bool{}
		for _, d := range nd.Diffs {
			if got[d.Path] || !want[d.Path] {
				trusted = false
			}
			got[d.Path] = true
		}
		trusted = trusted && len(got) == len(want)
	}
	if !trusted {
		findings = append(findings, model.Finding{Code: nd.Eco + ".diff-paths", Route: model.RouteHuman, Update: nd.Update,
			Detail: fmt.Sprintf("the per-file diffs of %s do not match the files that changed (a path git cannot write unambiguously); every diff is required", nd.Key)})
	}
	var out []model.DiffFile
	var idx strings.Builder
	fmt.Fprintf(&idx, "# Changed files: %s\n\n", nd.Key)
	fmt.Fprintf(&idx, "Written by the gate. Each row is one changed file of the %s, its diff in the evidence file named in the last column.\n", nd.What)
	idx.WriteString("Read the diff of every row marked required and list its ID in the verdict's \"examined\"; the gate merges only when all of them are listed.\n")
	idx.WriteString("A row marked optional is a file no consumer build reads (the reason says why): read it when it helps.\n\n")
	idx.WriteString("| ID | File | Bytes | Reading | Diff |\n|---|---|---|---|---|\n")
	if len(nd.Diffs) == 0 {
		fmt.Fprintf(&idx, "(the %s trees are identical)\n", nd.What)
	}
	for _, d := range nd.Diffs {
		why := ""
		if trusted && nd.Optional != nil {
			why = nd.Optional(d.Path)
		}
		n++
		id := fmt.Sprintf("D%05d", n)
		// Named by ID: no path can collide with another's part.
		file, written, err := env.Evidence.AddPart(nd.Name("diff/"+id+".diff"), d.Body)
		if err != nil {
			return nil, nil, err
		}
		// Bytes is what the reviewer reads: the written, normalized text.
		df := model.DiffFile{ID: id, Update: nd.Key, Path: safe(d.Path), File: file,
			Bytes: int64(written), Required: why == "", Why: why}
		if df.File == "" {
			// Binary or past the caps: the writer recorded why (a person
			// decides); the row stays, with nothing to read.
			df.File = "(not written)"
		}
		out = append(out, df)
		reading := "required"
		if !df.Required {
			reading = "optional: " + why
		}
		fmt.Fprintf(&idx, "| %s | %s | %d | %s | %s |\n", df.ID, cell(df.Path), df.Bytes, reading, df.File)
	}
	if err := env.Evidence.Add(nd.Name("diffs.md"), nd.Desc, []byte(idx.String())); err != nil {
		return nil, nil, err
	}
	return out, findings, nil
}

// cell keeps a table cell one cell: no pipe or line break.
func cell(s string) string {
	return strings.NewReplacer("|", "_", "\n", "_", "\r", "_").Replace(s)
}

// ChangedFiles is every file added, removed or edited between two trees.
func ChangedFiles(old, cur *Tree) []string {
	var out []string
	for _, rel := range cur.Files {
		if old == nil || !old.Has(rel) || !bytes.Equal(old.ReadFile(rel), cur.ReadFile(rel)) {
			out = append(out, rel)
		}
	}
	if old != nil {
		for _, rel := range old.Files {
			if !cur.Has(rel) {
				out = append(out, rel)
			}
		}
	}
	return out
}

// MaxMustRead bounds what a review must read in full: every required
// diff and every other file the reviewer must read whole (flagged items,
// upstream histories), the single-file evidence's total
// (evidence.DefaultTotalCap). Past it, a person decides.
const MaxMustRead = 4 << 20

// ReadingLimits are the person-routed findings for more required reading
// than a review can take: more than model.MaxRequiredDiffs required
// diffs, or more than MaxMustRead bytes of required diffs and extra
// (the other must-read files' written bytes) together.
func ReadingLimits(eco string, diffs []model.DiffFile, extra int) []model.Finding {
	var out []model.Finding
	required, n := 0, extra
	for _, d := range diffs {
		if d.Required {
			required++
			n += int(d.Bytes)
		}
	}
	if required > model.MaxRequiredDiffs {
		out = append(out, model.Finding{Code: eco + ".too-many-diffs", Route: model.RouteHuman,
			Detail: fmt.Sprintf("%d changed files a consumer build can read; more than %d is too many to review", required, model.MaxRequiredDiffs)})
	}
	if n > MaxMustRead {
		out = append(out, model.Finding{Code: eco + ".too-much-to-read", Route: model.RouteHuman,
			Detail: fmt.Sprintf("the required diffs and flagged items come to %d bytes; more than %d is more than a review can read", n, MaxMustRead)})
	}
	return out
}

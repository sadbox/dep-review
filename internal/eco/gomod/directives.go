package gomod

import (
	"go/scanner"
	"go/token"
	"strings"
)

// Directives go/build does not report (//go:linkname, //go:cgo_*,
// //go:generate) are found in the new version of a file only, from the Go
// scanner's comment tokens at any column (a directive inside a string or
// a /* */ comment is no comment token), plus a line scan for
// //go:generate, which `go generate` finds line by line. The old version
// is never read for them (README "Design rules").

// directive is one //go: comment.
type directive struct {
	text string // the comment, "//go:..." (or the //go:generate line)
	line int
}

// scanDirectives returns the //go: line comments of src and whether the
// scanner reported an error.
func scanDirectives(name string, src []byte) (out []directive, scanErr bool) {
	fset := token.NewFileSet()
	file := fset.AddFile(name, -1, len(src))
	var sc scanner.Scanner
	sc.Init(file, src, func(token.Position, string) { scanErr = true }, scanner.ScanComments)
	for {
		pos, tok, lit := sc.Scan()
		if tok == token.EOF {
			break
		}
		if tok == token.COMMENT && strings.HasPrefix(lit, "//go:") {
			out = append(out, directive{lit, file.Line(pos)})
		}
	}
	for i, line := range strings.Split(string(src), "\n") {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "//go:generate") && strings.HasPrefix(line, "//go:generate") {
			found := false
			for _, d := range out {
				found = found || (d.line == i+1 && d.text == t)
			}
			if !found {
				out = append(out, directive{t, i + 1})
			}
		}
	}
	return out, scanErr
}

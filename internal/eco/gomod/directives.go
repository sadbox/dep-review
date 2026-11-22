package gomod

import (
	"go/ast"
	"go/scanner"
	"go/token"
	"strings"
)

// Directives are read the way the go command reads them: from comment
// tokens of the Go scanner (go/build read.go: scanner.ScanComments, a
// COMMENT token starting "//go:"), so a directive-looking line inside a
// string or rune literal or a /* */ comment is not one, on either side.
// The one exception is //go:generate, which `go generate` finds line by
// line, string literals included.
//
// Over-approximations kept on the new side: every .go file counts
// whatever its build constraints, a file need not import "embed" for its
// //go:embed comments to count, and a file the scanner rejects is marked
// so the caller can send it to a person.

// directive is one //go: comment.
type directive struct {
	text string // the comment, "//go:..." (or the //go:generate line)
	line int
	col  int // 1 when the comment starts its line, as the compiler requires
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
			p := file.Position(pos)
			out = append(out, directive{lit, p.Line, p.Column})
		}
	}
	for i, line := range strings.Split(string(src), "\n") {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "//go:generate") && strings.HasPrefix(line, "//go:generate") {
			found := false
			for _, d := range out {
				found = found || (d.line == i+1 && d.text == t)
			}
			if !found {
				out = append(out, directive{t, i + 1, 1})
			}
		}
	}
	return out, scanErr
}

// embedArgs are the patterns of a //go:embed comment, parsed as go/build
// parses them (ast.ParseDirective, Directive.ParseArgs). ok is false for a
// comment that is not a go:embed directive (//go:embedx); err is set for
// one whose arguments do not parse.
func embedArgs(text string) (pats []string, ok bool, err error) {
	dir, ok := ast.ParseDirective(token.NoPos, text)
	if !ok || dir.Tool != "go" || dir.Name != "embed" {
		return nil, false, nil
	}
	args, err := dir.ParseArgs()
	if err != nil {
		return nil, true, err
	}
	for _, a := range args {
		pats = append(pats, a.Arg)
	}
	return pats, true, nil
}

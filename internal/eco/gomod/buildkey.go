package gomod

import (
	"bytes"
	"errors"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/scanner"
	"go/token"
	"path"
	"slices"
	"strings"
)

// The build constraint of a .go file as the go command honors it: a port
// of go/build's parseFileHeader and shouldBuild. Only the leading run of
// // comments and blank lines counts, ending at the last blank line before
// the first other line (a /* */ comment ends it too); a //go:build line
// there controls, otherwise the +build lines there do. Text that looks
// like a constraint anywhere else is not one.

var errMultipleGoBuild = errors.New("multiple //go:build comments")

func isGoBuildComment(line []byte) bool {
	if !bytes.HasPrefix(line, []byte("//go:build")) {
		return false
	}
	rest := bytes.TrimSpace(line)[len("//go:build"):]
	return len(rest) == 0 || len(bytes.TrimSpace(rest)) < len(rest)
}

// parseFileHeader is go/build's: the header (trimmed) and its //go:build
// line.
func parseFileHeader(content []byte) (trimmed, goBuild []byte, err error) {
	end := 0
	p := content
	ended := false
	inSlashStar := false
Lines:
	for len(p) > 0 {
		line := p
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			line, p = line[:i], p[i+1:]
		} else {
			p = p[len(p):]
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 && !ended {
			end = len(content) - len(p)
			continue Lines
		}
		if !bytes.HasPrefix(line, []byte("//")) {
			ended = true
		}
		if !inSlashStar && isGoBuildComment(line) {
			if goBuild != nil {
				return nil, nil, errMultipleGoBuild
			}
			goBuild = line
		}
	Comments:
		for len(line) > 0 {
			if inSlashStar {
				if i := bytes.Index(line, []byte("*/")); i >= 0 {
					inSlashStar = false
					line = bytes.TrimSpace(line[i+2:])
					continue Comments
				}
				continue Lines
			}
			if bytes.HasPrefix(line, []byte("//")) {
				continue Lines
			}
			if bytes.HasPrefix(line, []byte("/*")) {
				inSlashStar = true
				line = bytes.TrimSpace(line[2:])
				continue Comments
			}
			break Lines
		}
	}
	return content[:end], goBuild, nil
}

// honored is the constraint the go command applies to src (nil for
// none), as shouldBuild reads it; err where the go command fails.
func honored(src []byte) (constraint.Expr, error) {
	header, goBuild, err := parseFileHeader(src)
	if err != nil {
		return nil, err
	}
	if goBuild != nil {
		return constraint.Parse(string(goBuild))
	}
	var x constraint.Expr
	for _, line := range strings.Split(string(header), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "//") || !strings.Contains(line, "+build") || !constraint.IsPlusBuild(line) {
			continue
		}
		e, err := constraint.Parse(line)
		if err != nil {
			continue // shouldBuild ignores a +build line it cannot parse
		}
		if x == nil {
			x = e
		} else {
			x = &constraint.AndExpr{X: x, Y: e}
		}
	}
	return x, nil
}

// buildKey is what decides whether the go command compiles a .go file on
// some platform: its honored constraint and its _GOOS/_GOARCH file name
// suffix. A file whose key differs between the old and new tree is
// checked as a new file: dropping or moving a //go:build ignore line
// brings old code into the build without changing its text.
func buildKey(rel string, src []byte) string {
	key := "none"
	switch x, err := honored(src); {
	case err != nil:
		key = "error: " + err.Error()
	case x != nil:
		key = x.String()
	}
	base := strings.TrimSuffix(strings.TrimSuffix(path.Base(rel), ".go"), "_test")
	suffix := ""
	if parts := strings.Split(base, "_"); len(parts) >= 2 {
		for _, p := range parts[max(1, len(parts)-2):] {
			if slices.Contains(knownOS, p) || slices.Contains(knownArch, p) {
				suffix += "_" + p
			}
		}
	}
	return key + "|" + suffix
}

// excluded: the go command builds the file on no platform, judged with
// only GOOS and GOARCH set (every other tag false): an over-approximation
// on the old side, where it only makes more things count as new.
func excluded(src []byte) bool {
	x, err := honored(src)
	if err != nil {
		return true
	}
	if x == nil {
		return false
	}
	for _, goos := range knownOS {
		for _, goarch := range knownArch {
			if x.Eval(func(tag string) bool { return tag == goos || tag == goarch }) {
				return false
			}
		}
	}
	return true
}

// sameBuild: the old version of rel counts as the same compiled file as
// the new one (same honored constraint and suffix, and built somewhere).
// It fails closed: if either version does not parse, or either header
// holds a /* */ comment (where what is honored is easy to get wrong),
// the file counts as new.
func sameBuild(rel string, oldSrc, newSrc []byte) bool {
	for _, src := range [][]byte{oldSrc, newSrc} {
		if _, err := parser.ParseFile(token.NewFileSet(), rel, src, parser.PackageClauseOnly); err != nil || headerBlockComment(src) {
			return false
		}
	}
	return buildKey(rel, oldSrc) == buildKey(rel, newSrc) && !excluded(oldSrc)
}

// headerBlockComment: a /* */ comment comes before the package clause.
func headerBlockComment(src []byte) bool {
	fset := token.NewFileSet()
	file := fset.AddFile("x.go", -1, len(src))
	var sc scanner.Scanner
	sc.Init(file, src, nil, scanner.ScanComments)
	for {
		_, tok, lit := sc.Scan()
		switch {
		case tok == token.COMMENT:
			if strings.HasPrefix(lit, "/*") {
				return true
			}
		default:
			return false
		}
	}
}

// oldEmbedPatterns are the //go:embed patterns of the old version of a
// file that cmd/go acted on, under-approximated: //go:embed comment
// tokens (as go/build finds them) of a file that imports "embed" and
// parses, built the same way as the new version.
func oldEmbedPatterns(rel string, oldSrc, newSrc []byte) []string {
	if !sameBuild(rel, oldSrc, newSrc) {
		return nil
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, rel, oldSrc, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil || !slices.ContainsFunc(file.Imports, func(i *ast.ImportSpec) bool { return i.Path.Value == `"embed"` }) {
		return nil
	}
	// Only what the compiler accepts: //go:embed comments at column 1 in
	// the doc comment of a var declaration (or of one spec of a var
	// group).
	var out []string
	take := func(cg *ast.CommentGroup) {
		if cg == nil {
			return
		}
		for _, c := range cg.List {
			if fset.Position(c.Slash).Column != 1 {
				continue
			}
			if pats, ok, err := embedArgs(c.Text); ok && err == nil {
				out = append(out, pats...)
			}
		}
	}
	for _, d := range file.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		take(gd.Doc)
		for _, sp := range gd.Specs {
			take(sp.(*ast.ValueSpec).Doc)
		}
	}
	return out
}

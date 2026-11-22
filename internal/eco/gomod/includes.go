package gomod

import (
	"bytes"
	"path"
	"regexp"
	"strings"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
)

var (
	// An include whose file is named literally, in C, Objective-C or a
	// cgo preamble ("x.h", <x.h>), or in assembly (.include/.incbin).
	literalIncludeRe = regexp.MustCompile(`(?m)^[ \t]*(?://[ \t]*)?#[ \t]*(?:include|include_next|import)[ \t]*["<]([^">\n]+)[">]|^[ \t]*\.(?:include|incbin)[ \t]+"([^"\n]+)"`)
	// Any include at all, and the flags that include a file from the
	// command line.
	anyIncludeRe  = regexp.MustCompile(`(?m)#[ \t]*(?:include|include_next|import)\b|\.(?:include|incbin)\b`)
	flagIncludeRe = regexp.MustCompile(`(?m)^[ \t]*(?://[ \t]*)?#cgo\b.*(?:-include|-imacros)`)
	goSumLineRe   = regexp.MustCompile(`^[^\s]+ [^\s]+ h1:[A-Za-z0-9+/]{43}=$`)
)

// includes is what the module's C, assembly and cgo text includes by
// name: the base names it names literally, and whether any include is
// computed (a macro, a -include flag), which could be any file.
type includes struct {
	names    map[string]bool
	computed bool
}

func moduleIncludes(t *ecoutil.Tree) includes {
	inc := includes{names: map[string]bool{}}
	for _, rel := range t.Files {
		ext := path.Ext(rel)
		if !cgoSourceExts[ext] && ext != ".s" && ext != ".S" && ext != ".sx" && ext != ".go" {
			continue
		}
		src := t.ReadFile(rel)
		if ext == ".go" && !bytes.Contains(src, []byte("#")) {
			continue
		}
		lit := literalIncludeRe.FindAllSubmatch(src, -1)
		for _, m := range lit {
			name := m[1]
			if len(name) == 0 {
				name = m[2]
			}
			inc.names[path.Base(strings.TrimSpace(string(name)))] = true
		}
		if len(anyIncludeRe.FindAll(src, -1)) > len(lit) || flagIncludeRe.Match(src) {
			inc.computed = true
		}
	}
	return inc
}

// may reports whether rel can be the file an include names.
func (inc includes) may(rel string) bool { return inc.computed || inc.names[path.Base(rel)] }

// strictGoSum reports whether every line of a go.sum is a module hash
// line, which no C or assembly can be.
func strictGoSum(b []byte) bool {
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if !goSumLineRe.MatchString(l) {
			return false
		}
	}
	return true
}

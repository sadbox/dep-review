package actions

import (
	"regexp"
	"strconv"
	"strings"
)

// A small JavaScript lexer and binding finder for the two places that
// declare changed bundle code "unchanged": pureRename (module mode) and
// normalizeMinified (source-map mode). Whatever is declared unchanged is
// hidden from the reviewer, so both fail closed: only identifiers that are
// provably bound in the code at hand (or bundler-generated) may differ,
// never keywords, literals, property names or free globals.

type tokKind byte

const (
	tkIdent tokKind = iota
	tkSpace
	tkComment
	tkString
	tkNumber
	tkPunct
)

type jsTok struct {
	kind tokKind
	text string
	off  int // byte offset in the lexed text
}

func (t jsTok) is(s string) bool { return t.kind == tkPunct && t.text == s }

// lexJS splits s into tokens. String, template and regex literals and
// comments are single opaque tokens. Nested template literals and
// ambiguous "/" are approximated; a mis-lexed span only ever compares
// more strictly (as an opaque literal) or binds fewer names.
func lexJS(s string) []jsTok {
	out := lexJSRaw(s)
	off := 0
	for i := range out {
		out[i].off = off
		off += len(out[i].text)
	}
	return out
}

func lexJSRaw(s string) []jsTok {
	var out []jsTok
	// tmpl holds, per open template substitution ${...}, its brace depth.
	var tmpl []int
	i := 0
	// templatePart scans template text from i (just after "`" or the "}"
	// closing a substitution) to the closing "`" or the next "${".
	templatePart := func(start int) {
		for i < len(s) {
			switch {
			case s[i] == '\\':
				i += 2
				continue
			case s[i] == '`':
				i++
				out = append(out, jsTok{kind: tkString, text: s[start:min(i, len(s))]})
				return
			case s[i] == '$' && i+1 < len(s) && s[i+1] == '{':
				i += 2
				out = append(out, jsTok{kind: tkString, text: s[start:i]})
				tmpl = append(tmpl, 0)
				return
			}
			i++
		}
		i = min(i, len(s))
		out = append(out, jsTok{kind: tkString, text: s[start:i]})
	}
	for i < len(s) {
		c := s[i]
		start := i
		switch {
		case c == '`':
			i++
			templatePart(start)
		case c == '{' && len(tmpl) > 0:
			tmpl[len(tmpl)-1]++
			i++
			out = append(out, jsTok{kind: tkPunct, text: "{"})
		case c == '}' && len(tmpl) > 0 && tmpl[len(tmpl)-1] == 0:
			tmpl = tmpl[:len(tmpl)-1]
			i++
			templatePart(start)
		case c == '}' && len(tmpl) > 0:
			tmpl[len(tmpl)-1]--
			i++
			out = append(out, jsTok{kind: tkPunct, text: "}"})
		case isIdentStart(c):
			for i < len(s) && isIdentPart(s[i]) {
				i++
			}
			out = append(out, jsTok{kind: tkIdent, text: s[start:i]})
		case c >= '0' && c <= '9':
			for i < len(s) && (isIdentPart(s[i]) || s[i] == '.') {
				i++
			}
			out = append(out, jsTok{kind: tkNumber, text: s[start:i]})
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
				i++
			}
			out = append(out, jsTok{kind: tkSpace, text: s[start:i]})
		case c == '/' && i+1 < len(s) && s[i+1] == '/':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			out = append(out, jsTok{kind: tkComment, text: s[start:i]})
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			j := strings.Index(s[i+2:], "*/")
			if j < 0 {
				i = len(s)
			} else {
				i += j + 4
			}
			out = append(out, jsTok{kind: tkComment, text: s[start:i]})
		case c == '/' && regexAllowed(out):
			if j := scanRegex(s, i); j > i {
				i = j
				out = append(out, jsTok{kind: tkString, text: s[start:i]})
				continue
			}
			i++
			out = append(out, jsTok{kind: tkPunct, text: s[start:i]})
		case c == '\'' || c == '"':
			i++
			for i < len(s) && s[i] != c {
				if s[i] == '\\' {
					i++
				}
				i++
			}
			if i < len(s) {
				i++
			}
			if i > len(s) {
				i = len(s)
			}
			out = append(out, jsTok{kind: tkString, text: s[start:i]})
		default:
			i++
			out = append(out, jsTok{kind: tkPunct, text: s[start:i]})
		}
	}
	return out
}

var regexAfterKeyword = setOf(`return typeof instanceof in of new delete void throw case do else yield await`)

// regexAllowed reports whether a "/" here starts a regex literal rather
// than a division, from the previous significant token.
func regexAllowed(out []jsTok) bool {
	for k := len(out) - 1; k >= 0; k-- {
		t := out[k]
		switch t.kind {
		case tkSpace, tkComment:
			continue
		case tkIdent:
			return regexAfterKeyword[t.text]
		case tkNumber, tkString:
			return false
		}
		return !(t.is(")") || t.is("]") || t.is("}"))
	}
	return true
}

// scanRegex returns the end of a regex literal starting at s[i] == '/',
// or i when there is none on this line.
func scanRegex(s string, i int) int {
	j := i + 1
	class := false
	for j < len(s) {
		switch c := s[j]; {
		case c == '\\':
			j += 2
			continue
		case c == '\n' || c == '\r':
			return i
		case c == '[':
			class = true
		case c == ']':
			class = false
		case c == '/' && !class:
			j++
			for j < len(s) && isIdentPart(s[j]) {
				j++
			}
			return j
		}
		j++
	}
	return i
}

var jsReserved = setOf(`break case catch class const continue debugger default delete do else
	enum export extends false finally for function if import in instanceof new null return super
	switch this throw true try typeof var void while with yield let static await implements package
	protected interface private public undefined arguments NaN Infinity`)

// jsDangerous are globals and built-ins whose substitution for another
// name changes what code can do; they are never renamed or normalized.
var jsDangerous = setOf(`eval Function JSON Date Math atob btoa URL fetch require process globalThis
	window self Buffer import module exports setTimeout setInterval setImmediate queueMicrotask
	Reflect Proxy Symbol crypto Object Array String Number Boolean Error Promise RegExp WebAssembly
	document navigator location XMLHttpRequest WebSocket importScripts structuredClone global
	decodeURIComponent encodeURIComponent decodeURI encodeURI escape unescape __dirname __filename
	constructor prototype __proto__ Atomics SharedArrayBuffer Worker`)

func setOf(words string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(words) {
		m[w] = true
	}
	return m
}

// bundlerGenerated matches names bundlers invent for their runtime and
// import bindings, which change between builds without a source change.
var bundlerGenerated = regexp.MustCompile(`^(__webpack_\w+|__nccwpck_\w+|__WEBPACK_\w+|_0x[0-9a-fA-F]+|\w+__WEBPACK_IMPORTED_MODULE_\d+__|\w+_namespaceObject|import_\w+?\d*|[A-Za-z_$][\w$]*?_\d+)$`)

// sigIdx lists the indexes of significant (non-space, non-comment) tokens.
func sigIdx(ts []jsTok) []int {
	var out []int
	for i, t := range ts {
		if t.kind != tkSpace && t.kind != tkComment {
			out = append(out, i)
		}
	}
	return out
}

// boundIdents returns identifiers the code itself binds: var/let/const
// declarators (simple names only; destructuring is not followed),
// function and class names, function, arrow and catch parameters (simple
// names only). Anything it does not understand is simply not bound.
func boundIdents(ts []jsTok) map[string]bool {
	b := map[string]bool{}
	sig := sigIdx(ts)
	at := func(k int) jsTok {
		if k < 0 || k >= len(sig) {
			return jsTok{kind: tkPunct, text: ""}
		}
		return ts[sig[k]]
	}
	newlineBefore := func(k int) bool {
		if k <= 0 || k >= len(sig) {
			return false
		}
		for i := sig[k-1] + 1; i < sig[k]; i++ {
			if strings.Contains(ts[i].text, "\n") {
				return true
			}
		}
		return false
	}
	isOpen := func(t jsTok) bool { return t.is("(") || t.is("[") || t.is("{") }
	isClose := func(t jsTok) bool { return t.is(")") || t.is("]") || t.is("}") }
	// skipExpr returns the index of the "," or closing bracket that ends
	// the expression starting at j (a default value or computed key).
	skipExpr := func(j int) int {
		depth := 0
		for ; j < len(sig); j++ {
			t := at(j)
			switch {
			case isOpen(t):
				depth++
			case isClose(t):
				if depth == 0 {
					return j
				}
				depth--
			case depth == 0 && t.is(","):
				return j
			}
		}
		return j
	}
	// bindPattern binds the names a destructuring pattern opening at k
	// declares and returns the index of its closing bracket.
	var bindPattern func(k int) int
	bindPattern = func(k int) int {
		obj := at(k).is("{")
		// target binds an identifier or nested pattern at j and returns
		// the index after it, or -1 if j holds neither.
		target := func(j int) int {
			switch t := at(j); {
			case t.is("{") || t.is("["):
				return bindPattern(j) + 1
			case t.kind == tkIdent && !jsReserved[t.text]:
				b[t.text] = true
				return j + 1
			}
			return -1
		}
		j := k + 1
		for j < len(sig) {
			t := at(j)
			switch {
			case t.is("}") || t.is("]"):
				return j
			case t.is(","):
				j++
				continue
			case t.is(".") && at(j+1).is(".") && at(j+2).is("."):
				j += 3
				continue
			}
			next := -1
			if obj {
				switch {
				case at(j+1).is(":") && (t.kind == tkIdent || t.kind == tkString || t.kind == tkNumber):
					next = target(j + 2)
				case t.is("["): // computed key
					e := skipExpr(j + 1)
					if at(e).is("]") && at(e+1).is(":") {
						next = target(e + 2)
					}
				case t.kind == tkIdent && !jsReserved[t.text]: // shorthand
					b[t.text] = true
					next = j + 1
				}
			} else {
				next = target(j)
			}
			if next < 0 {
				// Not understood: skip this element without binding.
				j = skipExpr(j)
				if at(j).is(",") {
					continue
				}
				return j
			}
			j = next
			if at(j).is("=") {
				j = skipExpr(j + 1)
			}
		}
		return j
	}
	// params binds simple names in the parenthesized list opening at k.
	params := func(open int) {
		depth := 0
		for k := open; k < len(sig); k++ {
			t := at(k)
			if depth == 1 && (t.is("{") || t.is("[")) && (at(k-1).is("(") || at(k-1).is(",")) {
				k = bindPattern(k)
				continue
			}
			switch {
			case t.is("(") || t.is("[") || t.is("{"):
				depth++
			case t.is(")") || t.is("]") || t.is("}"):
				depth--
				if depth == 0 {
					return
				}
			case depth == 1 && t.kind == tkIdent && !jsReserved[t.text]:
				p, n := at(k-1), at(k+1)
				if (p.is("(") || p.is(",") || p.is(".")) && (n.is(",") || n.is(")") || n.is("=")) {
					b[t.text] = true
				}
			}
		}
	}
	for k := 0; k < len(sig); k++ {
		t := at(k)
		if t.kind == tkIdent {
			switch t.text {
			case "var", "let", "const":
				expect := true
				depth := 0
				for j := k + 1; j < len(sig); j++ {
					u := at(j)
					if depth == 0 && j > k+1 && newlineBefore(j) && !at(j-1).is(",") && !at(j-1).is("=") {
						break
					}
					if expect && depth == 0 {
						expect = false
						if u.is("{") || u.is("[") {
							j = bindPattern(j)
							continue
						}
						if u.kind == tkIdent && !jsReserved[u.text] {
							b[u.text] = true
						}
					}
					switch {
					case u.is("(") || u.is("[") || u.is("{"):
						depth++
					case u.is(")") || u.is("]") || u.is("}"):
						depth--
					case depth == 0 && u.is(","):
						expect = true
					}
					if depth < 0 || (depth == 0 && (u.is(";") || (u.kind == tkIdent && (u.text == "in" || u.text == "of")))) {
						break
					}
				}
			case "function", "class":
				j := k + 1
				if at(j).is("*") {
					j++
				}
				if n := at(j); n.kind == tkIdent && !jsReserved[n.text] {
					b[n.text] = true
					j++
				}
				if t.text == "function" && at(j).is("(") {
					params(j)
				}
			case "catch":
				if at(k+1).is("(") && at(k+2).kind == tkIdent && at(k+3).is(")") {
					b[at(k+2).text] = true
				}
			}
			continue
		}
		// Arrow functions: "=" immediately followed by ">".
		if t.is("=") && sig[k]+1 < len(ts) && ts[sig[k]+1].is(">") {
			p := at(k - 1)
			if p.kind == tkIdent && !jsReserved[p.text] {
				b[p.text] = true
			} else if p.is(")") {
				depth := 0
				for j := k - 1; j >= 0; j-- {
					if at(j).is(")") {
						depth++
					} else if at(j).is("(") {
						depth--
						if depth == 0 {
							params(j)
							break
						}
					}
				}
			}
		}
	}
	return b
}

type braceKind byte

const (
	ctxUnknown braceKind = iota // no enclosing bracket in this text
	ctxObject                   // object literal or class body
	ctxBlock                    // statement block
	ctxParen                    // ( or [
)

// bracketContext returns, per significant token, the kind of its
// innermost enclosing bracket. A "{" is a block after ")", ";", "{", "}",
// "=>" or else/do/try/finally, and otherwise an object literal (the
// fail-closed choice: property names are never renameable).
func bracketContext(ts []jsTok, sig []int) []braceKind {
	out := make([]braceKind, len(sig))
	var stack []braceKind
	for k, i := range sig {
		if len(stack) > 0 {
			out[k] = stack[len(stack)-1]
		}
		switch t := ts[i]; {
		case t.is("{"):
			kind := ctxObject
			if k > 0 {
				p := ts[sig[k-1]]
				switch {
				case p.is(")") || p.is(";") || p.is("{") || p.is("}") || p.is(">"):
					kind = ctxBlock
				case p.kind == tkIdent && (p.text == "else" || p.text == "do" || p.text == "try" || p.text == "finally" || p.text == "catch"):
					kind = ctxBlock
				}
			}
			stack = append(stack, kind)
		case t.is("(") || t.is("["):
			stack = append(stack, ctxParen)
		case t.is(")") || t.is("]") || t.is("}"):
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	return out
}

// propertyName reports whether significant token k is a property name:
// after "." (not a spread), an object key, a shorthand property, a method
// or accessor name. Where the enclosing bracket is not in the text, a
// key-like position counts as a property.
func propertyName(ts []jsTok, sig []int, k int, ctx braceKind) bool {
	at := func(j int) jsTok {
		if j < 0 || j >= len(sig) {
			return jsTok{kind: tkPunct, text: ""}
		}
		return ts[sig[j]]
	}
	p, n := at(k-1), at(k+1)
	if p.is(".") && !(at(k-2).is(".") && at(k-3).is(".")) {
		return true
	}
	if p.is("#") {
		return true // private class member
	}
	// method reports a method definition: name(params) { body }.
	method := func() bool {
		if !n.is("(") {
			return false
		}
		depth := 0
		for j := k + 1; j < len(sig); j++ {
			switch t := at(j); {
			case t.is("("):
				depth++
			case t.is(")"):
				depth--
				if depth == 0 {
					return at(j + 1).is("{")
				}
			}
		}
		return true // unterminated: assume the worst
	}
	afterSep := p.is("{") || p.is(",") || p.is(";") || p.is("}") || k == 0
	switch ctx {
	case ctxObject:
		if afterSep && (n.is(":") || n.is(",") || n.is("}") || n.is("=") || n.is(";") || method()) {
			return true
		}
		return p.kind == tkIdent && (p.text == "get" || p.text == "set" || p.text == "static" || p.text == "async") && n.is("(")
	case ctxUnknown:
		return afterSep && (n.is(":") || n.is("}"))
	}
	return false
}

// renameable returns, per token, whether an identifier there may be
// renamed without changing behavior, given the names bound in its scope.
func renameable(ts []jsTok, bound map[string]bool) []bool {
	out := make([]bool, len(ts))
	sig := sigIdx(ts)
	ctx := bracketContext(ts, sig)
	for k, i := range sig {
		t := ts[i]
		if t.kind != tkIdent || jsReserved[t.text] || jsDangerous[t.text] {
			continue
		}
		if propertyName(ts, sig, k, ctx[k]) {
			continue
		}
		out[i] = bound[t.text] || bundlerGenerated.MatchString(t.text)
	}
	return out
}

// pureRename reports whether a and b differ only by a consistent
// one-to-one renaming of identifiers each side binds itself (or that are
// bundler-generated). Comments must match too.
func pureRename(a, b string) bool {
	ta, tb := lexJS(a), lexJS(b)
	if len(ta) != len(tb) {
		return false
	}
	ra, rb := renameable(ta, boundIdents(ta)), renameable(tb, boundIdents(tb))
	fwd, rev := map[string]string{}, map[string]string{}
	for i := range ta {
		x, y := ta[i], tb[i]
		if x.kind != y.kind {
			return false
		}
		if x.kind != tkIdent {
			if x.text != y.text {
				return false
			}
			continue
		}
		if x.text == y.text && !ra[i] && !rb[i] {
			if v, ok := fwd[x.text]; ok && v != y.text {
				return false
			}
			if v, ok := rev[y.text]; ok && v != x.text {
				return false
			}
			continue
		}
		if x.text != y.text && (!ra[i] || !rb[i]) {
			return false
		}
		if v, ok := fwd[x.text]; ok && v != y.text {
			return false
		}
		if v, ok := rev[y.text]; ok && v != x.text {
			return false
		}
		fwd[x.text], rev[y.text] = y.text, x.text
	}
	return true
}

type identPair struct{ old, new string }

// renames checks minified chunks for identifier renames between two
// builds of one bundle. A minifier renames a bundle-level symbol
// everywhere at once, so its declaration and all its uses move to the same
// new name. A rename is accepted only if both names are bound in their
// bundle (or bundler-generated) and neither is a keyword, literal,
// property name or dangerous global. Names a chunk binds itself are
// locals and need only a consistent bijection inside the chunk. For
// bundle-level names, the declaration's rename (from the chunk that binds
// the name) is authoritative; without one, the strict majority of uses
// is. A use that disagrees is reported, so swapping one call target, or
// every use of two symbols, shows up as changed code.
type renames struct {
	fwd, rev           map[string]map[string]int  // uses of bundle-level names
	declFwd, declRev   map[string]map[string]bool // chunk-bound names
	allowFwd, allowRev map[string]map[string]bool // settled
}

// contextualNames are identifiers that are also keywords in some
// positions (for-of, accessors, modules); their unchanged occurrences are
// not evidence about a symbol and are not recorded.
var contextualNames = setOf(`of get set async static as from let yield await`)

func newRenames() *renames {
	return &renames{
		fwd:     map[string]map[string]int{},
		rev:     map[string]map[string]int{},
		declFwd: map[string]map[string]bool{},
		declRev: map[string]map[string]bool{},
	}
}

// chunkToks is one source's (or unmapped span's) tokens out of a bundle
// lexed as a whole, with their bundle-level renameable flags.
type chunkToks struct {
	toks []jsTok
	ren  []bool
}

func chunkOf(mb *mappedBundle, idx []int) chunkToks {
	c := chunkToks{toks: make([]jsTok, len(idx)), ren: make([]bool, len(idx))}
	for k, i := range idx {
		c.toks[k], c.ren[k] = mb.toks[i], mb.ren[i]
	}
	return c
}

// significant drops whitespace and comments: a minifier may reflow them.
// Comments are compared separately, as literal text.
func (c chunkToks) significant() (chunkToks, []string) {
	var out chunkToks
	var comments []string
	for i, t := range c.toks {
		switch t.kind {
		case tkSpace:
			continue
		case tkComment:
			comments = append(comments, t.text)
			continue
		}
		out.toks = append(out.toks, t)
		out.ren = append(out.ren, c.ren[i])
	}
	return out, comments
}

// align compares two chunks token by token and records their identifier
// correspondences. ok is false unless they differ only in renameable
// identifiers (and whitespace).
func (r *renames) align(a, b chunkToks) (pairs []identPair, ok bool) {
	a, ca := a.significant()
	b, cb := b.significant()
	if len(a.toks) != len(b.toks) || strings.Join(ca, "\x00") != strings.Join(cb, "\x00") {
		return nil, false
	}
	// Names the chunk binds itself are locals: a minifier renames them per
	// scope, so they only need a consistent bijection within the chunk.
	// Other names refer to bundle-level symbols and go into the
	// bundle-wide bijection.
	la, lb := boundIdents(a.toks), boundIdents(b.toks)
	lfwd, lrev := map[string]string{}, map[string]string{}
	pfwd, prev := map[string]string{}, map[string]string{}
	for i := range a.toks {
		x, y := a.toks[i], b.toks[i]
		if x.kind != y.kind || (x.kind != tkIdent && x.text != y.text) {
			return nil, false
		}
		if x.kind != tkIdent {
			continue
		}
		if i > 0 && a.toks[i-1].is("#") {
			// A private class member: minifiers rename these per class,
			// so they get the chunk-local bijection too.
			if v, ok := pfwd[x.text]; ok && v != y.text {
				return nil, false
			}
			if v, ok := prev[y.text]; ok && v != x.text {
				return nil, false
			}
			pfwd[x.text], prev[y.text] = y.text, x.text
			continue
		}
		ra, rb := a.ren[i], b.ren[i]
		if x.text == y.text && !ra && !rb {
			continue // keyword, property name, free global: literal match
		}
		if !ra || !rb || la[x.text] != lb[y.text] {
			return nil, false
		}
		if la[x.text] {
			if v, ok := lfwd[x.text]; ok && v != y.text {
				return nil, false
			}
			if v, ok := lrev[y.text]; ok && v != x.text {
				return nil, false
			}
			lfwd[x.text], lrev[y.text] = y.text, x.text
			continue
		}
		// The same name on both sides is recorded too, so a swap
		// elsewhere disagrees with it.
		if x.text == y.text && contextualNames[x.text] {
			continue
		}
		pairs = append(pairs, identPair{x.text, y.text})
	}
	for _, p := range pairs {
		if r.fwd[p.old] == nil {
			r.fwd[p.old] = map[string]int{}
		}
		if r.rev[p.new] == nil {
			r.rev[p.new] = map[string]int{}
		}
		r.fwd[p.old][p.new]++
		r.rev[p.new][p.old]++
	}
	// Chunk-bound names may be top-level symbols other chunks use; their
	// renames go into declFwd/declRev, decide those uses, and are checked
	// with the chunk.
	for o, n := range lfwd {
		if o == n && contextualNames[o] {
			continue
		}
		if r.declFwd[o] == nil {
			r.declFwd[o] = map[string]bool{}
		}
		if r.declRev[n] == nil {
			r.declRev[n] = map[string]bool{}
		}
		r.declFwd[o][n] = true
		r.declRev[n][o] = true
		pairs = append(pairs, identPair{o, n})
	}
	return pairs, true
}

// settle decides, per name, which renames are accepted.
func (r *renames) settle() {
	r.allowFwd = allowed(r.fwd, r.declFwd)
	r.allowRev = allowed(r.rev, r.declRev)
}

func allowed(uses map[string]map[string]int, decl map[string]map[string]bool) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	names := map[string]bool{}
	for k := range uses {
		names[k] = true
	}
	for k := range decl {
		names[k] = true
	}
	for k := range names {
		a := map[string]bool{}
		d := decl[k]
		for n := range d {
			a[n] = true
		}
		if len(d) != 1 {
			// No single declaration: also accept the strict majority of
			// uses (a name declared outside the aligned chunks, or a
			// local name reused across scopes).
			total := 0
			for _, c := range uses[k] {
				total += c
			}
			for n, c := range uses[k] {
				if 2*c > total {
					a[n] = true
				}
			}
		}
		out[k] = a
	}
	return out
}

func (r *renames) consistent(pairs []identPair) bool {
	for _, p := range pairs {
		if !r.allowFwd[p.old][p.new] || !r.allowRev[p.new][p.old] {
			return false
		}
	}
	return true
}

// canon renders a chunk for exact comparison: names the chunk binds are
// replaced by their order of first appearance (alpha-renaming), and on
// the old side bundle-level names are renamed by the settled renames.
// Unknown or disputed names are kept, so an old and a new chunk only
// render equal if one truly is a consistent rename of the other.
func (r *renames) canon(c chunkToks, old bool) string {
	c, comments := c.significant()
	local := boundIdents(c.toks)
	ids := map[string]int{}
	var sb strings.Builder
	for i, t := range c.toks {
		switch {
		case t.kind == tkIdent && c.ren[i] && local[t.text]:
			n, ok := ids[t.text]
			if !ok {
				n = len(ids)
				ids[t.text] = n
			}
			sb.WriteString("\x00" + strconv.Itoa(n) + "\x00")
		case old:
			sb.WriteString(r.renamed(t, c.ren[i]))
		default:
			sb.WriteString(t.text)
		}
		sb.WriteByte(' ')
	}
	return sb.String() + "\x00" + strings.Join(comments, "\x00")
}

func (r *renames) renamed(t jsTok, renameable bool) string {
	if t.kind != tkIdent || !renameable || len(r.allowFwd[t.text]) != 1 {
		return t.text
	}
	for n := range r.allowFwd[t.text] {
		if r.allowRev[n][t.text] {
			return n
		}
	}
	return t.text
}

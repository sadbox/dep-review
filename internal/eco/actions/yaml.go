package actions

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A deliberately small YAML reader for action.yml: block mappings, block
// sequences, plain/quoted/block scalars. Flow collections are kept as their
// raw text; anchors, aliases, tags and duplicate keys are errors. Anything
// it cannot read makes the caller route to a human, so it fails closed.

// yMap is an ordered mapping.
type yMap struct {
	keys []string
	m    map[string]any
}

func (m *yMap) get(k string) any {
	if m == nil {
		return nil
	}
	return m.m[k]
}

func (m *yMap) str(k string) string {
	s, _ := m.get(k).(string)
	return s
}

func (m *yMap) sub(k string) *yMap {
	s, _ := m.get(k).(*yMap)
	return s
}

// yFlow is a flow collection ([...] or {...}) the reader keeps as raw
// text instead of parsing. Callers that need its content must reject it.
type yFlow string

type yParser struct {
	lines []string
	i     int
}

// errLineBreak marks YAML the gate refuses to read at all because its
// line structure is ambiguous to a line-based reader.
var errLineBreak = errors.New("YAML contains a line break other than LF or CRLF, or a control character")

// checkYAMLText rejects text whose lines a YAML parser would split
// differently from the gate: a CR not followed by LF, NEL (U+0085), LS
// (U+2028) and PS (U+2029) are line breaks to YAML 1.1 parsers such as
// GitHub's, but splitting on "\n" keeps them inside one line, so a
// "# comment<CR>  post: evil.js" hides a key. Every other C0 control
// (tab, LF and the CR of a CRLF excepted), DEL, the C1 range, a BOM after
// the first character and invalid UTF-8 are refused too: YAML does not
// allow them and the gate does not guess how a parser recovers. Only
// after this check may CRLF be normalized to LF.
func checkYAMLText(text string) error {
	if !utf8.ValidString(text) {
		return fmt.Errorf("%w: invalid UTF-8", errLineBreak)
	}
	for i, r := range text {
		switch {
		case r == '\t' || r == '\n':
		case r == '\r':
			if !strings.HasPrefix(text[i+1:], "\n") {
				return fmt.Errorf("%w: CR without LF at byte %d", errLineBreak, i)
			}
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x2028 || r == 0x2029 || (r == 0xfeff && i > 0):
			return fmt.Errorf("%w: U+%04X at byte %d", errLineBreak, r, i)
		}
	}
	return nil
}

func parseYAML(text string) (any, error) {
	if err := checkYAMLText(text); err != nil {
		return nil, err
	}
	p := &yParser{lines: splitLines(strings.ReplaceAll(text, "\r\n", "\n"))}
	for _, l := range p.lines {
		if strings.HasPrefix(strings.TrimLeft(l, " "), "\t") && !blankOrComment(l) {
			return nil, fmt.Errorf("tab indentation")
		}
	}
	p.skipBlank()
	if p.i < len(p.lines) && strings.TrimSpace(p.lines[p.i]) == "---" {
		p.i++
		p.skipBlank()
	}
	if p.i >= len(p.lines) {
		return &yMap{m: map[string]any{}}, nil
	}
	v, err := p.node(0)
	if err != nil {
		return nil, err
	}
	p.skipBlank()
	if p.i < len(p.lines) && strings.TrimSpace(p.lines[p.i]) != "..." {
		return nil, fmt.Errorf("line %d: unexpected content", p.i+1)
	}
	// After a document end marker only blank and comment lines may follow:
	// a second document ("...\n---\nruns: ...") is something another
	// parser may read instead of the first.
	if p.i < len(p.lines) {
		p.i++
		p.skipBlank()
		if p.i < len(p.lines) {
			return nil, fmt.Errorf("line %d: content after the document end marker", p.i+1)
		}
	}
	return v, nil
}

func (p *yParser) skipBlank() {
	for p.i < len(p.lines) && blankOrComment(p.lines[p.i]) {
		p.i++
	}
}

func isDash(content string) bool {
	return content == "-" || strings.HasPrefix(content, "- ")
}

// node parses the block starting at the current line, whose indentation
// must be at least min.
func (p *yParser) node(min int) (any, error) {
	p.skipBlank()
	if p.i >= len(p.lines) {
		return "", nil
	}
	l := p.lines[p.i]
	n := lineIndent(l)
	if n < min {
		return "", nil
	}
	content := l[n:]
	switch {
	case isDash(content):
		return p.seq(n)
	case yamlKeyRx.MatchString(content):
		return p.mapping(n)
	}
	p.i++
	return p.value(content, n-1)
}

func (p *yParser) mapping(n int) (*yMap, error) {
	m := &yMap{m: map[string]any{}}
	for {
		p.skipBlank()
		if p.i >= len(p.lines) {
			return m, nil
		}
		l := p.lines[p.i]
		ind := lineIndent(l)
		if ind < n {
			return m, nil
		}
		if ind > n {
			return nil, fmt.Errorf("line %d: unexpected indentation", p.i+1)
		}
		content := l[n:]
		if isDash(content) {
			return m, nil // a compact sequence belonging to an outer key ends here
		}
		mm := yamlKeyRx.FindStringSubmatch(content)
		if mm == nil {
			return nil, fmt.Errorf("line %d: expected a mapping key", p.i+1)
		}
		key, err := keyName(mm)
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", p.i+1, err)
		}
		if key == "" || strings.HasPrefix(key, "<<") || strings.ContainsAny(key[:1], "&*!") {
			return nil, fmt.Errorf("line %d: unsupported key %q", p.i+1, key)
		}
		if _, dup := m.m[key]; dup {
			return nil, fmt.Errorf("line %d: duplicate key %q", p.i+1, key)
		}
		rest := content[len(mm[0]):]
		p.i++
		v, err := p.value(rest, n)
		if err != nil {
			return nil, err
		}
		m.keys = append(m.keys, key)
		m.m[key] = v
	}
}

func (p *yParser) seq(n int) ([]any, error) {
	var out []any
	for {
		p.skipBlank()
		if p.i >= len(p.lines) {
			return out, nil
		}
		l := p.lines[p.i]
		ind := lineIndent(l)
		if ind < n {
			return out, nil
		}
		content := l[n:]
		if ind > n || !isDash(content) {
			if ind == n {
				return out, nil // the parent mapping continues
			}
			return nil, fmt.Errorf("line %d: unexpected indentation in sequence", p.i+1)
		}
		after := strings.TrimLeft(content[1:], " ")
		if after == "" || strings.HasPrefix(after, "#") {
			p.i++
			p.skipBlank()
			if p.i < len(p.lines) && lineIndent(p.lines[p.i]) > n {
				v, err := p.node(n + 1)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			} else {
				out = append(out, "")
			}
			continue
		}
		m := len(l) - len(after)
		if isDash(after) || yamlKeyRx.MatchString(after) {
			// Re-indent the item's first line so its content parses as a
			// block at column m.
			p.lines[p.i] = strings.Repeat(" ", m) + after
			v, err := p.node(m)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}
		p.i++
		v, err := p.value(after, n)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
}

// value parses the scalar or nested block that follows a key (or dash) at
// column parent. rest is the text after "key:".
func (p *yParser) value(rest string, parent int) (any, error) {
	rest = strings.TrimSpace(rest)
	if strings.HasPrefix(rest, "&") || strings.HasPrefix(rest, "*") || strings.HasPrefix(rest, "!") {
		return nil, fmt.Errorf("line %d: anchors, aliases and tags are not supported", p.i)
	}
	switch {
	case rest == "" || strings.HasPrefix(rest, "#"):
		p.skipBlank()
		if p.i >= len(p.lines) {
			return "", nil
		}
		l := p.lines[p.i]
		ind := lineIndent(l)
		if ind > parent {
			return p.node(ind)
		}
		if ind == parent && isDash(l[ind:]) {
			return p.seq(ind)
		}
		return "", nil
	case isBlockScalarHeader(rest):
		return p.blockScalar(rest, parent), nil
	case rest[0] == '"' || rest[0] == '\'':
		for {
			s, tail, ok, err := unquote(rest)
			if err != nil {
				return nil, fmt.Errorf("line %d: %v", p.i, err)
			}
			if ok {
				tail = strings.TrimSpace(tail)
				if tail != "" && !strings.HasPrefix(tail, "#") {
					return nil, fmt.Errorf("line %d: text after quoted scalar", p.i)
				}
				return s, nil
			}
			if p.i >= len(p.lines) {
				return nil, fmt.Errorf("unterminated quoted scalar")
			}
			// Folding a line break into one space is right only for a
			// plain break: an escaped break ("\" at the end of the line)
			// joins without a space and a blank line is a newline, so the
			// gate would read a different main/pre/post/uses than GitHub.
			// Refuse those; trailing blanks before the break are dropped.
			rest = strings.TrimRight(rest, " \t")
			next := strings.TrimSpace(p.lines[p.i])
			if next == "" || (rest[0] == '"' && strings.HasSuffix(rest, `\`)) {
				return nil, fmt.Errorf("line %d: unsupported line folding in a quoted scalar", p.i+1)
			}
			rest += " " + next
			p.i++
		}
	case rest[0] == '[' || rest[0] == '{':
		for !flowBalanced(rest) {
			if p.i >= len(p.lines) {
				return nil, fmt.Errorf("unterminated flow collection")
			}
			rest += " " + strings.TrimSpace(p.lines[p.i])
			p.i++
		}
		return yFlow(stripComment(rest)), nil
	}
	v := stripComment(rest)
	// A comment ends a plain scalar: a continuation after one is not YAML.
	commented := v != strings.TrimSpace(rest)
	// Plain multi-line scalar: more-indented continuation lines.
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if blankOrComment(l) {
			if strings.TrimSpace(l) == "" {
				// A blank line inside a plain scalar is a newline (one per
				// blank line, and no folding space). Rather than model that,
				// refuse it if a continuation follows.
				j := p.i
				for j < len(p.lines) && strings.TrimSpace(p.lines[j]) == "" {
					j++
				}
				if j < len(p.lines) && lineIndent(p.lines[j]) > parent && !blankOrComment(p.lines[j]) && !yamlKeyRx.MatchString(p.lines[j][lineIndent(p.lines[j]):]) {
					return nil, fmt.Errorf("line %d: blank line inside a plain scalar", p.i+1)
				}
			}
			break
		}
		if lineIndent(l) <= parent {
			break
		}
		t := strings.TrimSpace(l)
		if yamlKeyRx.MatchString(t) || isDash(t) {
			return nil, fmt.Errorf("line %d: unexpected structure inside a plain scalar", p.i+1)
		}
		if commented {
			return nil, fmt.Errorf("line %d: plain scalar continues after a comment", p.i+1)
		}
		c := stripComment(t)
		commented = c != t
		v += " " + c
		p.i++
	}
	return v, nil
}

func (p *yParser) blockScalar(header string, parent int) string {
	header = stripComment(header)
	var lines []string
	content := -1
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if strings.TrimSpace(l) == "" {
			lines = append(lines, "")
			p.i++
			continue
		}
		ind := lineIndent(l)
		if ind <= parent {
			break
		}
		if content < 0 {
			content = ind
		}
		if ind < content {
			break
		}
		lines = append(lines, l[content:])
		p.i++
	}
	// Trailing blank lines belong to the scalar only with "+" chomping.
	for len(lines) > 0 && lines[len(lines)-1] == "" && !strings.Contains(header, "+") {
		lines = lines[:len(lines)-1]
	}
	if header[0] == '>' {
		return strings.Join(lines, " ")
	}
	s := strings.Join(lines, "\n")
	if !strings.Contains(header, "-") {
		s += "\n"
	}
	return s
}

// unquote parses a quoted scalar at the start of s. ok is false when the
// closing quote is not in s (a multi-line quoted scalar).
func unquote(s string) (val, tail string, ok bool, err error) {
	q := s[0]
	var sb strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		if q == '\'' {
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					sb.WriteByte('\'')
					i++
					continue
				}
				return sb.String(), s[i+1:], true, nil
			}
			sb.WriteByte(c)
			continue
		}
		switch c {
		case '"':
			return sb.String(), s[i+1:], true, nil
		case '\\':
			if i+1 >= len(s) {
				return "", "", false, nil
			}
			i++
			switch e := s[i]; e {
			case 'n':
				sb.WriteByte('\n')
			case 't':
				sb.WriteByte('\t')
			case 'r':
				sb.WriteByte('\r')
			case '0':
				sb.WriteByte(0)
			case '"', '\\', '/', ' ':
				sb.WriteByte(e)
			case 'u', 'x', 'U':
				w := map[byte]int{'x': 2, 'u': 4, 'U': 8}[e]
				if i+w >= len(s) {
					return "", "", false, fmt.Errorf("bad escape")
				}
				r, perr := strconv.ParseUint(s[i+1:i+1+w], 16, 32)
				// A surrogate or out-of-range code point is not a character;
				// refuse it rather than decode it to U+FFFD.
				if perr != nil || !utf8.ValidRune(rune(r)) || r > utf8.MaxRune {
					return "", "", false, fmt.Errorf("bad escape")
				}
				sb.WriteRune(rune(r))
				i += w
			default:
				return "", "", false, fmt.Errorf("unsupported escape \\%c", e)
			}
		default:
			sb.WriteByte(c)
		}
	}
	return "", "", false, nil
}

func flowBalanced(s string) bool {
	depth := 0
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if q != 0 {
			if c == q {
				q = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			q = c
		case '[', '{':
			depth++
		case ']', '}':
			depth--
		}
	}
	return depth <= 0 && q == 0
}

// stripComment removes a trailing " # comment" from a plain value.
func stripComment(v string) string {
	for i := 0; i < len(v); i++ {
		if v[i] == '#' && (i == 0 || v[i-1] == ' ' || v[i-1] == '\t') {
			return strings.TrimSpace(v[:i])
		}
	}
	return strings.TrimSpace(v)
}

// splitKeyValue splits "key: value # c" into key and the value text with a
// plain-scalar comment removed. The key follows keyName's rule.
func splitKeyValue(content string) (key, val string, err error) {
	content = strings.TrimLeft(content, " ")
	m := yamlKeyRx.FindStringSubmatch(content)
	if m == nil {
		return "", strings.TrimSpace(content), nil
	}
	if key, err = keyName(m); err != nil {
		return "", "", err
	}
	rest := strings.TrimSpace(content[len(m[0]):])
	if rest != "" && (rest[0] == '"' || rest[0] == '\'') {
		return key, rest, nil
	}
	return key, stripComment(rest), nil
}

// flatten renders a parsed value as sorted "path = value" lines, for
// structural diffs.
func flatten(prefix string, v any, out *[]string) {
	switch t := v.(type) {
	case *yMap:
		if len(t.keys) == 0 {
			*out = append(*out, prefix+" = {}")
		}
		for _, k := range t.keys {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			flatten(p, t.m[k], out)
		}
	case []any:
		if len(t) == 0 {
			*out = append(*out, prefix+" = []")
		}
		for i, e := range t {
			flatten(fmt.Sprintf("%s[%d]", prefix, i), e, out)
		}
	case string:
		*out = append(*out, prefix+" = "+strconv.Quote(t))
	case yFlow:
		*out = append(*out, prefix+" = (flow) "+strconv.Quote(string(t)))
	}
}

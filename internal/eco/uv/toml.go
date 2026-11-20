package uv

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ParseTOML parses the TOML subset uv.lock and pyproject.toml use: tables,
// arrays of tables, dotted and quoted keys, basic/literal (multi-line)
// strings, integers, floats, booleans, arrays and inline tables. Dates are
// kept as their raw text. Tables become map[string]any, arrays []any.
// It is the standard library's missing piece, not a general TOML library:
// anything outside the subset is an error, never a guess.
func ParseTOML(data string) (map[string]any, error) {
	p := &tomlParser{s: data, line: 1}
	root := map[string]any{}
	cur := root
	defined := map[string]bool{} // explicit [table] headers, to catch duplicates
	for {
		p.skipSpaceNewlinesComments()
		if p.eof() {
			return root, nil
		}
		switch {
		case strings.HasPrefix(p.s[p.i:], "[["):
			p.i += 2
			keys, err := p.keyPath()
			if err != nil {
				return nil, err
			}
			if !p.consume("]]") {
				return nil, p.errorf("expected ]]")
			}
			parent, err := walk(root, keys[:len(keys)-1])
			if err != nil {
				return nil, p.wrap(err)
			}
			last := keys[len(keys)-1]
			arr, _ := parent[last].([]any)
			if _, exists := parent[last]; exists && arr == nil {
				return nil, p.errorf("%q is not an array of tables", strings.Join(keys, "."))
			}
			t := map[string]any{}
			parent[last] = append(arr, t)
			cur = t
		case p.s[p.i] == '[':
			p.i++
			keys, err := p.keyPath()
			if err != nil {
				return nil, err
			}
			if !p.consume("]") {
				return nil, p.errorf("expected ]")
			}
			t, err := walk(root, keys)
			if err != nil {
				return nil, p.wrap(err)
			}
			// A table under the last [[array]] element is a different table each time.
			id := fmt.Sprintf("%p", t)
			if defined[id] {
				return nil, p.errorf("table [%s] defined twice", strings.Join(keys, "."))
			}
			defined[id] = true
			cur = t
		default:
			if err := p.keyValue(cur); err != nil {
				return nil, err
			}
		}
		p.skipSpace()
		p.skipComment()
		if !p.eof() && !p.newline() {
			return nil, p.errorf("expected end of line")
		}
	}
}

// walk descends keys from t, creating tables; an array of tables
// descends into its last element.
func walk(t map[string]any, keys []string) (map[string]any, error) {
	for _, k := range keys {
		switch v := t[k].(type) {
		case nil:
			n := map[string]any{}
			t[k] = n
			t = n
		case map[string]any:
			t = v
		case []any:
			if len(v) == 0 {
				return nil, fmt.Errorf("key %q is an empty array", k)
			}
			m, ok := v[len(v)-1].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("key %q is an array of values, not tables", k)
			}
			t = m
		default:
			return nil, fmt.Errorf("key %q is a value, not a table", k)
		}
	}
	return t, nil
}

type tomlParser struct {
	s    string
	i    int
	line int
}

func (p *tomlParser) eof() bool { return p.i >= len(p.s) }

func (p *tomlParser) errorf(format string, args ...any) error {
	return fmt.Errorf("toml line %d: %s", p.line, fmt.Sprintf(format, args...))
}

func (p *tomlParser) wrap(err error) error { return p.errorf("%v", err) }

func (p *tomlParser) consume(tok string) bool {
	if strings.HasPrefix(p.s[p.i:], tok) {
		p.i += len(tok)
		return true
	}
	return false
}

func (p *tomlParser) skipSpace() {
	for !p.eof() && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

func (p *tomlParser) skipComment() {
	if !p.eof() && p.s[p.i] == '#' {
		for !p.eof() && p.s[p.i] != '\n' {
			p.i++
		}
	}
}

func (p *tomlParser) newline() bool {
	if p.consume("\r\n") || p.consume("\n") {
		p.line++
		return true
	}
	return false
}

func (p *tomlParser) skipSpaceNewlinesComments() {
	for {
		p.skipSpace()
		p.skipComment()
		if !p.newline() {
			return
		}
	}
}

func (p *tomlParser) keyPath() ([]string, error) {
	var keys []string
	for {
		p.skipSpace()
		k, err := p.key()
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
		p.skipSpace()
		if !p.consume(".") {
			return keys, nil
		}
	}
}

func (p *tomlParser) key() (string, error) {
	if p.eof() {
		return "", p.errorf("expected key")
	}
	switch p.s[p.i] {
	case '"':
		return p.basicString()
	case '\'':
		return p.literalString()
	}
	start := p.i
	for !p.eof() {
		c := p.s[p.i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
			p.i++
			continue
		}
		break
	}
	if p.i == start {
		return "", p.errorf("expected key")
	}
	return p.s[start:p.i], nil
}

func (p *tomlParser) keyValue(t map[string]any) error {
	keys, err := p.keyPath()
	if err != nil {
		return err
	}
	p.skipSpace()
	if !p.consume("=") {
		return p.errorf("expected =")
	}
	p.skipSpace()
	v, err := p.value()
	if err != nil {
		return err
	}
	parent, err := walk(t, keys[:len(keys)-1])
	if err != nil {
		return p.wrap(err)
	}
	last := keys[len(keys)-1]
	if _, dup := parent[last]; dup {
		return p.errorf("duplicate key %q", strings.Join(keys, "."))
	}
	parent[last] = v
	return nil
}

func (p *tomlParser) value() (any, error) {
	if p.eof() {
		return nil, p.errorf("expected value")
	}
	switch c := p.s[p.i]; {
	case strings.HasPrefix(p.s[p.i:], `"""`):
		return p.multiBasic()
	case strings.HasPrefix(p.s[p.i:], `'''`):
		return p.multiLiteral()
	case c == '"':
		return p.basicString()
	case c == '\'':
		return p.literalString()
	case c == '[':
		return p.array()
	case c == '{':
		return p.inlineTable()
	}
	start := p.i
	for !p.eof() && !strings.ContainsRune(" \t\r\n,]}#", rune(p.s[p.i])) {
		p.i++
	}
	raw := p.s[start:p.i]
	switch raw {
	case "":
		return nil, p.errorf("expected value")
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	clean := strings.ReplaceAll(raw, "_", "")
	if n, err := strconv.ParseInt(clean, 0, 64); err == nil {
		return n, nil
	}
	if f, err := strconv.ParseFloat(clean, 64); err == nil {
		return f, nil
	}
	if raw[0] >= '0' && raw[0] <= '9' {
		return raw, nil // a date/time, kept as text
	}
	return nil, p.errorf("unsupported value %q", raw)
}

func (p *tomlParser) array() ([]any, error) {
	p.i++ // [
	out := []any{}
	for {
		p.skipSpaceNewlinesComments()
		if p.consume("]") {
			return out, nil
		}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.skipSpaceNewlinesComments()
		if p.consume(",") {
			continue
		}
		if p.consume("]") {
			return out, nil
		}
		return nil, p.errorf("expected , or ] in array")
	}
}

func (p *tomlParser) inlineTable() (map[string]any, error) {
	p.i++ // {
	t := map[string]any{}
	p.skipSpace()
	if p.consume("}") {
		return t, nil
	}
	for {
		p.skipSpace()
		if err := p.keyValue(t); err != nil {
			return nil, err
		}
		p.skipSpace()
		if p.consume(",") {
			continue
		}
		if p.consume("}") {
			return t, nil
		}
		return nil, p.errorf("expected , or } in inline table")
	}
}

func (p *tomlParser) literalString() (string, error) {
	p.i++
	end := strings.IndexAny(p.s[p.i:], "'\n")
	if end < 0 || p.s[p.i+end] != '\'' {
		return "", p.errorf("unterminated literal string")
	}
	s := p.s[p.i : p.i+end]
	p.i += end + 1
	return s, nil
}

func (p *tomlParser) multiLiteral() (string, error) {
	p.i += 3
	p.newline()
	end := strings.Index(p.s[p.i:], `'''`)
	if end < 0 {
		return "", p.errorf("unterminated multi-line literal string")
	}
	s := p.s[p.i : p.i+end]
	p.line += strings.Count(s, "\n")
	p.i += end + 3
	return s, nil
}

func (p *tomlParser) basicString() (string, error) {
	p.i++
	var b strings.Builder
	for {
		if p.eof() || p.s[p.i] == '\n' {
			return "", p.errorf("unterminated string")
		}
		c := p.s[p.i]
		switch c {
		case '"':
			p.i++
			return b.String(), nil
		case '\\':
			if err := p.escape(&b); err != nil {
				return "", err
			}
		default:
			b.WriteByte(c)
			p.i++
		}
	}
}

func (p *tomlParser) multiBasic() (string, error) {
	p.i += 3
	p.newline()
	var b strings.Builder
	for {
		if p.eof() {
			return "", p.errorf("unterminated multi-line string")
		}
		if p.consume(`"""`) {
			return b.String(), nil
		}
		c := p.s[p.i]
		switch {
		case c == '\\' && p.i+1 < len(p.s) && (p.s[p.i+1] == '\n' || p.s[p.i+1] == ' ' || p.s[p.i+1] == '\t' || p.s[p.i+1] == '\r'):
			// Line-ending backslash: trim whitespace and newlines.
			p.i++
			for !p.eof() && strings.ContainsRune(" \t\r\n", rune(p.s[p.i])) {
				if p.s[p.i] == '\n' {
					p.line++
				}
				p.i++
			}
		case c == '\\':
			if err := p.escape(&b); err != nil {
				return "", err
			}
		default:
			if c == '\n' {
				p.line++
			}
			b.WriteByte(c)
			p.i++
		}
	}
}

func (p *tomlParser) escape(b *strings.Builder) error {
	p.i++ // backslash
	if p.eof() {
		return p.errorf("bad escape")
	}
	c := p.s[p.i]
	p.i++
	switch c {
	case 'b':
		b.WriteByte('\b')
	case 't':
		b.WriteByte('\t')
	case 'n':
		b.WriteByte('\n')
	case 'f':
		b.WriteByte('\f')
	case 'r':
		b.WriteByte('\r')
	case 'e':
		b.WriteByte(0x1b)
	case '"':
		b.WriteByte('"')
	case '\\':
		b.WriteByte('\\')
	case 'u', 'U':
		n := 4
		if c == 'U' {
			n = 8
		}
		if p.i+n > len(p.s) {
			return p.errorf("bad unicode escape")
		}
		r, err := strconv.ParseUint(p.s[p.i:p.i+n], 16, 32)
		if err != nil || !utf8.ValidRune(rune(r)) {
			return p.errorf("bad unicode escape")
		}
		b.WriteRune(rune(r))
		p.i += n
	default:
		return p.errorf("bad escape \\%c", c)
	}
	return nil
}

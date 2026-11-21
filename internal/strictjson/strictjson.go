// Package strictjson decodes JSON that the gate and a JavaScript (or
// Python) consumer must read identically: lockfiles and manifests from the
// PR, and registry documents. encoding/json matches object keys to struct
// fields case-insensitively (with Unicode folding, so "reſolved" binds to
// "resolved") and lets the last of two duplicate keys win, while npm's
// JSON.parse is exact-case. Unmarshal refuses every input where those
// readings could differ, instead of picking one.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrRejected wraps every refusal; callers route it to RouteRefuse.
var ErrRejected = errors.New("ambiguous JSON")

func reject(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRejected, fmt.Sprintf(format, args...))
}

// Unmarshal decodes data into v (a non-nil pointer) after Check. Any
// decoding error, including a JSON type that does not fit a field (a
// string where a bool belongs), is also an ErrRejected: a zero value in
// place of what the consumer would read is not acceptable.
func Unmarshal(data []byte, v any) error { return unmarshal(data, v, false) }

// UnmarshalMetadata is Unmarshal for registry metadata (npm version
// documents, PyPI JSON), which carries free-form publisher text the gate
// never reads. Exact duplicate keys are refused at any depth, but keys
// differing only in case are refused only where the gate reads them: in
// an object decoded into a struct, a key that is not an exact field name
// but case-folds to one. Elsewhere (a map, or anything under an unknown
// key such as PyPI's info.project_urls) encoding/json keeps both keys
// apart just as JSON.parse does, so a case collision there is not an
// ambiguity.
func UnmarshalMetadata(data []byte, v any) error { return unmarshal(data, v, true) }

func unmarshal(data []byte, v any, metadata bool) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("strictjson: Unmarshal needs a non-nil pointer, got %T", v)
	}
	if err := check(data, rv.Type().Elem(), metadata); err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%w: %v", ErrRejected, err)
	}
	return nil
}

// Check validates data as exactly one JSON value and refuses:
//   - invalid UTF-8, and \u escapes that are lone surrogates (Go turns
//     both into U+FFFD; JavaScript keeps the code units);
//   - two keys in one object that are equal or differ only in case, at
//     any depth;
//   - a key in an object decoded into a struct of type t that is not an
//     exact field name but case-folds to one;
//   - anything after the value.
//
// t may be nil: then only the type-independent rules apply.
func Check(data []byte, t reflect.Type) error { return check(data, t, false) }

func check(data []byte, t reflect.Type, metadata bool) error {
	if !utf8.Valid(data) {
		return reject("invalid UTF-8")
	}
	if !json.Valid(data) {
		// json.Valid also rejects trailing data.
		var err error
		var x any
		if err = json.Unmarshal(data, &x); err == nil {
			err = errors.New("not a single JSON value")
		}
		return fmt.Errorf("%w: %v", ErrRejected, err)
	}
	if err := checkSurrogates(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := (walker{metadata}).walk(dec, t, "$"); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return reject("data after the top-level value")
	}
	return nil
}

// walk consumes one value. t is the Go type it will decode into, or nil
// when that is unknown (interface{}, json.RawMessage, an unknown key).
type walker struct {
	metadata bool // UnmarshalMetadata's rules
}

func (w walker) walk(dec *json.Decoder, t reflect.Type, at string) error {
	tok, err := dec.Token()
	if err != nil {
		return reject("%s: %v", at, err)
	}
	t = deref(t)
	switch tok {
	case json.Delim('{'):
		return w.object(dec, t, at)
	case json.Delim('['):
		var elem reflect.Type
		if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) && t != rawMessage {
			elem = t.Elem()
		}
		for i := 0; dec.More(); i++ {
			if err := w.walk(dec, elem, fmt.Sprintf("%s[%d]", at, i)); err != nil {
				return err
			}
		}
		_, err := dec.Token() // ]
		return err
	}
	return nil // scalar
}

func (w walker) object(dec *json.Decoder, t reflect.Type, at string) error {
	var fields map[string]reflect.Type // exact JSON name -> field type
	var elem reflect.Type
	if t != nil {
		switch t.Kind() {
		case reflect.Struct:
			fields = structFields(t)
		case reflect.Map:
			elem = t.Elem()
		}
	}
	seen := map[string]string{} // folded -> exact
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return reject("%s: %v", at, err)
		}
		key := tok.(string)
		f := fold(key)
		if w.metadata {
			f = key // only exact duplicates; the field check below covers binding
		}
		if prev, dup := seen[f]; dup {
			if prev == key {
				return reject("%s: duplicate key %q", at, key)
			}
			return reject("%s: keys %q and %q differ only in case", at, prev, key)
		}
		seen[f] = key
		next := elem
		if fields != nil {
			ft, exact := fields[key]
			if !exact {
				for name := range fields {
					if fold(name) == fold(key) || strings.EqualFold(name, key) {
						return reject("%s: key %q is not %q but would be read as it", at, key, name)
					}
				}
			}
			next = ft
		}
		if err := w.walk(dec, next, at+"."+key); err != nil {
			return err
		}
	}
	_, err := dec.Token() // }
	return err
}

var rawMessage = reflect.TypeFor[json.RawMessage]()

func deref(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == rawMessage || (t != nil && t.Kind() == reflect.Interface) {
		return nil
	}
	return t
}

// structFields lists the JSON names encoding/json would bind in t,
// including those promoted from embedded structs.
func structFields(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		tag := sf.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if sf.Anonymous && name == "" {
			et := sf.Type
			if et.Kind() == reflect.Pointer {
				et = et.Elem()
			}
			if et.Kind() == reflect.Struct {
				for k, v := range structFields(et) {
					if _, ok := out[k]; !ok {
						out[k] = v
					}
				}
				continue
			}
		}
		if !sf.IsExported() {
			continue
		}
		if name == "" {
			name = sf.Name
		}
		out[name] = sf.Type
	}
	return out
}

// fold is encoding/json's own key folding (ASCII upper-casing, and
// ToUpper(ToLower(r)) for other runes), so two keys fold equal exactly when
// encoding/json could bind them to the same field.
func fold(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < utf8.RuneSelf {
			if 'a' <= r && r <= 'z' {
				r -= 'a' - 'A'
			}
			b.WriteRune(r)
			continue
		}
		b.WriteRune(unicode.ToUpper(unicode.ToLower(r)))
	}
	return b.String()
}

// checkSurrogates refuses \u escapes that do not form a valid UTF-16
// surrogate pair. data is valid JSON, so strings and escapes are well
// formed.
func checkSurrogates(data []byte) error {
	inStr := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if !inStr {
			if c == '"' {
				inStr = true
			}
			continue
		}
		switch c {
		case '"':
			inStr = false
		case '\\':
			if data[i+1] != 'u' {
				i++
				continue
			}
			r := hex4(data[i+2 : i+6])
			i += 5
			switch {
			case r >= 0xDC00 && r <= 0xDFFF:
				return reject("lone low surrogate \\u%04X", r)
			case r >= 0xD800 && r <= 0xDBFF:
				if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
					return reject("lone high surrogate \\u%04X", r)
				}
				lo := hex4(data[i+3 : i+7])
				if lo < 0xDC00 || lo > 0xDFFF {
					return reject("lone high surrogate \\u%04X", r)
				}
				i += 6
			}
		}
	}
	return nil
}

func hex4(b []byte) rune {
	var r rune
	for _, c := range b {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			r |= rune(c-'A') + 10
		}
	}
	return r
}

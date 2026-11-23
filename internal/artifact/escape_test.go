package artifact

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// u is the string of one code point. The tests name invisible characters
// by number so that this file holds none.
func u(r rune) string { return string(r) }

func TestEscape(t *testing.T) {
	tests := []struct {
		name string
		in   string
		text string // escapeText
		line string // escapeLine
	}{
		{"plain", "let a = 1;", "let a = 1;", "let a = 1;"},
		{"letters and digits outside ASCII stay", "na" + u(0xEF) + "ve " + u(0x65E5) + u(0x0663), "na" + u(0xEF) + "ve " + u(0x65E5) + u(0x0663), "na" + u(0xEF) + "ve " + u(0x65E5) + u(0x0663)},
		{"symbols and punctuation outside ASCII are shown", u(0x1F642) + " a" + u(0x2014) + "b", "<U+1F642> a<U+2014>b", "<U+1F642> a<U+2014>b"},
		{"a combining mark is shown", "e" + u(0x0301), "e<U+0301>", "e<U+0301>"},
		{"newline and tab", "a\tb\nc", "a\tb\nc", "a<0x09>b<0x0A>c"},
		{"the CR of a CRLF is shown", "a\r\nb", "a<0x0D>\nb", "a<0x0D><0x0A>b"},
		{"lone CR is shown", "a\rb", "a<0x0D>b", "a<0x0D>b"},
		{"CR at the very end is shown", "a\r", "a<0x0D>", "a<0x0D>"},
		{"two CRs before LF", "a\r\r\nb", "a<0x0D><0x0D>\nb", "a<0x0D><0x0D><0x0A>b"},
		// What a list of characters to hide did not have (none of these is
		// a control or a format character).
		{"braille blank", "a" + u(0x2800) + "b", "a<U+2800>b", "a<U+2800>b"},
		{"spaces outside ASCII", "a" + u(0xA0) + "b" + u(0x3000) + "c", "a<U+00A0>b<U+3000>c", "a<U+00A0>b<U+3000>c"},
		{"grapheme joiner", "a" + u(0x034F) + "b", "a<U+034F>b", "a<U+034F>b"},
		{"mongolian variation selector", "a" + u(0x180B) + "b", "a<U+180B>b", "a<U+180B>b"},
		{"the replacement character itself", "a" + u(0xFFFD) + "b", "a<U+FFFD>b", "a<U+FFFD>b"},
		{"C0 controls", "a\x01\x1b[31m\x7f", "a<0x01><0x1B>[31m<0x7F>", "a<0x01><0x1B>[31m<0x7F>"},
		{"vertical tab and form feed end no line", "a\vb\fc", "a<0x0B>b<0x0C>c", "a<0x0B>b<0x0C>c"},
		{"NEL", "a" + u(0x85) + "b", "a<U+0085>b", "a<U+0085>b"},
		{"line and paragraph separator", "a" + u(0x2028) + "b" + u(0x2029) + "c", "a<U+2028>b<U+2029>c", "a<U+2028>b<U+2029>c"},
		{"bidi override", "if (x" + u(0x202E) + ") {", "if (x<U+202E>) {", "if (x<U+202E>) {"},
		{"bidi isolate", u(0x2066) + "x" + u(0x2069), "<U+2066>x<U+2069>", "<U+2066>x<U+2069>"},
		{"marks", u(0x200E) + u(0x200F) + u(0x061C), "<U+200E><U+200F><U+061C>", "<U+200E><U+200F><U+061C>"},
		{"zero width", "a" + u(0x200B) + "b" + u(0x200D) + "c" + u(0xFEFF), "a<U+200B>b<U+200D>c<U+FEFF>", "a<U+200B>b<U+200D>c<U+FEFF>"},
		{"soft hyphen", "pass" + u(0xAD) + "word", "pass<U+00AD>word", "pass<U+00AD>word"},
		{"tag letters", "a" + u(0xE0041) + "b", "a<U+E0041>b", "a<U+E0041>b"},
		{"variation selectors", "a" + u(0xFE0F) + "b" + u(0xE0100), "a<U+FE0F>b<U+E0100>", "a<U+FE0F>b<U+E0100>"},
		{"hangul filler", "var " + u(0x3164) + " = 1", "var <U+3164> = 1", "var <U+3164> = 1"},
		{"invalid UTF-8", "a\xffb\xc3", "a<0xFF>b<0xC3>", "a<0xFF>b<0xC3>"},
		{"NUL", "a\x00b", "a<0x00>b", "a<0x00>b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeText(tt.in); got != tt.text {
				t.Errorf("escapeText(%q) = %q, want %q", tt.in, got, tt.text)
			}
			if got := escapeLine(tt.in); got != tt.line {
				t.Errorf("escapeLine(%q) = %q, want %q", tt.in, got, tt.line)
			}
		})
	}
}

// Everything v0.1.9's evidence.Normalize made visible is made visible
// here: the C0 controls but tab and LF; DEL; NEL; the line and paragraph
// separators; the bidi controls.
func TestEscapeCoversV019(t *testing.T) {
	var runes []rune
	for r := rune(0); r < 0x20; r++ {
		if r != '\t' && r != '\n' {
			runes = append(runes, r)
		}
	}
	runes = append(runes, 0x7f, 0x85, 0x2028, 0x2029, 0x200E, 0x200F, 0x061C)
	for r := rune(0x202A); r <= 0x202E; r++ {
		runes = append(runes, r)
	}
	for r := rune(0x2066); r <= 0x2069; r++ {
		runes = append(runes, r)
	}
	for _, r := range runes {
		in := "a" + string(r) + "b"
		got := escapeText(in)
		if strings.ContainsRune(got, r) {
			t.Errorf("U+%04X is still in %q", r, got)
		}
		if !strings.HasPrefix(got, "a<") || !strings.HasSuffix(got, ">b") {
			t.Errorf("U+%04X: got %q, want a visible escape", r, got)
		}
	}
}

// After escapeText the only thing that ends a line is "\n", and after
// escapeLine nothing does. Checked for every character that some language
// or terminal treats as a line end, in every position.
func TestEscapeLeavesNoOtherLineEnd(t *testing.T) {
	for _, in := range []string{"\r", "a\r", "\rb", "a\rb", "a\r\rb", "a\r\r\nb", "a\n\rb", "\r\n", "a\r\n\rb\r"} {
		got := escapeText(in)
		if strings.Contains(got, "\r") || strings.Count(got, "\n") != strings.Count(in, "\n") {
			t.Errorf("escapeText(%q) = %q: a CR is left, or the number of lines changed", in, got)
		}
		if line := escapeLine(in); strings.ContainsAny(line, "\r\n") {
			t.Errorf("escapeLine(%q) = %q: still more than one line", in, line)
		}
	}
	ends := []string{"\v", "\f", u(0x85), u(0x2028), u(0x2029), "\x1c", "\x1d", "\x1e"}
	for _, e := range ends {
		for _, in := range []string{e, "a" + e, e + "b", "a" + e + "b", "a" + e + e + "b", "a\n" + e + "\nb"} {
			got := escapeText(in)
			if strings.Count(got, "\n") != strings.Count(in, "\n") {
				t.Errorf("escapeText(%q) = %q: the number of lines changed", in, got)
			}
			if strings.Contains(got, e) {
				t.Errorf("escapeText(%q) = %q: %q is still there", in, got, e)
			}
			if line := escapeLine(in); strings.ContainsAny(line, "\n"+e) {
				t.Errorf("escapeLine(%q) = %q: still more than one line", in, line)
			}
		}
	}
}

func TestEscapeIsValidUTF8(t *testing.T) {
	for _, in := range []string{"\xff\xfe\xfd", "ok\xc3", "\xe2\x80", "\xed\xa0\x80"} {
		if got := escapeLine(in); !utf8.ValidString(got) {
			t.Errorf("escapeLine(%q) = %q is not valid UTF-8", in, got)
		}
	}
}

// The escaper is an allowlist: of everything outside ASCII only letters
// and decimal digits pass, and of those not the four that Unicode says
// are drawn as nothing. Whatever else Unicode holds or comes to hold is
// shown as an escape, with no list of bad characters to keep up.
func TestEscapeIsAnAllowlist(t *testing.T) {
	passed := 0
	for r := rune(0x80); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue // surrogates are not characters
		}
		in := string(r)
		got := escapeText(in)
		if got != escapeLine(in) {
			t.Fatalf("U+%04X: escapeText %q, escapeLine %q", r, got, escapeLine(in))
		}
		if got == in {
			passed++
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
				t.Fatalf("U+%04X passes and is neither a letter nor a digit", r)
			}
			if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zs, unicode.Zl, unicode.Zp, unicode.M, unicode.Variation_Selector, unicode.Other_Default_Ignorable_Code_Point) {
				t.Fatalf("U+%04X passes and is a control, a format character, a space, a mark or drawn as nothing", r)
			}
			continue
		}
		for i := 0; i < len(got); i++ {
			if got[i] < 0x20 || got[i] >= 0x7f {
				t.Fatalf("U+%04X: the escape %q is not printable ASCII", r, got)
			}
		}
	}
	if passed < 100_000 {
		t.Errorf("only %d characters outside ASCII pass; letters of other scripts should", passed)
	}
	// In ASCII: the printable characters, and in text the line feed and
	// the tab.
	for c := 0; c < 0x80; c++ {
		in := string(rune(c))
		printable := c >= 0x20 && c < 0x7f
		if got := escapeLine(in) == in; got != printable {
			t.Errorf("escapeLine passes 0x%02X: %v", c, got)
		}
		if got := escapeText(in) == in; got != (printable || c == '\n' || c == '\t') {
			t.Errorf("escapeText passes 0x%02X: %v", c, got)
		}
	}
}

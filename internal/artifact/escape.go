package artifact

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The package has one escaper, used for everything a publisher wrote that
// ends up in front of the model or in a comment: diff lines, file paths,
// the paths in Unread. It is an allowlist, so that no character it was
// never told about can end a line, reorder text, hide, or pass for
// another: printable ASCII and the letters and digits of other scripts
// stay, and everything else becomes "<0xNN>" (a byte that is not UTF-8,
// or an ASCII control) or "<U+XXXX>".

// escapeText escapes diff text, which is made of lines: "\n" and tab stay.
// A carriage return never does, not even before "\n".
func escapeText(s string) string { return escape(s, true) }

// escapeLine escapes text that must stay on one line (a path): line feeds
// and tabs are shown too.
func escapeLine(s string) string { return escape(s, false) }

func escape(s string, lines bool) string {
	// Most text is plain ASCII, and is returned without a copy.
	i := 0
	for i < len(s) && plainASCII(s[i], lines) {
		i++
	}
	if i == len(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	b.WriteString(s[:i])
	for i < len(s) {
		if plainASCII(s[i], lines) {
			b.WriteByte(s[i])
			i++
			continue
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r < utf8.RuneSelf || r == utf8.RuneError && n == 1:
			// An ASCII control, or a byte that is not UTF-8. Diff text
			// never has the second (such a file is unread); a path can.
			fmt.Fprintf(&b, "<0x%02X>", s[i])
		case shownLetter(r):
			b.WriteString(s[i : i+n])
		default:
			fmt.Fprintf(&b, "<U+%04X>", r)
		}
		i += n
	}
	return b.String()
}

// plainASCII reports whether the byte c is kept as it is: printable ASCII
// and, in text made of lines, the line feed and the tab.
func plainASCII(c byte, lines bool) bool {
	return c >= 0x20 && c < 0x7f || lines && (c == '\n' || c == '\t')
}

// shownLetter reports whether r, a rune outside ASCII, is kept as it is: a
// letter or a decimal digit that a reader sees. Unicode's own list of
// characters to be drawn as nothing has four letters, the Hangul fillers,
// which are valid in a JavaScript identifier.
func shownLetter(r rune) bool {
	return (unicode.IsLetter(r) || unicode.IsDigit(r)) && !unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r)
}

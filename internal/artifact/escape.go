package artifact

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The package has one escaper, used for everything a publisher wrote that
// ends up in front of the model or in a comment: diff lines, file paths,
// the paths in Unread. After it, what the reader sees is what is there:
// no character can end a line, reorder text or hide.
//
// A character that is escaped becomes "<0xNN>" (a byte or an ASCII
// control) or "<U+XXXX>" (anything else).

// escapeText escapes diff text. "\n" stays, because the text is made of
// lines; a tab stays; a CR stays only directly before "\n" (a CRLF line
// end). A CR anywhere else ends a line for JavaScript and Python but not
// for the reader, so it is shown.
func escapeText(s string) string { return escape(s, true) }

// escapeLine escapes text that must stay on one line (a path): line
// feeds, carriage returns and tabs are shown too.
func escapeLine(s string) string { return escape(s, false) }

func escape(s string, lines bool) string {
	if clean(s, lines) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n <= 1:
			// Not UTF-8. Diff text never has this (such a file is
			// unread, not shown); a path can.
			fmt.Fprintf(&b, "<0x%02X>", s[i])
		case lines && (r == '\n' || r == '\t'):
			b.WriteByte(byte(r))
		case lines && r == '\r' && i+1 < len(s) && s[i+1] == '\n':
			b.WriteByte('\r')
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, "<0x%02X>", r)
		case hidden(r):
			fmt.Fprintf(&b, "<U+%04X>", r)
		default:
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}

// clean reports whether escape would return s unchanged. Most text is,
// and then no copy is made.
func clean(s string, lines bool) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 0x80:
			// Not ASCII: take the slow path, which decodes.
			return false
		case c >= 0x20 && c != 0x7f:
		case lines && (c == '\n' || c == '\t'):
		case lines && c == '\r' && i+1 < len(s) && s[i+1] == '\n':
		default:
			return false
		}
	}
	return true
}

// hidden reports whether r, a rune above the ASCII controls, is one a
// reader cannot see or that changes how the text around it reads.
//
// The Unicode categories do most of the work, so the list does not have
// to be kept by hand: Cc is the C1 controls (U+0085 NEL among them, a
// line end to JavaScript); Cf is every format character (the bidi
// controls and isolates, zero-width spaces and joiners, the byte order
// mark, the soft hyphen, the invisible "tag" letters); Zl and Zp are the
// line and paragraph separators. The rest are characters in other
// categories that render as nothing: variation selectors, which can
// carry hidden bytes, and the Hangul fillers, which are letters and so
// valid in a JavaScript identifier.
func hidden(r rune) bool {
	switch {
	case unicode.Is(unicode.Cc, r), unicode.Is(unicode.Cf, r),
		unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
		return true
	case r >= 0xFE00 && r <= 0xFE0F, r >= 0xE0100 && r <= 0xE01EF:
		return true
	case r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0:
		return true
	}
	return false
}

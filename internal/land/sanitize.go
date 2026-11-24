package land

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// cellMax is how many characters of a third-party value the comment
// shows.
const cellMax = 200

// neutral replaces the characters that mean something to GitHub even
// where a code span should already have made them plain: a backtick would
// end the span, a pipe would end the table cell (a backslash in front of
// it does not reliably prevent that, so it is not escaped but replaced),
// angle brackets could start HTML or end the marker's comment, and an "@"
// could address a bot that reads comment bodies without parsing Markdown
// (Dependabot acts on commands from an account that can write).
var neutral = strings.NewReplacer("`", "'", "|", "\u00a6", "<", "\u2039", ">", "\u203a", "@", "\uff20")

// inline makes third-party text safe to show: one line of at most cellMax
// characters with nothing invisible in it and nothing GitHub would act
// on.
func inline(s string) string {
	// Cut in bytes first, so that a huge input costs little. cellMax
	// characters are at most four bytes each.
	long := len(s) > 4*cellMax
	if long {
		s = s[:4*cellMax]
	}
	s = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			// Line and paragraph separators included: one line.
			return ' '
		case r == utf8.RuneError, unicode.IsControl(r), unicode.Is(unicode.Cf, r):
			// Invalid bytes, controls, and everything that hides or
			// reorders text: bidi overrides and isolates, zero-width and
			// other format characters.
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(neutral.Replace(s)), " ")
	if utf8.RuneCountInString(s) > cellMax {
		s, long = string([]rune(s)[:cellMax]), true
	}
	if long {
		s += " [cut]"
	}
	return s
}

// code is the only way third-party text enters a comment: inline, inside
// a code span. Empty text is an empty cell.
func code(s string) string {
	if s = inline(s); s == "" {
		return ""
	}
	return "`" + s + "`"
}

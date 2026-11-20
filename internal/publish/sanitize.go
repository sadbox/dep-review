package publish

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	summaryMax = 3000
	inlineMax  = 200
)

var (
	htmlTagRe  = regexp.MustCompile(`(?s)<[^<>]*>`)
	imageRe    = regexp.MustCompile(`!\[([^\]\n]*)\]\([^)\n]*\)`)
	linkRe     = regexp.MustCompile(`\[([^\]\n]*)\]\([^)\n]*\)`)
	refLinkRe  = regexp.MustCompile(`\[([^\]\n]*)\]\[[^\]\n]*\]`)
	refDefRe   = regexp.MustCompile(`(?m)^[ \t]*\[[^\]\n]+\]:.*$`)
	issueRefRe = regexp.MustCompile(`#([0-9])`)
	ghRefRe    = regexp.MustCompile(`(?i)\b(GH)-([0-9])`)
)

// invisible reports runes that can hide or reorder text: controls other
// than newline and tab, bidi overrides and isolates, zero-width and
// format characters, and the BOM.
func invisible(r rune) bool {
	if r == '\n' || r == '\t' {
		return false
	}
	if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
		return true
	}
	switch r {
	case utf8.RuneError, '\u2028', '\u2029':
		return true
	}
	return false
}

func clean(s string) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.Map(func(r rune) rune {
		if invisible(r) {
			return -1
		}
		return r
	}, s)
}

// neutralize removes markup and anything GitHub would turn into a
// notification or a link.
func neutralize(s string) string {
	s = htmlTagRe.ReplaceAllString(s, "")
	s = strings.NewReplacer("<", "\u2039", ">", "\u203a").Replace(s)
	s = imageRe.ReplaceAllString(s, "$1")
	s = linkRe.ReplaceAllString(s, "$1")
	s = refLinkRe.ReplaceAllString(s, "$1")
	s = refDefRe.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "@", "\uff20")
	s = issueRefRe.ReplaceAllString(s, "\uff03$1")
	s = ghRefRe.ReplaceAllString(s, "$1\u2011$2")
	s = strings.ReplaceAll(s, "`", "'")
	return s
}

func capRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	i := 0
	for j := range s {
		if i == n {
			return s[:j] + " [truncated]"
		}
		i++
	}
	return s
}

// SanitizeSummary prepares the model's summary for a comment: plain text,
// no markup, no mentions, no references, capped, safe to place inside a
// ``` fence (it contains no backticks).
func SanitizeSummary(s string) string {
	// Cap first in bytes so a huge input costs little, then again in runes.
	if len(s) > 4*summaryMax*4 {
		s = s[:4*summaryMax*4]
	}
	s = neutralize(clean(s))
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " \t")
	}
	s = strings.TrimSpace(strings.Join(lines, "\n"))
	for strings.Contains(s, "\n\n\n") {
		s = strings.ReplaceAll(s, "\n\n\n", "\n\n")
	}
	return capRunes(s, summaryMax)
}

// Inline prepares a short value (a dependency name, a version, a finding
// detail) for a table cell code span: one line, no markup, no backticks,
// pipes escaped.
func Inline(s string) string {
	if len(s) > 4*inlineMax*4 {
		s = s[:4*inlineMax*4]
	}
	s = neutralize(clean(s))
	s = strings.Join(strings.Fields(s), " ")
	s = capRunes(s, inlineMax)
	return strings.ReplaceAll(s, "|", `\|`)
}

// code wraps an Inline value in a code span, or renders an empty cell.
func code(s string) string {
	s = Inline(s)
	if s == "" {
		return ""
	}
	return "`" + s + "`"
}

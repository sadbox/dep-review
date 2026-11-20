// Command dep-review is the gate's deterministic half: classify, fetch,
// review-prep, review (the sandboxed reviewer), proxy (its credential
// proxy), publish and sweep. See README.md.
package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"unicode/utf8"
)

// extraCommands holds the sandboxtest build's test-only commands.
var extraCommands = map[string]func([]string) error{}

func main() {
	// Errors and log lines can carry text from a dependency, a registry or
	// git's stderr. Everything that reaches the job log goes through
	// logLine: one line, no control characters, no workflow commands.
	log.SetOutput(lineWriter{os.Stderr})
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dep-review classify|fetch|review-prep|review|proxy|publish|sweep [flags]")
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "classify":
		err = runClassify(args)
	case "fetch":
		err = runFetch(args)
	case "review-prep":
		err = runReviewPrep(args)
	case "review":
		err = runReview(args)
	case "proxy":
		err = runProxy(args)
	case "publish":
		err = runPublish(args)
	case "sweep":
		err = runSweep(args)
	default:
		if f, ok := extraCommands[cmd]; ok {
			err = f(args)
		} else {
			err = fmt.Errorf("unknown command %q", cmd)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, logLine("dep-review: "+err.Error()))
		os.Exit(1)
	}
}

const maxLogLine = 2000 // runes

// logLine makes s safe to print to a GitHub Actions log: one line,
// control and bidi characters escaped, "::" and "##[" (workflow commands,
// new and legacy syntax) broken up, at most maxLogLine runes.
func logLine(s string) string {
	var b strings.Builder
	n := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if n >= maxLogLine {
			b.WriteString(" [truncated]")
			break
		}
		n++
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\u%04x`, utf8.RuneError)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			fmt.Fprintf(&b, `\x%02x`, r)
		case r == 0x2028 || r == 0x2029 || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0xfeff:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	for strings.Contains(out, "::") {
		out = strings.ReplaceAll(out, "::", ": :")
	}
	for strings.Contains(out, "##[") {
		out = strings.ReplaceAll(out, "##[", "# #[")
	}
	return out
}

// lineWriter sanitizes each log record (the log package writes one record
// per Write) and ends it with a single newline.
type lineWriter struct{ w io.Writer }

func (l lineWriter) Write(p []byte) (int, error) {
	if _, err := io.WriteString(l.w, logLine(strings.TrimSuffix(string(p), "\n"))+"\n"); err != nil {
		return 0, err
	}
	return len(p), nil
}

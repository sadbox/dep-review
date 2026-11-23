package artifact

import (
	"regexp"
	"strings"
)

// Markers are the fixed, plain-text patterns of the targeted read (spec
// section 7), used only when an update's diff is too large to send whole.
// They choose which hunks the model is shown of a file that does not fit,
// and nothing else: whatever they leave out is listed as unread and the
// read is partial, whatever a publisher writes into or keeps out of a
// hunk.

// hunkMarkers is the fixed list. Each pattern is matched against one
// added line of a diff, "+" included.
var hunkMarkers = []struct {
	what    string
	pattern string
}{
	{"a new import",
		`\bimport\b|\brequire\s*\(` +
			// A Go import spec on a line of its own: "path" or name "path".
			`|^\+\s*(?:[A-Za-z_.][A-Za-z0-9_.]*\s+)?"[^"\s]+"\s*$`},
	{"a URL",
		`[A-Za-z][A-Za-z0-9+.-]*://`},
	{"an IP address",
		`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`},
	{"a process call",
		`child_process|\bexec(?:File|Sync|FileSync)?\s*\(|\bspawn(?:Sync)?\s*\(|os/exec|exec\.Command|syscall\.` +
			`|\beval\s*\(|\bnew Function\b|process\.(?:env|binding|dlopen)|os\.(?:Getenv|Environ|StartProcess)` +
			`|\bsubprocess\b|os\.system|/bin/(?:ba)?sh\b|\b(?:bash|sh|cmd|powershell|pwsh)(?:\.exe)?\s+[-/]`},
	{"a network call",
		`\bfetch\s*\(|XMLHttpRequest|WebSocket|net\.(?:Dial|Listen|connect|createConnection|Socket)|net/http` +
			`|\bhttps?\.(?:Get|Post|Head|Do|NewRequest|request|get)\b|\bdns\.(?:lookup|resolve)|\b(?:curl|wget|nc|ncat)\s`},
	{"a long encoded string",
		`[A-Za-z0-9+/=_-]{120,}|(?:\\x[0-9A-Fa-f]{2}){16,}|(?:\\u[0-9A-Fa-f]{4}){12,}` +
			`|\batob\s*\(|(?i:base64)|fromCharCode|Buffer\.from\s*\(`},
}

// markerRE is hunkMarkers as one expression.
var markerRE = func() *regexp.Regexp {
	var all []string
	for _, m := range hunkMarkers {
		all = append(all, "(?:"+m.pattern+")")
	}
	return regexp.MustCompile(strings.Join(all, "|"))
}()

// marked reports whether any added line of a hunk matches a marker.
func marked(hunk string) bool {
	for line := range strings.Lines(hunk) {
		if strings.HasPrefix(line, "+") && markerRE.MatchString(strings.TrimRight(line, "\r\n")) {
			return true
		}
	}
	return false
}

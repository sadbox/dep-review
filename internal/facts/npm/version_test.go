package npm

import (
	"fmt"
	"strings"
	"testing"
)

func TestIncreaseAndMajor(t *testing.T) {
	tests := []struct {
		from, to string
		increase bool
		// major is "yes", "no", or "" for left ungathered.
		major string
	}{
		{"1.2.3", "1.2.4", true, "no"},
		{"1.2.3", "1.3.0", true, "no"},
		{"1.9.0", "1.10.0", true, "no"},
		{"1.2.3", "2.0.0", true, "yes"},
		{"0.24.0", "0.25.0", true, "no"},
		{"0.9.9", "1.0.0", true, "yes"},
		{"9.0.0", "10.0.0", true, "yes"},
		{"", "1.0.0", true, "no"},
		{"1.2.3", "1.2.3", false, "no"},
		{"1.2.4", "1.2.3", false, "no"},
		{"2.0.0", "1.9.9", false, "yes"},
		{"1.2.3", "1.2.4-beta.1", false, ""},
		{"1.2.3-beta.1", "1.2.3", false, ""},
		{"1.2.3", "1.2.4+build.5", false, ""},
		{"1.2.3", "v1.2.4", false, ""},
		{"1.2", "1.3", false, ""},
		{"1.2.3", "1.2.04", false, ""},
		{"1.2.3", "0.0.0-insiders.00ef99d", false, ""},
		{"", "1.0.0-rc.1", false, "no"},
		{"1.2.3", "", false, ""},
		{"1.2.3", "latest", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.from+"->"+tt.to, func(t *testing.T) {
			inc := increaseFact(tt.from, tt.to, "lock")
			if !inc.Gathered() || inc.OK != tt.increase {
				t.Errorf("Increase = %+v, want a gathered %v", inc, tt.increase)
			}
			maj := majorFact(tt.from, tt.to, "lock")
			switch tt.major {
			case "yes":
				if !maj.Holds() {
					t.Errorf("Major = %+v, want yes", maj)
				}
			case "no":
				if !maj.Gathered() || maj.OK {
					t.Errorf("Major = %+v, want a gathered no", maj)
				}
			default:
				if maj.Gathered() || maj.OK {
					t.Errorf("Major = %+v, want it left ungathered", maj)
				}
			}
		})
	}
}

func TestValidNameAndVersion(t *testing.T) {
	for name, want := range map[string]bool{
		"chart.js":                        true,
		"@tailwindcss/oxide-wasm32-wasi":  true,
		"JSONStream":                      true,
		"left_pad":                        true,
		"":                                false,
		"@scope":                          false,
		"@scope/":                         false,
		"@scope/a/b":                      false,
		"a/b":                             false,
		"../etc/passwd":                   false,
		".hidden":                         false,
		"a b":                             false,
		"a?x=1":                           false,
		"a#frag":                          false,
		"a%2fb":                           false,
		"-/npm/v1/attestations/x":         false,
		strings.Repeat("a", maxNameLen):   true,
		strings.Repeat("a", maxNameLen+1): false,
	} {
		if got := validName(name); got != want {
			t.Errorf("validName(%q) = %v, want %v", name, got, want)
		}
	}
	for version, want := range map[string]bool{
		"1.2.3":                  true,
		"1.2.3-beta.1":           true,
		"0.0.0-insiders.00ef99d": true,
		"1.2.3+build":            true,
		"1.2":                    false,
		"":                       false,
		"1.2.3/../x":             false,
		"1.2.3 ":                 false,
		"latest":                 false,
	} {
		if got := validVersion(version); got != want {
			t.Errorf("validVersion(%q) = %v, want %v", version, got, want)
		}
	}
}

// escaped is the escape quote writes for r. It is built here, and the
// characters under test are built from their code points, so that this
// file itself holds nothing but ASCII.
func escaped(r rune) string { return fmt.Sprintf("%cu%04x", 0x5c, r) }

func TestShowAndQuote(t *testing.T) {
	const (
		bidiOverride  = rune(0x202e)
		zeroWidth     = rune(0x200b)
		lineSeparator = rune(0x2028)
		eAcute        = rune(0xe9)
	)
	tests := []struct{ in, want string }{
		{"chart.js", "chart.js"},
		{"@scope/name", "@scope/name"},
		{"node_modules/a", "node_modules/a"},
		{"", `""`},
		{"two words", `"two words"`},
		{"line\nbreak", `"line\nbreak"`},
		{"tab\there", `"tab\there"`},
		{"<img src=x>", `"<img src=x>"`},
		{"[link](http://example)", `"[link](http://example)"`},
		{"backtick`", "\"backtick`\""},
		{"bidi" + string(bidiOverride) + "override", `"bidi` + escaped(bidiOverride) + `override"`},
		{"zero" + string(zeroWidth) + "width", `"zero` + escaped(zeroWidth) + `width"`},
		{"line" + string(lineSeparator) + "separator", `"line` + escaped(lineSeparator) + `separator"`},
		{"caf" + string(eAcute), `"caf` + escaped(eAcute) + `"`},
		// Longer than a name can be: quoted and cut.
		{strings.Repeat("a", 300), `"` + strings.Repeat("a", 160) + `..."`},
		{strings.Repeat("ab ", 100), `"` + strings.Repeat("ab ", 53) + `a..."`},
	}
	for _, tt := range tests {
		if got := show(tt.in); got != tt.want {
			t.Errorf("show(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}
	// A cut never splits a character: 160 bytes of a two-byte character
	// are 80 whole ones.
	long := strings.Repeat(string(eAcute), 200)
	if got, want := quote(long), `"`+strings.Repeat(escaped(eAcute), 80)+`..."`; got != want {
		t.Errorf("quote cut a character in half: %s", got)
	}
	// And a cut that lands inside a character backs up to its start.
	odd := "a" + strings.Repeat(string(eAcute), 200)
	if got, want := quote(odd), `"a`+strings.Repeat(escaped(eAcute), 79)+`..."`; got != want {
		t.Errorf("quote cut a character in half: %s", got)
	}
}

func TestSupportedNPM(t *testing.T) {
	for version, want := range map[string]bool{
		"8.19.4":       false,
		"9.9.4":        true,
		"10.9.11":      true,
		"11.20.0":      true,
		"11.0.0-pre.1": true,
		"7.24.2":       false,
		"6.14.18":      false,
		"12.0.0":       false,
		"":             false,
		"11":           false,
		"v11.20.0":     false,
		"11.20.0\n":    false,
		"11.20.0 rm":   false,
	} {
		if got := supportedNPM(version) == nil; got != want {
			t.Errorf("supportedNPM(%q) = %v, want %v", version, got, want)
		}
	}
}

package gomod

import (
	"encoding/base64"
	"testing"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
	"github.com/sadbox/dep-review/internal/model"
)

func TestWellKnownModule(t *testing.T) {
	for path, want := range map[string]bool{
		"golang.org/x/net":                  true,
		"golang.org/x/sys":                  true,
		"google.golang.org/grpc":            true,
		"google.golang.org/protobuf":        true,
		"cloud.google.com/go":               true,
		"cloud.google.com/go/storage":       true,
		"golang.org/x":                      false,
		"golang.org/xnet":                   false,
		"google.golang.org":                 false,
		"google.golang.org.evil.example/x":  false,
		"cloud.google.com/gox":              false,
		"cloud.google.com/other":            false,
		"github.com/google/uuid":            false,
		"github.com/aws/aws-sdk-go-v2":      false,
		"example.com/golang.org/x/net":      false,
		"golang.org/x/../../evil.example/x": false,
	} {
		if got := wellKnownModule(path); got != want {
			t.Errorf("wellKnownModule(%q) = %v, want %v", path, got, want)
		}
	}
}

// TestLenientRoutes: leniency moves exactly cgo, C and assembly source,
// link-reachable testdata binaries and unresolved embeds from a person to
// review, and nothing else.
func TestLenientRoutes(t *testing.T) {
	const asm = "TEXT ·f(SB),0,$0\nRET\n"
	mod := map[string]string{"go.mod": "module golang.org/x/m\n\ngo 1.24\n", "a.go": "package m\n\nfunc f()\n"}
	with := func(files map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range mod {
			out[k] = v
		}
		for k, v := range files {
			out[k] = v
		}
		return out
	}
	tests := []struct {
		name    string
		old     map[string]string
		cur     map[string]string
		lenient bool // every person-routed finding becomes review
	}{
		{"assembly", with(map[string]string{"f_amd64.s": asm}), with(map[string]string{"f_amd64.s": asm + "RET\n"}), true},
		{"c source", with(map[string]string{"x.c": "int f(void) { return 0; }\n"}), with(map[string]string{"x.c": "int f(void) { return 1; }\n"}), true},
		{"testdata fixture in an asm module", with(map[string]string{"f_amd64.s": asm}), with(map[string]string{"f_amd64.s": asm, "testdata/fixture.png": "\x89PNG\r\n\x1a\n\x00\x01"}), true},
		{"testdata library in an asm module", with(map[string]string{"f_amd64.s": asm}), with(map[string]string{"f_amd64.s": asm, "testdata/libx.so": "\x7fELF\x00\x00"}), false},
		{"testdata syso", with(nil), with(map[string]string{"testdata/p/x.syso": "\x7fELF\x00\x00"}), false},
		{"testdata object under a fixture name", with(map[string]string{"f_amd64.s": asm}), with(map[string]string{"f_amd64.s": asm, "testdata/fixture.png": "\x7fELF\x02\x01\x01\x00"}), false},
		{"testdata archive under a fixture name", with(map[string]string{"f_amd64.s": asm}), with(map[string]string{"f_amd64.s": asm, "testdata/fixture.png": "!<arch>\n\x00\x01foo"}), false},
		{"testdata fixture a cgo line names", with(map[string]string{"c.go": "package m\n\n// #cgo LDFLAGS: ${SRCDIR}/testdata/fixture.png\nimport \"C\"\n"}),
			with(map[string]string{"c.go": "package m\n\n// #cgo LDFLAGS: ${SRCDIR}/testdata/fixture.png\nimport \"C\"\n", "testdata/fixture.png": "\x89PNG\r\n\x1a\n\x00\x01"}), false},
		{"testdata binary of no known format", with(map[string]string{"f_amd64.s": asm}), with(map[string]string{"f_amd64.s": asm, "testdata/fixture.png": "\x00\x01\x02\x03"}), false},
		{"testdata fixture a non-cgo text file names", with(map[string]string{"f_amd64.s": asm}), with(map[string]string{"f_amd64.s": asm, "link.ld": "INPUT(testdata/FIXTURE.PNG)\n", "testdata/fixture.png": "\x89PNG\r\n\x1a\n\x00\x01"}), false},
		{"testdata fixture named by its stem", with(map[string]string{"f_amd64.s": asm}), with(map[string]string{"f_amd64.s": asm, "x.h": "#define F \"testdata/fixture\"\n", "testdata/fixture.png": "\x89PNG\r\n\x1a\n\x00\x01"}), false},
		{"testdata fixture assembly includes", with(map[string]string{"f_amd64.s": asm}), with(map[string]string{"f_amd64.s": "#include \"testdata/fixture.png\"\n" + asm, "testdata/fixture.png": "\x89PNG\r\n\x1a\n\x00\x01"}), false},
		{"binary outside testdata", with(nil), with(map[string]string{"x.bin": "\x00\x01\x02"}), false},
		{"embedded testdata binary", with(nil), with(map[string]string{"e.go": "package m\n\nimport _ \"embed\"\n\n//go:embed testdata/x.bin\nvar b []byte\n", "testdata/x.bin": "\x00\x01\x02"}), false},
		{"unparseable", with(nil), with(map[string]string{"u.go": "package m\nfunc {{{\n"}), false},
		{"blob that decodes to bytes", with(nil), with(map[string]string{"b.go": "package m\n\nvar s = \"" + b64("\x00\x01\x02\x03\x04\x05\x06\x07", 80) + "\"\n"}), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var old *ecoutil.Tree
			if tt.old != nil {
				old = writeTree(t, tt.old)
			}
			h := CheckTrees(old, writeTree(t, tt.cur))
			before := h.findings("m")
			if !hasRoute(before, model.RouteHuman) {
				t.Fatalf("not a person's to begin with: %+v", before)
			}
			h.lenient = true
			after := h.findings("m")
			if got := !hasRoute(after, model.RouteHuman); got != tt.lenient {
				t.Errorf("lenient: no person-routed finding = %v, want %v: %+v", got, tt.lenient, after)
			}
			if len(after) != len(before) {
				t.Errorf("leniency changed the findings: %d -> %d", len(before), len(after))
			}
			if !slicesEqualFlagged(h.flagged("k"), h.flagged("k")) {
				t.Errorf("unstable flagged list")
			}
		})
	}
}

func hasRoute(fs []model.Finding, r model.Route) bool {
	for _, f := range fs {
		if f.Route == r {
			return true
		}
	}
	return false
}

func slicesEqualFlagged(a, b []model.FlaggedItem) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// b64 is n copies of s, base64-encoded.
func b64(s string, n int) string {
	var raw []byte
	for range n {
		raw = append(raw, s...)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/model"
)

func TestSanitizeName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"gomod/golang.org/x/image@v0.47.0..v0.48.0.diff", "gomod/golang.org/x/image@v0.47.0..v0.48.0.diff"},
		{"../../etc/passwd", "_./_./etc/passwd"},
		{"/abs/path", "abs/path"},
		{"a/./b", "a/_/b"},
		{"..", "_."},
		{"", "_"},
		{"///", "_"},
		{`win\..\x`, "win/_./x"},
		{"npm/@tailwindcss/cli 4.3.4->4.3.5", "npm/@tailwindcss/cli_4.3.4-_4.3.5"},
		{".hidden", "_hidden"},
		{"ü/€", "_/_"},
	}
	for _, tt := range tests {
		got := SanitizeName(tt.in)
		if got != tt.want {
			t.Errorf("SanitizeName(%q) = %q, want %q", tt.in, got, tt.want)
		}
		for _, p := range strings.Split(got, "/") {
			if p == ".." || p == "." || p == "" {
				t.Errorf("SanitizeName(%q) = %q has unsafe element %q", tt.in, got, p)
			}
		}
	}
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"plain", "hello\n\tworld\r\n", "hello\n\tworld\r\n", true},
		{"nul", "a\x00b", "", false},
		{"invalid utf8 sparse", "abcdefghijklmnopqrstuvwxyz\xff", "abcdefghijklmnopqrstuvwxyz�", true},
		{"mostly invalid", "\xff\xfe\xfd\xfc\xfb", "", false},
		{"control", strings.Repeat("x", 20) + "\x1b[31m", strings.Repeat("x", 20) + "<0x1B>[31m", true},
		{"bidi", "if x ‮{", "if x <U+202E>{", true},
		{"empty", "", "", true},
	}
	for _, tt := range tests {
		got, ok := Normalize([]byte(tt.in))
		if ok != tt.ok || string(got) != tt.want {
			t.Errorf("%s: Normalize(%q) = %q, %v; want %q, %v", tt.name, tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestDirCapsAndFindings(t *testing.T) {
	out := filepath.Join(t.TempDir(), "ev")
	d, err := Create(out, WithCaps(100, 250))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	steps := []struct {
		untrusted bool
		name      string
		content   string
	}{
		{false, "summary.md", "small\n"},
		{true, "../../escape.diff", strings.Repeat("a", 50)},
		{true, "big.diff", strings.Repeat("b", 500)},              // cut to the file cap
		{true, "bin.dat", "\x00\x01\x02"},                         // never written
		{true, "bidi.txt", "x⁦y"},                                 // flagged
		{true, "fill.diff", strings.Repeat("c", 90)},              // total cap reached part way
		{true, "late.diff", "never fits"},                         // omitted
		{true, "big.diff", "same name again, must not overwrite"}, // renamed
	}
	for _, s := range steps {
		var err error
		if s.untrusted {
			err = d.AddUntrusted(s.name, "desc", []byte(s.content))
		} else {
			err = d.Add(s.name, "desc", []byte(s.content))
		}
		if err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
	}
	if !d.Truncated() {
		t.Error("Truncated() = false, want true")
	}
	codes := map[string]bool{}
	for _, f := range d.Findings() {
		codes[f.Code] = true
		if f.Route != model.RouteHuman {
			t.Errorf("finding %s route %s, want human", f.Code, f.Route)
		}
	}
	for _, c := range []string{"evidence.binary", "evidence.bidi-control", "evidence.omitted"} {
		if !codes[c] {
			t.Errorf("missing finding %s; have %v", c, codes)
		}
	}

	var total int64
	for _, f := range d.Files() {
		total += f.Bytes
		if f.Bytes > 100 {
			t.Errorf("%s: %d bytes exceeds file cap", f.Path, f.Bytes)
		}
		st, err := os.Lstat(filepath.Join(out, filepath.FromSlash(f.Path)))
		if err != nil {
			t.Fatalf("%s listed but not on disk: %v", f.Path, err)
		}
		if !st.Mode().IsRegular() || st.Size() != f.Bytes {
			t.Errorf("%s: mode %v size %d, want regular %d", f.Path, st.Mode(), st.Size(), f.Bytes)
		}
		if !strings.HasPrefix(f.Path, "gate/") && !strings.HasPrefix(f.Path, "untrusted/") {
			t.Errorf("%s outside gate/ and untrusted/", f.Path)
		}
		if strings.HasPrefix(f.Path, "untrusted/") != f.Untrusted {
			t.Errorf("%s: untrusted=%v", f.Path, f.Untrusted)
		}
	}
	if total > 250 {
		t.Errorf("total %d exceeds cap", total)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(out), "escape.diff")); err == nil {
		t.Error("file escaped the evidence directory")
	}
	big, _ := os.ReadFile(filepath.Join(out, "untrusted", "big.diff"))
	if !strings.Contains(string(big), "truncated here") {
		t.Errorf("big.diff lacks truncation marker: %q", big)
	}
	if _, err := os.Stat(filepath.Join(out, "untrusted", "bin.dat")); err == nil {
		t.Error("binary file was written")
	}

	ev := model.Evidence{Route: model.RouteHuman, Files: d.Files(), Truncated: d.Truncated()}
	if err := d.WriteEvidence(ev); err != nil {
		t.Fatal(err)
	}
	if err := d.WriteEvidence(ev); err == nil {
		t.Error("second WriteEvidence succeeded")
	}
	var back model.Evidence
	b, _ := os.ReadFile(filepath.Join(out, EvidenceJSON))
	if err := json.Unmarshal(b, &back); err != nil || back.Route != model.RouteHuman {
		t.Errorf("evidence.json round trip: %v %+v", err, back)
	}
}

func TestCreateRefusesNonEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("/etc", filepath.Join(dir, "gate")); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(dir); err == nil {
		t.Fatal("Create on a non-empty directory succeeded")
	}
}

// Parts have caps of their own and are not listed; AddLarge is listed
// under the part caps. A cut or omitted part is truncation.
func TestParts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ev")
	d, err := Create(dir, WithCaps(10, 20), WithPartCaps(30, 50))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	p, n, err := d.AddPart("gomod/m/diff/a.go.diff", []byte(strings.Repeat("a", 25)))
	if err != nil || p != "untrusted/gomod/m/diff/a.go.diff" || n != 25 {
		t.Fatalf("AddPart = %q, %d, %v", p, n, err)
	}
	if d.Truncated() || len(d.Files()) != 0 {
		t.Fatalf("a part within its caps: truncated %v, files %v", d.Truncated(), d.Files())
	}
	if n, err := d.AddLarge("gomod/m/flagged.md", "flagged", []byte(strings.Repeat("b", 20))); err != nil || n != 20 {
		t.Fatal(n, err)
	}
	if fs := d.Files(); len(fs) != 1 || fs[0].Bytes != 20 || d.Truncated() {
		t.Fatalf("AddLarge: files %v, truncated %v", fs, d.Truncated())
	}
	// The part total (25 + 20) leaves 5 bytes: the next part is cut.
	if _, _, err := d.AddPart("gomod/m/diff/b.go.diff", []byte(strings.Repeat("c", 25))); err != nil {
		t.Fatal(err)
	}
	if !d.Truncated() {
		t.Error("a part past the scan cap was not truncation")
	}
	// The ordinary caps are untouched by parts.
	if err := d.AddUntrusted("x.diff", "x", []byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	if fs := d.Files(); len(fs) != 2 || fs[1].Bytes != 10 {
		t.Errorf("AddUntrusted after parts: %v", fs)
	}
	// A binary part is not written and is a finding.
	if p, _, _ := d.AddPart("gomod/m/diff/bin.diff", []byte("\x00\x01")); p != "" || len(d.Findings()) == 0 {
		t.Errorf("binary part: path %q, findings %v", p, d.Findings())
	}
}

// The length AddPart reports is what was written: Normalize turns each
// escape character into "<0x1B>", six bytes the reviewer reads.
func TestPartWrittenLength(t *testing.T) {
	d, err := Create(filepath.Join(t.TempDir(), "ev"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	in := []byte(strings.Repeat("a\x1b\n", 100))
	_, n, err := d.AddPart("x.diff", in)
	if err != nil || n != 100*len("a<0x1B>\n") {
		t.Errorf("written %d (input %d), %v", n, len(in), err)
	}
}

package ecoutil

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tarOf(t *testing.T, files map[string]string, order ...string) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, name := range order {
		body := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func gz(t *testing.T, b []byte) string {
	t.Helper()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	zw.Write(b)
	zw.Close()
	p := filepath.Join(t.TempDir(), "a.tgz")
	if err := os.WriteFile(p, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Regression for the review's TestPOCTarEOF: a second tar appended after
// the first one's end-of-archive marker. archive/tar stops at the marker,
// so the gate saw only the benign files; an extractor that keeps reading
// past it installs package/evil.js. The tail must be reported.
func TestExtractTarTrailingData(t *testing.T) {
	first := tarOf(t, map[string]string{"package/package.json": `{"name":"x","version":"1.0.0"}` + "\n", "package/index.js": "benign\n"}, "package/package.json", "package/index.js")
	second := tarOf(t, map[string]string{"package/evil.js": "evil()\n"}, "package/evil.js")
	tests := []struct {
		name    string
		archive []byte
		reject  string
	}{
		{"plain archive", first, ""},
		{"extra zero padding", append(append([]byte{}, first...), make([]byte, 8192)...), ""},
		{"concatenated archive", append(append([]byte{}, first...), second...), "end-of-archive marker"},
		{"appended bytes", append(append([]byte{}, first...), []byte("#!/bin/sh\n")...), "end-of-archive marker"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr, err := ExtractTarGz(gz(t, tt.archive), filepath.Join(t.TempDir(), "x"), true)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(tr.Files, ",") != "index.js,package.json" {
				t.Errorf("files %v", tr.Files)
			}
			got := strings.Join(tr.Rejected, "; ")
			if (tt.reject == "") != (got == "") || !strings.Contains(got, tt.reject) {
				t.Errorf("rejected %q, want %q", got, tt.reject)
			}
		})
	}

	// Two gzip members (gzip -c a b): Go reads them as one stream, and the
	// second member's tar is still past the marker.
	var two bytes.Buffer
	for _, b := range [][]byte{first, second} {
		zw := gzip.NewWriter(&two)
		zw.Write(b)
		zw.Close()
	}
	p := filepath.Join(t.TempDir(), "two.tgz")
	os.WriteFile(p, two.Bytes(), 0o600)
	tr, err := ExtractTarGz(p, filepath.Join(t.TempDir(), "y"), true)
	if err != nil || len(tr.Rejected) != 1 {
		t.Errorf("two gzip members: %v %v", tr, err)
	}
}

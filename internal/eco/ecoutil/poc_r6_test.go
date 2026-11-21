package ecoutil

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"
)

// secret is the member content a consumer extracts; the gate must render it
// (or say the rendering is incomplete).
const secret = "\x7fELF\x02\x01\x01\x00 SECRET-PAYLOAD-BYTES-NOT-RENDERED"

func tarWith(t *testing.T, flag byte, name string, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	if err := tw.WriteHeader(&tar.Header{Name: "README", Typeflag: tar.TypeReg, Size: 3, Mode: 0o644, Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	tw.Write([]byte("hi\n"))
	if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: flag, Size: int64(len(data)), Mode: 0o755, Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	return b.Bytes()
}

// What a Go consumer extracting by FileInfo().Mode().IsRegular() (or GNU
// tar) gets out of the archive.
func extractRegular(t *testing.T, b []byte) map[string]string {
	out := map[string]string{}
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.FileInfo().Mode().IsRegular() {
			d, _ := io.ReadAll(tr)
			out[h.Name] = string(d)
		}
	}
}

func TestR6TarContiguousMemberNotRendered(t *testing.T) {
	for _, flag := range []byte{tar.TypeCont, 'Z'} {
		raw := tarWith(t, flag, "bin/helper", []byte(secret))
		if got := extractRegular(t, raw)["bin/helper"]; got != secret {
			t.Fatalf("consumer did not get the payload: %q", got)
		}
		for name, b := range map[string][]byte{"tar": raw, "tar.gz": gzr6(raw)} {
			d := DescribeBinary(b, nil, false, nil)
			if reached(d) && !strings.Contains(d.Text, "content of bin/helper") {
				t.Errorf("type %q %s: Complete=true, member content never rendered:\n%s", flag, name, d.Text)
			}
		}
	}
}

func gzr6(b []byte) []byte {
	var o bytes.Buffer
	z := gzip.NewWriter(&o)
	z.Write(b)
	z.Close()
	return o.Bytes()
}

// A tar whose first member is named "PK\x03\x04..." and that ends in a small
// zip: magicType says zip, the zip has one text member (complete), a tar
// reader extracts the ELF.
func TestR6TarZipPolyglot(t *testing.T) {
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	tw.WriteHeader(&tar.Header{Name: "PK\x03\x04helper", Typeflag: tar.TypeReg, Size: int64(len(secret)), Mode: 0o755, Format: tar.FormatUSTAR})
	tw.Write([]byte(secret))
	tw.Close()
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	w, _ := zw.Create("README.txt")
	w.Write([]byte("nothing to see\n"))
	zw.Close()
	poly := append(tb.Bytes(), zb.Bytes()...)
	if got := extractRegular(t, poly)["PK\x03\x04helper"]; got != secret {
		t.Fatalf("tar consumer did not get the payload: %q", got)
	}
	d := DescribeBinary(poly, nil, false, nil)
	t.Logf("type line: %s", strings.SplitN(d.Text, "\n", 4)[2])
	if reached(d) {
		t.Errorf("tar/zip polyglot: Complete=true from the zip view, tar member never rendered:\n%s", d.Text)
	}
}

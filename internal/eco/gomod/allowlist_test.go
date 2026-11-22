package gomod

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
)

// embeddedChange is a module whose non-test code embeds name, unchanged,
// while name's bytes change from old to cur.
func embeddedChange(t *testing.T, name, old, cur string) *report {
	t.Helper()
	src := "package p\n\nimport _ \"embed\"\n\n//go:embed " + name + "\nvar b []byte\n"
	return CheckTrees(writeTree(t, map[string]string{"p.go": src, name: old}), writeTree(t, map[string]string{"p.go": src, name: cur}))
}

func zipOf(t *testing.T, base int64, name, data string) []byte {
	t.Helper()
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	zw.SetOffset(base)
	w, _ := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
	w.Write([]byte(data))
	zw.Close()
	return zb.Bytes()
}

// TestR7HiddenDataGoesToAPerson (round 8; the review's ecoutil
// TestR7TarPaddingHidesZip, TestR7GzipExtraHidesZip, TestR7TarPAXRecordHidden
// end to end): data a parser does not model never keeps a binary on
// review, and the rendering says what it saw.
func TestR7HiddenDataGoesToAPerson(t *testing.T) {
	// A zip in a tar member's block padding.
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	tw.WriteHeader(&tar.Header{Name: "index.js", Typeflag: tar.TypeReg, Size: 3, Mode: 0o644, Format: tar.FormatUSTAR})
	tw.Write([]byte("ok\n"))
	tw.Close()
	padded := tb.Bytes()
	copy(padded[512+3:], zipOf(t, 512+3, "index.js", hiddenJS7))

	// A zip in a gzip header's FEXTRA field.
	var gb bytes.Buffer
	gw := gzip.NewWriter(&gb)
	gw.Extra = zipOf(t, 12, "index.js", hiddenJS7)
	gw.Write([]byte("console.log('ok')\n"))
	gw.Close()

	// A large PAX record.
	var pb bytes.Buffer
	pw := tar.NewWriter(&pb)
	pw.WriteHeader(&tar.Header{Name: "README", Typeflag: tar.TypeReg, Size: 3, Mode: 0o644,
		PAXRecords: map[string]string{"VENDOR.payload": strings.Repeat("\x7fELF payload ", 4096)}, Format: tar.FormatPAX})
	pw.Write([]byte("hi\n"))
	pw.Close()

	for name, tc := range map[string]struct {
		file, data, note string
	}{
		"zip in tar padding": {"assets.tar", string(padded), ""},
		"zip in gzip FEXTRA": {"assets.gz", gb.String(), "gzip header extra field"},
		"PAX record":         {"assets.tar", pb.String(), "PAX record VENDOR.payload"},
	} {
		t.Run(name, func(t *testing.T) {
			h := embeddedChange(t, tc.file, "\x00\x01 old", tc.data)
			wantPerson(t, h, tc.file)
			ctx := strings.Join(h.ctx[codeBinary][tc.file], "")
			if !strings.Contains(ctx, ecoutil.ForThePerson) || !strings.Contains(ctx, tc.note) {
				t.Errorf("rendering lacks the label or %q:\n%.2000s", tc.note, ctx)
			}
		})
	}
}

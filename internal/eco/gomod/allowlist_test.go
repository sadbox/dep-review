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

// TestNonASCIIEmbedPattern (round 8, H1): a non-test //go:embed pattern
// with a non-ASCII character makes the reference search incomplete, so no
// binary of the module is found inert; a test-only one does not.
func TestNonASCIIEmbedPattern(t *testing.T) {
	png := "\x89PNG\r\n\x1a\n\x00\x00"
	for _, tc := range []struct {
		name, file string
		person     bool
	}{
		{"non-test", "p_embed.go", true},
		{"test only", "p_embed_test.go", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "package p\n\nimport _ \"embed\"\n\n//go:embed café.txt\nvar b []byte\n"
			h := CheckTrees(nil, writeTree(t, map[string]string{"p.go": "package p\n", tc.file: src, "café.txt": "x\n", "fixtures/logo.png": png}))
			got := false
			for _, i := range h.items(codeIncomplete) {
				got = got || i == "gomod.binary-file fixtures/logo.png"
			}
			if got != tc.person {
				t.Errorf("logo.png to a person = %v, want %v\n%s", got, tc.person, strings.Join(h.ctx[codeBinary]["fixtures/logo.png"], ""))
			}
		})
	}
}

// TestNonASCIITouchingToken (round 8, H1): a token touching a non-ASCII
// byte in a non-test file mentions every wanted name it is part of
// ("ſecret.bin" splits into "ecret.bin").
func TestNonASCIITouchingToken(t *testing.T) {
	h := CheckTrees(nil, writeTree(t, map[string]string{
		"p.go":       "package p\n\nconst name = \"ſecret.bin\"\n",
		"secret.bin": "\x00\x01 payload",
	}))
	wantPerson(t, h, "secret.bin")
	if ctx := strings.Join(h.ctx[codeBinary]["secret.bin"], ""); !strings.Contains(ctx, "a non-test file mentions its name") {
		t.Errorf("no mention recorded:\n%s", ctx)
	}
}

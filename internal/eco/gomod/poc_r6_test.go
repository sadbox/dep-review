package gomod

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
)

func r6TarGz(t *testing.T, flag byte, payload string) string {
	t.Helper()
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	tw := tar.NewWriter(z)
	tw.WriteHeader(&tar.Header{Name: "README", Typeflag: tar.TypeReg, Size: 3, Mode: 0o644, Format: tar.FormatUSTAR})
	tw.Write([]byte("hi\n"))
	tw.WriteHeader(&tar.Header{Name: "bin/helper", Typeflag: flag, Size: int64(len(payload)), Mode: 0o755, Format: tar.FormatUSTAR})
	tw.Write([]byte(payload))
	tw.Close()
	z.Close()
	return b.String()
}

// G1: the module already embeds tools.tar.gz (directive unchanged). The new
// version's archive holds its helper as a tar type '7' (contiguous) member:
// a Go consumer that extracts entries with FileInfo().Mode().IsRegular()
// (or GNU tar) writes it out; the gate lists the entry but never renders
// it, and still calls the rendering complete.
func TestR6EmbeddedTarContiguousMember(t *testing.T) {
	src := "package p\n\nimport _ \"embed\"\n\n//go:embed tools.tar.gz\nvar tools []byte\n"
	old := writeTree(t, map[string]string{"p.go": src, "tools.tar.gz": r6TarGz(t, tar.TypeReg, "\x7fELF old helper")})
	cur := writeTree(t, map[string]string{"p.go": src, "tools.tar.gz": r6TarGz(t, tar.TypeCont, "\x7fELF\x02\x01\x01 NEW EVIL HELPER")})
	h := CheckTrees(old, cur)
	t.Logf("flagged: %v", h.flagged("m"))
	wantPerson(t, h, "tools.tar.gz")
}

// G2: on a case-insensitive file system (macOS, Windows) //go:embed
// PAYLOAD.BIN embeds payload.bin (go run confirmed on darwin/arm64, go1.27.4).
// The gate matches patterns and mentions case-sensitively and says
// "NO WAY TO THE BUILD FOUND". The embedding file is darwin-only, so a
// Linux CI builds green; only payload.bin changes.
func TestR6EmbedCaseFold(t *testing.T) {
	src := "//go:build darwin\n\npackage p\n\nimport _ \"embed\"\n\n//go:embed PAYLOAD.BIN\nvar payload []byte\n"
	old := writeTree(t, map[string]string{"p_embed.go": src, "payload.bin": "\x00\x01old helper"})
	cur := writeTree(t, map[string]string{"p_embed.go": src, "payload.bin": "\x00\x02" + strings.Repeat("NEW EVIL HELPER ", 4)})
	h := CheckTrees(old, cur)
	t.Logf("flagged: %v\ncontext:\n%s", h.flagged("m"), strings.Join(h.ctx[codeBinary]["payload.bin"], ""))
	wantPerson(t, h, "payload.bin")
}

// G3: base64 of text that is itself an encoded binary in a form decodeEncoded
// does not know (Go \x escapes). The same text at top level goes to a
// person; one level down it is "the decoded text, in full", complete.
func TestR6NestedUndecodableBlob(t *testing.T) {
	var esc strings.Builder
	for _, c := range []byte("\x7fELF\x02\x01\x01\x00" + strings.Repeat("\x90\x0f\x05", 200)) {
		fmt.Fprintf(&esc, "\\x%02x", c)
	}
	lit := base64.StdEncoding.EncodeToString([]byte(esc.String()))
	cur := writeTree(t, map[string]string{"p.go": "package p\n\nvar payload = \"" + lit + "\"\n"})
	h := CheckTrees(nil, cur)
	t.Logf("codes: %v incomplete: %v", h.codes(), h.items(codeIncomplete))
	if len(h.hits[codeBlob]) == 0 {
		t.Fatal("blob not flagged")
	}
	wantPerson(t, h, "p.go")

	// Control: the escaped text as a top-level raw literal goes to a person.
	cur2 := writeTree(t, map[string]string{"p.go": "package p\n\nvar payload = `" + esc.String() + "`\n"})
	h2 := CheckTrees(nil, cur2)
	t.Logf("top-level control: incomplete: %v", h2.items(codeIncomplete))
}

// r6SysoTar is an amd64 COFF object (one .rsrc section holding payload)
// whose first 512 bytes are also a valid ustar header for a zero-size
// entry, followed by the tar end marker; the section data and the symbol
// table lie after it. cmd/link reads it as COFF (first bytes 64 86);
// magicType tests "ustar" at 257 before the COFF machine.
func r6SysoTar(payload []byte) []byte {
	b := make([]byte, 1536)
	le := func(off int, v uint32, n int) {
		for i := 0; i < n; i++ {
			b[off+i] = byte(v >> (8 * i))
		}
	}
	p := uint32(1536)
	le(0, 0x8664, 2)
	le(2, 1, 2)                        // one section
	le(8, p+uint32(len(payload)), 4)   // symbol table pointer
	le(12, 0, 4)                       // no symbols
	copy(b[20:], ".rsrc")              // section name
	le(20+16, uint32(len(payload)), 4) // SizeOfRawData
	le(20+20, p, 4)                    // PointerToRawData
	le(20+36, 0x40000040, 4)           // initialized data, readable
	copy(b[100:], "0000644\x00")
	copy(b[108:], "0000000\x00")
	copy(b[116:], "0000000\x00")
	copy(b[124:], "00000000000\x00")
	copy(b[136:], "00000000000\x00")
	b[156] = '0'
	copy(b[257:], "ustar\x0000")
	copy(b[148:], "        ")
	sum := 0
	for _, c := range b[:512] {
		sum += int(c)
	}
	copy(b[148:], fmt.Sprintf("%06o\x00 ", sum))
	b = append(b, payload...)
	b = append(b, 4, 0, 0, 0) // empty string table
	return b
}

// G4: a .syso is compiled/linked by extension, so only a complete
// rendering keeps it on review; the tar view of the COFF object is complete.
func TestR6SysoTarPolyglot(t *testing.T) {
	syso := r6SysoTar([]byte("EVIL-RESOURCE-PAYLOAD"))
	if dir := os.Getenv("R6_SYSO_OUT"); dir != "" {
		os.WriteFile(dir+"/rsrc_windows_amd64.syso", syso, 0o644)
	}
	cur := writeTree(t, map[string]string{"p.go": "package p\n", "rsrc_windows_amd64.syso": string(syso)})
	h := CheckTrees(nil, cur)
	t.Logf("context:\n%s", strings.Join(h.ctx[codeBinary]["rsrc_windows_amd64.syso"], ""))
	wantPerson(t, h, "rsrc_windows_amd64.syso")
}

// G2b: the testdata variant: a new non-test //go:embed TESTDATA/X.BIN
// (embeds testdata/x.bin on macOS). main hard-stopped the new directive.
func TestR6EmbedCaseFoldTestdata(t *testing.T) {
	src := "//go:build darwin\n\npackage p\n\nimport _ \"embed\"\n\n//go:embed TESTDATA/X.BIN\nvar payload []byte\n"
	old := writeTree(t, map[string]string{"p.go": "package p\n"})
	cur := writeTree(t, map[string]string{"p.go": "package p\n", "p_embed.go": src, "testdata/x.bin": "\x00\x02 NEW EVIL HELPER"})
	h := CheckTrees(old, cur)
	t.Logf("flagged: %v incomplete: %v", h.flagged("m"), h.items(codeIncomplete))
	if len(h.hits[codeBinary]) == 0 {
		t.Errorf("testdata/x.bin is embedded on darwin but not flagged at all")
	}
}

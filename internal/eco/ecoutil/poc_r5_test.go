package ecoutil

import (
	"bytes"
	"compress/gzip"
	"testing"
)

// R4-G: a broken ELF is incomplete; the same bytes gzipped are Complete,
// though the inner ELF's structure was never read.
func TestR4GzipWrapsUnreadELF(t *testing.T) {
	inner := []byte("\x7fELF\x02\x01\x01 truncated header, never parsed")
	if d := DescribeBinary(inner, nil, false, &Budget{Left: 1 << 30}); reached(d) {
		t.Fatalf("bare broken ELF complete")
	}
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(inner)
	w.Close()
	d := DescribeBinary(buf.Bytes(), nil, false, &Budget{Left: 1 << 30})
	if reached(d) {
		t.Errorf("gzip of an unparsed ELF counts as Complete:\n%s", d.Text)
	}
}

// R4-S: an ELF executable with no section headers still loads its
// DT_NEEDED libraries through PT_DYNAMIC; debug/elf reads DT_NEEDED only
// from SHT_DYNAMIC, so the gate lists 0 libraries and calls it Complete.
func TestR4SectionlessELFImports(t *testing.T) {
	// layout: ehdr(64) | phdr PT_LOAD(56) | phdr PT_DYNAMIC(56) | dynstr | dyn
	dynstr := []byte("\x00libevil.so\x00")
	strOff := 64 + 56*2
	dynOff := strOff + len(dynstr)
	le := func(b []byte, v uint64, n int) {
		for i := 0; i < n; i++ {
			b[i] = byte(v >> (8 * i))
		}
	}
	dyn := make([]byte, 16*3)
	le(dyn[0:], 1, 8)  // DT_NEEDED
	le(dyn[8:], 1, 8)  // offset 1 in strtab
	le(dyn[16:], 5, 8) // DT_STRTAB
	le(dyn[24:], uint64(0x400000+strOff), 8)
	total := dynOff + len(dyn)
	b := make([]byte, total)
	copy(b, "\x7fELF\x02\x01\x01")
	le(b[16:], 2, 2)  // ET_EXEC
	le(b[18:], 62, 2) // EM_X86_64
	le(b[20:], 1, 4)
	le(b[24:], 0x400000, 8)
	le(b[32:], 64, 8) // phoff
	le(b[52:], 64, 2)
	le(b[54:], 56, 2)
	le(b[56:], 2, 2) // phnum
	ph := b[64:]
	le(ph[0:], 1, 4) // PT_LOAD
	le(ph[4:], 5, 4)
	le(ph[16:], 0x400000, 8)
	le(ph[24:], 0x400000, 8)
	le(ph[32:], uint64(total), 8)
	le(ph[40:], uint64(total), 8)
	ph = b[64+56:]
	le(ph[0:], 2, 4) // PT_DYNAMIC
	le(ph[8:], uint64(dynOff), 8)
	le(ph[16:], uint64(0x400000+dynOff), 8)
	le(ph[32:], uint64(len(dyn)), 8)
	le(ph[40:], uint64(len(dyn)), 8)
	copy(b[strOff:], dynstr)
	copy(b[dynOff:], dyn)
	d := DescribeBinary(b, nil, false, &Budget{Left: 1 << 30})
	if reached(d) {
		t.Errorf("sectionless ELF with DT_NEEDED libevil.so via PT_DYNAMIC is Complete:\n%s", d.Text)
	}
}

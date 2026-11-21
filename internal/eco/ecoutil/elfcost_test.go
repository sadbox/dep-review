package ecoutil

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"strings"
	"testing"
)

type elfSec struct {
	name    string
	typ     elf.SectionType
	link    uint32
	entsize uint64
	data    []byte
}

// buildELF lays out a 64-bit little-endian ELF with the given sections
// (index 0 is the null section; a .shstrtab is appended).
func buildELF(secs []elfSec) []byte {
	shstr := []byte{0}
	nameOff := make([]uint32, len(secs))
	for i, s := range secs {
		nameOff[i] = uint32(len(shstr))
		shstr = append(append(shstr, s.name...), 0)
	}
	shstrName := uint32(len(shstr))
	shstr = append(append(shstr, ".shstrtab"...), 0)
	var body bytes.Buffer
	offs := make([]uint64, len(secs))
	for i, s := range secs {
		offs[i] = uint64(64 + body.Len())
		body.Write(s.data)
	}
	shOff := uint64(64 + body.Len())
	body.Write(shstr)
	h := elf.Header64{Type: uint16(elf.ET_DYN), Machine: uint16(elf.EM_X86_64), Version: 1,
		Shoff: uint64(64 + body.Len()), Ehsize: 64, Shentsize: 64, Shnum: uint16(len(secs) + 2), Shstrndx: uint16(len(secs) + 1)}
	copy(h.Ident[:], "\x7fELF")
	h.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	h.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	h.Ident[elf.EI_VERSION] = 1
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, h)
	b.Write(body.Bytes())
	binary.Write(&b, binary.LittleEndian, elf.Section64{})
	for i, s := range secs {
		binary.Write(&b, binary.LittleEndian, elf.Section64{Name: nameOff[i], Type: uint32(s.typ), Off: offs[i],
			Size: uint64(len(s.data)), Link: s.link, Entsize: s.entsize})
	}
	binary.Write(&b, binary.LittleEndian, elf.Section64{Name: shstrName, Type: uint32(elf.SHT_STRTAB), Off: shOff, Size: uint64(len(shstr))})
	return b.Bytes()
}

// dynsyms is n 24-byte symbols (after the null one) all named at off.
func dynsyms(n int, off uint32) []byte {
	b := make([]byte, 24*(n+1))
	for i := 1; i <= n; i++ {
		binary.LittleEndian.PutUint32(b[24*i:], off)
	}
	return b
}

// longStrtab: a 16 KiB name at offset 1.
func longStrtab() []byte { return append(append([]byte{0}, bytes.Repeat([]byte("N"), 16<<10)...), 0) }

// TestELFNameCostFixedRecords (round 5): .dynsym is read with debug/elf's
// fixed record size whatever Entsize says, so an Entsize of 0 cannot
// hide 2000 names of 16 KiB.
func TestELFNameCostFixedRecords(t *testing.T) {
	// Sections: 1 .dynsym (link 2), 2 .dynstr.
	data := buildELF([]elfSec{
		{".dynsym", elf.SHT_DYNSYM, 2, 0, dynsyms(2000, 1)},
		{".dynstr", elf.SHT_STRTAB, 0, 0, longStrtab()},
	})
	var d Description
	if n := allocated(func() { d = DescribeBinary(data, nil, false, nil) }); n > 8<<20 {
		t.Errorf("rendering allocated %d MiB building names (%d KiB file)", n>>20, len(data)>>10)
	}
	if reached(d) || !strings.Contains(d.Text, "names would cost") {
		t.Errorf("name amplification through Entsize 0 not caught:\n%.1500s", d.Text)
	}
}

// TestELFNameCostVersions (round 5): the .gnu.version_r names
// ImportedSymbols builds are counted too.
func TestELFNameCostVersions(t *testing.T) {
	const n = 2000
	vn := make([]byte, 16+16*n)
	binary.LittleEndian.PutUint16(vn[0:], 1)         // vn_version
	binary.LittleEndian.PutUint16(vn[2:], uint16(n)) // vn_cnt
	binary.LittleEndian.PutUint32(vn[8:], 16)        // vn_aux
	for i := range n {
		at := 16 + 16*i
		binary.LittleEndian.PutUint32(vn[at+8:], 1) // vna_name: the long string
		if i < n-1 {
			binary.LittleEndian.PutUint32(vn[at+12:], 16) // vna_next
		}
	}
	// 1 .dynsym, 2 .dynstr, 3 .gnu.version, 4 .gnu.version_r.
	data := buildELF([]elfSec{
		{".dynsym", elf.SHT_DYNSYM, 2, 24, dynsyms(1, 0)},
		{".dynstr", elf.SHT_STRTAB, 0, 0, longStrtab()},
		{".gnu.version", elf.SHT_GNU_VERSYM, 1, 2, make([]byte, 4)},
		{".gnu.version_r", elf.SHT_GNU_VERNEED, 2, 0, vn},
	})
	var d Description
	if n := allocated(func() { d = DescribeBinary(data, nil, false, nil) }); n > 8<<20 {
		t.Errorf("rendering allocated %d MiB building version names (%d KiB file)", n>>20, len(data)>>10)
	}
	if reached(d) || !strings.Contains(d.Text, "names would cost") {
		t.Errorf("version-name amplification not caught:\n%.1500s", d.Text)
	}
	// The same layout with few names stays cheap and complete.
	small := buildELF([]elfSec{
		{".dynsym", elf.SHT_DYNSYM, 2, 24, dynsyms(3, 1)},
		{".dynstr", elf.SHT_STRTAB, 0, 0, []byte("\x00puts\x00")},
	})
	if d := DescribeBinary(small, nil, false, nil); !reached(d) {
		t.Errorf("a small dynamic ELF is incomplete:\n%s", d.Text)
	}
}

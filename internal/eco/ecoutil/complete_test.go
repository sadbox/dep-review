package ecoutil

import (
	"bytes"
	"compress/gzip"
	"debug/macho"
	"encoding/binary"
	"strings"
	"testing"
)

// TestCompleteOnlyAtTheEnd (round 4): every early stop the automated scan
// found yields an incomplete rendering.
func TestCompleteOnlyAtTheEnd(t *testing.T) {
	var g bytes.Buffer
	zw := gzip.NewWriter(&g)
	zw.Write(bytes.Repeat([]byte("payload "), 4096))
	zw.Close()
	whole := g.Bytes()
	if d := DescribeBinary(whole, nil, false, nil); !d.Complete {
		t.Errorf("a whole gzip stream is incomplete:\n%s", d.Text)
	}
	if d := DescribeBinary(whole[:len(whole)/2], nil, false, nil); d.Complete {
		t.Errorf("a gzip stream cut before its end is complete:\n%s", d.Text)
	}

	thin := machO(macho.Cpu386)
	if d := DescribeBinary(thin, nil, false, nil); !d.Complete {
		t.Errorf("a minimal Mach-O is incomplete:\n%s", d.Text)
	}
	if d := DescribeBinary(fatMachO(maxArches), nil, false, nil); !d.Complete {
		t.Errorf("a universal binary of %d architectures is incomplete:\n%s", maxArches, d.Text)
	}
	if d := DescribeBinary(fatMachO(maxArches+1), nil, false, nil); d.Complete || !strings.Contains(d.Text, "1 more architectures") {
		t.Errorf("a universal binary past the cap is complete:\n%s", d.Text)
	}
	if d := DescribeBinary([]byte("\x89PNG\r\n\x1a\nimage"), nil, false, nil); d.Complete {
		t.Errorf("a type with no parser is complete")
	}
}

// machO is a minimal 32-bit Mach-O object for cpu with no load commands.
func machO(cpu macho.Cpu) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, macho.FileHeader{Magic: macho.Magic32, Cpu: cpu, Type: macho.TypeObj})
	return b.Bytes()
}

// fatMachO is a universal binary of n distinct thin objects.
func fatMachO(n int) []byte {
	cpus := []macho.Cpu{macho.Cpu386, macho.CpuAmd64, macho.CpuArm, macho.CpuArm64, macho.CpuPpc, macho.CpuPpc64, 13, 14, 15, 16, 17}
	var body bytes.Buffer
	hdr := 8 + 20*n
	type arch struct{ cpu, sub, off, size, align uint32 }
	var arches []arch
	for i := range n {
		th := machO(cpus[i])
		arches = append(arches, arch{uint32(cpus[i]), 0, uint32(hdr + body.Len()), uint32(len(th)), 0})
		body.Write(th)
	}
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint32(macho.MagicFat))
	binary.Write(&b, binary.BigEndian, uint32(n))
	for _, a := range arches {
		binary.Write(&b, binary.BigEndian, a)
	}
	b.Write(body.Bytes())
	return b.Bytes()
}

// TestNameBytes (round 4, L1): the name cost is exactly what building the
// names takes, however many share one string.
func TestNameBytes(t *testing.T) {
	strtab := []byte("\x00abc\x00" + strings.Repeat("A", 1000) + "\x00x")
	tests := []struct {
		offs []uint64
		want uint64
	}{
		{nil, 0},
		{[]uint64{1}, 3},
		{[]uint64{1, 2, 3, 4}, 3 + 2 + 1 + 0},
		{[]uint64{5, 5, 5}, 3000},
		{[]uint64{1006}, 1}, // no NUL until the end
		{[]uint64{9999}, 0}, // outside the table
		{[]uint64{5, 1, 5}, 2003},
	}
	for _, tt := range tests {
		if got := nameBytes(strtab, append([]uint64(nil), tt.offs...)); got != tt.want {
			t.Errorf("nameBytes(%v) = %d, want %d", tt.offs, got, tt.want)
		}
	}
}

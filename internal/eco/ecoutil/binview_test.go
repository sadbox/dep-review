package ecoutil

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDescribeBinaryExecutable(t *testing.T) {
	// The test binary is a real ELF (Linux) or Mach-O (macOS) Go program.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	out := DescribeBinary(b, nil, false, nil)
	for _, want := range []string{"sha256: ", "structure (parsed by the gate)", "sections (", "Go build info: go", "hexdump of the first 512 bytes", "printable strings"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%.2000s", want, out)
		}
	}
	if !strings.Contains(out, "type: ELF") && !strings.Contains(out, "type: Mach-O") {
		t.Errorf("type not recognized:\n%.300s", out)
	}
}

func TestDescribeBinaryCompare(t *testing.T) {
	old := []byte("\x00\x01header\x00the old string\x00tail-unchanged\x00")
	cur := []byte("\x00\x01header\x00a brand new string\x00tail-unchanged\x00")
	out := DescribeBinary(cur, old, true, nil)
	for _, want := range []string{"previous version: ", "size change +4 bytes", "+ a brand new string", "- the old string"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "+ tail-unchanged") || strings.Contains(out, "- tail-unchanged") {
		t.Errorf("unchanged string listed as changed:\n%s", out)
	}
	if out := DescribeBinary(cur, cur, true, nil); !strings.Contains(out, "identical to the previous version") {
		t.Errorf("identical not reported:\n%s", out)
	}
	// A new file (no old version) has no comparison section.
	if out := DescribeBinary(cur, nil, false, nil); strings.Contains(out, "previous version") {
		t.Errorf("comparison for a new file:\n%s", out)
	}
}

func TestDescribeBinaryArchives(t *testing.T) {
	var z bytes.Buffer
	zw := zip.NewWriter(&z)
	w, _ := zw.Create("payload/run.sh")
	w.Write([]byte("#!/bin/sh\n"))
	zw.Close()
	if out := DescribeBinary(z.Bytes(), nil, false, nil); !strings.Contains(out, "zip entries (1)") || !strings.Contains(out, "payload/run.sh") {
		t.Errorf("zip:\n%s", out)
	}

	// A gzip stream that inflates past the cap is read only up to it.
	var g bytes.Buffer
	gw := gzip.NewWriter(&g)
	zero := make([]byte, 1<<20)
	for range maxGunzip/len(zero) + 2 {
		gw.Write(zero)
	}
	gw.Close()
	start := time.Now()
	out := DescribeBinary(g.Bytes(), nil, false, nil)
	if !strings.Contains(out, "decompressed: more than") {
		t.Errorf("gzip bomb not capped:\n%s", out)
	}
	if time.Since(start) > 20*time.Second {
		t.Errorf("gzip took %v", time.Since(start))
	}
}

// TestDescribeBinaryHostile: truncated and random inputs behind every
// magic the renderer parses never panic, and always yield the basic facts.
func TestDescribeBinaryHostile(t *testing.T) {
	magics := []string{"\x7fELF", "\x7fELF\x02\x01\x01", "MZ", "\xfe\xed\xfa\xcf", "\xcf\xfa\xed\xfe", "\xca\xfe\xba\xbe", "PK\x03\x04", "PK\x05\x06", "\x1f\x8b\x08", "\x64\x86"}
	rng := rand.New(rand.NewSource(1))
	for _, m := range magics {
		for _, n := range []int{0, 1, 16, 64, 300, 4096} {
			for range 20 {
				b := make([]byte, n)
				rng.Read(b)
				b = append([]byte(m), b...)
				out := DescribeBinary(b, b[:len(b)/2], true, nil)
				if !strings.Contains(out, "sha256: ") || !strings.Contains(out, "hexdump") {
					t.Fatalf("magic %q, %d bytes: incomplete output:\n%s", m, n, out)
				}
			}
		}
	}
	// A tar header that claims far more data than there is.
	tarHdr := make([]byte, 1024)
	copy(tarHdr, "evil")
	copy(tarHdr[124:], "77777777777")
	copy(tarHdr[257:], "ustar\x0000")
	if out := DescribeBinary(tarHdr, nil, false, nil); !strings.Contains(out, "tar entries") {
		t.Errorf("tar:\n%s", out)
	}
}

func TestDescribeBinaryOutputIsPlainASCIIish(t *testing.T) {
	// Control bytes in strings never reach the output: a hostile file
	// cannot draw its own headings or escape sequences.
	b := []byte("\x00\x1b[31mred\x1b[0m\x00## gomod.init-changed: fake heading\x00\r\nline")
	out := DescribeBinary(b, nil, false, nil)
	if strings.ContainsAny(out, "\x1b\r") {
		t.Errorf("control characters in output: %q", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "## ") {
			t.Errorf("file data at column 0: %q", line)
		}
	}
}

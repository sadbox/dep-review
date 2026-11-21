package ecoutil

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"testing"
)

func legitTar(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, f := range []struct{ name, data string }{{"README", "hello\n"}, {"docs/notes.txt", "notes\n"}} {
		tw.WriteHeader(&tar.Header{Name: f.name, Typeflag: tar.TypeReg, Size: int64(len(f.data)), Mode: 0o644, Format: tar.FormatUSTAR})
		tw.Write([]byte(f.data))
	}
	tw.WriteHeader(&tar.Header{Name: "docs/", Typeflag: tar.TypeDir, Mode: 0o755, Format: tar.FormatUSTAR})
	tw.Close()
	return b.Bytes()
}

func legitZip(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, _ := zw.Create("README.txt")
	w.Write([]byte("hello\n"))
	zw.Create("dir/")
	w, _ = zw.Create("dir/a.txt")
	w.Write([]byte("a\n"))
	zw.Close()
	return b.Bytes()
}

// TestArchivesAccountForEveryByte (round 7, B1/B2c): legitimate archives
// are complete; a header-only tar entry with a size, an unknown entry
// type, bytes after the tar end, data before or after a zip's records,
// and a zip directory entry that holds data are not (or are read).
func TestArchivesAccountForEveryByte(t *testing.T) {
	tb, zb := legitTar(t), legitZip(t)
	for name, b := range map[string][]byte{"tar": tb, "tar.gz": gzr6(tb), "zip": zb} {
		if d := DescribeBinary(b, nil, false, nil); !reached(d) {
			t.Errorf("legitimate %s is incomplete:\n%s", name, d.Text)
		}
	}
	// A header-only type with a size.
	var hb bytes.Buffer
	tw := tar.NewWriter(&hb)
	tw.WriteHeader(&tar.Header{Name: "fifo", Typeflag: tar.TypeFifo, Size: 0, Mode: 0o644, Format: tar.FormatUSTAR})
	tw.Close()
	withSize := bytes.Clone(hb.Bytes())
	copy(withSize[124:], "00000000005\x00") // size field of the first header
	fixChecksum(withSize[:512])
	bad := map[string][]byte{
		"tar with junk after its end": append(bytes.Clone(tb), []byte("\x7fELF trailing payload")...),
		"zip with a prefix":           append([]byte("prefix bytes "), zb...),
		"zip with a suffix":           append(bytes.Clone(zb), "trailing"...),
		"fifo entry with a size":      withSize,
	}
	for name, b := range bad {
		if d := DescribeBinary(b, nil, false, nil); reached(d) {
			t.Errorf("%s is complete:\n%s", name, d.Text)
		}
	}
	// A zip "directory" holding data is read like a file.
	var db bytes.Buffer
	zw := zip.NewWriter(&db)
	w, _ := zw.CreateHeader(&zip.FileHeader{Name: "binX", Method: zip.Store})
	w.Write([]byte("\x7fELF\x02\x01\x01 hidden in a directory entry"))
	zw.Close()
	// Rename it "bin/" in both headers: a directory entry that holds data.
	dirZip := bytes.ReplaceAll(db.Bytes(), []byte("binX"), []byte("bin/"))
	// archive/zip will not read a directory entry: then incomplete.
	if d := DescribeBinary(dirZip, nil, false, nil); reached(d) {
		t.Errorf("a zip directory entry with an unread ELF is complete:\n%s", d.Text)
	}
}

func fixChecksum(h []byte) {
	copy(h[148:156], "        ")
	sum := 0
	for _, c := range h {
		sum += int(c)
	}
	copy(h[148:], []byte(octal6(sum)+"\x00 "))
}

func octal6(n int) string {
	s := ""
	for i := 0; i < 6; i++ {
		s = string(rune('0'+n%8)) + s
		n /= 8
	}
	return s
}

// TestLinkerSniffOrder (round 7, B2a/b): a COFF object that is also a tar
// is sniffed as COFF for a linker input, and is never complete.
func TestLinkerSniffOrder(t *testing.T) {
	b := make([]byte, 1024)
	binary_le16(b, 0x8664)
	copy(b[257:], "ustar\x0000")
	if typ, all := typeFor(b, LinkerInput); typ != "COFF object (amd64)" || len(all) != 2 {
		t.Errorf("linker sniff = %q (all %q)", typ, all)
	}
	if typ, _ := typeFor(b, Generic); typ != "tar archive" {
		t.Errorf("generic sniff = %q", typ)
	}
	if d := DescribeAs(b, nil, false, nil, LinkerInput); reached(d) {
		t.Errorf("a COFF/tar polyglot is complete:\n%s", d.Text)
	}
}

func binary_le16(b []byte, v uint16) { b[0], b[1] = byte(v), byte(v>>8) }

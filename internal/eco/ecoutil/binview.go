package ecoutil

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
)

// Limits for DescribeBinary. The input is hostile: every list is capped,
// structured parsing is skipped past maxParse bytes, and each parser runs
// under recover so a malformed file costs its section, never the gate.
const (
	maxParse      = 64 << 20 // bytes handed to debug/*, archive/* and compress/*
	maxGunzip     = 64 << 20 // decompressed bytes read from a gzip stream
	hexdumpBytes  = 512
	minString     = 6
	maxStringLen  = 160
	maxStrings    = 300  // printable strings shown
	maxStringSet  = 5000 // distinct strings kept per side for the old/new comparison
	maxStringDiff = 150
	maxListed     = 100 // sections, symbols, libraries, archive entries
)

// DescribeBinary renders bytes a reviewer cannot read as text: size,
// SHA-256, the type its magic number names, the structure the standard
// library's parsers find (ELF, Mach-O and PE/COFF headers, sections,
// imported libraries and symbols, Go build info; zip, tar and gzip
// entries), a hexdump of the start and its printable strings. With an old
// version (hadOld) it also compares the two. Everything it prints from the
// file (names, strings) is third-party data; the caller writes the result
// as untrusted evidence.
func DescribeBinary(cur, old []byte, hadOld bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "size: %d bytes\nsha256: %x\ntype: %s\n", len(cur), sha256.Sum256(cur), magicType(cur))
	if s := structure(cur); s != "" {
		b.WriteString("\nstructure (parsed by the gate):\n")
		b.WriteString(s)
	}
	if hadOld {
		b.WriteString("\n")
		b.WriteString(compareBinary(old, cur))
	}
	fmt.Fprintf(&b, "\nhexdump of the first %d bytes:\n", min(len(cur), hexdumpBytes))
	b.WriteString(Hexdump(cur[:min(len(cur), hexdumpBytes)]))
	strs, total := printableStrings(cur, maxStrings)
	fmt.Fprintf(&b, "\nprintable strings (at least %d characters): %d found", minString, total)
	if total > len(strs) {
		fmt.Fprintf(&b, ", first %d shown", len(strs))
	}
	b.WriteString("\n")
	for _, s := range strs {
		b.WriteString("    | " + s + "\n")
	}
	return b.String()
}

// magicType names a file by its leading bytes. http.DetectContentType is
// the fallback.
func magicType(b []byte) string {
	has := func(off int, magic string) bool {
		return len(b) >= off+len(magic) && string(b[off:off+len(magic)]) == magic
	}
	switch {
	case has(0, "\x7fELF"):
		return "ELF"
	case has(0, "MZ"):
		return "PE (Windows executable or DLL) or DOS MZ"
	case has(0, "\xfe\xed\xfa\xce"), has(0, "\xce\xfa\xed\xfe"), has(0, "\xfe\xed\xfa\xcf"), has(0, "\xcf\xfa\xed\xfe"):
		return "Mach-O"
	case has(0, "\xca\xfe\xba\xbe"):
		return "Mach-O universal (fat) binary or Java class file"
	case has(0, "!<arch>\n"):
		return "ar archive (static library, e.g. a Go .a or C .a)"
	case has(0, "PK\x03\x04"), has(0, "PK\x05\x06"):
		return "zip archive"
	case has(0, "\x1f\x8b"):
		return "gzip"
	case has(257, "ustar"):
		return "tar archive"
	case has(0, "\x00asm"):
		return "WebAssembly module"
	case has(0, "\x89PNG\r\n\x1a\n"):
		return "PNG image"
	case has(0, "\xff\xd8\xff"):
		return "JPEG image"
	case has(0, "GIF87a"), has(0, "GIF89a"):
		return "GIF image"
	case has(0, "%PDF-"):
		return "PDF document"
	case has(0, "BZh"):
		return "bzip2"
	case has(0, "\xfd7zXZ\x00"):
		return "xz"
	case has(0, "\x28\xb5\x2f\xfd"):
		return "zstd"
	case has(0, "7z\xbc\xaf\x27\x1c"):
		return "7-zip archive"
	case has(0, "SQLite format 3\x00"):
		return "SQLite database"
	case coffMachine(b) != "":
		return "COFF object (" + coffMachine(b) + ")"
	}
	return "unknown magic; content sniffing says " + http.DetectContentType(b)
}

// coffMachine recognizes a bare COFF object (what a Windows .syso is) by
// its machine field.
func coffMachine(b []byte) string {
	if len(b) < 20 {
		return ""
	}
	switch binary.LittleEndian.Uint16(b) {
	case 0x14c:
		return "i386"
	case 0x8664:
		return "amd64"
	case 0xaa64:
		return "arm64"
	case 0x1c4:
		return "arm"
	}
	return ""
}

// guard runs one parser and turns a panic into a line of text.
func guard(what string, f func() string) (s string) {
	defer func() {
		if r := recover(); r != nil {
			s = "  " + what + ": the parser failed on this input\n"
		}
	}()
	return f()
}

func structure(b []byte) string {
	if len(b) > maxParse {
		return fmt.Sprintf("  not parsed: larger than %d bytes\n", maxParse)
	}
	var out strings.Builder
	r := bytes.NewReader(b)
	switch t := magicType(b); {
	case t == "ELF":
		out.WriteString(guard("ELF", func() string { return describeELF(r) }))
	case strings.HasPrefix(t, "PE"), strings.HasPrefix(t, "COFF"):
		out.WriteString(guard("PE/COFF", func() string { return describePE(r) }))
	case strings.HasPrefix(t, "Mach-O"):
		out.WriteString(guard("Mach-O", func() string { return describeMachO(r) }))
	case t == "zip archive":
		out.WriteString(guard("zip", func() string { return describeZip(r) }))
	case t == "tar archive":
		out.WriteString(guard("tar", func() string { return describeTar(r) }))
	case t == "gzip":
		out.WriteString(guard("gzip", func() string { return describeGzip(r) }))
	default:
		return ""
	}
	out.WriteString(guard("Go build info", func() string { return describeBuildInfo(r) }))
	return out.String()
}

// list writes up to maxListed items, one per line, marking the rest.
func list(b *strings.Builder, title string, items []string) {
	fmt.Fprintf(b, "  %s (%d):\n", title, len(items))
	for i, it := range items {
		if i == maxListed {
			fmt.Fprintf(b, "    ... %d more\n", len(items)-maxListed)
			break
		}
		b.WriteString("    | " + clip(it) + "\n")
	}
}

func clip(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '.'
		}
		return r
	}, s)
	if len(s) > maxStringLen {
		return s[:maxStringLen] + "..."
	}
	return s
}

func describeELF(r io.ReaderAt) string {
	f, err := elf.NewFile(r)
	if err != nil {
		return "  ELF: not parsed: " + clip(err.Error()) + "\n"
	}
	defer f.Close()
	var b strings.Builder
	fmt.Fprintf(&b, "  ELF %s %s %s, OS ABI %s, entry 0x%x\n", f.Class, f.Data, f.Type, f.OSABI, f.Entry)
	fmt.Fprintf(&b, "  machine: %s\n", f.Machine)
	var secs []string
	for _, s := range f.Sections {
		secs = append(secs, fmt.Sprintf("%s %s size %d", s.Name, s.Type, s.Size))
	}
	list(&b, "sections", secs)
	if libs, err := f.ImportedLibraries(); err == nil {
		list(&b, "imported libraries", libs)
	}
	if syms, err := f.ImportedSymbols(); err == nil {
		var names []string
		for _, s := range syms {
			names = append(names, s.Name+" "+s.Library)
		}
		list(&b, "imported symbols", names)
	}
	if syms, err := f.Symbols(); err == nil {
		fmt.Fprintf(&b, "  symbol table: %d symbols\n", len(syms))
	}
	return b.String()
}

func describePE(r io.ReaderAt) string {
	f, err := pe.NewFile(r)
	if err != nil {
		return "  PE/COFF: not parsed: " + clip(err.Error()) + "\n"
	}
	defer f.Close()
	var b strings.Builder
	fmt.Fprintf(&b, "  PE/COFF machine 0x%x, characteristics 0x%x, %d symbols\n", f.Machine, f.Characteristics, len(f.Symbols))
	var secs []string
	for _, s := range f.Sections {
		secs = append(secs, fmt.Sprintf("%s size %d characteristics 0x%x", s.Name, s.Size, s.Characteristics))
	}
	list(&b, "sections", secs)
	if libs, err := f.ImportedLibraries(); err == nil {
		list(&b, "imported libraries", libs)
	}
	if syms, err := f.ImportedSymbols(); err == nil {
		list(&b, "imported symbols", syms)
	}
	return b.String()
}

func describeMachO(r io.ReaderAt) string {
	var b strings.Builder
	one := func(f *macho.File) {
		fmt.Fprintf(&b, "  Mach-O %s %s, %d load commands\n", f.Cpu, f.Type, len(f.Loads))
		var secs []string
		for _, s := range f.Sections {
			secs = append(secs, fmt.Sprintf("%s,%s size %d", s.Seg, s.Name, s.Size))
		}
		list(&b, "sections", secs)
		if libs, err := f.ImportedLibraries(); err == nil {
			list(&b, "imported libraries", libs)
		}
		if syms, err := f.ImportedSymbols(); err == nil {
			list(&b, "imported symbols", syms)
		}
	}
	if fat, err := macho.NewFatFile(r); err == nil {
		defer fat.Close()
		fmt.Fprintf(&b, "  universal binary, %d architectures\n", len(fat.Arches))
		for i, a := range fat.Arches {
			if i == 8 {
				fmt.Fprintf(&b, "  ... %d more architectures\n", len(fat.Arches)-8)
				break
			}
			one(a.File)
		}
		return b.String()
	} else if !errors.Is(err, macho.ErrNotFat) {
		return "  Mach-O universal: not parsed (a Java class file shares this magic): " + clip(err.Error()) + "\n"
	}
	f, err := macho.NewFile(r)
	if err != nil {
		return "  Mach-O: not parsed: " + clip(err.Error()) + "\n"
	}
	defer f.Close()
	one(f)
	return b.String()
}

func describeZip(r *bytes.Reader) string {
	z, err := zip.NewReader(r, r.Size())
	if err != nil {
		return "  zip: not parsed: " + clip(err.Error()) + "\n"
	}
	var b strings.Builder
	var names []string
	for _, f := range z.File {
		names = append(names, fmt.Sprintf("%s (%d bytes, compressed %d)", f.Name, f.UncompressedSize64, f.CompressedSize64))
	}
	list(&b, "zip entries", names)
	return b.String()
}

func tarEntries(r io.Reader) []string {
	tr := tar.NewReader(r)
	var names []string
	for len(names) <= maxListed {
		h, err := tr.Next()
		if err != nil {
			if err != io.EOF {
				names = append(names, "(stopped: "+err.Error()+")")
			}
			break
		}
		names = append(names, fmt.Sprintf("%s (type %q, %d bytes, mode %o)", h.Name, h.Typeflag, h.Size, h.Mode))
	}
	return names
}

func describeTar(r io.Reader) string {
	var b strings.Builder
	list(&b, "tar entries (first ones)", tarEntries(r))
	return b.String()
}

func describeGzip(r io.Reader) string {
	z, err := gzip.NewReader(r)
	if err != nil {
		return "  gzip: not parsed: " + clip(err.Error()) + "\n"
	}
	defer z.Close()
	var b strings.Builder
	if z.Name != "" {
		fmt.Fprintf(&b, "  gzip header name: %s\n", clip(z.Name))
	}
	data, err := io.ReadAll(io.LimitReader(z, maxGunzip+1))
	switch {
	case len(data) > maxGunzip:
		fmt.Fprintf(&b, "  decompressed: more than %d bytes (stopped)\n", maxGunzip)
		data = data[:maxGunzip]
	case err != nil:
		fmt.Fprintf(&b, "  decompressed: %d bytes, then an error: %s\n", len(data), clip(err.Error()))
	default:
		fmt.Fprintf(&b, "  decompressed: %d bytes\n", len(data))
	}
	t := magicType(data)
	fmt.Fprintf(&b, "  decompressed type: %s\n", t)
	if t == "tar archive" {
		list(&b, "tar entries (first ones)", tarEntries(bytes.NewReader(data)))
	}
	return b.String()
}

func describeBuildInfo(r io.ReaderAt) string {
	bi, err := buildinfo.Read(r)
	if err != nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "  Go build info: %s, main module %s %s\n", clip(bi.GoVersion), clip(bi.Main.Path), clip(bi.Main.Version))
	var deps []string
	for _, d := range bi.Deps {
		deps = append(deps, d.Path+" "+d.Version)
	}
	list(&b, "Go module dependencies built in", deps)
	return b.String()
}

// compareBinary describes how cur differs from old.
func compareBinary(old, cur []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "previous version: %d bytes, sha256 %x, type %s\n", len(old), sha256.Sum256(old), magicType(old))
	if bytes.Equal(old, cur) {
		b.WriteString("identical to the previous version\n")
		return b.String()
	}
	n := min(len(old), len(cur))
	diff := 0
	for i := 0; i < n; i++ {
		if old[i] != cur[i] {
			diff++
		}
	}
	fmt.Fprintf(&b, "bytes that differ at the same offset: %d of the first %d; size change %+d bytes\n", diff, n, len(cur)-len(old))
	os, _ := printableStrings(old, maxStringSet)
	ns, _ := printableStrings(cur, maxStringSet)
	inOld := map[string]bool{}
	for _, s := range os {
		inOld[s] = true
	}
	inNew := map[string]bool{}
	for _, s := range ns {
		inNew[s] = true
	}
	added := uniqueNotIn(ns, inOld)
	removed := uniqueNotIn(os, inNew)
	fmt.Fprintf(&b, "printable strings only in the new version: %d (compared over the first %d distinct strings of each)\n", len(added), maxStringSet)
	for i, s := range added {
		if i == maxStringDiff {
			fmt.Fprintf(&b, "    ... %d more\n", len(added)-maxStringDiff)
			break
		}
		b.WriteString("    + " + s + "\n")
	}
	fmt.Fprintf(&b, "printable strings only in the previous version: %d\n", len(removed))
	for i, s := range removed {
		if i == maxStringDiff {
			fmt.Fprintf(&b, "    ... %d more\n", len(removed)-maxStringDiff)
			break
		}
		b.WriteString("    - " + s + "\n")
	}
	return b.String()
}

func uniqueNotIn(ss []string, other map[string]bool) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range ss {
		if !other[s] && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// printableStrings returns up to limit distinct runs of at least minString
// printable ASCII characters (each clipped to maxStringLen), in order, and
// how many runs there are in all.
func printableStrings(b []byte, limit int) ([]string, int) {
	var out []string
	seen := map[string]bool{}
	total := 0
	start := -1
	flush := func(end int) {
		if start >= 0 && end-start >= minString {
			total++
			s := string(b[start:end])
			if len(s) > maxStringLen {
				s = s[:maxStringLen] + "..."
			}
			if len(out) < limit && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
		start = -1
	}
	for i, c := range b {
		if c >= 0x20 && c < 0x7f || c == '\t' {
			if start < 0 {
				start = i
			}
			continue
		}
		flush(i)
	}
	flush(len(b))
	return out, total
}

// Hexdump is a classic offset / hex / ASCII dump, printable ASCII only.
func Hexdump(b []byte) string {
	var s strings.Builder
	for off := 0; off < len(b); off += 16 {
		row := b[off:min(off+16, len(b))]
		h := hex.EncodeToString(row)
		var pairs []string
		for i := 0; i < len(h); i += 2 {
			pairs = append(pairs, h[i:i+2])
		}
		ascii := slices.Clone(row)
		for i, c := range ascii {
			if c < 0x20 || c >= 0x7f {
				ascii[i] = '.'
			}
		}
		fmt.Fprintf(&s, "    %08x  %-47s  |%s|\n", off, strings.Join(pairs, " "), ascii)
	}
	return s.String()
}

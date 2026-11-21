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
	"time"
)

// Limits for DescribeBinary. The input is hostile: every list is capped,
// structured parsing is skipped past maxParse bytes, each parser runs
// under recover, and (with Isolate) in a child process with a memory
// limit and a timeout, so a malformed file costs its own rendering, never
// the gate.
const (
	maxParse      = 64 << 20 // bytes handed to debug/*, archive/* and compress/*
	maxGunzip     = 64 << 20 // decompressed bytes read from a gzip stream
	hexdumpBytes  = 512
	minString     = 6
	maxStringLen  = 160
	maxStrings    = 300  // printable strings shown
	maxStringSet  = 5000 // distinct strings kept per side for the old/new comparison
	maxStringDiff = 150
	maxListed     = 100 // sections, libraries, archive entries
	maxSymbols    = 50  // symbol names; past this only counts are shown
	// maxNameBytes bounds symbols x string table, the bytes the debug/*
	// parsers could spend building names that all point at one long
	// string. Past it no names are built at all.
	maxNameBytes = 16 << 20
)

// Budget bounds the work DescribeBinary does across every call that
// shares it (one module's binaries): bytes handed to the structured
// parsers plus bytes decompressed (Left), and wall time (Deadline, zero
// for none). nil means no shared bound, only the per-file caps.
type Budget struct {
	Left     int64
	Deadline time.Time
}

// Take reserves n bytes; it reports false, reserving nothing, when fewer
// are left or the deadline has passed.
func (b *Budget) Take(n int64) bool {
	if b == nil {
		return true
	}
	if b.Left < n || (!b.Deadline.IsZero() && time.Now().After(b.Deadline)) {
		return false
	}
	b.Left -= n
	return true
}

// left is n, or less if the budget has less left.
func (b *Budget) left(n int64) int64 {
	if b == nil {
		return n
	}
	return min(n, max(b.Left, 0))
}

// budgetNote is printed in place of what a spent budget skipped.
const budgetNote = "the gate's parse budget for this module is spent"

// Status says whether DescribeBinary rendered a file's structure.
type Status int

const (
	// NoParser: the file's type has no structured parser (an image, a
	// database, unknown bytes); only the generic facts are shown.
	NoParser Status = iota
	// Structured: the structure was rendered.
	Structured
	// NotStructured: the type has a parser but the structure was not
	// rendered (budget spent, too large, the parser failed, or the
	// isolated parser crashed or timed out).
	NotStructured
)

// Description is DescribeBinary's result.
type Description struct {
	Text      string
	Structure Status
}

// DescribeBinary renders bytes a reviewer cannot read as text: size,
// SHA-256, the type its magic number names, the structure the standard
// library's parsers find (ELF, Mach-O and PE/COFF headers, sections,
// imported libraries and symbols, Go build info; zip, tar and gzip
// entries), a hexdump of the start and its printable strings. With an old
// version (hadOld) it also compares the two. Everything it prints from the
// file (names, strings) is third-party data; the caller writes the result
// as untrusted evidence. Only the structure step parses the file; the rest
// is linear scanning, done in this process.
func DescribeBinary(cur, old []byte, hadOld bool, budget *Budget) Description {
	var b strings.Builder
	fmt.Fprintf(&b, "size: %d bytes\nsha256: %x\ntype: %s\n", len(cur), sha256.Sum256(cur), magicType(cur))
	text, st := structure(cur, budget)
	if text != "" {
		b.WriteString("\nstructure (parsed by the gate):\n")
		b.WriteString(text)
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
	return Description{Text: b.String(), Structure: st}
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

// parsed reports whether the structure step parses files of type t.
func parsed(t string) bool {
	return t == "ELF" || strings.HasPrefix(t, "PE") || strings.HasPrefix(t, "COFF") || strings.HasPrefix(t, "Mach-O") ||
		t == "zip archive" || t == "tar archive" || t == "gzip"
}

// structure renders the file's structure: here, or in the isolated child
// process when Isolate was called. The bytes parsed are charged first;
// what the parsers decompress is charged after.
func structure(b []byte, budget *Budget) (string, Status) {
	if !parsed(magicType(b)) {
		return "", NoParser
	}
	if len(b) > maxParse {
		return fmt.Sprintf("  not parsed: larger than %d bytes\n", maxParse), NotStructured
	}
	if !budget.Take(int64(len(b))) {
		return "  not parsed: " + budgetNote + "\n", NotStructured
	}
	limit := budget.left(maxGunzip)
	var res childResult
	if iso := isolation; iso != nil {
		res = iso.run(b, limit)
	} else {
		res = structureLocal(b, limit)
	}
	budget.Take(min(res.Used, limit))
	return res.Text, res.Status
}

// childResult is the structure step's output (and the child's reply).
type childResult struct {
	Text   string `json:"text"`
	Status Status `json:"status"`
	Used   int64  `json:"used"` // bytes decompressed
}

// renderer is one structure rendering: it records a failure in any parser.
type renderer struct {
	limit  int64 // bytes that may be decompressed
	used   int64
	failed bool
}

// guard runs one parser and turns a panic into a line of text.
func (rd *renderer) guard(what string, f func() string) (s string) {
	defer func() {
		if r := recover(); r != nil {
			rd.failed = true
			s = "  " + what + ": the parser failed on this input\n"
		}
	}()
	return f()
}

// fail records a parser error and returns its line.
func (rd *renderer) fail(what string, err error) string {
	rd.failed = true
	return "  " + what + ": not parsed: " + clip(err.Error()) + "\n"
}

func structureLocal(b []byte, limit int64) childResult {
	rd := &renderer{limit: limit}
	var out strings.Builder
	r := bytes.NewReader(b)
	compressed := false
	switch t := magicType(b); {
	case t == "ELF":
		var s string
		s, compressed = rd.describeELFGuarded(r)
		out.WriteString(s)
	case strings.HasPrefix(t, "PE"), strings.HasPrefix(t, "COFF"):
		out.WriteString(rd.guard("PE/COFF", func() string { return rd.describePE(b, r) }))
	case strings.HasPrefix(t, "Mach-O"):
		out.WriteString(rd.guard("Mach-O", func() string { return rd.describeMachO(r) }))
	case t == "zip archive":
		out.WriteString(rd.guard("zip", func() string { return rd.describeZip(r) }))
	case t == "tar archive":
		out.WriteString(rd.guard("tar", func() string { return describeTar(r) }))
	case t == "gzip":
		out.WriteString(rd.guard("gzip", func() string { return rd.describeGzip(r) }))
	}
	if !compressed {
		// buildinfo reads section data, which for a compressed ELF
		// section would inflate it.
		out.WriteString(rd.guard("Go build info", func() string { return describeBuildInfo(r) }))
	}
	st := Structured
	if rd.failed {
		st = NotStructured
	}
	return childResult{Text: out.String(), Status: st, Used: rd.used}
}

// list writes up to maxListed items, one per line, marking the rest.
func list(b *strings.Builder, title string, items []string) {
	listN(b, title, items, maxListed)
}

func listN(b *strings.Builder, title string, items []string, n int) {
	fmt.Fprintf(b, "  %s (%d):\n", title, len(items))
	for i, it := range items {
		if i == n {
			fmt.Fprintf(b, "    ... %d more (names not shown)\n", len(items)-n)
			break
		}
		b.WriteString("    | " + clip(it) + "\n")
	}
}

func clip(s string) string {
	if len(s) > 4*maxStringLen {
		s = s[:4*maxStringLen]
	}
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

func (rd *renderer) describeELFGuarded(r *bytes.Reader) (s string, compressed bool) {
	s = rd.guard("ELF", func() string {
		var out string
		out, compressed = rd.describeELF(r)
		return out
	})
	return s, compressed
}

// describeELF renders headers and sections, and imported libraries and
// symbols only when building their names is cheap (maxNameBytes) and no
// section is compressed (reading one would inflate it).
func (rd *renderer) describeELF(r io.ReaderAt) (string, bool) {
	f, err := elf.NewFile(r)
	if err != nil {
		return rd.fail("ELF", err), false
	}
	defer f.Close()
	var b strings.Builder
	fmt.Fprintf(&b, "  ELF %s %s %s, OS ABI %s, entry 0x%x\n", f.Class, f.Data, f.Type, f.OSABI, f.Entry)
	fmt.Fprintf(&b, "  machine: %s\n", f.Machine)
	var secs []string
	compressed := false
	symbols := map[elf.SectionType]uint64{}
	nameCost := uint64(0)
	for _, s := range f.Sections {
		flag := ""
		if s.Flags&elf.SHF_COMPRESSED != 0 {
			compressed = true
			flag = " (compressed; not inflated)"
		}
		secs = append(secs, fmt.Sprintf("%s %s size %d%s", s.Name, s.Type, s.Size, flag))
		if (s.Type == elf.SHT_SYMTAB || s.Type == elf.SHT_DYNSYM) && s.Entsize > 0 {
			n := s.Size / s.Entsize
			symbols[s.Type] += n
			if int(s.Link) < len(f.Sections) {
				nameCost += n * f.Sections[s.Link].Size
			}
		}
		if s.Type == elf.SHT_DYNAMIC && s.Entsize > 0 && int(s.Link) < len(f.Sections) {
			nameCost += s.Size / s.Entsize * f.Sections[s.Link].Size
		}
	}
	list(&b, "sections", secs)
	fmt.Fprintf(&b, "  symbol tables: %d symbols, %d dynamic symbols\n", symbols[elf.SHT_SYMTAB], symbols[elf.SHT_DYNSYM])
	switch {
	case compressed:
		b.WriteString("  imported libraries and symbols: not read (a section is compressed)\n")
	case nameCost > maxNameBytes:
		b.WriteString("  imported libraries and symbols: not read (their names could cost too much to build); counts above\n")
	default:
		if libs, err := f.ImportedLibraries(); err == nil {
			list(&b, "imported libraries", libs)
		}
		if syms, err := f.ImportedSymbols(); err == nil {
			var names []string
			for _, s := range syms {
				names = append(names, s.Name+" "+s.Library)
			}
			listN(&b, "imported symbols", names, maxSymbols)
		}
	}
	return b.String(), compressed
}

// peNameCost reads, from the raw headers, the symbol count and string
// table size of a PE image or COFF object: pe.NewFile builds every
// symbol name up front.
func peNameCost(b []byte) (syms uint32, cost uint64, ok bool) {
	off := 0
	if len(b) >= 0x40 && b[0] == 'M' && b[1] == 'Z' {
		off = int(binary.LittleEndian.Uint32(b[0x3c:]))
		if off < 0 || off+4 > len(b) || string(b[off:off+4]) != "PE\x00\x00" {
			return 0, 0, false
		}
		off += 4
	}
	if off+20 > len(b) {
		return 0, 0, false
	}
	ptr := uint64(binary.LittleEndian.Uint32(b[off+8:]))
	syms = binary.LittleEndian.Uint32(b[off+12:])
	strOff := ptr + 18*uint64(syms)
	var strSize uint64
	if ptr != 0 && strOff+4 <= uint64(len(b)) {
		strSize = uint64(binary.LittleEndian.Uint32(b[strOff:]))
	}
	return syms, uint64(syms) * max(strSize, 1), true
}

func (rd *renderer) describePE(raw []byte, r io.ReaderAt) string {
	syms, cost, ok := peNameCost(raw)
	if !ok {
		return rd.fail("PE/COFF", errors.New("unreadable headers"))
	}
	if cost > maxNameBytes {
		return fmt.Sprintf("  PE/COFF: %d symbols; not parsed further (building their names could cost too much)\n", syms)
	}
	f, err := pe.NewFile(r)
	if err != nil {
		return rd.fail("PE/COFF", err)
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
		listN(&b, "imported symbols", syms, maxSymbols)
	}
	return b.String()
}

// describeMachO: macho.NewFile builds the symbol table's names as it
// parses, so a file built to amplify them is stopped by the isolated
// child's memory limit, not here.
func (rd *renderer) describeMachO(r io.ReaderAt) string {
	var b strings.Builder
	one := func(f *macho.File) {
		nsyms := 0
		if f.Symtab != nil {
			nsyms = len(f.Symtab.Syms)
		}
		fmt.Fprintf(&b, "  Mach-O %s %s, %d load commands, %d symbols\n", f.Cpu, f.Type, len(f.Loads), nsyms)
		var secs []string
		for _, s := range f.Sections {
			secs = append(secs, fmt.Sprintf("%s,%s size %d", s.Seg, s.Name, s.Size))
		}
		list(&b, "sections", secs)
		if libs, err := f.ImportedLibraries(); err == nil {
			list(&b, "imported libraries", libs)
		}
		if syms, err := f.ImportedSymbols(); err == nil {
			listN(&b, "imported symbols", syms, maxSymbols)
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
		return rd.fail("Mach-O universal (a Java class file shares this magic)", err)
	}
	f, err := macho.NewFile(r)
	if err != nil {
		return rd.fail("Mach-O", err)
	}
	defer f.Close()
	one(f)
	return b.String()
}

func (rd *renderer) describeZip(r *bytes.Reader) string {
	z, err := zip.NewReader(r, r.Size())
	if err != nil {
		return rd.fail("zip", err)
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

func (rd *renderer) describeGzip(r io.Reader) string {
	z, err := gzip.NewReader(r)
	if err != nil {
		return rd.fail("gzip", err)
	}
	defer z.Close()
	var b strings.Builder
	if z.Name != "" {
		fmt.Fprintf(&b, "  gzip header name: %s\n", clip(z.Name))
	}
	limit := min(rd.limit, maxGunzip)
	if limit <= 0 {
		rd.failed = true
		b.WriteString("  not decompressed: " + budgetNote + "\n")
		return b.String()
	}
	data, err := io.ReadAll(io.LimitReader(z, limit+1))
	rd.used += min(int64(len(data)), limit)
	switch {
	case int64(len(data)) > limit && limit < maxGunzip:
		fmt.Fprintf(&b, "  decompressed: stopped after %d bytes: %s\n", limit, budgetNote)
		data = data[:limit]
	case int64(len(data)) > limit:
		fmt.Fprintf(&b, "  decompressed: more than %d bytes (stopped)\n", maxGunzip)
		data = data[:limit]
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
			if len(out) < limit {
				s := string(b[start:min(end, start+maxStringLen)])
				if end-start > maxStringLen {
					s += "..."
				}
				if !seen[s] {
					seen[s] = true
					out = append(out, s)
				}
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

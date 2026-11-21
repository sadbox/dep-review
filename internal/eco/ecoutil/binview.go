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
	"sync"
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
	maxListed     = 200 // sections, libraries, archive entries, Go deps
	maxSymbols    = 500 // imported symbol names
	maxArches     = 8   // architectures of a Mach-O universal binary
	// maxNameBytes bounds symbols x string table, the bytes the debug/*
	// parsers could spend building names that all point at one long
	// string. Past it no names are built at all.
	maxNameBytes = 16 << 20
)

// Budget bounds the work DescribeBinary does across every call that
// shares it: bytes handed to the structured parsers plus bytes
// decompressed (Left, one module's binaries), and wall time (Clock,
// shared by every module of a fetch; nil for none). A nil Budget means
// no shared bound, only the per-file caps.
type Budget struct {
	Left  int64
	Clock *Clock
}

// Take reserves n bytes; it reports false, reserving nothing, when fewer
// are left or the clock has run out.
func (b *Budget) Take(n int64) bool {
	if b == nil {
		return true
	}
	if b.Left < n || !b.Clock.ok() {
		return false
	}
	b.Left -= n
	return true
}

// Clock is a wall-time allowance that starts with the first work charged
// to it (not when it is made), so time spent before rendering begins
// does not count. It is safe for concurrent use.
type Clock struct {
	mu      sync.Mutex
	d       time.Duration
	start   time.Time
	expired bool
}

// NewClock is a Clock allowing d once started.
func NewClock(d time.Duration) *Clock { return &Clock{d: d} }

func (c *Clock) ok() bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.start.IsZero() {
		c.start = now
	}
	return !c.expired && now.Sub(c.start) < c.d
}

// Started is when the clock started, zero before any work.
func (c *Clock) Started() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.start
}

// Expire runs the clock out (tests).
func (c *Clock) Expire() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expired = true
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

// Description is DescribeBinary's result. Complete is the gate's positive
// assertion that the structure step reached the end of the file's
// structure: every section, entry, library and imported symbol listed,
// nothing skipped, stopped, capped, out of budget or time, and no parser
// error. Every other outcome, a type the gate has no parser for
// included, is incomplete. The hexdump and printable strings are samples
// and do not count either way; neither do symbol tables shown as counts
// (the evidence says so).
type Description struct {
	Text     string
	Complete bool
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
	text, complete := structure(cur, budget)
	b.WriteString("\nstructure (parsed by the gate):\n")
	b.WriteString(text)
	if complete {
		b.WriteString("  (the gate read this structure to its end)\n")
	} else {
		b.WriteString("  (the gate did NOT read this structure in full)\n")
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
	return Description{Text: b.String(), Complete: complete}
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
func structure(b []byte, budget *Budget) (string, bool) {
	switch t := magicType(b); {
	case !parsed(t):
		return "  not parsed: the gate has no parser for this type\n", false
	case len(b) > maxParse:
		return fmt.Sprintf("  not parsed: larger than %d bytes\n", maxParse), false
	case !budget.Take(int64(len(b))):
		return "  not parsed: " + budgetNote + "\n", false
	}
	limit := budget.left(maxGunzip)
	var res childResult
	if iso := isolation; iso != nil {
		res = iso.run(b, limit)
	} else {
		res = structureLocal(b, limit)
	}
	budget.Take(min(res.Used, limit))
	return res.Text, res.Complete
}

// childResult is the structure step's output (and the child's reply).
type childResult struct {
	Text     string `json:"text"`
	Complete bool   `json:"complete"`
	Used     int64  `json:"used"` // bytes decompressed
}

// renderer is one structure rendering. Its describe functions each return
// (text, complete); complete is true only from a describer's final
// return, after everything it covers was read. An early return, a cap or
// a panic (guard) is incomplete by construction.
type renderer struct {
	limit int64 // bytes that may be decompressed
	used  int64
}

// step runs one describer, turning a panic into an incomplete line.
func step(what string, f func() (string, bool)) (s string, complete bool) {
	defer func() {
		if r := recover(); r != nil {
			s, complete = "  "+what+": the parser failed on this input\n", false
		}
	}()
	return f()
}

// failed is a describer's line for a parser error.
func failed(what string, err error) (string, bool) {
	return "  " + what + ": not parsed: " + clip(err.Error()) + "\n", false
}

func structureLocal(b []byte, limit int64) childResult {
	rd := &renderer{limit: limit}
	r := bytes.NewReader(b)
	var text string
	var complete, exe bool
	switch t := magicType(b); {
	case t == "ELF":
		text, complete = step("ELF", func() (string, bool) { return describeELF(b, r) })
		exe = true
	case strings.HasPrefix(t, "PE"), strings.HasPrefix(t, "COFF"):
		text, complete = step("PE/COFF", func() (string, bool) { return describePE(b, r) })
		exe = true
	case strings.HasPrefix(t, "Mach-O"):
		text, complete = step("Mach-O", func() (string, bool) { return describeMachO(r) })
		exe = true
	case t == "zip archive":
		text, complete = step("zip", func() (string, bool) { return describeZip(r) })
	case t == "tar archive":
		text, complete = step("tar", func() (string, bool) { return describeTar(r) })
	case t == "gzip":
		text, complete = step("gzip", func() (string, bool) { return rd.describeGzip(r) })
	default:
		return childResult{Text: "  not parsed: the gate has no parser for this type\n"}
	}
	if exe && complete {
		// Only after a complete executable rendering: for ELF that means
		// no compressed section, which reading build info would inflate.
		bi, ok := step("Go build info", func() (string, bool) { return describeBuildInfo(r) })
		text += bi
		complete = ok
	}
	return childResult{Text: text, Complete: complete, Used: rd.used}
}

// list writes items, one per line. complete is false when there are more
// than n (the rest are not shown).
func list(b *strings.Builder, title string, items []string, n int) bool {
	fmt.Fprintf(b, "  %s (%d):\n", title, len(items))
	for i, it := range items {
		if i == n {
			fmt.Fprintf(b, "    ... %d more (not shown)\n", len(items)-n)
			return false
		}
		b.WriteString("    | " + clip(it) + "\n")
	}
	return true
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

// nameBytes is exactly what building the names at offs in strtab costs
// (the sum of the C strings' lengths, as debug/* builds them), in one
// pass over strtab after sorting the offsets: O(len(strtab) + n log n),
// however many names share one long string. An offset outside the table
// costs nothing (the parser fails or yields "").
func nameBytes(strtab []byte, offs []uint64) uint64 {
	slices.Sort(offs)
	var total uint64
	nul := -1 // index of the first NUL at or after the current offset
	for _, o := range offs {
		if o >= uint64(len(strtab)) {
			continue
		}
		i := int(o)
		if nul < i {
			j := bytes.IndexByte(strtab[i:], 0)
			if j < 0 {
				nul = len(strtab)
			} else {
				nul = i + j
			}
		}
		total += uint64(nul - i)
	}
	return total
}

// sectionBytes is a section's raw bytes from the file, or nil if they lie
// outside it.
func sectionBytes(raw []byte, off, size uint64) []byte {
	if off > uint64(len(raw)) || size > uint64(len(raw))-off {
		return nil
	}
	return raw[off : off+size]
}

// elfNameCost is what ImportedLibraries and ImportedSymbols would spend
// building names: each .dynsym entry's name and each DT_NEEDED string.
// .symtab is never read (only counted).
func elfNameCost(f *elf.File, raw []byte) uint64 {
	var cost uint64
	for _, s := range f.Sections {
		if int(s.Link) >= len(f.Sections) {
			continue
		}
		strtab := sectionBytes(raw, f.Sections[s.Link].Offset, f.Sections[s.Link].Size)
		data := sectionBytes(raw, s.Offset, s.Size)
		if strtab == nil || data == nil {
			continue
		}
		var offs []uint64
		switch {
		case s.Type == elf.SHT_DYNSYM && s.Entsize > 0:
			for at := uint64(0); at+4 <= uint64(len(data)); at += s.Entsize {
				offs = append(offs, uint64(f.ByteOrder.Uint32(data[at:])))
			}
		case s.Type == elf.SHT_DYNAMIC:
			ent := uint64(16)
			if f.Class == elf.ELFCLASS32 {
				ent = 8
			}
			for at := uint64(0); at+ent <= uint64(len(data)); at += ent {
				var tag, val uint64
				if ent == 16 {
					tag, val = f.ByteOrder.Uint64(data[at:]), f.ByteOrder.Uint64(data[at+8:])
				} else {
					tag, val = uint64(f.ByteOrder.Uint32(data[at:])), uint64(f.ByteOrder.Uint32(data[at+4:]))
				}
				if elf.DynTag(tag) == elf.DT_NEEDED {
					offs = append(offs, val)
				}
			}
		}
		cost += nameBytes(strtab, offs) + uint64(len(offs))
	}
	return cost
}

// describeELF renders headers, every section, symbol table counts, and
// imported libraries and symbols. It is complete only if no section is
// compressed (reading one would inflate it), building the imported names
// is cheap (maxNameBytes, computed exactly) and every list fits.
func describeELF(raw []byte, r io.ReaderAt) (string, bool) {
	f, err := elf.NewFile(r)
	if err != nil {
		return failed("ELF", err)
	}
	defer f.Close()
	var b strings.Builder
	fmt.Fprintf(&b, "  ELF %s %s %s, OS ABI %s, entry 0x%x\n", f.Class, f.Data, f.Type, f.OSABI, f.Entry)
	fmt.Fprintf(&b, "  machine: %s\n", f.Machine)
	var secs []string
	compressed := false
	symbols := map[elf.SectionType]uint64{}
	for _, s := range f.Sections {
		flag := ""
		if s.Flags&elf.SHF_COMPRESSED != 0 {
			compressed = true
			flag = " (compressed; not inflated)"
		}
		secs = append(secs, fmt.Sprintf("%s %s size %d%s", s.Name, s.Type, s.Size, flag))
		if (s.Type == elf.SHT_SYMTAB || s.Type == elf.SHT_DYNSYM) && s.Entsize > 0 {
			symbols[s.Type] += s.Size / s.Entsize
		}
	}
	if !list(&b, "sections", secs, maxListed) {
		return b.String(), false
	}
	fmt.Fprintf(&b, "  symbol tables: %d symbols (counted, names not read), %d dynamic symbols\n", symbols[elf.SHT_SYMTAB], symbols[elf.SHT_DYNSYM])
	if compressed {
		b.WriteString("  imported libraries and symbols: not read (a section is compressed)\n")
		return b.String(), false
	}
	if c := elfNameCost(f, raw); c > maxNameBytes {
		fmt.Fprintf(&b, "  imported libraries and symbols: not read (their names would cost %d bytes to build)\n", c)
		return b.String(), false
	}
	libs, err := f.ImportedLibraries()
	if err != nil {
		b.WriteString("  imported libraries: not read: " + clip(err.Error()) + "\n")
		return b.String(), false
	}
	if !list(&b, "imported libraries", libs, maxListed) {
		return b.String(), false
	}
	syms, err := f.ImportedSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		b.WriteString("  imported symbols: not read: " + clip(err.Error()) + "\n")
		return b.String(), false
	}
	var names []string
	for _, s := range syms {
		names = append(names, s.Name+" "+s.Library)
	}
	if !list(&b, "imported symbols", names, maxSymbols) {
		return b.String(), false
	}
	return b.String(), true
}

// coffHeader is what the gate reads itself from a PE image's or COFF
// object's headers, without pe.NewFile (which builds every symbol name
// up front): machine, characteristics, the section table, the symbol
// count, the string table and what building the names would cost.
type coffHeader struct {
	machine, characteristics uint16
	sections                 []string
	nsec                     int
	syms                     uint32
	strSize                  uint64
	nameCost                 uint64
}

func readCOFF(b []byte) (coffHeader, bool) {
	var h coffHeader
	off := 0
	if len(b) >= 0x40 && b[0] == 'M' && b[1] == 'Z' {
		off = int(binary.LittleEndian.Uint32(b[0x3c:]))
		if off < 0 || off > len(b)-4 || string(b[off:off+4]) != "PE\x00\x00" {
			return h, false
		}
		off += 4
	}
	if off > len(b)-20 {
		return h, false
	}
	h.machine = binary.LittleEndian.Uint16(b[off:])
	h.nsec = int(binary.LittleEndian.Uint16(b[off+2:]))
	ptr := uint64(binary.LittleEndian.Uint32(b[off+8:]))
	h.syms = binary.LittleEndian.Uint32(b[off+12:])
	opt := int(binary.LittleEndian.Uint16(b[off+16:]))
	h.characteristics = binary.LittleEndian.Uint16(b[off+18:])
	sec := off + 20 + opt
	for i := 0; i < h.nsec && i <= maxListed; i++ {
		at := sec + 40*i
		if at < 0 || at > len(b)-40 {
			break
		}
		name := strings.TrimRight(string(b[at:at+8]), "\x00")
		h.sections = append(h.sections, fmt.Sprintf("%s size %d characteristics 0x%x", name, binary.LittleEndian.Uint32(b[at+16:]), binary.LittleEndian.Uint32(b[at+36:])))
	}
	// Symbol records are 18 bytes; a name whose first 4 bytes are zero is
	// an offset into the string table that follows them (pe.NewFile
	// builds each one). Aux records are counted as names too: an upper
	// bound, still computed in one pass.
	symEnd := ptr + 18*uint64(h.syms)
	if ptr != 0 && symEnd+4 <= uint64(len(b)) {
		h.strSize = uint64(binary.LittleEndian.Uint32(b[symEnd:]))
		strtab := sectionBytes(b, symEnd, h.strSize)
		var offs []uint64
		for i := uint64(0); i < uint64(h.syms); i++ {
			rec := b[ptr+18*i:]
			if binary.LittleEndian.Uint32(rec) == 0 {
				offs = append(offs, uint64(binary.LittleEndian.Uint32(rec[4:])))
			} else {
				h.nameCost += 8
			}
		}
		if strtab != nil {
			h.nameCost += nameBytes(strtab, offs)
		}
		h.nameCost += uint64(len(offs))
	}
	return h, true
}

// describePE renders the headers the gate reads itself, every section,
// then imported libraries and symbols through pe.NewFile when building
// the symbol names is cheap. Complete only if all of that was read.
func describePE(raw []byte, r io.ReaderAt) (string, bool) {
	h, ok := readCOFF(raw)
	if !ok {
		return failed("PE/COFF", errors.New("unreadable headers"))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "  PE/COFF machine 0x%x, characteristics 0x%x, %d symbols, string table %d bytes\n", h.machine, h.characteristics, h.syms, h.strSize)
	fmt.Fprintf(&b, "  sections (%d):\n", h.nsec)
	for i, s := range h.sections {
		if i == maxListed {
			break
		}
		b.WriteString("    | " + clip(s) + "\n")
	}
	if len(h.sections) != h.nsec || h.nsec > maxListed {
		fmt.Fprintf(&b, "    ... %d of %d sections not shown (past the cap or beyond the end of the file)\n", h.nsec-min(len(h.sections), maxListed), h.nsec)
		return b.String(), false
	}
	if h.nameCost > maxNameBytes {
		fmt.Fprintf(&b, "  imported libraries and symbols: not read (the symbol names would cost %d bytes to build)\n", h.nameCost)
		return b.String(), false
	}
	f, err := pe.NewFile(r)
	if err != nil {
		s, _ := failed("PE/COFF imports", err)
		return b.String() + s, false
	}
	defer f.Close()
	libs, err := f.ImportedLibraries()
	if err != nil {
		b.WriteString("  imported libraries: not read: " + clip(err.Error()) + "\n")
		return b.String(), false
	}
	if !list(&b, "imported libraries", libs, maxListed) {
		return b.String(), false
	}
	syms, err := f.ImportedSymbols()
	if err != nil {
		b.WriteString("  imported symbols: not read: " + clip(err.Error()) + "\n")
		return b.String(), false
	}
	if !list(&b, "imported symbols", syms, maxSymbols) {
		return b.String(), false
	}
	return b.String(), true
}

// describeMachO: macho.NewFile builds the symbol table's names as it
// parses, so a file built to amplify them is stopped by the isolated
// child's memory limit, not here.
func describeMachO(r io.ReaderAt) (string, bool) {
	var b strings.Builder
	one := func(f *macho.File) bool {
		nsyms := 0
		if f.Symtab != nil {
			nsyms = len(f.Symtab.Syms)
		}
		fmt.Fprintf(&b, "  Mach-O %s %s, %d load commands, %d symbols\n", f.Cpu, f.Type, len(f.Loads), nsyms)
		var secs []string
		for _, s := range f.Sections {
			secs = append(secs, fmt.Sprintf("%s,%s size %d", s.Seg, s.Name, s.Size))
		}
		if !list(&b, "sections", secs, maxListed) {
			return false
		}
		libs, err := f.ImportedLibraries()
		if err != nil || !list(&b, "imported libraries", libs, maxListed) {
			return false
		}
		syms, err := f.ImportedSymbols()
		// A file with no symbol table imports no symbols.
		if err != nil && !strings.Contains(err.Error(), "missing symbol table") {
			return false
		}
		return list(&b, "imported symbols", syms, maxSymbols)
	}
	if fat, err := macho.NewFatFile(r); err == nil {
		defer fat.Close()
		fmt.Fprintf(&b, "  universal binary, %d architectures\n", len(fat.Arches))
		for i, a := range fat.Arches {
			if i == maxArches {
				fmt.Fprintf(&b, "  ... %d more architectures (not shown)\n", len(fat.Arches)-maxArches)
				return b.String(), false
			}
			if !one(a.File) {
				return b.String(), false
			}
		}
		return b.String(), true
	} else if !errors.Is(err, macho.ErrNotFat) {
		return failed("Mach-O universal (a Java class file shares this magic)", err)
	}
	f, err := macho.NewFile(r)
	if err != nil {
		return failed("Mach-O", err)
	}
	defer f.Close()
	if !one(f) {
		return b.String(), false
	}
	return b.String(), true
}

func describeZip(r *bytes.Reader) (string, bool) {
	z, err := zip.NewReader(r, r.Size())
	if err != nil {
		return failed("zip", err)
	}
	var b strings.Builder
	var names []string
	for _, f := range z.File {
		names = append(names, fmt.Sprintf("%s (%d bytes, compressed %d)", f.Name, f.UncompressedSize64, f.CompressedSize64))
	}
	if !list(&b, "zip entries", names, maxListed) {
		return b.String(), false
	}
	return b.String(), true
}

// tarEntries lists entries up to the end of the archive; complete is
// false when it stopped first (a cap or an error).
func tarEntries(r io.Reader) ([]string, bool) {
	tr := tar.NewReader(r)
	var names []string
	for len(names) <= maxListed {
		h, err := tr.Next()
		if err == io.EOF {
			return names, true
		}
		if err != nil {
			return append(names, "(stopped: "+err.Error()+")"), false
		}
		names = append(names, fmt.Sprintf("%s (type %q, %d bytes, mode %o)", h.Name, h.Typeflag, h.Size, h.Mode))
	}
	return names, false
}

func describeTar(r io.Reader) (string, bool) {
	var b strings.Builder
	names, done := tarEntries(r)
	ok := list(&b, "tar entries", names, maxListed)
	return b.String(), done && ok
}

// describeGzip is complete only when the stream decompressed to its end
// within the limit and, if it holds a tar archive, the archive was
// listed in full.
func (rd *renderer) describeGzip(r io.Reader) (string, bool) {
	z, err := gzip.NewReader(r)
	if err != nil {
		return failed("gzip", err)
	}
	defer z.Close()
	var b strings.Builder
	if z.Name != "" {
		fmt.Fprintf(&b, "  gzip header name: %s\n", clip(z.Name))
	}
	limit := min(rd.limit, maxGunzip)
	if limit <= 0 {
		b.WriteString("  not decompressed: " + budgetNote + "\n")
		return b.String(), false
	}
	data, err := io.ReadAll(io.LimitReader(z, limit+1))
	rd.used += min(int64(len(data)), limit)
	switch {
	case int64(len(data)) > limit:
		fmt.Fprintf(&b, "  decompressed: stopped after %d bytes (limit or %s)\n", limit, budgetNote)
		return b.String(), false
	case err != nil:
		fmt.Fprintf(&b, "  decompressed: %d bytes, then an error: %s\n", len(data), clip(err.Error()))
		return b.String(), false
	}
	fmt.Fprintf(&b, "  decompressed: %d bytes, to the end of the stream\n", len(data))
	t := magicType(data)
	fmt.Fprintf(&b, "  decompressed type: %s\n", t)
	if t == "tar archive" {
		names, done := tarEntries(bytes.NewReader(data))
		if !list(&b, "tar entries", names, maxListed) || !done {
			return b.String(), false
		}
	}
	return b.String(), true
}

// describeBuildInfo is complete when the file has no Go build info (it is
// not a Go program) or when all of it was listed.
func describeBuildInfo(r io.ReaderAt) (string, bool) {
	bi, err := buildinfo.Read(r)
	if err != nil {
		// A non-Go program, or an object file (a bare COFF .syso, an ELF
		// relocatable) buildinfo does not read at all: no build info.
		if m := err.Error(); strings.Contains(m, "not a Go executable") || strings.Contains(m, "unrecognized file format") {
			return "  Go build info: none (not a Go program)\n", true
		}
		return failed("Go build info", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "  Go build info: %s, main module %s %s\n", clip(bi.GoVersion), clip(bi.Main.Path), clip(bi.Main.Version))
	var deps []string
	for _, d := range bi.Deps {
		deps = append(deps, d.Path+" "+d.Version)
	}
	if !list(&b, "Go module dependencies built in", deps, maxListed) {
		return b.String(), false
	}
	return b.String(), true
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

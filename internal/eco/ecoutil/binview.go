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
	"unicode/utf8"
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
	return DescribeAs(cur, old, hadOld, budget, Generic)
}

// Sniff is how the file's consumer decides what it is.
type Sniff byte

const (
	// Generic: by magic number, as DescribeBinary always did.
	Generic Sniff = iota
	// LinkerInput: as cmd/link's ldobj does for a .syso or a library or
	// object file: ELF, Mach-O, COFF (machine at bytes 0-1), XCOFF first.
	LinkerInput
)

// DescribeAs is DescribeBinary for a file its consumer sniffs as s.
func DescribeAs(cur, old []byte, hadOld bool, budget *Budget, s Sniff) Description {
	var b strings.Builder
	t, all := typeFor(cur, s)
	fmt.Fprintf(&b, "size: %d bytes\nsha256: %x\ntype: %s\n", len(cur), sha256.Sum256(cur), t)
	if len(all) > 1 {
		fmt.Fprintf(&b, "its bytes match more than one type's magic: %s\n", strings.Join(all, "; "))
	}
	text, complete := structure(cur, budget, s)
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

// magics are the types the gate recognizes by magic number, in the
// order magicType names them. Each is tested on its own: a file that
// matches more than one (a polyglot, read differently by different
// consumers) is never rendered complete.
var magics = []struct {
	name  string
	match func(b []byte) bool
}{
	{"ELF", func(b []byte) bool { return has(b, 0, "\x7fELF") }},
	{"PE (Windows executable or DLL) or DOS MZ", func(b []byte) bool { return has(b, 0, "MZ") }},
	{"Mach-O", func(b []byte) bool {
		return has(b, 0, "\xfe\xed\xfa\xce") || has(b, 0, "\xce\xfa\xed\xfe") || has(b, 0, "\xfe\xed\xfa\xcf") || has(b, 0, "\xcf\xfa\xed\xfe")
	}},
	{"Mach-O universal (fat) binary or Java class file", func(b []byte) bool { return has(b, 0, "\xca\xfe\xba\xbe") }},
	{"ar archive (static library, e.g. a Go .a or C .a)", func(b []byte) bool { return has(b, 0, "!<arch>\n") }},
	{"zip archive", func(b []byte) bool { return has(b, 0, "PK\x03\x04") || has(b, 0, "PK\x05\x06") }},
	{"gzip", func(b []byte) bool { return has(b, 0, "\x1f\x8b") }},
	{"tar archive", func(b []byte) bool { return has(b, 257, "ustar") }},
	{"WebAssembly module", func(b []byte) bool { return has(b, 0, "\x00asm") }},
	{"PNG image", func(b []byte) bool { return has(b, 0, "\x89PNG\r\n\x1a\n") }},
	{"JPEG image", func(b []byte) bool { return has(b, 0, "\xff\xd8\xff") }},
	{"GIF image", func(b []byte) bool { return has(b, 0, "GIF87a") || has(b, 0, "GIF89a") }},
	{"PDF document", func(b []byte) bool { return has(b, 0, "%PDF-") }},
	{"bzip2", func(b []byte) bool { return has(b, 0, "BZh") }},
	{"xz", func(b []byte) bool { return has(b, 0, "\xfd7zXZ\x00") }},
	{"zstd", func(b []byte) bool { return has(b, 0, "\x28\xb5\x2f\xfd") }},
	{"7-zip archive", func(b []byte) bool { return has(b, 0, "7z\xbc\xaf\x27\x1c") }},
	{"SQLite database", func(b []byte) bool { return has(b, 0, "SQLite format 3\x00") }},
	{"COFF object", func(b []byte) bool { return coffMachine(b) != "" }},
	{"XCOFF object", func(b []byte) bool { return has(b, 0, "\x01\xdf") || has(b, 0, "\x01\xf7") }},
}

func has(b []byte, off int, magic string) bool {
	return len(b) >= off+len(magic) && string(b[off:off+len(magic)]) == magic
}

// magicTypes is every type whose magic b matches.
func magicTypes(b []byte) []string {
	var out []string
	for _, m := range magics {
		if m.match(b) {
			name := m.name
			if name == "COFF object" {
				name += " (" + coffMachine(b) + ")"
			}
			out = append(out, name)
		}
	}
	return out
}

// magicType names a file by its leading bytes: the first type it matches,
// http.DetectContentType's guess if none.
func magicType(b []byte) string {
	if ts := magicTypes(b); len(ts) > 0 {
		return ts[0]
	}
	return "unknown magic; content sniffing says " + http.DetectContentType(b)
}

// typeFor is the type the consumer s sees, and every type b matches.
func typeFor(b []byte, s Sniff) (string, []string) {
	all := magicTypes(b)
	if s == LinkerInput {
		for _, want := range []string{"ELF", "Mach-O", "COFF object", "XCOFF object"} {
			for _, t := range all {
				if strings.HasPrefix(t, want) {
					return t, all
				}
			}
		}
	}
	return magicType(b), all
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
func structure(b []byte, budget *Budget, sn Sniff) (string, bool) {
	t, all := typeFor(b, sn)
	switch {
	case len(all) > 1:
		return "  not parsed: a file of more than one type is read differently by different tools\n", false
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
		res = iso.run(b, limit, sn)
	} else {
		res = structureLocal(b, limit, sn)
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
// building names, mirroring debug/elf: the first section of each type
// (SectionByType), fixed record sizes whatever a section's Entsize says
// (24/16 bytes per symbol, 16/8 per dynamic entry), every .dynsym name and
// DT_NEEDED string exactly, and, when a .gnu.version table makes
// ImportedSymbols read them, the .gnu.version_d and .gnu.version_r names
// walked exactly as debug/elf walks them (each counted at its upper bound,
// the rest of the string table). A section debug/elf would read but that
// is not in the file (SHT_NOBITS, or past its end) would make it allocate
// its declared size: that costs more than any limit. The walk stops once
// the cost passes limit, so it is bounded however the tables are built.
func elfNameCost(f *elf.File, raw []byte, limit uint64) uint64 {
	over := limit + 1
	data := func(s *elf.Section) ([]byte, bool) {
		if s == nil {
			return nil, true
		}
		if s.Type == elf.SHT_NOBITS {
			return nil, s.Size == 0
		}
		b := sectionBytes(raw, s.Offset, s.Size)
		return b, b != nil
	}
	strOf := func(s *elf.Section) ([]byte, bool) {
		if s == nil {
			return nil, true
		}
		if int(s.Link) >= len(f.Sections) {
			return nil, true // debug/elf fails; nothing built
		}
		return data(f.Sections[s.Link])
	}
	symSize, dynSize := uint64(24), uint64(16)
	if f.Class == elf.ELFCLASS32 {
		symSize, dynSize = 16, 8
	}
	var cost uint64
	dynsym := f.SectionByType(elf.SHT_DYNSYM)
	syms, ok1 := data(dynsym)
	dynstr, ok2 := strOf(dynsym)
	if !ok1 || !ok2 {
		return over
	}
	var offs []uint64
	for at := uint64(0); at+symSize <= uint64(len(syms)); at += symSize {
		offs = append(offs, uint64(f.ByteOrder.Uint32(syms[at:])))
	}
	cost += nameBytes(dynstr, offs) + uint64(len(offs))

	dyn := f.SectionByType(elf.SHT_DYNAMIC)
	dd, ok1 := data(dyn)
	dstr, ok2 := strOf(dyn)
	if !ok1 || !ok2 {
		return over
	}
	offs = offs[:0]
	for at := uint64(0); at+dynSize <= uint64(len(dd)); at += dynSize {
		var tag, val uint64
		if dynSize == 16 {
			tag, val = f.ByteOrder.Uint64(dd[at:]), f.ByteOrder.Uint64(dd[at+8:])
		} else {
			tag, val = uint64(f.ByteOrder.Uint32(dd[at:])), uint64(f.ByteOrder.Uint32(dd[at+4:]))
		}
		if elf.DynTag(tag) == elf.DT_NEEDED {
			offs = append(offs, val)
		}
	}
	cost += nameBytes(dstr, offs) + uint64(len(offs))
	if cost > limit || f.SectionByType(elf.SHT_GNU_VERSYM) == nil {
		return cost
	}
	if _, ok := data(f.SectionByType(elf.SHT_GNU_VERSYM)); !ok {
		return over
	}
	name := func(off uint64) uint64 { // upper bound of one getString, plus one
		if off >= uint64(len(dynstr)) {
			return 1
		}
		return uint64(len(dynstr)) - off + 1
	}
	// dynamicVersions (.gnu.version_d): 20-byte entries, 8-byte aux.
	vd, ok := data(f.SectionByType(elf.SHT_GNU_VERDEF))
	if !ok {
		return over
	}
	for i := 0; i+20 <= len(vd); {
		if f.ByteOrder.Uint16(vd[i:]) != 1 {
			break // debug/elf fails here
		}
		cnt := int(f.ByteOrder.Uint16(vd[i+6:]))
		aux := int(f.ByteOrder.Uint32(vd[i+12:]))
		next := int(f.ByteOrder.Uint32(vd[i+16:]))
		if cnt == 0 {
			break
		}
		for c, j := 0, i+aux; c < cnt && j >= 0 && j+8 <= len(vd); c++ {
			if cost += name(uint64(f.ByteOrder.Uint32(vd[j:]))); cost > limit {
				return cost
			}
			vnext := int(f.ByteOrder.Uint32(vd[j+4:]))
			if vnext == 0 {
				break
			}
			j += vnext
		}
		if next == 0 {
			break
		}
		i += next
	}
	// dynamicVersionNeeds (.gnu.version_r): 16-byte entries, 16-byte aux.
	vn, ok := data(f.SectionByType(elf.SHT_GNU_VERNEED))
	if !ok {
		return over
	}
	for i := 0; i+16 <= len(vn); {
		if f.ByteOrder.Uint16(vn[i:]) != 1 {
			break
		}
		cnt := int(f.ByteOrder.Uint16(vn[i+2:]))
		if cost += name(uint64(f.ByteOrder.Uint32(vn[i+4:]))); cost > limit {
			return cost
		}
		aux := int(f.ByteOrder.Uint32(vn[i+8:]))
		next := int(f.ByteOrder.Uint32(vn[i+12:]))
		for c, j := 0, i+aux; c < cnt && j >= 0 && j+16 <= len(vn); c++ {
			if cost += name(uint64(f.ByteOrder.Uint32(vn[j+8:]))); cost > limit {
				return cost
			}
			anext := int(f.ByteOrder.Uint32(vn[j+12:]))
			if anext == 0 {
				break
			}
			j += anext
		}
		if next == 0 {
			break
		}
		i += next
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
	var progs []string
	dynamicProg := false
	for _, p := range f.Progs {
		progs = append(progs, fmt.Sprintf("%s flags %s offset 0x%x size %d", p.Type, p.Flags, p.Off, p.Filesz))
		dynamicProg = dynamicProg || p.Type == elf.PT_DYNAMIC || p.Type == elf.PT_INTERP
	}
	if !list(&b, "program headers", progs, maxListed) {
		return b.String(), false
	}
	// debug/elf reads imported libraries and symbols from sections only:
	// with no section headers, or a dynamic segment but no SHT_DYNAMIC
	// section, what the loader would load is not what the gate read.
	if len(f.Sections) <= 1 {
		b.WriteString("  no section headers: imports not read (the loader would still use the program headers)\n")
		return b.String(), false
	}
	if dynamicProg && f.SectionByType(elf.SHT_DYNAMIC) == nil {
		b.WriteString("  a dynamic or interpreter segment without a dynamic section: imports not read\n")
		return b.String(), false
	}
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
	if c := elfNameCost(f, raw, maxNameBytes); c > maxNameBytes {
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

// maxDepth bounds nesting (a gzip of a tar of a zip...); maxInnerText is
// the largest plain-text member quoted whole inside a rendering.
const (
	maxDepth     = 3
	maxInnerText = 64 << 10
)

// PlainText reports valid UTF-8 with no control character but tab,
// newline and carriage return (C0, DEL and C1 all count as control).
func PlainText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return false
		}
	}
	return true
}

func structureLocal(b []byte, limit int64, sn Sniff) childResult {
	rd := &renderer{limit: limit}
	text, complete := rd.render(b, 0, sn)
	return childResult{Text: text, Complete: complete, Used: rd.used}
}

// render describes b's structure, at nesting depth. It is complete only
// if the describer for b's type reached its end, and, for an archive or
// a compressed stream, every member (or the stream's content) is itself
// complete or plain text quoted whole.
func (rd *renderer) render(b []byte, depth int, sn Sniff) (string, bool) {
	r := bytes.NewReader(b)
	var text string
	var complete, exe bool
	t, all := typeFor(b, sn)
	if len(all) > 1 {
		return "  not parsed: its bytes match more than one type's magic (" + strings.Join(all, "; ") + ")\n", false
	}
	switch {
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
		text, complete = step("zip", func() (string, bool) { return rd.describeZip(r, depth) })
	case t == "tar archive":
		text, complete = step("tar", func() (string, bool) { return rd.describeTar(r, depth) })
	case t == "gzip":
		text, complete = step("gzip", func() (string, bool) { return rd.describeGzip(r, depth) })
	default:
		return "  not parsed: the gate has no parser for this type (" + t + ")\n", false
	}
	if exe && complete {
		// Only after a complete executable rendering: for ELF that means
		// no compressed section, which reading build info would inflate.
		bi, ok := step("Go build info", func() (string, bool) { return describeBuildInfo(r) })
		text += bi
		complete = ok
	}
	return text, complete
}

// inner renders the content of an archive member or a compressed stream:
// plain text is quoted whole (up to maxInnerText), anything else is
// rendered one level deeper, indented.
func (rd *renderer) inner(name string, data []byte, depth int) (string, bool) {
	var b strings.Builder
	fmt.Fprintf(&b, "  content of %s: %d bytes, type %s\n", clip(name), len(data), magicType(data))
	switch {
	case PlainText(data):
		if len(data) > maxInnerText {
			fmt.Fprintf(&b, "  plain text larger than %d bytes: not shown\n", maxInnerText)
			return b.String(), false
		}
		b.WriteString("  plain text, in full:\n")
		for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
			b.WriteString("      > " + line + "\n")
		}
		return b.String(), true
	case depth+1 >= maxDepth:
		b.WriteString("  not read: nested too deep\n")
		return b.String(), false
	}
	text, ok := rd.render(data, depth+1, Generic)
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		b.WriteString("    " + line + "\n")
	}
	return b.String(), ok
}

// take reads up to the decompression limit left from r; ok is false when
// the content is longer.
func (rd *renderer) take(r io.Reader) ([]byte, bool, error) {
	left := rd.limit - rd.used
	if left <= 0 {
		return nil, false, nil
	}
	data, err := io.ReadAll(io.LimitReader(r, left+1))
	rd.used += min(int64(len(data)), left)
	if int64(len(data)) > left {
		return nil, false, err
	}
	return data, true, err
}

func (rd *renderer) describeZip(r *bytes.Reader, depth int) (string, bool) {
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
	if why := zipAccounted(r, z); why != "" {
		b.WriteString("  zip: " + why + "\n")
		return b.String(), false
	}
	for _, f := range z.File {
		// A directory entry is skipped only if it holds nothing.
		if f.FileInfo().IsDir() && f.CompressedSize64 == 0 && f.UncompressedSize64 == 0 {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			b.WriteString("  " + clip(f.Name) + ": not read: " + clip(err.Error()) + "\n")
			return b.String(), false
		}
		data, ok, err := rd.take(rc)
		rc.Close()
		switch {
		case err != nil:
			fmt.Fprintf(&b, "  %s: not read: %s\n", clip(f.Name), clip(err.Error()))
			return b.String(), false
		case !ok:
			fmt.Fprintf(&b, "  %s: not read in full (%s)\n", clip(f.Name), budgetNote)
			return b.String(), false
		}
		text, ok := rd.inner(f.Name, data, depth)
		b.WriteString(text)
		if !ok {
			return b.String(), false
		}
	}
	return b.String(), true
}

// zipAccounted checks that the archive's entries and directories account
// for every byte: the first local header at offset 0, each entry's data
// right after its header, the central directory right after the last
// entry (and its data descriptor), the end record right after the central
// directory, and nothing after the end record but its comment. It returns
// why not, or "".
func zipAccounted(r *bytes.Reader, z *zip.Reader) string {
	b := make([]byte, r.Size())
	if _, err := r.ReadAt(b, 0); err != nil {
		return "unreadable"
	}
	e := bytes.LastIndex(b, []byte("PK\x05\x06"))
	if e < 0 || e+22 > len(b) {
		return "no end-of-central-directory record"
	}
	comment := int(binary.LittleEndian.Uint16(b[e+20:]))
	cdSize := uint64(binary.LittleEndian.Uint32(b[e+12:]))
	cdOff := uint64(binary.LittleEndian.Uint32(b[e+16:]))
	switch {
	case e+22+comment != len(b):
		return "bytes after the end-of-central-directory record and its comment"
	case cdOff == 0xffffffff || cdSize == 0xffffffff:
		return "zip64 layout, which the gate does not account for"
	case cdOff+cdSize != uint64(e):
		return "bytes between the central directory and its end record"
	}
	pos := uint64(0)
	for _, f := range z.File {
		if pos+30 > uint64(len(b)) || string(b[pos:pos+4]) != "PK\x03\x04" {
			return "data before or between the local file headers"
		}
		hdr := 30 + uint64(binary.LittleEndian.Uint16(b[pos+26:])) + uint64(binary.LittleEndian.Uint16(b[pos+28:]))
		data, err := f.DataOffset()
		if err != nil || uint64(data) != pos+hdr {
			return "an entry whose data does not follow its local header"
		}
		pos = uint64(data) + f.CompressedSize64
		if f.Flags&0x8 != 0 { // data descriptor
			if pos+4 <= uint64(len(b)) && string(b[pos:pos+4]) == "PK\x07\x08" {
				pos += 4
			}
			pos += 12
		}
	}
	if pos != cdOff {
		return "bytes between the last entry and the central directory"
	}
	return ""
}

// describeTar lists every entry to the end of the archive, renders the
// content of every entry that has any, and accounts for every byte: what
// the reader consumed plus an all-zero tail is the whole file. Entry
// types it does not model, or a header-only type with a size, make the
// rendering incomplete.
func (rd *renderer) describeTar(r *bytes.Reader, depth int) (string, bool) {
	var b strings.Builder
	tr := tar.NewReader(r)
	for n := 0; ; n++ {
		h, err := tr.Next()
		if err == io.EOF {
			rest := make([]byte, r.Len())
			r.Read(rest)
			if len(bytes.Trim(rest, "\x00")) > 0 {
				fmt.Fprintf(&b, "  tar: %d bytes after the end of the archive are not padding\n", len(rest))
				return b.String(), false
			}
			return b.String(), true
		}
		if err != nil {
			b.WriteString("  tar: stopped: " + clip(err.Error()) + "\n")
			return b.String(), false
		}
		if n == maxListed {
			b.WriteString("  tar: more entries than the gate lists\n")
			return b.String(), false
		}
		fmt.Fprintf(&b, "  tar entry %s (type %q, %d bytes, mode %o)\n", clip(h.Name), h.Typeflag, h.Size, h.Mode)
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeCont, tar.TypeGNUSparse:
			// Content: read and rendered below.
		case tar.TypeLink, tar.TypeSymlink, tar.TypeChar, tar.TypeBlock, tar.TypeDir, tar.TypeFifo:
			if h.Size > 0 {
				b.WriteString("  tar: a header-only entry with a size; what tools do with it differs\n")
				return b.String(), false
			}
			continue
		default:
			b.WriteString("  tar: an entry type the gate does not model\n")
			return b.String(), false
		}
		data, ok, err := rd.take(tr)
		if !ok || err != nil {
			fmt.Fprintf(&b, "  %s: not read in full\n", clip(h.Name))
			return b.String(), false
		}
		text, ok := rd.inner(h.Name, data, depth)
		b.WriteString(text)
		if !ok {
			return b.String(), false
		}
	}
}

// describeGzip is complete only when the stream decompressed to its end
// within the limit and its content is itself complete or plain text.
func (rd *renderer) describeGzip(r io.Reader, depth int) (string, bool) {
	z, err := gzip.NewReader(r)
	if err != nil {
		return failed("gzip", err)
	}
	defer z.Close()
	var b strings.Builder
	if z.Name != "" {
		fmt.Fprintf(&b, "  gzip header name: %s\n", clip(z.Name))
	}
	data, ok, err := rd.take(z)
	switch {
	case !ok:
		fmt.Fprintf(&b, "  decompressed: stopped at the limit (%s)\n", budgetNote)
		return b.String(), false
	case err != nil:
		fmt.Fprintf(&b, "  decompressed: %d bytes, then an error: %s\n", len(data), clip(err.Error()))
		return b.String(), false
	}
	fmt.Fprintf(&b, "  decompressed: %d bytes, to the end of the stream\n", len(data))
	text, ok := rd.inner("the stream", data, depth)
	b.WriteString(text)
	return b.String(), ok
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

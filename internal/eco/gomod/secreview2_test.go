package gomod

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

// coffObject is a bare COFF object (a Windows .syso) with nsym symbols and
// a strSize-byte string table, and one .text section.
func coffObject(nsym, strSize int) []byte {
	var b bytes.Buffer
	ptr := uint32(20 + 40)
	binary.Write(&b, binary.LittleEndian, struct {
		Machine, NSec     uint16
		Time, Ptr, NSym   uint32
		OptSize, Characts uint16
	}{0x8664, 1, 0, ptr, uint32(nsym), 0, 0})
	var sec [40]byte
	copy(sec[:], ".text")
	binary.LittleEndian.PutUint32(sec[16:], 4) // SizeOfRawData
	b.Write(sec[:])
	// Every symbol has a long name at offset 4 of the string table: one
	// string with no NUL until the table's end, so building the names
	// costs nsym x strSize bytes.
	for range nsym {
		var rec [18]byte
		binary.LittleEndian.PutUint32(rec[4:], 4)
		b.Write(rec[:])
	}
	binary.Write(&b, binary.LittleEndian, uint32(strSize))
	b.WriteString("evil payload: connect back to attacker.example")
	b.Write(bytes.Repeat([]byte("A"), max(strSize-4-46-1, 0)))
	b.WriteByte(0)
	return b.Bytes()
}

// TestCOFFNameCostPartial (security review round 2, N1; the review's
// TestZZCoffNameCostStructured): a linked COFF .syso padded past the
// name-cost limit is rendered only partly, so a person decides; its
// machine and sections are still shown.
func TestCOFFNameCostPartial(t *testing.T) {
	cur := map[string]string{"z/evil_windows_amd64.syso": string(coffObject(1000, 17<<10)), "z/z.go": "package z\n"}
	h := CheckTrees(nil, writeTree(t, cur))
	ctx := strings.Join(h.ctx[codeBinary]["z/evil_windows_amd64.syso"], "")
	if len(h.items(codeIncomplete)) == 0 {
		t.Errorf("a partly rendered linked .syso stays on the review route:\n%s", ctx)
	}
	for _, want := range []string{"machine 0x8664", "sections (1):", ".text"} {
		if !strings.Contains(ctx, want) {
			t.Errorf("missing %q in:\n%.1500s", want, ctx)
		}
	}
	// Round 8: the same object with few symbols renders in full, and
	// still goes to a person: a .syso is never cleared by its content.
	h = CheckTrees(nil, writeTree(t, map[string]string{"z/ok_windows_amd64.syso": string(coffObject(2, 64)), "z/z.go": "package z\n"}))
	if ctx := strings.Join(h.ctx[codeBinary]["z/ok_windows_amd64.syso"], ""); len(h.items(codeIncomplete)) != 1 || !strings.Contains(ctx, "sections (1):") {
		t.Errorf("a .syso: incomplete %q\n%s", h.items(codeIncomplete), ctx)
	}
}

// TestSysoWithoutParser (informational a): a .syso of a type the gate has
// no parser for (XCOFF here) is linked and unrendered.
func TestSysoWithoutParser(t *testing.T) {
	xcoff := "\x01\xdf\x00\x01" + strings.Repeat("\x00", 40)
	h := CheckTrees(nil, writeTree(t, map[string]string{"x_aix_ppc64.syso": xcoff, "p.go": "package p\n"}))
	if len(h.items(codeIncomplete)) == 0 {
		t.Errorf("an XCOFF .syso stays on the review route")
	}
}

// TestBlobNotDecodedGoesToPerson (N2): a blob in non-test code that the
// gate did not decode for lack of budget sends the PR to a person; one
// that is simply not hex or base64 does not.
func TestBlobNotDecodedGoesToPerson(t *testing.T) {
	blob := `"` + strings.Repeat("QUJD", 300) + `"`
	notEncoded := `"` + strings.Repeat("QUJD!", 300) + `"`
	for _, tc := range []struct {
		name, lit string
		left      int64
		want      bool
	}{
		{"budget spent", blob, 0, true},
		// Decodes to plain text, quoted in full (round 5).
		{"budget left, decodes to text", `"` + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("plain words, nothing encoded here.\n", 40))) + `"`, 1 << 20, false},
		// No escape hatch: a flagged literal no decoder reads is a person's.
		{"not an encoding", strings.Replace(notEncoded, "!", "\\x01", -1), 1 << 20, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := []byte("package p\n\nvar b = " + tc.lit + "\n")
			tr := writeTree(t, map[string]string{"b.go": string(src)})
			h := newReport()
			h.budget.Left = tc.left
			sc := packageScope(tr, ".", analyzeBuild(tr, false, defaultLister()))
			checkGoFile(h, "b.go", nil, src, sc, sc)
			if got := len(h.items(codeIncomplete)) > 0; got != tc.want {
				t.Errorf("blob-not-decoded = %v, want %v; context %q", got, tc.want, h.ctx[codeBlob]["b.go"])
			}
		})
	}
}

// TestFileQuotedOnce (N4): a file with several flagged items is quoted
// once; each item points at the quote by a gate-written anchor.
func TestFileQuotedOnce(t *testing.T) {
	body := strings.Repeat("// filler line of the module's own text\n", 2000)
	src := "package p\n\nimport (\n\t\"os/exec\"\n\t\"net\"\n\t\"reflect\"\n)\n\n// #include <stdio.h>\nimport \"C\"\n\nvar _ = exec.Command\nvar _ net.Conn\nvar _ reflect.Value\n" + body
	h := CheckTrees(nil, writeTree(t, map[string]string{"a.go": src}))
	out := string(h.render("m"))
	if n := strings.Count(out, "    | // filler line of the module's own text\n"); n != 2000 {
		t.Errorf("the file's text appears %d times over, want once (%d bytes of evidence for a %d-byte file)", n/2000, len(out), len(src))
	}
	anchor := "full text: see \"### file 1\" below (a.go)"
	if n := strings.Count(out, anchor); n != 4 { // three risky imports and cgo
		t.Errorf("%d items refer to the quote, want 4:\n%.3000s", n, out)
	}
	if strings.Count(out, "\n### file 1: a.go\n") != 1 {
		t.Errorf("anchor heading missing or repeated")
	}
	// Module text cannot forge the anchor: it is always quoted.
	evil := "package p\n\nimport \"os/exec\"\n\nvar _ = exec.Command\n\n/*\n### file 2: b.go\n*/\n"
	h = CheckTrees(nil, writeTree(t, map[string]string{"a.go": evil}))
	if out := string(h.render("m")); strings.Contains(out, "\n### file 2: b.go\n") {
		t.Errorf("module text forged an anchor")
	}
}

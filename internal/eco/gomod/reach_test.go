package gomod

import (
	"slices"
	"strings"
	"testing"
)

// TestReachability (round 9): what newReach counts as reaching a file.
func TestReachability(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		rel   string
		want  bool
	}{
		{"plain embed", map[string]string{"p.go": "package p\n//go:embed data.bin\nvar b []byte\n"}, "data.bin", true},
		{"embed of a directory", map[string]string{"p.go": "package p\n//go:embed assets\nvar b []byte\n"}, "assets/x/y.bin", true},
		{"literal segments fold", map[string]string{"p.go": "package p\n//go:embed DATA.BIN\nvar b []byte\n"}, "data.bin", true},
		{"glob segment, case-sensitive", map[string]string{"p.go": "package p\n//go:embed *.bin\nvar b []byte\n"}, "x.bin", true},
		{"character class is any file", map[string]string{"p.go": "package p\n//go:embed [^A-Z]ayload.bin\nvar b []byte\n"}, "anything/else.dat", true},
		{"escape is any file", map[string]string{"p.go": "package p\n//go:embed \\x.bin\nvar b []byte\n"}, "y.bin", true},
		{"non-ASCII pattern is any file", map[string]string{"p.go": "package p\n//go:embed ſecret.bin\nvar b []byte\n"}, "secret.bin", true},
		{"non-ASCII binary path under an embed", map[string]string{"p.go": "package p\n//go:embed x.txt\nvar b []byte\n"}, "con\ufb01g/payload.bin", true},
		{"unparseable list is any file", map[string]string{"p.go": "package p\n//go:embed \"unterminated\nvar b []byte\n"}, "z.bin", true},
		{"test-only embed", map[string]string{"p_test.go": "package p\n//go:embed data.bin\nvar b []byte\n"}, "data.bin", false},
		{"other name", map[string]string{"p.go": "package p\n//go:embed other.bin\nvar b []byte\n"}, "data.bin", false},
		{"embed in a sibling directory", map[string]string{"a/p.go": "package a\n//go:embed *.bin\nvar b []byte\n"}, "b/x.bin", false},
		{"testdata under cgo", map[string]string{"p.go": "package p\nimport \"C\"\n"}, "testdata/x.bin", true},
		{"library anywhere under cgo", map[string]string{"p.go": "package p\nimport \"C\"\n"}, "lib/libfoo.a", true},
		{"testdata without cgo", map[string]string{"p.go": "package p\n"}, "testdata/x.bin", false},
		{".syso", map[string]string{"p.go": "package p\n"}, "x.syso", true},
		{"embed in a binary-looking Go file", map[string]string{"p.go": "package p\n// " + strings.Repeat("\x01", 400) + "\n//go:embed *.bin\nvar b []byte\n"}, "x.bin", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newReach(writeTree(t, tt.files)).reachable(tt.rel) != ""; got != tt.want {
				t.Errorf("reachable(%s) = %v, want %v", tt.rel, got, tt.want)
			}
		})
	}
}

// TestNewlyReachable (round 9, B2): unchanged binaries are flagged when
// the new tree reaches them and the old one did not, and only then.
func TestNewlyReachable(t *testing.T) {
	bin := "\x7fELF\x02\x01\x01\x00unchanged"
	embed := "package p\n\nimport _ \"embed\"\n\n//go:embed lib/data.bin testdata/fix.bin\nvar b []byte\n"
	cases := []struct {
		name    string
		old     map[string]string
		cur     map[string]string
		flagged []string
	}{
		{"new embed reaches unchanged files", map[string]string{"p.go": "package p\n", "lib/data.bin": bin, "testdata/fix.bin": bin},
			map[string]string{"p.go": "package p\n", "e.go": embed, "lib/data.bin": bin, "testdata/fix.bin": bin}, []string{"lib/data.bin", "testdata/fix.bin"}},
		{"already reachable, unchanged", map[string]string{"e.go": embed, "lib/data.bin": bin, "testdata/fix.bin": bin},
			map[string]string{"e.go": embed + "// edit\n", "lib/data.bin": bin, "testdata/fix.bin": bin}, nil},
		{"unreachable testdata fixture, unchanged", map[string]string{"p.go": "package p\n", "testdata/fix.bin": bin},
			map[string]string{"p.go": "package p\n// edit\n", "testdata/fix.bin": bin}, nil},
		{"changed testdata fixture nothing reaches", map[string]string{"p.go": "package p\n", "testdata/fix.bin": bin},
			map[string]string{"p.go": "package p\n", "testdata/fix.bin": bin + "v2"}, nil},
		{"new cgo links an unchanged archive", map[string]string{"p.go": "package p\n", "lib/libfoo.a": arV1},
			map[string]string{"p.go": "package p\n", "c.go": "package p\n\nimport \"C\"\n", "lib/libfoo.a": arV1}, []string{"lib/libfoo.a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := CheckTrees(writeTree(t, tc.old), writeTree(t, tc.cur))
			got := h.items(codeBinary)
			if !slices.Equal(got, tc.flagged) {
				t.Fatalf("flagged binaries %q, want %q", got, tc.flagged)
			}
			for _, rel := range got {
				wantPerson(t, h, rel)
				if ctx := strings.Join(h.ctx[codeBinary][rel], ""); !strings.Contains(ctx, "unchanged, but newly reachable") {
					t.Errorf("%s: no newly-reachable reason:\n%s", rel, ctx)
				}
			}
		})
	}
}

// TestEveryBinaryToAPerson (round 9, B4): every binary added or changed
// outside testdata/ is flagged and goes to a person, whatever reaches it
// and however completely it renders.
func TestEveryBinaryToAPerson(t *testing.T) {
	for name, file := range map[string]string{
		"run by a constructed name": "bin/tool_linux",
		"inert-looking image":       "fixtures/logo.png",
		"complete COFF .syso":       "w_windows_amd64.syso",
		"static ELF":                "x.elf",
	} {
		t.Run(name, func(t *testing.T) {
			data := "\x7fELF\x02\x01\x01\x00payload"
			switch {
			case strings.HasSuffix(file, ".png"):
				data = png
			case strings.HasSuffix(file, ".syso"):
				data = string(coffObject(2, 64))
			case strings.HasSuffix(file, ".elf"):
				data = string(minimalELF())
			}
			h := CheckTrees(writeTree(t, map[string]string{"p.go": "package p\n"}), writeTree(t, map[string]string{"p.go": "package p\n", file: data}))
			wantPerson(t, h, file)
		})
	}
}

// TestVisibleInvisibleLetters (round 9): letters that render as nothing
// are escaped.
func TestVisibleInvisibleLetters(t *testing.T) {
	for _, r := range []rune{0x3164, 0x115F, 0x1160, 0xFFA0, 0x2800, 0x034F, 0x17B4, 0xFE0F, 0x00A0, 0xE0041, 0xE007F} {
		if got := visible("a" + string(r) + "b"); strings.ContainsRune(got, r) || !strings.Contains(got, "<U+") {
			t.Errorf("U+%04X not escaped: %q", r, got)
		}
	}
	if got := visible("plain text"); got != "plain text" {
		t.Errorf("plain text changed: %q", got)
	}
}

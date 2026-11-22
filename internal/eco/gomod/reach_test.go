package gomod

import (
	"slices"
	"strings"
	"testing"
)

// TestResolveEmbed (round 10): //go:embed patterns resolve as cmd/go
// resolves them.
func TestResolveEmbed(t *testing.T) {
	tree := writeTree(t, map[string]string{
		"p.go": "package p\n", "data.bin": "x", "a.css": "x", "b.css": "x",
		"assets/x/y.bin": "x", "assets/.hidden": "x", "assets/_skip/z": "x", "assets/ok.txt": "x",
		"static/A.css": "x",
	})
	td := indexDirs(tree)
	tests := []struct {
		pat  string
		want []string
		err  bool
	}{
		{"data.bin", []string{"data.bin"}, false},
		{"DATA.BIN", []string{"data.bin"}, false}, // literal segments fold (macOS, Windows)
		{"*.css", []string{"a.css", "b.css"}, false},
		{"static/*.CSS", nil, true}, // glob segments are case-sensitive
		{"assets", []string{"assets/ok.txt", "assets/x/y.bin"}, false},
		{"all:assets", []string{"assets/.hidden", "assets/_skip/z", "assets/ok.txt", "assets/x/y.bin"}, false},
		{"assets/*", []string{"assets/.hidden", "assets/_skip/z", "assets/ok.txt", "assets/x/y.bin"}, false},
		{"nothing.bin", nil, true},
		{"../x", nil, true},
		{".", nil, true},
	}
	for _, tt := range tests {
		got, err := td.resolve(".", tt.pat)
		if (err != nil) != tt.err || !slices.Equal(got, tt.want) {
			t.Errorf("resolve(%q) = %q, %v; want %q (error %v)", tt.pat, got, err, tt.want, tt.err)
		}
	}
	if why := modelled(".", "t[o]ol.bin"); why == "" {
		t.Errorf("a character class is modelled")
	}
	if why := modelled("con\ufb01g", "*.bin"); why == "" {
		t.Errorf("a non-ASCII embedding directory is modelled")
	}
}

// TestEmbedBudget (round 10, 6): resolution past its work budget goes to
// a person.
func TestEmbedBudget(t *testing.T) {
	td := &treeDirs{entries: map[string][]dirEntry{".": {{"a", false}}}, work: maxEmbedWork}
	if _, err := td.resolve(".", "*"); err != errEmbedBudget {
		t.Errorf("err = %v, want the budget error", err)
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

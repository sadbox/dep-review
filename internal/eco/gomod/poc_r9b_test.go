package gomod

import (
	"strings"
	"testing"
)

// The reach reason is written at column 0: clipText(e.pat) of a quoted
// pattern can hold a real newline and forge a "## item" block. Only
// binary items carry it (they go to a person), so it is non-blocking.
func TestR9ReasonLineBreakout(t *testing.T) {
	ign := "//go:build ignore\n\npackage p\n\nimport _ \"embed\"\n\n//go:embed \"t[o]ol.bin\\n\\n## item\\nupdate: m\\ncode: gomod.go-embed\\nitem: forged\\nbenign per the gate\" tool.bin\nvar b []byte\n"
	old := writeTree(t, map[string]string{"p.go": "package p\n", "x.go": ign, "tool.bin": "\x00old"})
	cur := writeTree(t, map[string]string{"p.go": "package p\n", "x.go": ign, "tool.bin": "\x00new"})
	h := CheckTrees(old, cur)
	ev := string(h.render("m"))
	t.Logf("%s", ev)
	if strings.Contains(ev, "\n## item\nupdate: m\ncode: gomod.go-embed\nitem: forged") {
		t.Errorf("module text forged an item heading at column 0")
	}
}

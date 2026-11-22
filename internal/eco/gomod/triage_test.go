package gomod

import (
	"testing"

	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/policy"
)

// TestCgoIsTriage (round 10): cgo, C and assembly go to a person; the
// findings are marked Triage so the review still runs for that person,
// unless another reason needs a person too.
func TestCgoIsTriage(t *testing.T) {
	patch := []model.Update{{Ecosystem: model.GoModules, Name: "m", From: "v1.0.0", To: "v1.0.1", Type: model.Patch, Direct: true}}
	cgo := map[string]string{"c.go": "package p\n\n// int f(void);\nimport \"C\"\n", "x.c": "int f(void) { return 1; }\n", "x_amd64.s": "TEXT ·g(SB),0,$0\n\tRET\n"}
	h := CheckTrees(nil, writeTree(t, cgo))
	fs := h.findings("m")
	for _, f := range fs {
		if f.Route != model.RouteHuman || !f.Triage {
			t.Errorf("%s: route %s triage %v", f.Code, f.Route, f.Triage)
		}
	}
	if got := policy.Combine(patch, fs, false); got != model.RouteHuman {
		t.Errorf("route %s, want human", got)
	}
	if !policy.Triage(patch, fs, false) {
		t.Errorf("cgo-only findings are not triage")
	}
	// The items stay in the flagged list for the reviewer.
	if len(h.flagged("m")) != 3 {
		t.Errorf("flagged %v", h.flagged("m"))
	}
	// An unparseable Go file is a person's alone: no triage.
	cgo["bad.go"] = "package p\nfunc {{{\n"
	if policy.Triage(patch, CheckTrees(nil, writeTree(t, cgo)).findings("m"), false) {
		t.Errorf("triage despite an unparseable file")
	}
}

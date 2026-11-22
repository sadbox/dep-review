package gomod

import (
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
)

// TestSharedClock (N3, N2): one rendering clock is shared by every module
// of a fetch, and it starts with the first rendering, not when a
// module's report is made.
func TestSharedClock(t *testing.T) {
	clock := ecoutil.NewClock(time.Hour)
	a, b := newReportWith(clock), newReportWith(clock)
	if !clock.Started().IsZero() {
		t.Errorf("the clock started before any rendering")
	}
	if !a.budget.Take(1) || !b.budget.Take(1) {
		t.Fatalf("fresh budgets refuse work")
	}
	if clock.Started().IsZero() {
		t.Errorf("the clock did not start at the first rendering")
	}
	clock.Expire()
	if a.budget.Take(1) || b.budget.Take(1) {
		t.Errorf("an expired shared clock still allows work")
	}

	// Once it runs out, linked binaries and compiled blobs go to a person.
	broken := "\x7fELF\x02\x01\x01 truncated header"
	blob := `"` + strings.Repeat("QUJD", 300) + `"`
	tr := writeTree(t, map[string]string{"x.syso": broken, "p.go": "package p\n\nvar b = " + blob + "\n"})
	h := checkTrees(nil, tr, clock, defaultLister())
	if len(h.items(codeIncomplete)) == 0 || len(h.items(codeIncomplete)) == 0 {
		t.Errorf("after the clock ran out: opaque %q, undecoded %q", h.items(codeIncomplete), h.items(codeIncomplete))
	}
}

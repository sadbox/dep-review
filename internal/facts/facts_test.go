package facts

import (
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/advisory"
	"github.com/sadbox/dep-review/internal/allow"
)

func TestShow(t *testing.T) {
	tests := []struct{ in, want string }{
		{"plain", "plain"},
		{"two\nlines\tand a tab", `two\nlines\tand a tab`},
		{"bidi " + string(rune(0x202e)) + " override", "bidi " + `\` + "u202e override"},
		{"nul \x00 byte", `nul \x00 byte`},
		{strings.Repeat("a", 300), strings.Repeat("a", 200) + "..."},
	}
	for _, tc := range tests {
		if got := Show(tc.in); got != tc.want {
			t.Errorf("Show(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The states a gatherer words its facts in: only an unreachable source is
// a wait. Everything else that is not an answer has no Source, which
// allow.Decide sends to a person.
func TestStates(t *testing.T) {
	if f := NotEstablished("why"); f.OK || f.Unavailable || f.Gathered() || f.Source != "" || f.Value != "not established: why" {
		t.Errorf("NotEstablished = %+v", f)
	}
	if f := NotEstablishedTime("why"); f.Known() || f.OK || f.Unavailable || f.Source != "" || !f.Time.IsZero() || f.Value != "not established: why" {
		t.Errorf("NotEstablishedTime = %+v", f)
	}
	if f := Unanswered("why", "source", true); f != allow.Unavailable("why", "source") {
		t.Errorf("Unanswered, unreachable = %+v", f)
	}
	if f := Unanswered("why", "source", false); f != NotEstablished("why") {
		t.Errorf("Unanswered, an answer that cannot be used = %+v", f)
	}
}

func TestNotRegular(t *testing.T) {
	tests := []struct {
		base, head string
		want       string // part of the problem; empty for a regular file
	}{
		{"100644", "100644", ""},
		{"100755", "100755", "Dockerfile is not a regular file at both commits (mode 100755 at base, 100755 at head)"},
		{"100644", "100755", "mode 100644 at base, 100755 at head"},
		{"100644", "120000", "120000 at head"},
		{"160000", "160000", "mode 160000 at base"},
		{"", "100644", "mode absent at base, 100644 at head"},
		{"100644", "", "absent at head"},
		{"100644\n", "100644", `mode 100644\n at base`},
	}
	for _, tc := range tests {
		got := NotRegular(File{Path: "Dockerfile", BaseMode: tc.base, HeadMode: tc.head})
		if (got == "") != (tc.want == "") || !strings.Contains(got, tc.want) {
			t.Errorf("modes %q and %q: %q, want %q", tc.base, tc.head, got, tc.want)
		}
	}
	if got := NotRegular(File{Path: "a\nb", HeadMode: "100644"}); strings.Contains(got, "\n") {
		t.Errorf("the path reached the problem as it is: %q", got)
	}
}

func TestAdvisoryClean(t *testing.T) {
	yes := allow.Yes("none", "advisories")
	no := allow.No("GHSA-xxxx-xxxx-xxxx", "advisories")
	down := allow.Unavailable("the database did not answer", "advisories")
	said := allow.Fact{Value: "the answer is not a list"}
	tests := []struct {
		name               string
		malware, advisory  allow.Fact
		holds, unavailable bool
		gathered           bool
		value              string // part of the value
	}{
		{"nothing known", yes, yes, true, false, true, "none; none"},
		{"malware", no, yes, false, false, true, "GHSA-xxxx-xxxx-xxxx"},
		{"a new advisory", yes, no, false, false, true, "GHSA-xxxx-xxxx-xxxx"},
		{"the database is down", down, down, false, true, false, "did not answer"},
		{"a no is the answer whatever went unanswered", down, no, false, false, true, "GHSA-xxxx-xxxx-xxxx"},
		{"an answer that cannot be used is not waited out", down, said, false, false, false, "the answer is not a list"},
		{"malware not checked", allow.Fact{}, yes, false, false, false, "not established: malware advisories were not checked"},
		{"new advisories not checked", yes, allow.Fact{}, false, false, false, "not established: new advisories were not checked"},
		{"nothing checked", allow.Fact{}, allow.Fact{}, false, false, false, "not established: malware advisories were not checked"},
	}
	for _, tc := range tests {
		got := AdvisoryClean(advisory.Result{NoMalware: tc.malware, NoNewAdvisory: tc.advisory})
		if got.Holds() != tc.holds || got.Unavailable != tc.unavailable || got.Gathered() != tc.gathered || !strings.Contains(got.Value, tc.value) {
			t.Errorf("%s: %+v", tc.name, got)
		}
	}
}

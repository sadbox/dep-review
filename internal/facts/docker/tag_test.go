package docker

import (
	"strings"
	"testing"
)

func TestCompareTags(t *testing.T) {
	tests := []struct {
		from, to string
		increase bool
		major    bool
	}{
		// The comparator's shape: same precision, identical suffix, higher.
		{"1.27-bookworm", "1.28-bookworm", true, false},
		{"1.27-bookworm", "2.0-bookworm", true, true},
		{"22-bookworm-slim", "24-bookworm-slim", true, true},
		{"1.27.3", "1.27.4", true, false},
		{"1.27.3", "1.28.0", true, false},
		{"1.27.3-alpine3.22", "1.27.4-alpine3.22", true, false},
		{"1.9", "1.10", true, false}, // numbers, not strings
		{"9", "10", true, true},
		{"0.9", "0.10", true, false},
		{"0.9", "1.0", true, true},
		{"20261101", "20261122", true, true}, // a lone number is its own leading component
		{"1.2.3-a_b.c-d", "1.2.4-a_b.c-d", true, false},

		// The same tag is a digest refresh, whatever the tag looks like.
		{"1.27-bookworm", "1.27-bookworm", true, false},
		{"nonroot", "nonroot", true, false},
		{"latest", "latest", true, false},
		{"24.04", "24.04", true, false},
		{"bookworm-20261110-slim", "bookworm-20261110-slim", true, false},

		// Not higher.
		{"1.28-bookworm", "1.27-bookworm", false, false},
		{"2.0", "1.9", false, false},
		{"1.27.4", "1.27.3", false, false},

		// Not the same precision.
		{"1.27", "1.27.1", false, false},
		{"1.27.0", "1.28", false, false},
		{"1", "1.0", false, false},

		// Not the same suffix.
		{"1.27-bookworm", "1.28-trixie", false, false},
		{"1.27-bookworm", "1.28", false, false},
		{"1.27", "1.28-bookworm", false, false},
		{"1.27.3-alpine3.21", "1.27.4-alpine3.22", false, false},
		{"1.27", "1.28-rc1", false, false},
		{"1.27-bookworm", "1.28-Bookworm", false, false},

		// Not the comparator's shape at all.
		{"1.27", "1.28rc1", false, false},
		{"v1.2.3", "v1.2.4", false, false},
		{"latest", "1.27", false, false},
		{"1.27", "latest", false, false},
		{"bookworm", "trixie", false, false},
		{"bookworm-20261101", "bookworm-20261110", false, false},
		{"24.04", "24.10", false, false}, // a leading zero is not a number here
		{"01.2", "01.3", false, false},
		{"1.2.3.4", "1.2.3.5", false, false},
		{"1234567890", "1234567891", false, false}, // ten digits
		{"1.27-", "1.28-", false, false},
		{"1.27.", "1.28.", false, false},
		{"1..2", "1..3", false, false},
		{"-1", "-2", false, false},
		{"1.27+build", "1.28+build", false, false},

		// No tag on one side or on both.
		{"", "1.27", false, false},
		{"1.27", "", false, false},
		{"", "", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.from+" to "+tc.to, func(t *testing.T) {
			increase, major := compareTags(tc.from, tc.to)
			if increase.OK != tc.increase || major.OK != tc.major {
				t.Errorf("increase %v (%s), major %v (%s); want %v and %v",
					increase.OK, increase.Value, major.OK, major.Value, tc.increase, tc.major)
			}
			// Both are always gathered, with something to show.
			if !increase.Gathered() || !major.Gathered() || increase.Value == "" || major.Value == "" {
				t.Errorf("not gathered: %+v %+v", increase, major)
			}
			// A major that is not an increase would be a contradiction, and
			// a "not a major" beside a failed comparison must say that it
			// was not established.
			if major.OK && !increase.OK {
				t.Errorf("major without increase")
			}
			if !increase.OK && !strings.HasPrefix(major.Value, "not established: ") {
				t.Errorf("major beside a failed comparison says %q", major.Value)
			}
		})
	}
}

func TestVersionOf(t *testing.T) {
	tests := []struct {
		tag     string
		version string // what x/mod/semver is given
		suffix  string
		ok      bool
	}{
		{"1", "v1", "", true},
		{"0", "v0", "", true},
		{"1.27", "v1.27", "", true},
		{"1.27.3", "v1.27.3", "", true},
		{"1.27-bookworm", "v1.27", "-bookworm", true},
		{"22.11.0-bookworm-slim", "v22.11.0", "-bookworm-slim", true},
		{"1-2", "v1", "-2", true},
		{"999999999", "v999999999", "", true},
		{"1000000000", "", "", false},
		{"1.1000000000", "", "", false},
		{"00", "", "", false},
		{"1.07", "", "", false},
		{"", "", "", false},
		{"nonroot", "", "", false},
		{"1.27 ", "", "", false},
		{"1.27\n", "", "", false},
		{"1.2.3.4", "", "", false},
		{"1.2.3+build", "", "", false},
		{"1.27-", "", "", false},
		{"v1.27", "", "", false},
	}
	for _, tc := range tests {
		version, suffix, ok := versionOf(tc.tag)
		if ok != tc.ok || version != tc.version || suffix != tc.suffix {
			t.Errorf("%q: %q %q %v, want %q %q %v", tc.tag, version, suffix, ok, tc.version, tc.suffix, tc.ok)
		}
	}
}

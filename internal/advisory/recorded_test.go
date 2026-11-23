package advisory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/gh"
)

// The recorded cases run a real gh.Client against answers recorded from
// api.github.com, so they cover the request as it is really sent (path,
// query, paging) and the answer as it really looks.
//
//	go test ./internal/advisory/                     replay testdata; no network
//	ADVISORY_LIVE=1 go test ./internal/advisory/     ask the real API; compare the yes/no of every fact
//	ADVISORY_RECORD=1 go test ./internal/advisory/   ask the real API and rewrite testdata
//
// Live and record use GH_TOKEN when it is set and work without one (the
// endpoint is public; without a token the limit is 60 requests an hour,
// and one run makes about 40).
//
// testdata holds response bodies exactly as received. They are public
// records of the GitHub Advisory Database (CC BY 4.0).

const (
	sourceGoReviewed      = "GET api.github.com/advisories?type=reviewed&ecosystem=go, affects="
	sourceGoMalware       = "GET api.github.com/advisories?type=malware&ecosystem=go, affects="
	sourceNPMReviewed     = "GET api.github.com/advisories?type=reviewed&ecosystem=npm, affects="
	sourceNPMMalware      = "GET api.github.com/advisories?type=malware&ecosystem=npm, affects="
	sourceActionsReviewed = "GET api.github.com/advisories?type=reviewed&ecosystem=actions, affects="
	sourceActionsMalware  = "GET api.github.com/advisories?type=malware&ecosystem=actions, affects="
)

var recordedCases = []struct {
	name string
	q    Query
	// perPage, when set, replaces the page size of 100.
	perPage int
	want    Result
	// requests is every request the case must make, in order, as the
	// affects value of each.
	requests []string
}{
	{
		// The spec's own example: two advisories drop out and both name
		// 0.17.0. The go.mod versions carry a "v"; the database's do not.
		name: "go security fix",
		q:    Query{Ecosystem: allow.GoModules, Name: "golang.org/x/net", From: "v0.16.0", To: "v0.17.0"},
		want: Result{
			SecurityFix: allow.Yes("GHSA-4374-p667-p6c8, GHSA-qppj-fm5r-hxr3: affects v0.16.0, not v0.17.0, first patched version v0.17.0",
				sourceGoReviewed+"golang.org/x/net@0.16.0 and golang.org/x/net@0.17.0"),
			NoMalware: allow.Yes("no malware advisory affects v0.17.0",
				"GET api.github.com/advisories?type=malware&ecosystem=go, affects=golang.org/x/net@0.17.0"),
			NoNewAdvisory: allow.Yes("no reviewed advisory affects v0.17.0 and not v0.16.0; on both: GHSA-4v7x-pqxf-cx7m, GHSA-5cv4-jp36-h3mw, GHSA-qxp5-gwg8-xv66, GHSA-vvgc-356p-c3xw",
				sourceGoReviewed+"golang.org/x/net@0.16.0 and golang.org/x/net@0.17.0"),
		},
		requests: []string{"golang.org/x/net@0.16.0", "golang.org/x/net@0.17.0", "golang.org/x/net@0.17.0"},
	},
	{
		// The September 2025 compromise of chalk: a malware advisory on
		// exactly one version, and no reviewed advisory at all.
		name: "npm malware on the new version",
		q:    Query{Ecosystem: allow.NPM, Name: "chalk", From: "5.6.0", To: "5.6.1"},
		want: Result{
			SecurityFix:   allow.No("no reviewed advisory affects 5.6.0 and not 5.6.1", sourceNPMReviewed+"chalk@5.6.0 and chalk@5.6.1"),
			NoMalware:     allow.No("GHSA-2v46-p5h4-248w: malware advisory affects 5.6.1", sourceNPMMalware+"chalk@5.6.1"),
			NoNewAdvisory: allow.Yes("no reviewed advisory affects 5.6.1 and not 5.6.0", sourceNPMReviewed+"chalk@5.6.0 and chalk@5.6.1"),
		},
		requests: []string{"chalk@5.6.0", "chalk@5.6.1", "chalk@5.6.1"},
	},
	{
		// The same version as a dependency the base commit did not have.
		name: "npm malware on a new name",
		q:    Query{Ecosystem: allow.NPM, Name: "chalk", To: "5.6.1"},
		want: Result{
			SecurityFix:   allow.No("new name: there is no old version for an advisory to affect", "the update: it has no old version"),
			NoMalware:     allow.No("GHSA-2v46-p5h4-248w: malware advisory affects 5.6.1", sourceNPMMalware+"chalk@5.6.1"),
			NoNewAdvisory: allow.Yes("no reviewed advisory affects 5.6.1", sourceNPMReviewed+"chalk@5.6.1"),
		},
		requests: []string{"chalk@5.6.1", "chalk@5.6.1"},
	},
	{
		// debug 4.4.2 was the same compromise. Its malware advisory
		// (GHSA-8mgj-vmr8-frr6) was withdrawn in favour of a reviewed one,
		// and the API still returns the withdrawn one. The reviewed one
		// is new on 4.4.2, which is what stops the update.
		name: "npm withdrawn malware advisory, new reviewed advisory",
		q:    Query{Ecosystem: allow.NPM, Name: "debug", From: "4.4.1", To: "4.4.2"},
		want: Result{
			SecurityFix:   allow.No("no reviewed advisory affects 4.4.1 and not 4.4.2", sourceNPMReviewed+"debug@4.4.1 and debug@4.4.2"),
			NoMalware:     allow.Yes("no malware advisory affects 4.4.2", sourceNPMMalware+"debug@4.4.2"),
			NoNewAdvisory: allow.No("GHSA-4x49-vf9v-38px: affects 4.4.2, not 4.4.1", sourceNPMReviewed+"debug@4.4.1 and debug@4.4.2"),
		},
		requests: []string{"debug@4.4.1", "debug@4.4.2", "debug@4.4.2"},
	},
	{
		name: "npm security fix away from the compromised version",
		q:    Query{Ecosystem: allow.NPM, Name: "debug", From: "4.4.2", To: "4.4.3"},
		want: Result{
			SecurityFix:   allow.Yes("GHSA-4x49-vf9v-38px: affects 4.4.2, not 4.4.3, first patched version 4.4.3", sourceNPMReviewed+"debug@4.4.2 and debug@4.4.3"),
			NoMalware:     allow.Yes("no malware advisory affects 4.4.3", sourceNPMMalware+"debug@4.4.3"),
			NoNewAdvisory: allow.Yes("no reviewed advisory affects 4.4.3 and not 4.4.2", sourceNPMReviewed+"debug@4.4.2 and debug@4.4.3"),
		},
		requests: []string{"debug@4.4.2", "debug@4.4.3", "debug@4.4.3"},
	},
	{
		// 0.7.29 has two reviewed advisories: GHSA-236c-vhj4-gfxg,
		// withdrawn, and GHSA-pjwm-rvh2-c87w, live.
		name: "npm new advisory beside a withdrawn one",
		q:    Query{Ecosystem: allow.NPM, Name: "ua-parser-js", From: "0.7.28", To: "0.7.29"},
		want: Result{
			SecurityFix:   allow.No("no reviewed advisory affects 0.7.28 and not 0.7.29", sourceNPMReviewed+"ua-parser-js@0.7.28 and ua-parser-js@0.7.29"),
			NoMalware:     allow.Yes("no malware advisory affects 0.7.29", sourceNPMMalware+"ua-parser-js@0.7.29"),
			NoNewAdvisory: allow.No("GHSA-pjwm-rvh2-c87w: affects 0.7.29, not 0.7.28", sourceNPMReviewed+"ua-parser-js@0.7.28 and ua-parser-js@0.7.29"),
		},
		requests: []string{"ua-parser-js@0.7.28", "ua-parser-js@0.7.29", "ua-parser-js@0.7.29"},
	},
	{
		// The same question one advisory to a page. The withdrawn
		// advisory is on the first page and the live one on the second:
		// a checker that read only the first page would answer "nothing
		// new".
		name:    "npm new advisory on the second page",
		q:       Query{Ecosystem: allow.NPM, Name: "ua-parser-js", From: "0.7.28", To: "0.7.29"},
		perPage: 1,
		want: Result{
			SecurityFix:   allow.No("no reviewed advisory affects 0.7.28 and not 0.7.29", sourceNPMReviewed+"ua-parser-js@0.7.28 and ua-parser-js@0.7.29"),
			NoMalware:     allow.Yes("no malware advisory affects 0.7.29", sourceNPMMalware+"ua-parser-js@0.7.29"),
			NoNewAdvisory: allow.No("GHSA-pjwm-rvh2-c87w: affects 0.7.29, not 0.7.28", sourceNPMReviewed+"ua-parser-js@0.7.28 and ua-parser-js@0.7.29"),
		},
		requests: []string{"ua-parser-js@0.7.28", "ua-parser-js@0.7.29", "ua-parser-js@0.7.29", "ua-parser-js@0.7.29"},
	},
	{
		// GHSA-pjwm-rvh2-c87w lists three ranges for the one package,
		// each with its own first patched version; the withdrawn
		// GHSA-236c-vhj4-gfxg lists the same and must not count. The fix
		// is real and the new version still is not clean: a later
		// advisory (GHSA-fhg7-m89q-25r3) starts at 0.7.30.
		name: "npm security fix that brings a new advisory",
		q:    Query{Ecosystem: allow.NPM, Name: "ua-parser-js", From: "0.7.29", To: "0.7.30"},
		want: Result{
			SecurityFix:   allow.Yes("GHSA-pjwm-rvh2-c87w: affects 0.7.29, not 0.7.30, first patched version 0.7.30", sourceNPMReviewed+"ua-parser-js@0.7.29 and ua-parser-js@0.7.30"),
			NoMalware:     allow.Yes("no malware advisory affects 0.7.30", sourceNPMMalware+"ua-parser-js@0.7.30"),
			NoNewAdvisory: allow.No("GHSA-fhg7-m89q-25r3: affects 0.7.30, not 0.7.29", sourceNPMReviewed+"ua-parser-js@0.7.29 and ua-parser-js@0.7.30"),
		},
		requests: []string{"ua-parser-js@0.7.29", "ua-parser-js@0.7.30", "ua-parser-js@0.7.30"},
	},
	{
		// Two advisories are fixed and two remain on both versions. The
		// fixed ones also list other packages and another ecosystem
		// (lodash-es, rubygems lodash-rails), whose first patched
		// versions are not this package's.
		name: "npm security fix with advisories left on both",
		q:    Query{Ecosystem: allow.NPM, Name: "lodash", From: "4.17.20", To: "4.17.21"},
		want: Result{
			SecurityFix:   allow.Yes("GHSA-29mw-wpgm-hmr9, GHSA-35jh-r3h4-6jhm: affects 4.17.20, not 4.17.21, first patched version 4.17.21", sourceNPMReviewed+"lodash@4.17.20 and lodash@4.17.21"),
			NoMalware:     allow.Yes("no malware advisory affects 4.17.21", sourceNPMMalware+"lodash@4.17.21"),
			NoNewAdvisory: allow.Yes("no reviewed advisory affects 4.17.21 and not 4.17.20; on both: GHSA-r5fr-rjxr-66jc, GHSA-xxjr-mmjv-4gpg", sourceNPMReviewed+"lodash@4.17.20 and lodash@4.17.21"),
		},
		requests: []string{"lodash@4.17.20", "lodash@4.17.21", "lodash@4.17.21"},
	},
	{
		// As a new dependency there is no old version to share the two
		// remaining advisories with: both are new.
		name: "npm new name with advisories",
		q:    Query{Ecosystem: allow.NPM, Name: "lodash", To: "4.17.21"},
		want: Result{
			SecurityFix:   allow.No("new name: there is no old version for an advisory to affect", "the update: it has no old version"),
			NoMalware:     allow.Yes("no malware advisory affects 4.17.21", sourceNPMMalware+"lodash@4.17.21"),
			NoNewAdvisory: allow.No("GHSA-r5fr-rjxr-66jc, GHSA-xxjr-mmjv-4gpg: affects 4.17.21 (new name: there is no old version to compare)", sourceNPMReviewed+"lodash@4.17.21"),
		},
		requests: []string{"lodash@4.17.21", "lodash@4.17.21"},
	},
	{
		// A scoped name: "@" is also what separates name from version.
		name: "npm scoped name",
		q:    Query{Ecosystem: allow.NPM, Name: "@babel/traverse", From: "7.23.0", To: "7.23.2"},
		want: Result{
			SecurityFix:   allow.Yes("GHSA-67hx-6x53-jw92: affects 7.23.0, not 7.23.2, first patched version 7.23.2", sourceNPMReviewed+"@babel/traverse@7.23.0 and @babel/traverse@7.23.2"),
			NoMalware:     allow.Yes("no malware advisory affects 7.23.2", sourceNPMMalware+"@babel/traverse@7.23.2"),
			NoNewAdvisory: allow.Yes("no reviewed advisory affects 7.23.2 and not 7.23.0", sourceNPMReviewed+"@babel/traverse@7.23.0 and @babel/traverse@7.23.2"),
		},
		requests: []string{"@babel/traverse@7.23.0", "@babel/traverse@7.23.2", "@babel/traverse@7.23.2"},
	},
	{
		// The workflow spells the action in another case than the
		// database does. Asked as written, NAME@VERSION finds nothing.
		name: "actions security fix, name in another case",
		q:    Query{Ecosystem: allow.GitHubActions, Name: "TJ-Actions/Changed-Files", From: "v45.0.7", To: "v46.0.1"},
		want: Result{
			SecurityFix: allow.Yes("GHSA-mrrh-fwg8-r2c3: affects v45.0.7, not v46.0.1, first patched version v46.0.1",
				sourceActionsReviewed+"TJ-Actions/Changed-Files and tj-actions/changed-files@45.0.7 and tj-actions/changed-files@46.0.1"),
			NoMalware: allow.Yes("no malware advisory affects v46.0.1", sourceActionsMalware+"TJ-Actions/Changed-Files"),
			NoNewAdvisory: allow.Yes("no reviewed advisory affects v46.0.1 and not v45.0.7",
				sourceActionsReviewed+"TJ-Actions/Changed-Files and tj-actions/changed-files@45.0.7 and tj-actions/changed-files@46.0.1"),
		},
		requests: []string{"TJ-Actions/Changed-Files", "TJ-Actions/Changed-Files", "tj-actions/changed-files@45.0.7", "tj-actions/changed-files@46.0.1"},
	},
	{
		// GHSA-mcph-m25j-8j63 is fixed by this update, but the database
		// names its first patched version "41", not "41.0.0". Only a
		// leading "v" is ever normalised, so this is not a security fix
		// and the update waits its ordinary age.
		name: "actions first patched version in another spelling",
		q:    Query{Ecosystem: allow.GitHubActions, Name: "tj-actions/changed-files", From: "v40.2.3", To: "v41.0.0"},
		want: Result{
			SecurityFix: allow.No("GHSA-mcph-m25j-8j63: affects v40.2.3, not v41.0.0, but first patched version is not v41.0.0",
				sourceActionsReviewed+"tj-actions/changed-files and tj-actions/changed-files@40.2.3 and tj-actions/changed-files@41.0.0"),
			NoMalware: allow.Yes("no malware advisory affects v41.0.0", sourceActionsMalware+"tj-actions/changed-files"),
			NoNewAdvisory: allow.Yes("no reviewed advisory affects v41.0.0 and not v40.2.3; on both: GHSA-mrrh-fwg8-r2c3",
				sourceActionsReviewed+"tj-actions/changed-files and tj-actions/changed-files@40.2.3 and tj-actions/changed-files@41.0.0"),
		},
		requests: []string{"tj-actions/changed-files", "tj-actions/changed-files", "tj-actions/changed-files@40.2.3", "tj-actions/changed-files@41.0.0"},
	},
	{
		// The database spells this one with a capital. Both versions are
		// affected, and the Value shows the advisory was found.
		name: "actions name the database capitalises",
		q:    Query{Ecosystem: allow.GitHubActions, Name: "azure/setup-kubectl", From: "v2.0.0", To: "v2.1.0"},
		want: Result{
			SecurityFix: allow.No("no reviewed advisory affects v2.0.0 and not v2.1.0",
				sourceActionsReviewed+"azure/setup-kubectl and Azure/setup-kubectl@2.0.0 and Azure/setup-kubectl@2.1.0"),
			NoMalware: allow.Yes("no malware advisory affects v2.1.0", sourceActionsMalware+"azure/setup-kubectl"),
			NoNewAdvisory: allow.Yes("no reviewed advisory affects v2.1.0 and not v2.0.0; on both: GHSA-p756-rfxh-x63h",
				sourceActionsReviewed+"azure/setup-kubectl and Azure/setup-kubectl@2.0.0 and Azure/setup-kubectl@2.1.0"),
		},
		requests: []string{"azure/setup-kubectl", "azure/setup-kubectl", "Azure/setup-kubectl@2.0.0", "Azure/setup-kubectl@2.1.0"},
	},
	{
		// An action with no advisory under any spelling: two requests,
		// and no version is ever asked about.
		name: "actions name the database does not know",
		q:    Query{Ecosystem: allow.GitHubActions, Name: "actions/setup-go", From: "v6.0.0", To: "v6.1.0"},
		want: Result{
			SecurityFix:   allow.No("no reviewed advisory affects v6.0.0 and not v6.1.0", sourceActionsReviewed+"actions/setup-go"),
			NoMalware:     allow.Yes("no malware advisory affects v6.1.0", sourceActionsMalware+"actions/setup-go"),
			NoNewAdvisory: allow.Yes("no reviewed advisory affects v6.1.0 and not v6.0.0", sourceActionsReviewed+"actions/setup-go"),
		},
		requests: []string{"actions/setup-go", "actions/setup-go"},
	},

	// Go pseudo-versions. The database's "no advisories" is what grants,
	// and it is also its answer for a version it cannot read, so each of
	// the three forms of a pseudo-version is recorded on the new side of
	// an update twice: below a fix, where the advisory must be in the
	// answer, and above it, where it must not. The versions of the first
	// four cases are real commits of the two modules; the two after a
	// pre-release are made up, since neither module ever tagged one.
	{
		// No release before it (v0.0.0-TIME-COMMIT). The fix is itself a
		// pseudo-version, and the database names it as first patched.
		name: "go pseudo-version to the pseudo-version that fixes it",
		q:    Query{Ecosystem: allow.GoModules, Name: "golang.org/x/sys", From: sysBelow, To: sysFix},
		want: Result{
			SecurityFix:   allow.Yes("GHSA-p782-xgp4-8hr8: affects "+sysBelow+", not "+sysFix+", first patched version "+sysFix, sourceGoReviewed+"golang.org/x/sys@"+sysBelow[1:]+" and golang.org/x/sys@"+sysFix[1:]),
			NoMalware:     allow.Yes("no malware advisory affects "+sysFix, sourceGoMalware+"golang.org/x/sys@"+sysFix[1:]),
			NoNewAdvisory: allow.Yes("no reviewed advisory affects "+sysFix+" and not "+sysBelow, sourceGoReviewed+"golang.org/x/sys@"+sysBelow[1:]+" and golang.org/x/sys@"+sysFix[1:]),
		},
		requests: []string{"golang.org/x/sys@" + sysBelow[1:], "golang.org/x/sys@" + sysFix[1:], "golang.org/x/sys@" + sysFix[1:]},
	},
	{
		name: "go new name at a pseudo-version below the fix",
		q:    Query{Ecosystem: allow.GoModules, Name: "golang.org/x/sys", To: sysBelow},
		want: Result{
			SecurityFix:   allow.No("new name: there is no old version for an advisory to affect", "the update: it has no old version"),
			NoMalware:     allow.Yes("no malware advisory affects "+sysBelow, sourceGoMalware+"golang.org/x/sys@"+sysBelow[1:]),
			NoNewAdvisory: allow.No("GHSA-p782-xgp4-8hr8: affects "+sysBelow+" (new name: there is no old version to compare)", sourceGoReviewed+"golang.org/x/sys@"+sysBelow[1:]),
		},
		requests: []string{"golang.org/x/sys@" + sysBelow[1:], "golang.org/x/sys@" + sysBelow[1:]},
	},
	{
		// After a release (vX.Y.(Z+1)-0.TIME-COMMIT), below the release
		// that fixes: the advisory is on both sides.
		name: "go release to a pseudo-version below the fix",
		q:    Query{Ecosystem: allow.GoModules, Name: "golang.org/x/oauth2", From: "v0.26.0", To: oauthBelow},
		want: Result{
			SecurityFix:   allow.No("no reviewed advisory affects v0.26.0 and not "+oauthBelow, sourceGoReviewed+"golang.org/x/oauth2@0.26.0 and golang.org/x/oauth2@"+oauthBelow[1:]),
			NoMalware:     allow.Yes("no malware advisory affects "+oauthBelow, sourceGoMalware+"golang.org/x/oauth2@"+oauthBelow[1:]),
			NoNewAdvisory: allow.Yes("no reviewed advisory affects "+oauthBelow+" and not v0.26.0; on both: GHSA-6v2p-p543-phr9", sourceGoReviewed+"golang.org/x/oauth2@0.26.0 and golang.org/x/oauth2@"+oauthBelow[1:]),
		},
		requests: []string{"golang.org/x/oauth2@0.26.0", "golang.org/x/oauth2@" + oauthBelow[1:], "golang.org/x/oauth2@" + oauthBelow[1:]},
	},
	{
		// The same form above the fix. The advisory is gone, and it is not
		// a security fix by the gate's definition: the database names the
		// release, not this commit, as first patched.
		name: "go release to a pseudo-version above the fix",
		q:    Query{Ecosystem: allow.GoModules, Name: "golang.org/x/oauth2", From: "v0.26.0", To: oauthAbove},
		want: Result{
			SecurityFix:   allow.No("GHSA-6v2p-p543-phr9: affects v0.26.0, not "+oauthAbove+", but first patched version is not "+oauthAbove, sourceGoReviewed+"golang.org/x/oauth2@0.26.0 and golang.org/x/oauth2@"+oauthAbove[1:]),
			NoMalware:     allow.Yes("no malware advisory affects "+oauthAbove, sourceGoMalware+"golang.org/x/oauth2@"+oauthAbove[1:]),
			NoNewAdvisory: allow.Yes("no reviewed advisory affects "+oauthAbove+" and not v0.26.0", sourceGoReviewed+"golang.org/x/oauth2@0.26.0 and golang.org/x/oauth2@"+oauthAbove[1:]),
		},
		requests: []string{"golang.org/x/oauth2@0.26.0", "golang.org/x/oauth2@" + oauthAbove[1:], "golang.org/x/oauth2@" + oauthAbove[1:]},
	},
	{
		// From a pseudo-version to the release that fixes it: the old side
		// is asked about like the new one.
		name: "go pseudo-version to the release that fixes it",
		q:    Query{Ecosystem: allow.GoModules, Name: "golang.org/x/oauth2", From: oauthBelow, To: "v0.27.0"},
		want: Result{
			SecurityFix:   allow.Yes("GHSA-6v2p-p543-phr9: affects "+oauthBelow+", not v0.27.0, first patched version v0.27.0", sourceGoReviewed+"golang.org/x/oauth2@"+oauthBelow[1:]+" and golang.org/x/oauth2@0.27.0"),
			NoMalware:     allow.Yes("no malware advisory affects v0.27.0", sourceGoMalware+"golang.org/x/oauth2@0.27.0"),
			NoNewAdvisory: allow.Yes("no reviewed advisory affects v0.27.0 and not "+oauthBelow, sourceGoReviewed+"golang.org/x/oauth2@"+oauthBelow[1:]+" and golang.org/x/oauth2@0.27.0"),
		},
		requests: []string{"golang.org/x/oauth2@" + oauthBelow[1:], "golang.org/x/oauth2@0.27.0", "golang.org/x/oauth2@0.27.0"},
	},
	{
		// After a pre-release (vX.Y.Z-PRE.0.TIME-COMMIT). It is below the
		// release it leads up to only by semver's ordering of what follows
		// the dash, which the database therefore reads.
		name: "go release to a pseudo-version after a pre-release, below the fix",
		q:    Query{Ecosystem: allow.GoModules, Name: "golang.org/x/oauth2", From: "v0.26.0", To: oauthPreBelow},
		want: Result{
			SecurityFix:   allow.No("no reviewed advisory affects v0.26.0 and not "+oauthPreBelow, sourceGoReviewed+"golang.org/x/oauth2@0.26.0 and golang.org/x/oauth2@"+oauthPreBelow[1:]),
			NoMalware:     allow.Yes("no malware advisory affects "+oauthPreBelow, sourceGoMalware+"golang.org/x/oauth2@"+oauthPreBelow[1:]),
			NoNewAdvisory: allow.Yes("no reviewed advisory affects "+oauthPreBelow+" and not v0.26.0; on both: GHSA-6v2p-p543-phr9", sourceGoReviewed+"golang.org/x/oauth2@0.26.0 and golang.org/x/oauth2@"+oauthPreBelow[1:]),
		},
		requests: []string{"golang.org/x/oauth2@0.26.0", "golang.org/x/oauth2@" + oauthPreBelow[1:], "golang.org/x/oauth2@" + oauthPreBelow[1:]},
	},
	{
		name: "go release to a pseudo-version after a pre-release, above the fix",
		q:    Query{Ecosystem: allow.GoModules, Name: "golang.org/x/oauth2", From: "v0.26.0", To: oauthPreAbove},
		want: Result{
			SecurityFix:   allow.No("GHSA-6v2p-p543-phr9: affects v0.26.0, not "+oauthPreAbove+", but first patched version is not "+oauthPreAbove, sourceGoReviewed+"golang.org/x/oauth2@0.26.0 and golang.org/x/oauth2@"+oauthPreAbove[1:]),
			NoMalware:     allow.Yes("no malware advisory affects "+oauthPreAbove, sourceGoMalware+"golang.org/x/oauth2@"+oauthPreAbove[1:]),
			NoNewAdvisory: allow.Yes("no reviewed advisory affects "+oauthPreAbove+" and not v0.26.0", sourceGoReviewed+"golang.org/x/oauth2@0.26.0 and golang.org/x/oauth2@"+oauthPreAbove[1:]),
		},
		requests: []string{"golang.org/x/oauth2@0.26.0", "golang.org/x/oauth2@" + oauthPreAbove[1:], "golang.org/x/oauth2@" + oauthPreAbove[1:]},
	},
}

// The pseudo-versions of the recorded cases. GHSA-p782-xgp4-8hr8 is fixed
// in golang.org/x/sys at sysFix, GHSA-6v2p-p543-phr9 in
// golang.org/x/oauth2 at v0.27.0.
const (
	sysBelow      = "v0.0.0-20220406163625-3f8b81556e12"
	sysFix        = "v0.0.0-20220412211240-33da011f77ad"
	oauthBelow    = "v0.26.1-0.20250214215532-3f78298beea3"
	oauthAbove    = "v0.27.1-0.20250228195905-9c82a8cf7ac2"
	oauthPreBelow = "v0.27.0-rc.1.0.20250214215532-3f78298beea3"
	oauthPreAbove = "v0.28.0-rc.1.0.20250228195905-9c82a8cf7ac2"
)

func TestRecorded(t *testing.T) {
	live := os.Getenv("ADVISORY_LIVE") != ""
	record := os.Getenv("ADVISORY_RECORD") != ""

	var transport http.RoundTripper
	var rec *recorder
	var rep *replay
	switch {
	case record:
		rec = &recorder{next: http.DefaultTransport, byRequest: map[string]fixture{}, bodies: map[string][]byte{}}
		transport = rec
	case live:
		transport = http.DefaultTransport
	default:
		rep = loadReplay(t)
		transport = rep
	}

	ran := 0
	for _, tc := range recordedCases {
		t.Run(tc.name, func(t *testing.T) {
			ran++
			client := gh.New(os.Getenv("GH_TOKEN"))
			if !live && !record {
				client = gh.New("")
				// An unrecorded request is a test failure, not something
				// to try again.
				client.MaxRetries = 0
			}
			seen := &observer{next: transport}
			client.HTTP = &http.Client{Transport: seen}

			checker := New(client)
			if tc.perPage != 0 {
				checker.perPage = tc.perPage
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			got, err := checker.Check(ctx, tc.q)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}

			if !slices.Equal(seen.affects, tc.requests) {
				t.Errorf("requests (affects of each):\n got %q\nwant %q", seen.affects, tc.requests)
			}
			compare := sameFact
			if live && !record {
				// The database moves: an advisory published tomorrow
				// changes a Value. What each case is about does not.
				compare = sameAnswer
			}
			compare(t, "SecurityFix", got.SecurityFix, tc.want.SecurityFix)
			compare(t, "NoMalware", got.NoMalware, tc.want.NoMalware)
			compare(t, "NoNewAdvisory", got.NoNewAdvisory, tc.want.NoNewAdvisory)
		})
	}

	// With -run picking some cases, the rest of testdata is neither
	// stale nor to be thrown away.
	if ran != len(recordedCases) {
		return
	}
	if record && !t.Failed() {
		rec.write(t)
	}
	if rep != nil {
		rep.unused(t)
	}
}

func sameFact(t *testing.T, name string, got, want allow.Fact) {
	t.Helper()
	if got != want {
		t.Errorf("%s:\n got %+v\nwant %+v", name, got, want)
	}
}

func sameAnswer(t *testing.T, name string, got, want allow.Fact) {
	t.Helper()
	if got.OK != want.OK || got.Gathered() != want.Gathered() {
		t.Errorf("%s:\n got %+v\nwant ok=%v gathered=%v", name, got, want.OK, want.Gathered())
	}
}

// fixture is one recorded exchange.
type fixture struct {
	// Request is the path and query exactly as the client sent them.
	Request string `json:"request"`
	Status  int    `json:"status"`
	// Link is the response's Link header, which carries the next page.
	Link string `json:"link,omitempty"`
	// Body names the file in testdata with the response body.
	Body string `json:"body"`
}

// index is testdata/index.json.
type index struct {
	Note     string    `json:"note"`
	Fixtures []fixture `json:"fixtures"`
}

const indexNote = "Responses of GET https://api.github.com/advisories, recorded by ADVISORY_RECORD=1 go test ./internal/advisory/. " +
	"Bodies are exactly as received. Source: GitHub Advisory Database, https://github.com/advisories, CC BY 4.0."

// observer notes the affects value of every request a case makes.
type observer struct {
	next    http.RoundTripper
	affects []string
}

func (o *observer) RoundTrip(req *http.Request) (*http.Response, error) {
	o.affects = append(o.affects, req.URL.Query().Get("affects"))
	return o.next.RoundTrip(req)
}

// replay answers from testdata and fails on anything that is not there.
// A fake that answered an unknown request with an empty list would make
// every "nothing found" in these tests meaningless.
type replay struct {
	t         *testing.T
	byRequest map[string]fixture
	mu        sync.Mutex
	used      map[string]bool
}

func loadReplay(t *testing.T) *replay {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "index.json"))
	if err != nil {
		t.Fatalf("no recorded answers (ADVISORY_RECORD=1 records them): %v", err)
	}
	var idx index
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatalf("testdata/index.json: %v", err)
	}
	r := &replay{t: t, byRequest: map[string]fixture{}, used: map[string]bool{}}
	for _, f := range idx.Fixtures {
		r.byRequest[f.Request] = f
	}
	return r
}

func (r *replay) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.URL.RequestURI()
	if req.Method != http.MethodGet || req.URL.Scheme != "https" || req.URL.Host != "api.github.com" {
		r.t.Errorf("request %s %s is not a GET to https://api.github.com", req.Method, req.URL)
		return nil, fmt.Errorf("not a GET to the API")
	}
	f, ok := r.byRequest[key]
	if !ok {
		r.t.Errorf("request not in testdata: %s", key)
		return nil, fmt.Errorf("unrecorded request %s", key)
	}
	body, err := os.ReadFile(filepath.Join("testdata", f.Body))
	if err != nil {
		r.t.Errorf("%v", err)
		return nil, err
	}
	r.mu.Lock()
	r.used[key] = true
	r.mu.Unlock()
	h := http.Header{"Content-Type": {"application/json; charset=utf-8"}}
	if f.Link != "" {
		h.Set("Link", f.Link)
	}
	return &http.Response{
		StatusCode: f.Status,
		Status:     http.StatusText(f.Status),
		Header:     h,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}, nil
}

// unused fails for a recorded answer no case asked for: a stale file in
// testdata is an answer nobody checks.
func (r *replay) unused(t *testing.T) {
	t.Helper()
	for key := range r.byRequest {
		if !r.used[key] {
			t.Errorf("testdata has an answer no case asks for: %s", key)
		}
	}
}

// recorder passes requests to the real API and keeps what came back. The
// request's headers are never kept: one of them is the token.
type recorder struct {
	next      http.RoundTripper
	mu        sync.Mutex
	byRequest map[string]fixture
	bodies    map[string][]byte
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.URL.RequestURI()
	r.mu.Lock()
	f, seen := r.byRequest[key]
	body := r.bodies[f.Body]
	r.mu.Unlock()
	if !seen {
		resp, err := r.next.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		body, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			// Not recorded: gh.Client retries a rate limit, and the
			// answer after the retry is the one to keep.
			resp.Body = io.NopCloser(bytes.NewReader(body))
			return resp, nil
		}
		f = fixture{Request: key, Status: resp.StatusCode, Link: resp.Header.Get("Link"), Body: fixtureName(req)}
		r.mu.Lock()
		r.byRequest[key] = f
		r.bodies[f.Body] = body
		r.mu.Unlock()
	}
	h := http.Header{"Content-Type": {"application/json; charset=utf-8"}}
	if f.Link != "" {
		h.Set("Link", f.Link)
	}
	return &http.Response{
		StatusCode: f.Status,
		Status:     http.StatusText(f.Status),
		Header:     h,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}, nil
}

var unsafeInFileName = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

// fixtureName names the body file after the question asked, so a diff of
// testdata reads as a list of questions.
func fixtureName(req *http.Request) string {
	q := req.URL.Query()
	name := q.Get("type") + "_" + q.Get("ecosystem") + "_" + unsafeInFileName.ReplaceAllString(q.Get("affects"), "_")
	// Two names that differ only in case are two questions, and some
	// file systems would make them one file.
	if strings.ToLower(q.Get("affects")) != q.Get("affects") {
		name += fmt.Sprintf("_%x", sha256.Sum256([]byte(q.Get("affects"))))[:9]
	}
	if q.Get("per_page") != "100" {
		name += "_per" + q.Get("per_page")
	}
	if after := q.Get("after"); after != "" {
		name += fmt.Sprintf("_after%x", sha256.Sum256([]byte(after)))[:14]
	}
	return name + ".json"
}

func (r *recorder) write(t *testing.T) {
	t.Helper()
	old, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range old {
		if err := os.Remove(f); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	idx := index{Note: indexNote}
	files := map[string]string{}
	for _, f := range r.byRequest {
		if other, taken := files[f.Body]; taken {
			t.Fatalf("%s and %s would both be recorded as %s", other, f.Request, f.Body)
		}
		files[f.Body] = f.Request
		idx.Fixtures = append(idx.Fixtures, f)
		if err := os.WriteFile(filepath.Join("testdata", f.Body), r.bodies[f.Body], 0o644); err != nil {
			t.Fatal(err)
		}
	}
	slices.SortFunc(idx.Fixtures, func(a, b fixture) int { return strings.Compare(a.Request, b.Request) })
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false) // keep "&" readable in the request lines
	enc.SetIndent("", "  ")
	if err := enc.Encode(idx); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("testdata", "index.json"), out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("recorded %d answers", len(idx.Fixtures))
}

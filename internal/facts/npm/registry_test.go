package npm

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/advisory"
	"github.com/sadbox/dep-review/internal/allow"
)

// fixturePackument reads a recorded registry answer through the client
// the gatherer uses.
func fixturePackument(t *testing.T, name string) packumentAnswer {
	t.Helper()
	reg := &registry{client: newFakeRegistry(t, nil), packuments: map[string]packumentAnswer{}}
	a, err := reg.packument(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	if a.doc == nil {
		t.Fatalf("no recorded packument for %s: %+v", name, a)
	}
	return a
}

// fromRegistry builds the update a lock would show for name moving
// between two versions the registry has, with the registry's own hashes.
func fromRegistry(t *testing.T, a packumentAnswer, name, from, to string) update {
	t.Helper()
	entry := func(version string) []node {
		doc, published, problem := a.doc.version(version)
		if !published || problem != "" {
			return []node{{Path: "node_modules/" + name, Name: name, Version: version, Resolved: tarballURL(name, version), Integrity: otherHash}}
		}
		return []node{{Path: "node_modules/" + name, Name: name, Version: version, Resolved: doc.Dist.Tarball, Integrity: doc.Dist.Integrity}}
	}
	u := update{Name: name, From: from, To: to, New: entry(to)}
	if from != "" {
		u.Old = entry(from)
	}
	return u
}

func TestURLs(t *testing.T) {
	tests := []struct{ name, version, packument, tarball, attestation, purl string }{
		{
			"chart.js", "4.4.7",
			"https://registry.npmjs.org/chart.js",
			"https://registry.npmjs.org/chart.js/-/chart.js-4.4.7.tgz",
			"https://registry.npmjs.org/-/npm/v1/attestations/chart.js@4.4.7",
			"pkg:npm/chart.js@4.4.7",
		},
		{
			"@tailwindcss/oxide-wasm32-wasi", "4.3.5",
			"https://registry.npmjs.org/@tailwindcss%2foxide-wasm32-wasi",
			"https://registry.npmjs.org/@tailwindcss/oxide-wasm32-wasi/-/oxide-wasm32-wasi-4.3.5.tgz",
			"https://registry.npmjs.org/-/npm/v1/attestations/@tailwindcss%2foxide-wasm32-wasi@4.3.5",
			"pkg:npm/%40tailwindcss/oxide-wasm32-wasi@4.3.5",
		},
	}
	for _, tt := range tests {
		if got := packumentURL(tt.name); got != tt.packument {
			t.Errorf("packumentURL(%s) = %s, want %s", tt.name, got, tt.packument)
		}
		if got := tarballURL(tt.name, tt.version); got != tt.tarball {
			t.Errorf("tarballURL(%s) = %s, want %s", tt.name, got, tt.tarball)
		}
		if got := attestationURL(tt.name, tt.version); got != tt.attestation {
			t.Errorf("attestationURL(%s) = %s, want %s", tt.name, got, tt.attestation)
		}
		if got := purl(tt.name, tt.version); got != tt.purl {
			t.Errorf("purl(%s) = %s, want %s", tt.name, got, tt.purl)
		}
	}
	// The recorded registry answers agree with the URLs the gate builds.
	a := fixturePackument(t, "@tailwindcss/oxide-wasm32-wasi")
	doc, _, _ := a.doc.version("4.3.5")
	if doc.Dist.Tarball != tests[1].tarball {
		t.Errorf("the registry's dist.tarball is %s, the gate builds %s", doc.Dist.Tarball, tests[1].tarball)
	}
	if !strings.Contains(string(doc.Dist.Attestations), tests[1].attestation) {
		t.Errorf("the registry's attestations URL is not the one the gate builds: %s", doc.Dist.Attestations)
	}
}

func TestSha512Of(t *testing.T) {
	for integrity, want := range map[string]bool{
		chartNew:                            true,
		otherHash:                           true,
		"":                                  false,
		"sha1-W4o6d2Xf4AEmHd6RVYnngvjJTR4=": false,
		"sha512-short==":                    false,
		// Two hashes: npm takes a download that matches either.
		chartNew + " " + otherHash:                       false,
		chartNew + " sha1-W4o6d2Xf4AEmHd6RVYnngvjJTR4=":  false,
		chartNew + "?foo":                                false,
		" " + chartNew:                                   false,
		strings.Replace(chartNew, "sha512", "sha256", 1): false,
		strings.Replace(chartNew, "sha512", "SHA512", 1): false,
	} {
		if _, got := sha512Of(integrity); got != want {
			t.Errorf("sha512Of(%q) = %v, want %v", integrity, got, want)
		}
	}
}

func TestBoundFact(t *testing.T) {
	a := fixturePackument(t, "chart.js")
	good := fromRegistry(t, a, "chart.js", "4.4.6", "4.4.7")
	with := func(edit func(u *update)) update {
		u := good
		u.New = append([]node(nil), good.New...)
		edit(&u)
		return u
	}
	tests := []struct {
		name string
		u    update
		a    packumentAnswer
		// want is a piece of the Value of a gathered no; empty means
		// the fact holds.
		want string
	}{
		{"the registry's own tarball and hash", good, a, ""},
		{"two copies that agree", with(func(u *update) {
			second := u.New[0]
			second.Path = "node_modules/x/node_modules/chart.js"
			u.New = append(u.New, second)
		}), a, ""},
		{"two copies with different hashes", with(func(u *update) {
			second := u.New[0]
			second.Path = "node_modules/x/node_modules/chart.js"
			second.Integrity = otherHash
			u.New = append(u.New, second)
		}), a, "two different hashes"},
		{"a second copy from elsewhere", with(func(u *update) {
			second := u.New[0]
			second.Path = "node_modules/x/node_modules/chart.js"
			second.Resolved = "https://registry.npmjs.org/chart.js/-/chart.js-4.4.6.tgz"
			u.New = append(u.New, second)
		}), a, "node_modules/x/node_modules/chart.js resolves to"},
		{"an alias", with(func(u *update) { u.New[0].Path = "node_modules/charts" }), a, "node_modules/charts holds chart.js: an alias"},
		{"a path outside node_modules", with(func(u *update) { u.New[0].Path = "packages/chart.js" }), a, "packages/chart.js holds chart.js"},
		{"another package's tarball", with(func(u *update) { u.New[0].Resolved = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz" }), a, "resolves to"},
		{"the tarball over http", with(func(u *update) { u.New[0].Resolved = strings.Replace(u.New[0].Resolved, "https://", "http://", 1) }), a, "resolves to"},
		{"the yarn mirror", with(func(u *update) {
			u.New[0].Resolved = strings.Replace(u.New[0].Resolved, "registry.npmjs.org", "registry.yarnpkg.com", 1)
		}), a, "resolves to"},
		{"a tarball URL with a fragment", with(func(u *update) { u.New[0].Resolved += "#x" }), a, "resolves to"},
		{"no source", with(func(u *update) { u.New[0].Resolved = "" }), a, `resolves to ""`},
		{"a link", with(func(u *update) { u.New[0].Resolved = "file:../chart.js"; u.New[0].Integrity = "" }), a, `resolves to "file:../chart.js"`},
		{"no hash", with(func(u *update) { u.New[0].Integrity = "" }), a, "not exactly one sha512 hash"},
		{"a sha1 hash", with(func(u *update) { u.New[0].Integrity = "sha1-W4o6d2Xf4AEmHd6RVYnngvjJTR4=" }), a, "not exactly one sha512 hash"},
		{"two hashes in one integrity", with(func(u *update) { u.New[0].Integrity += " " + otherHash }), a, "not exactly one sha512 hash"},
		{"a hash the registry does not report", with(func(u *update) { u.New[0].Integrity = otherHash }), a, "the registry reports"},
		{"a version the registry does not have", with(func(u *update) {
			u.To = "4.4.99"
			u.New[0].Version = "4.4.99"
			u.New[0].Resolved = tarballURL("chart.js", "4.4.99")
		}), a, "4.4.99 is not on the registry (unpublished)"},
		{"a name that is not a package name", with(func(u *update) { u.Name = "../x" }), a, "not a shape the registry serves"},
		{"a version that is not a version", with(func(u *update) { u.To = "4.4.7/../../x" }), a, "not a shape the registry serves"},
		{"no such package", good, packumentAnswer{gone: true}, "the registry has no package of this name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := boundFact(tt.u, tt.a, "registry")
			if tt.want == "" {
				if !f.Holds() {
					t.Errorf("Bound = %+v, want it to hold", f)
				}
				return
			}
			if f.OK || !f.Gathered() || !strings.Contains(f.Value, tt.want) {
				t.Errorf("Bound = %+v, want a gathered no saying %q", f, tt.want)
			}
		})
	}

	t.Run("the registry did not answer", func(t *testing.T) {
		f := boundFact(good, packumentAnswer{failed: "the registry did not answer: \"HTTP status 503\""}, "registry")
		if f.OK || f.Gathered() || !strings.Contains(f.Value, "503") {
			t.Errorf("Bound = %+v, want it left ungathered with the reason", f)
		}
	})
	// What the lock says is wrong whatever the registry says, so a
	// registry outage does not hide it.
	t.Run("an off-registry source during a registry outage", func(t *testing.T) {
		u := with(func(u *update) { u.New[0].Resolved = "https://example.com/x.tgz" })
		f := boundFact(u, packumentAnswer{failed: "down"}, "registry")
		if f.OK || !f.Gathered() {
			t.Errorf("Bound = %+v, want a gathered no", f)
		}
	})
}

func TestTimeFacts(t *testing.T) {
	a := fixturePackument(t, "@kurkle/color")
	u := fromRegistry(t, a, "@kurkle/color", "", "0.3.4")
	first, created := timeFacts(u, a, packumentURL(u.Name))
	if want := time.Date(2024, 11, 19, 18, 44, 10, 106e6, time.UTC); !first.Known() || !first.Time.Equal(want) {
		t.Errorf("FirstSeen = %+v, want %s", first, want)
	}
	if want := `https://registry.npmjs.org/@kurkle%2fcolor time[0.3.4]`; first.Source != want {
		t.Errorf("FirstSeen.Source = %q, want %q", first.Source, want)
	}
	if want := time.Date(2020, 2, 5, 19, 59, 45, 29e6, time.UTC); !created.Known() || !created.Time.Equal(want) {
		t.Errorf("NameCreated = %+v, want %s", created, want)
	}

	// event-stream 3.3.6 was unpublished: its time is still there, and
	// that alone says nothing about it being installable.
	es := fixturePackument(t, "event-stream")
	first, _ = timeFacts(fromRegistry(t, es, "event-stream", "3.3.5", "3.3.6"), es, "registry")
	if !first.Known() {
		t.Errorf("FirstSeen of an unpublished version = %+v, want the registry's time", first)
	}

	for name, a := range map[string]packumentAnswer{
		"no answer":  {failed: "the registry did not answer"},
		"no package": {gone: true},
		"no times":   {doc: &packument{Name: "x"}},
	} {
		first, created := timeFacts(update{Name: "x", To: "1.0.0"}, a, "registry")
		if first.Known() || created.Known() || first.Value == "" || created.Value == "" {
			t.Errorf("%s: FirstSeen = %+v, NameCreated = %+v, want both unknown with a reason", name, first, created)
		}
	}

	bad := fixturePackument(t, "chart.js")
	for _, raw := range []string{`"yesterday"`, `1733071666`, `null`, `{"time":"2024-12-01T16:47:46.119Z"}`, `"0001-01-01T00:00:00Z"`} {
		bad.doc.Time["4.4.7"] = []byte(raw)
		first, _ := timeFacts(update{Name: "chart.js", To: "4.4.7"}, bad, "registry")
		if first.Known() {
			t.Errorf("time %s was read as %+v", raw, first)
		}
	}
}

func TestCleanFact(t *testing.T) {
	ok := nothingKnown()
	// What the advisory checker returns when the database did not answer,
	// and what gatherUpdate makes of a fact the checker left blank.
	down := allow.Unavailable("GitHub's Advisory Database did not answer (HTTP 503, after retries)", "GET api.github.com/advisories")
	blank := allow.Fact{Value: "the advisory database gave no answer"}
	const (
		yes         = "yes"
		no          = "no"
		unknown     = "never gathered"
		unavailable = "unavailable"
	)
	state := func(f allow.Fact) string {
		switch {
		case f.Holds():
			return yes
		case f.Unavailable:
			return unavailable
		case f.Source == "":
			return unknown
		}
		return no
	}
	tests := []struct {
		name, pkg, from, to string
		adv                 advisory.Result
		// state is which of the four the fact is; want is a piece of its
		// Value.
		state string
		want  string
	}{
		{"published, not deprecated, nothing known", "chart.js", "4.4.6", "4.4.7", ok, yes, "published and not deprecated; no malware advisory; no new advisory"},
		// Every version of left-pad is deprecated on the real registry.
		{"deprecated", "left-pad", "1.2.0", "1.3.0", ok, no, `deprecated on the registry: "\"use String.prototype.padStart()\""`},
		// event-stream 3.3.6 was removed from the real registry.
		{"unpublished", "event-stream", "3.3.5", "3.3.6", ok, no, "3.3.6 is not on the registry (unpublished)"},
		{"malware", "chart.js", "4.4.6", "4.4.7", advisory.Result{NoMalware: allow.No("GHSA-1 (malware)", "advisories"), NoNewAdvisory: ok.NoNewAdvisory}, no, "GHSA-1 (malware)"},
		{"a new advisory", "chart.js", "4.4.6", "4.4.7", advisory.Result{NoMalware: ok.NoMalware, NoNewAdvisory: allow.No("GHSA-2 affects 4.4.7 and not 4.4.6", "advisories")}, no, "GHSA-2"},
		{"the advisory database did not answer", "chart.js", "4.4.6", "4.4.7", advisory.Result{NoMalware: down, NoNewAdvisory: down}, unavailable, "did not answer (HTTP 503"},
		{"advisories silent", "chart.js", "4.4.6", "4.4.7", advisory.Result{NoMalware: blank, NoNewAdvisory: blank}, unknown, "gave no answer"},
		{"advisories silent on one question", "chart.js", "4.4.6", "4.4.7", advisory.Result{NoMalware: ok.NoMalware, NoNewAdvisory: blank}, unknown, "gave no answer"},
		{"one question unanswered, the other unreadable", "chart.js", "4.4.6", "4.4.7", advisory.Result{NoMalware: down, NoNewAdvisory: blank}, unknown, "gave no answer"},
		// A deprecation is a no whatever the advisory database did.
		{"deprecated and advisories silent", "left-pad", "1.2.0", "1.3.0", advisory.Result{NoMalware: blank, NoNewAdvisory: blank}, no, "deprecated on the registry"},
		{"deprecated and the advisory database down", "left-pad", "1.2.0", "1.3.0", advisory.Result{NoMalware: down, NoNewAdvisory: down}, no, "deprecated on the registry"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := fixturePackument(t, tt.pkg)
			f := cleanFact(fromRegistry(t, a, tt.pkg, tt.from, tt.to), a, "registry", tt.adv)
			if state(f) != tt.state || !strings.Contains(f.Value, tt.want) {
				t.Errorf("Clean = %+v (%s), want %s, saying %q", f, state(f), tt.state, tt.want)
			}
		})
	}

	// The registry itself: not answering is unavailable, an answer that
	// cannot be used is never gathered, and a "no" from the advisories is
	// the answer either way.
	unreachable := packumentAnswer{failed: "the registry did not answer: HTTP status 503", unreachable: true}
	unusable := packumentAnswer{failed: "the registry's answer could not be used: HTTP status 403"}
	malware := advisory.Result{NoMalware: allow.No("GHSA-1 (malware)", "advisories"), NoNewAdvisory: ok.NoNewAdvisory}
	for _, tt := range []struct {
		name  string
		a     packumentAnswer
		adv   advisory.Result
		state string
	}{
		{"registry did not answer, advisories fine", unreachable, ok, unavailable},
		{"registry did not answer, malware known", unreachable, malware, no},
		{"registry and advisory database both down", unreachable, advisory.Result{NoMalware: down, NoNewAdvisory: down}, unavailable},
		{"registry answer unusable, advisories fine", unusable, ok, unknown},
		{"registry answer unusable, malware known", unusable, malware, no},
		{"registry answer unusable, advisory database down", unusable, advisory.Result{NoMalware: down, NoNewAdvisory: down}, unknown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := cleanFact(update{Name: "x", To: "1.0.0"}, tt.a, "registry", tt.adv)
			if state(f) != tt.state || f.Value == "" {
				t.Errorf("Clean = %+v (%s), want %s", f, state(f), tt.state)
			}
		})
	}
	t.Run("a deprecation that was withdrawn", func(t *testing.T) {
		a := fixturePackument(t, "left-pad")
		a.doc.Versions["1.3.0"] = []byte(strings.Replace(string(a.doc.Versions["1.3.0"]), `"use String.prototype.padStart()"`, `""`, 1))
		f := cleanFact(fromRegistry(t, a, "left-pad", "1.2.0", "1.3.0"), a, "registry", ok)
		if !f.Holds() {
			t.Errorf("Clean = %+v, want an empty deprecation message to be no deprecation", f)
		}
	})
}

// TestNoRegressRealPackages runs NoRegress on recorded metadata of real
// packages whose install step is known.
func TestNoRegressRealPackages(t *testing.T) {
	tests := []struct {
		name, pkg, from, to string
		// lockFlag is the lock's hasInstallScript for the old and the
		// new entry.
		oldFlag, newFlag bool
		want             string
		holds            bool
	}{
		{"core-js keeps its postinstall", "core-js", "3.38.0", "3.38.1", true, true, "install scripts unchanged (postinstall: ", true},
		// 2.4.0 builds with node-gyp on install; 2.4.1 ships prebuilt
		// binaries and has no install script.
		{"@parcel/watcher drops its install script", "@parcel/watcher", "2.4.0", "2.4.1", true, false, "no install script", true},
		{"@parcel/watcher gains it going back", "@parcel/watcher", "2.4.1", "2.4.0", false, true, `install scripts change from none to install: "node-gyp rebuild"`, false},
		{"chart.js has none", "chart.js", "4.4.6", "4.4.7", false, false, "no install script", true},
		{"the lock flags a script the registry does not show", "chart.js", "4.4.6", "4.4.7", false, true, "the lock marks 4.4.7 as having an install script", false},
		{"the lock flagged both", "chart.js", "4.4.6", "4.4.7", true, true, "install scripts unchanged (none)", true},
		{"a new name with an install script", "core-js", "", "3.38.1", false, true, "a new dependency with an install script", false},
		{"a new name without one", "@kurkle/color", "", "0.3.4", false, false, "no install script", true},
		{"the old version is gone from the registry", "event-stream", "3.3.6", "3.3.5", false, false, "3.3.6 is no longer on the registry", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := fixturePackument(t, tt.pkg)
			u := fromRegistry(t, a, tt.pkg, tt.from, tt.to)
			u.New[0].HasInstallScript = tt.newFlag
			if tt.from != "" {
				u.Old[0].HasInstallScript = tt.oldFlag
			}
			reg := &registry{client: newFakeRegistry(t, nil), packuments: map[string]packumentAnswer{}}
			f, err := noRegressFact(context.Background(), reg, u, a, "registry")
			if err != nil {
				t.Fatal(err)
			}
			if !f.Gathered() || f.OK != tt.holds || !strings.Contains(f.Value, tt.want) {
				t.Errorf("NoRegress = %+v, want holds %v saying %q", f, tt.holds, tt.want)
			}
		})
	}
}

// TestProvenanceRecorded reads the real tailwindcss attestations.
func TestProvenanceRecorded(t *testing.T) {
	reg := &registry{client: newFakeRegistry(t, nil), packuments: map[string]packumentAnswer{}}
	want := identity{
		BuildType:    "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
		Builder:      "https://github.com/actions/runner/github-hosted",
		Repository:   "https://github.com/tailwindlabs/tailwindcss",
		Workflow:     ".github/workflows/release.yml",
		RepositoryID: "106017343",
		OwnerID:      "67109815",
	}
	for version, integrity := range map[string]string{"4.3.4": tailwindOld, "4.3.5": tailwindNew} {
		id, problem, state, err := reg.provenance(context.Background(), "tailwindcss", version, integrity)
		if err != nil || problem != "" || state != holds {
			t.Fatalf("%s: %q, %v", version, problem, err)
		}
		if id != want {
			t.Errorf("%s:\n got %+v\nwant %+v", version, id, want)
		}
	}
	// The statement of one version says nothing about another's bytes.
	_, problem, _, err := reg.provenance(context.Background(), "tailwindcss", "4.3.5", tailwindOld)
	if err != nil || !strings.Contains(problem, "not about the tarball the lock pins") {
		t.Errorf("a statement checked against another hash: %q, %v", problem, err)
	}
}

func TestProvenanceShapes(t *testing.T) {
	url := attestationURL("tailwindcss", "4.3.5")
	payload := statementPayload(t, "tailwindcss", "4.3.5", tailwindNew, "https://github.com/o/r", ".github/workflows/w.yml")
	tests := []struct {
		name, body, want string
	}{
		{"good", envelopeJSON(slsaPredicate, intotoPayload, payload), ""},
		{"not JSON", "<html>", "could not be read"},
		{"no attestations", `{"attestations":[]}`, "0 SLSA v1 provenance statements"},
		{"only the publish attestation", envelopeJSON("https://github.com/npm/attestation/tree/main/specs/publish/v0.1", intotoPayload, "e30="), "0 SLSA v1 provenance statements"},
		{"SLSA v0.2 only", envelopeJSON("https://slsa.dev/provenance/v0.2", intotoPayload, payload), "0 SLSA v1 provenance statements"},
		{"two provenance statements", envelopeJSON(slsaPredicate, intotoPayload, payload, payload), "2 SLSA v1 provenance statements"},
		{"another payload type", envelopeJSON(slsaPredicate, "text/plain", payload), "not an in-toto statement"},
		{"payload is not base64", envelopeJSON(slsaPredicate, intotoPayload, "!!!"+payload), "not base64"},
		{"payload is not JSON", envelopeJSON(slsaPredicate, intotoPayload, "bm90IGpzb24="), "could not be read"},
		{"payload is another kind of statement", envelopeJSON(slsaPredicate, intotoPayload, "e30="), "not SLSA v1"},
		{"for another version", attestationJSON(t, "tailwindcss", "4.3.4", tailwindNew, "https://github.com/o/r", "w.yml"), "not about the tarball"},
		{"for another package", attestationJSON(t, "tailwindcss-evil", "4.3.5", tailwindNew, "https://github.com/o/r", "w.yml"), "not about the tarball"},
		{"for other bytes", attestationJSON(t, "tailwindcss", "4.3.5", otherHash, "https://github.com/o/r", "w.yml"), "not about the tarball"},
		{"no repository", attestationJSON(t, "tailwindcss", "4.3.5", tailwindNew, "", "w.yml"), "names no source repository"},
		{"no workflow", attestationJSON(t, "tailwindcss", "4.3.5", tailwindNew, "https://github.com/o/r", ""), "names no source repository"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := &registry{client: newFakeRegistry(t, map[string]string{url: tt.body}), packuments: map[string]packumentAnswer{}}
			id, problem, state, err := reg.provenance(context.Background(), "tailwindcss", "4.3.5", tailwindNew)
			if err != nil || state != holds {
				t.Fatal(err)
			}
			if tt.want == "" {
				if problem != "" || id.Repository != "https://github.com/o/r" {
					t.Errorf("identity = %+v, problem = %q", id, problem)
				}
				return
			}
			if !strings.Contains(problem, tt.want) || id != (identity{}) {
				t.Errorf("identity = %+v, problem = %q; want no identity and %q", id, problem, tt.want)
			}
		})
	}
	// A 404 is the registry's answer. A 500 or a 429 is no answer:
	// nothing was learned, and asking again may. A 403 is an answer that
	// cannot be used: nothing was learned, and asking again will not.
	for _, tt := range []struct {
		status, want string
		state        verdict
	}{
		{"404", "the registry has no attestations for it", holds},
		{"500", `the registry did not answer: "HTTP status 500"`, unreachable},
		{"429", `the registry did not answer: "HTTP status 429"`, unreachable},
		{"403", "the registry's answer could not be used", unknown},
	} {
		reg := &registry{client: newFakeRegistry(t, map[string]string{url: tt.status}), packuments: map[string]packumentAnswer{}}
		_, problem, state, err := reg.provenance(context.Background(), "tailwindcss", "4.3.5", tailwindNew)
		if err != nil || state != tt.state || !strings.Contains(problem, tt.want) {
			t.Errorf("status %s: problem = %q, state %v, %v; want %q, state %v", tt.status, problem, state, err, tt.want, tt.state)
		}
	}
}

func TestRegistryGetLimits(t *testing.T) {
	url := packumentURL("big")
	reg := &registry{client: newFakeRegistry(t, map[string]string{url: `{"name":"big","versions":{}}`}), packuments: map[string]packumentAnswer{}}
	if _, err := reg.get(context.Background(), url, 5); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("a body over the limit: %v", err)
	}
	if body, err := reg.get(context.Background(), url, 1<<10); err != nil || len(body) == 0 {
		t.Errorf("a body under the limit: %v", err)
	}
	// The registry answering for another name is not an answer.
	other := &registry{client: newFakeRegistry(t, map[string]string{packumentURL("small"): `{"name":"big","versions":{}}`}), packuments: map[string]packumentAnswer{}}
	a, err := other.packument(context.Background(), "small")
	if err != nil || a.doc != nil || !strings.Contains(a.failed, "answered for big") {
		t.Errorf("a document for another name: %+v, %v", a, err)
	}
}

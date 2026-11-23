package npm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/facts"
)

// The fixtures under testdata are public data only.
//
// testdata/cases/<case>/{base,head}/ holds a package.json and a
// package-lock.json. The "plain", "bundled", "newname", "lockv1" and
// "lockv2" locks were written by "npm install --package-lock-only" from
// the package.json next to them; the other cases are "plain" with one
// edit to the head lock (see caseNotes). <side>.ls.json is what the real
// npm printed for that side, with the scratch directory rewritten to
// scratchPath.
//
// testdata/registry/ holds answers of registry.npmjs.org, cut down to the
// versions and fields the tests use.
//
// To record again (needs npm, node and the network):
//
//	DEP_REVIEW_NPM_RECORD=1 go test ./internal/facts/npm/ -run 'TestRecord'
const (
	recordEnv   = "DEP_REVIEW_NPM_RECORD"
	liveEnv     = "DEP_REVIEW_NPM_LIVE"
	scratchPath = "/scratch/project"
	casesDir    = "testdata/cases"
	registryDir = "testdata/registry"
)

// caseNotes says what each case is, and is the list of cases.
var caseNotes = map[string]string{
	"plain":       "chart.js 4.4.6->4.4.7, core-js 3.38.0->3.38.1 (unchanged postinstall), tailwindcss 4.3.4->4.3.5 (provenance); date-fns stays",
	"bundled":     "@tailwindcss/oxide-wasm32-wasi 4.3.4->4.3.5, which bundles six dependencies",
	"newname":     "chart.js 3.9.1->4.4.7, which adds the new name @kurkle/color",
	"lockonly":    "plain with ranges in package.json: only the lock changes",
	"lockv1":      "plain as lockfileVersion 1",
	"lockv2":      "plain as lockfileVersion 2",
	"unreachable": "plain, head lock has an entry node_modules/zzz nothing depends on",
	"rehash":      "plain, head lock gives date-fns 4.1.0 another hash",
	"flagflip":    "plain, head lock sets hasInstallScript on date-fns 4.1.0",
	"offregistry": "plain, head lock resolves chart.js 4.4.7 on another host",
	"gitsource":   "plain, head lock resolves chart.js 4.4.7 from git, with no hash",
	"lockscripts": "plain, head lock entry for date-fns carries a scripts object",
	"casekeys":    "plain, head lock entry for chart.js also has Integrity, Resolved, Version and Name",
	"outofsync":   "plain, head lock has chart.js 4.4.5 where package.json wants 4.4.7",
	"special":     "an alias, a git dependency, a tarball URL, a workspace link and an override; same at both commits",
}

// recorded is one <side>.ls.json.
type recorded struct {
	NPM    string         `json:"npm"`
	Exit   int            `json:"exit"`
	Stdout jsontext.Value `json:"stdout"`
}

// testCase is one directory under testdata/cases.
type testCase struct {
	name                       string
	baseManifest, headManifest []byte
	baseLock, headLock         []byte
}

func loadCase(t *testing.T, name string) testCase {
	t.Helper()
	read := func(side, file string) []byte {
		data, err := os.ReadFile(filepath.Join(casesDir, name, side, file))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	return testCase{
		name:         name,
		baseManifest: read("base", "package.json"),
		headManifest: read("head", "package.json"),
		baseLock:     read("base", "package-lock.json"),
		headLock:     read("head", "package-lock.json"),
	}
}

// files is the pull request's changed files for the case: the lock, and
// package.json when it differs, as git would report them.
func (c testCase) files(dir string) []facts.File {
	files := []facts.File{{
		Path: dir + "package-lock.json", BaseMode: "100644", HeadMode: "100644",
		Base: c.baseLock, Head: c.headLock,
	}}
	if !bytes.Equal(c.baseManifest, c.headManifest) {
		files = append(files, facts.File{
			Path: dir + "package.json", BaseMode: "100644", HeadMode: "100644",
			Base: c.baseManifest, Head: c.headManifest,
		})
	}
	return files
}

// swapped is the case run backwards: head becomes base.
func (c testCase) swapped() testCase {
	return testCase{name: c.name, baseManifest: c.headManifest, headManifest: c.baseManifest, baseLock: c.headLock, headLock: c.baseLock}
}

// replayTool is a tool that answers from the recorded output of the
// cases it was given, keyed by the lock's bytes.
type replayTool struct {
	version string
	byLock  map[[32]byte]lsOutput
}

func (r replayTool) Version(context.Context) (string, error) { return r.version, nil }

func (r replayTool) List(_ context.Context, _, lock []byte) (lsOutput, error) {
	out, ok := r.byLock[sha256.Sum256(lock)]
	if !ok {
		return lsOutput{}, errors.New("no recorded npm ls output for this lock; record it with " + recordEnv + "=1")
	}
	return out, nil
}

// replay returns the recorded npm for the given cases.
func replay(t *testing.T, cases ...testCase) replayTool {
	t.Helper()
	r := replayTool{byLock: map[[32]byte]lsOutput{}}
	for _, c := range cases {
		// Key by the files on disk, not by the case's fields: a swapped
		// case still gets each lock's own recording.
		onDisk := loadCase(t, c.name)
		for side, lock := range map[string][]byte{"base": onDisk.baseLock, "head": onDisk.headLock} {
			rec := readRecorded(t, c.name, side)
			r.version = rec.NPM
			r.byLock[sha256.Sum256(lock)] = lsOutput{Stdout: rec.Stdout, Exit: rec.Exit}
		}
	}
	return r
}

func recordedPath(name, side string) string {
	return filepath.Join(casesDir, name, side+".ls.json")
}

func readRecorded(t *testing.T, name, side string) recorded {
	t.Helper()
	data, err := os.ReadFile(recordedPath(name, side))
	if err != nil {
		t.Fatal(err)
	}
	var rec recorded
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatalf("%s: %v", recordedPath(name, side), err)
	}
	return rec
}

// rewriteScratch replaces the scratch directory npm printed with
// scratchPath, so recorded output does not depend on where it was made
// and carries no trace of the machine.
func rewriteScratch(stdout []byte) []byte {
	var root struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(stdout, &root); err != nil || root.Path == "" {
		return stdout
	}
	return bytes.ReplaceAll(stdout, []byte(root.Path), []byte(scratchPath))
}

// realTool finds the local npm, or skips the test.
func realTool(t *testing.T) (realNPM, string) {
	t.Helper()
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm is not installed")
	}
	n, err := findNPM("")
	if err != nil {
		t.Fatal(err)
	}
	version, err := n.Version(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := supportedNPM(version); err != nil {
		t.Skip(err)
	}
	return n, version
}

// TestRecordNPM writes every case's <side>.ls.json from the local npm.
func TestRecordNPM(t *testing.T) {
	if os.Getenv(recordEnv) == "" {
		t.Skip("set " + recordEnv + "=1 to record npm ls output")
	}
	n, version := realTool(t)
	for name := range caseNotes {
		c := loadCase(t, name)
		sides := map[string][2][]byte{"base": {c.baseManifest, c.baseLock}, "head": {c.headManifest, c.headLock}}
		for side, f := range sides {
			manifest := f[0]
			if bytes.Equal(c.baseManifest, c.headManifest) {
				// A package.json that does not change is not among the
				// pull request's files, so the gatherer never has it.
				manifest = nil
			}
			out, err := n.List(context.Background(), manifest, f[1])
			if err != nil {
				t.Fatalf("%s %s: %v", name, side, err)
			}
			stdout := bytes.TrimSpace(rewriteScratch(out.Stdout))
			if !jsontext.Value(stdout).IsValid() {
				t.Fatalf("%s %s: npm did not print JSON", name, side)
			}
			file := fmt.Sprintf("{\"npm\":%q,\"exit\":%d,\"stdout\":%s}\n", version, out.Exit, stdout)
			if err := os.WriteFile(recordedPath(name, side), []byte(file), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// registryFile maps a registry URL to its fixture file.
func registryFile(url string) (string, bool) {
	rest, ok := strings.CutPrefix(url, registryURL+"/")
	if !ok {
		return "", false
	}
	if att, ok := strings.CutPrefix(rest, "-/npm/v1/attestations/"); ok {
		return filepath.Join(registryDir, "attestations", strings.ReplaceAll(att, "%2f", "__")+".json"), true
	}
	return filepath.Join(registryDir, "packuments", strings.ReplaceAll(rest, "%2f", "__")+".json"), true
}

// fakeRegistry is the http.RoundTripper the tests give the gatherer. It
// answers from override first (a body, or "404", or "500"), then from the
// fixture files, and fails the test for a URL it has neither for: no test
// reaches the network by accident.
type fakeRegistry struct {
	t        *testing.T
	override map[string]string
	// asked counts the requests per URL.
	asked map[string]int
}

func newFakeRegistry(t *testing.T, override map[string]string) *http.Client {
	return &http.Client{Transport: &fakeRegistry{t: t, override: override, asked: map[string]int{}}}
}

func (f *fakeRegistry) RoundTrip(req *http.Request) (*http.Response, error) {
	url := req.URL.String()
	f.asked[url]++
	answer := func(status int, body []byte) (*http.Response, error) {
		return &http.Response{
			StatusCode: status, Status: http.StatusText(status), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(body)), Request: req,
		}, nil
	}
	if body, ok := f.override[url]; ok {
		switch body {
		case "404":
			return answer(http.StatusNotFound, []byte(`{"error":"Not found"}`))
		case "500":
			return answer(http.StatusInternalServerError, []byte(`{"error":"boom"}`))
		case "429":
			return answer(http.StatusTooManyRequests, []byte(`{"error":"slow down"}`))
		case "403":
			return answer(http.StatusForbidden, []byte(`{"error":"forbidden"}`))
		}
		return answer(http.StatusOK, []byte(body))
	}
	file, ok := registryFile(url)
	if !ok {
		f.t.Errorf("request to %s: not the registry", url)
		return nil, errors.New("not the registry")
	}
	body, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		if _, err := os.Stat(strings.TrimSuffix(file, ".json") + ".404"); err == nil {
			return answer(http.StatusNotFound, []byte(`{"error":"Not found"}`))
		}
		f.t.Errorf("request to %s: no fixture %s", url, file)
		return nil, errors.New("no fixture")
	}
	if err != nil {
		return nil, err
	}
	return answer(http.StatusOK, body)
}

// registryRecords is what TestRecordRegistry fetches: per package, the
// versions to keep and whether to keep their attestations.
var registryRecords = []struct {
	name         string
	versions     []string
	attestations bool
}{
	{"chart.js", []string{"3.9.1", "4.4.6", "4.4.7"}, false},
	{"core-js", []string{"3.38.0", "3.38.1"}, false},
	{"tailwindcss", []string{"4.3.4", "4.3.5"}, true},
	{"@tailwindcss/oxide-wasm32-wasi", []string{"4.3.4", "4.3.5"}, false},
	{"@kurkle/color", []string{"0.3.4"}, false},
	{"date-fns", []string{"4.1.0"}, false},
	// Every version of left-pad is deprecated.
	{"left-pad", []string{"1.2.0", "1.3.0"}, false},
	// event-stream 3.3.6 was unpublished: "time" still has it, "versions"
	// does not.
	{"event-stream", []string{"3.3.5", "3.3.6"}, false},
	// @parcel/watcher 2.4.0 has gypfile and an install script the
	// registry added; 2.4.1 has its own install script.
	{"@parcel/watcher", []string{"2.4.0", "2.4.1"}, false},
}

// keptVersionKeys are the fields of a version document kept in a fixture:
// the ones the gatherer reads, and "license" as one it does not.
var keptVersionKeys = []string{"name", "version", "scripts", "deprecated", "gypfile", "hasInstallScript", "bundleDependencies", "bundledDependencies", "license"}

// TestRecordRegistry writes testdata/registry from the real registry.
func TestRecordRegistry(t *testing.T) {
	if os.Getenv(recordEnv) == "" {
		t.Skip("set " + recordEnv + "=1 to record registry answers")
	}
	reg := &registry{client: http.DefaultClient, packuments: map[string]packumentAnswer{}}
	ctx := context.Background()
	write := func(url string, value any) {
		file, _ := registryFile(url)
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(value, jsontext.WithIndent("  "), json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, rec := range registryRecords {
		body, err := reg.get(ctx, packumentURL(rec.name), maxPackument)
		if err != nil {
			t.Fatalf("%s: %v", rec.name, err)
		}
		var full struct {
			Name     string                               `json:"name"`
			Time     map[string]jsontext.Value            `json:"time"`
			Versions map[string]map[string]jsontext.Value `json:"versions"`
		}
		if err := json.Unmarshal(body, &full); err != nil {
			t.Fatalf("%s: %v", rec.name, err)
		}
		times := map[string]jsontext.Value{"created": full.Time["created"], "modified": full.Time["modified"]}
		versions := map[string]map[string]jsontext.Value{}
		for _, v := range rec.versions {
			if when, ok := full.Time[v]; ok {
				times[v] = when
			}
			doc, ok := full.Versions[v]
			if !ok {
				continue
			}
			kept := map[string]jsontext.Value{}
			for _, key := range keptVersionKeys {
				if value, ok := doc[key]; ok {
					kept[key] = value
				}
			}
			var dist map[string]jsontext.Value
			if err := json.Unmarshal(doc["dist"], &dist); err != nil {
				t.Fatalf("%s@%s: %v", rec.name, v, err)
			}
			keptDist := map[string]jsontext.Value{}
			for _, key := range []string{"tarball", "integrity", "attestations"} {
				if value, ok := dist[key]; ok {
					keptDist[key] = value
				}
			}
			kept["dist"], err = json.Marshal(keptDist, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			versions[v] = kept

			if !rec.attestations {
				continue
			}
			body, err := reg.get(ctx, attestationURL(rec.name, v), maxAttestation)
			if err != nil {
				t.Fatalf("%s@%s attestations: %v", rec.name, v, err)
			}
			// Keep the signed statements and drop the signatures and
			// certificates, which nothing here reads.
			var att struct {
				Attestations []struct {
					PredicateType string `json:"predicateType"`
					Bundle        struct {
						Envelope struct {
							Payload     string `json:"payload"`
							PayloadType string `json:"payloadType"`
						} `json:"dsseEnvelope"`
					} `json:"bundle"`
				} `json:"attestations"`
			}
			if err := json.Unmarshal(body, &att); err != nil {
				t.Fatalf("%s@%s attestations: %v", rec.name, v, err)
			}
			write(attestationURL(rec.name, v), att)
		}
		write(packumentURL(rec.name), map[string]any{"name": full.Name, "time": times, "versions": versions})
	}
}

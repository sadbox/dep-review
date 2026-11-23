package gather

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha512"
	"encoding/base64"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/wire"
)

// tarball is an npm tarball of the given files and its lockfile
// integrity.
func tarball(t *testing.T, files map[string]string) ([]byte, string) {
	t.Helper()
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, name := range names {
		if err := tw.WriteHeader(&tar.Header{Name: "package/" + name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(files[name]))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(files[name])); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha512.Sum512(buf.Bytes())
	return buf.Bytes(), "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

// registry answers for the npm registry from memory. Nothing in the test
// reaches the network.
type registry map[string][]byte

func (r registry) RoundTrip(req *http.Request) (*http.Response, error) {
	body, ok := r[req.URL.String()]
	status := http.StatusOK
	if !ok {
		status = http.StatusNotFound
	}
	return &http.Response{
		StatusCode: status, Status: http.StatusText(status), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: req,
	}, nil
}

// The reader NewPreparer builds is internal/artifact's own, and it looks
// at the verified npm tarballs with the npm gatherer's function: an
// install script that shows in neither the registry's metadata nor the
// lock, only in a bundled package inside the tarball, costs the update
// its NoRegress (spec section 11, amendment 5).
func TestNewPreparerInspectsNPM(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	oldFiles := map[string]string{
		"package.json": `{"name":"demo","version":"1.2.3"}`,
		"index.js":     "module.exports = 1\n",
	}
	for _, tc := range []struct {
		name     string
		newFiles map[string]string
		holds    bool
	}{
		{"a plain update", map[string]string{
			"package.json": `{"name":"demo","version":"1.3.0"}`,
			"index.js":     "module.exports = 2\n",
		}, true},
		{"a bundled package with an install script", map[string]string{
			"package.json":                    `{"name":"demo","version":"1.3.0"}`,
			"index.js":                        "module.exports = 2\n",
			"node_modules/inner/package.json": `{"name":"inner","scripts":{"postinstall":"node steal.js"}}`,
		}, false},
		{"a new binding.gyp", map[string]string{
			"package.json": `{"name":"demo","version":"1.3.0"}`,
			"index.js":     "module.exports = 2\n",
			"binding.gyp":  "{}",
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldBytes, oldHash := tarball(t, oldFiles)
			newBytes, newHash := tarball(t, tc.newFiles)
			client := &http.Client{Transport: registry{
				"https://registry.npmjs.org/demo/-/demo-1.2.3.tgz": oldBytes,
				"https://registry.npmjs.org/demo/-/demo-1.3.0.tgz": newBytes,
			}}
			preparer, err := NewPreparer(t.TempDir(), client, nil)
			if err != nil {
				t.Fatal(err)
			}

			u := goodUpdate(t, allow.NPM, "demo")
			j := newJob(t, model.NPM, u)
			j.fetch.Preparer = preparer
			j.gatherer.res.Artifacts = []artifact.Pair{{
				Ecosystem: allow.NPM, Name: "demo", From: "1.2.3", To: "1.3.0",
				Old: artifact.Ref{Kind: artifact.NPMTarball, Name: "demo", Version: "1.2.3", Hash: oldHash},
				New: artifact.Ref{Kind: artifact.NPMTarball, Name: "demo", Version: "1.3.0", Hash: newHash},
			}}
			dir, f := j.run(t)

			got := f.Facts.Updates[0]
			if got.Prepared.Status != wire.Prepared || got.Prepared.State != allow.ReadFull || len(got.Prepared.Chunks) != 1 {
				t.Fatalf("read %+v", got.Prepared)
			}
			text, err := readChunk(filepath.Join(dir, wire.ChunksDir), got.Prepared.Chunks[0])
			if err != nil || !strings.Contains(text, "+module.exports = 2") {
				t.Errorf("chunk %q, %v", text, err)
			}
			if got.NoRegress.Holds() != tc.holds || !got.NoRegress.Gathered() {
				t.Errorf("no regress %+v, want holds %v", got.NoRegress, tc.holds)
			}
			want := allow.Merge
			if !tc.holds {
				want = allow.Person
			}
			d := decide(t, f, cleanVerdicts(f))
			if d.Outcome != want || (!tc.holds && d.Reasons[0] != allow.ReasonRegress) {
				t.Errorf("decision %s %v, want %s", d.Outcome, d.Reasons, want)
			}
		})
	}
}

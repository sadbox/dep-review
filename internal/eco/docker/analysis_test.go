package docker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/policy"
)

func layerOf(t *testing.T, files ...tfile) *layerResult {
	t.Helper()
	gz, did := tarGz(t, files)
	budget := int64(1 << 20)
	lr, err := readLayer(bytes.NewReader(gz), "application/vnd.oci.image.layer.v1.tar+gzip", 0, &budget)
	if err != nil {
		t.Fatal(err)
	}
	if lr.DiffID != did {
		t.Fatalf("diff id %s != %s", lr.DiffID, did)
	}
	return lr
}

func TestComposeLayers(t *testing.T) {
	l0 := layerOf(t,
		tfile{path: "a/", typ: 'd'}, tfile{path: "a/x", body: "x"}, tfile{path: "a/y", body: "y"},
		tfile{path: "b/", typ: 'd'}, tfile{path: "b/c", body: "c"}, tfile{path: "l", typ: 'l', link: "a"},
		tfile{path: "./etc/os-release", body: "ID=debian\n"}, tfile{path: "etc/hard", typ: 'h', link: "etc/os-release"},
		tfile{path: "../escape", body: "no"})
	l1 := layerOf(t, tfile{path: "a/.wh.x", body: ""}, tfile{path: ".wh.b", body: ""})
	l2 := layerOf(t, tfile{path: "a/.wh..wh..opq", body: ""}, tfile{path: "a/z", body: "z"})
	fs := compose([]*layerResult{l0, l1, l2})
	got := sortedKeys(fs.Files)
	want := []string{"a", "a/z", "etc/hard", "etc/os-release", "l"}
	if !slices.Equal(got, want) {
		t.Errorf("rootfs %v, want %v", got, want)
	}
	if fs.Files["etc/hard"].SHA256 != fs.Files["etc/os-release"].SHA256 || string(fs.Captured["etc/hard"]) != "ID=debian\n" {
		t.Errorf("hardlink not resolved: %+v", fs.Files["etc/hard"])
	}
	if len(l0.Anomalies) != 1 {
		t.Errorf("anomalies %v", l0.Anomalies)
	}
	if fs.canon("l/z") != "a/z" || fs.canon("/l/../l/z") != "a/z" {
		t.Errorf("canon %s", fs.canon("l/z"))
	}
	budget := int64(0)
	if _, err := readLayer(strings.NewReader(""), "application/vnd.oci.image.layer.v1.tar+zstd", 0, &budget); !errors.Is(err, errZstd) {
		t.Errorf("zstd: %v", err)
	}
	if _, err := readLayer(strings.NewReader(""), "application/x-weird", 0, &budget); !errors.Is(err, errUnsupportedLayer) {
		t.Errorf("weird: %v", err)
	}
}

func md5hex(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }
func apkQ1(s string) string {
	h := sha1.Sum([]byte(s))
	return "Q1" + base64.StdEncoding.EncodeToString(h[:])
}
func osRel(id, ver string) tfile {
	return tfile{path: "etc/os-release", body: "ID=" + id + "\nVERSION_ID=\"" + ver + "\"\n"}
}

// debImage is a small dpkg-based rootfs: libfoo owns usr/lib/libfoo.so,
// base owns /bin/tool (usrmerge: bin -> usr/bin).
func debImage(foo, fooBody, md5Body, shadowDay string, extra ...tfile) []tfile {
	status := "Package: base\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n\n" +
		"Package: libfoo\nStatus: install ok installed\nVersion: " + foo + "\nArchitecture: amd64\nSource: foo\n"
	return append([]tfile{
		osRel("debian", "13"),
		{path: "bin", typ: 'l', link: "usr/bin"},
		{path: "usr/bin/tool", body: "tool", mode: 0o755},
		{path: "usr/lib/libfoo.so", body: fooBody},
		{path: "etc/shadow", body: "root:*:" + shadowDay + ":0:99999:7:::\n", mode: 0o640},
		{path: "var/lib/dpkg/status", body: status},
		{path: "var/lib/dpkg/info/base.list", body: "/.\n/bin/tool\n"},
		{path: "var/lib/dpkg/info/base.md5sums", body: md5hex("tool") + "  bin/tool\n"},
		{path: "var/lib/dpkg/info/libfoo.list", body: "/.\n/usr/lib/libfoo.so\n"},
		{path: "var/lib/dpkg/info/libfoo.md5sums", body: md5hex(md5Body) + "  usr/lib/libfoo.so\n"},
		{path: "var/log/dpkg.log", body: "installed libfoo " + foo + "\n"},
	}, extra...)
}

func runSynthetic(t *testing.T, image string, oldEnv, newEnv []string, oldLayers, newLayers [][]tfile, osv *osvClient) (*updateResult, model.Route) {
	t.Helper()
	f := newFakeRegistry(t)
	repo := "library/" + image
	om := f.image(repo, "linux/amd64", oldEnv, oldLayers...)
	nm := f.image(repo, "linux/amd64", newEnv, newLayers...)
	oi, ni := f.index(repo, om), f.index(repo, nm)
	f.tags[repo+":1"] = ni
	ch := fromChange{Path: "Dockerfile", Line: 1, Old: mustRef(t, image+":1@"+oi), New: mustRef(t, image+":1@"+ni)}
	a := f.analyzer(nil)
	a.osv = osv
	u, err := a.analyze(context.Background(), ch, []string{"linux/amd64"}, "example")
	if err != nil {
		t.Fatal(err)
	}
	return u, policy.Combine([]model.Update{u.Update}, u.Findings, false)
}

func TestAttributionDpkg(t *testing.T) {
	env := []string{"PATH=/usr/bin"}
	old := [][]tfile{debImage("1.0", "foo1", "foo1", "20000")}
	for _, tc := range []struct {
		name    string
		newEnv  []string
		new     [][]tfile
		route   model.Route
		codes   []string
		classes map[string]int
	}{
		{name: "package bump", new: [][]tfile{debImage("1.1", "foo2", "foo2", "20010")},
			route: model.RouteReview, codes: []string{codeArchiveNotVerified},
			classes: map[string]int{"package": 1, "package-db": 2, "normalized": 2}},
		{name: "split layer and unexplained file",
			new:   [][]tfile{debImage("1.1", "foo2", "foo2", "20000"), {{path: "etc/apt/sources.list.d/x.sources", body: "URIs: http://evil/\n"}}},
			route: model.RouteHuman, codes: []string{codeArchiveNotVerified, codeUnexplainedFiles}},
		{name: "content does not match md5sums", new: [][]tfile{debImage("1.1", "foo2-patched", "foo2", "20000")},
			route: model.RouteHuman, codes: []string{codeArchiveNotVerified, codeUnexplainedFiles}},
		{name: "unchanged package's file deleted",
			new:   [][]tfile{debImage("1.0", "foo1", "foo1", "20000"), {{path: "usr/bin/.wh.tool"}}},
			route: model.RouteHuman, codes: []string{codeArchiveNotVerified, codeUnexplainedFiles}},
		{name: "shadow changed beyond lastchg", new: [][]tfile{debImage("1.0", "foo1", "foo1", "20000", tfile{path: "etc/shadow", body: "root:$6$x:20000:0:99999:7:::\n", mode: 0o640})},
			route: model.RouteHuman, codes: []string{codeArchiveNotVerified, codeUnexplainedFiles}},
		{name: "package added", new: [][]tfile{debImage("1.0", "foo1", "foo1", "20000", tfile{path: "var/lib/dpkg/status", body: "Package: base\nStatus: install ok installed\nVersion: 1\n\nPackage: libfoo\nStatus: install ok installed\nVersion: 1.0\n\nPackage: netcat\nStatus: install ok installed\nVersion: 1\n"})},
			route: model.RouteHuman, codes: []string{codeArchiveNotVerified, codePackageAdded}},
		{name: "release change", new: [][]tfile{debImage("1.0", "foo1", "foo1", "20000", osRel("debian", "14"))},
			route: model.RouteHuman, codes: []string{codeArchiveNotVerified, codeReleaseChanged, codeUnexplainedFiles}},
		{name: "config change", newEnv: []string{"PATH=/usr/bin", "LD_PRELOAD=/x.so"}, new: [][]tfile{debImage("1.1", "foo2", "foo2", "20000")},
			route: model.RouteHuman, codes: []string{codeArchiveNotVerified, codeConfigChanged}},
		{name: "payload with version constant", newEnv: []string{"PATH=/usr/bin", "GOLANG_VERSION=1.27.4"},
			new:   [][]tfile{debImage("1.0", "foo1", "foo1", "20000", tfile{path: "usr/local/go/VERSION", body: "go1.27.4\n"})},
			route: model.RouteReview, codes: []string{codeArchiveNotVerified}, classes: map[string]int{"upstream": 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldEnv := env
			newEnv := tc.newEnv
			if newEnv == nil {
				newEnv = env
			}
			if strings.Contains(tc.name, "payload") {
				oldEnv = []string{"PATH=/usr/bin", "GOLANG_VERSION=1.27.3"}
				old := [][]tfile{debImage("1.0", "foo1", "foo1", "20000", tfile{path: "usr/local/go/VERSION", body: "go1.27.3\n"})}
				u, r := runSynthetic(t, "golang", oldEnv, newEnv, old, tc.new, nil)
				check(t, u, r, tc.route, tc.codes, tc.classes)
				return
			}
			u, r := runSynthetic(t, "debian", oldEnv, newEnv, old, tc.new, nil)
			check(t, u, r, tc.route, tc.codes, tc.classes)
		})
	}
}

func check(t *testing.T, u *updateResult, r, route model.Route, want []string, classes map[string]int) {
	t.Helper()
	var got []string
	for _, f := range u.Findings {
		got = append(got, f.Code)
	}
	slices.Sort(got)
	slices.Sort(want)
	if r != route || !slices.Equal(got, want) {
		t.Errorf("route %s findings %s; want %s %v", r, codes(u.Findings), route, want)
	}
	for k, n := range classes {
		if len(u.Results) != 1 || u.Results[0].ClassCounts[k] != n {
			var files []string
			for _, c := range u.Results[0].Files {
				files = append(files, c.Path+"="+c.Class+":"+c.Why)
			}
			t.Errorf("class %s: %d, want %d; files %v", k, u.Results[0].ClassCounts[k], n, files)
		}
	}
}

// apkIndex builds a signed APKINDEX.tar.gz.
func apkIndex(t *testing.T, key *rsa.PrivateKey, keyName, body string) []byte {
	t.Helper()
	member := func(files map[string]string, end bool) []byte {
		var raw bytes.Buffer
		tw := tar.NewWriter(&raw)
		for _, n := range sortedKeys(files) {
			tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(files[n])), Typeflag: tar.TypeReg})
			tw.Write([]byte(files[n]))
		}
		if end {
			tw.Close()
		} else {
			tw.Flush()
		}
		var out bytes.Buffer
		zw := gzip.NewWriter(&out)
		zw.Write(raw.Bytes())
		zw.Close()
		return out.Bytes()
	}
	idx := member(map[string]string{"DESCRIPTION": "v3.24", "APKINDEX": body}, true)
	sum := sha1.Sum(idx)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return append(member(map[string]string{".SIGN.RSA." + keyName: string(sig)}, false), idx...)
}

func TestAttributionApk(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	const kn = "alpine-devel@example.org-1.rsa.pub"
	img := func(musl, muslBody, index string, extra ...tfile) [][]tfile {
		db := fmt.Sprintf("P:musl\nV:%s\nA:x86_64\nC:Q1abc=\no:musl\nF:lib\nR:ld-musl.so.1\nZ:%s\n\nP:alpine-keys\nV:2.6-r0\nF:etc/apk/keys\nR:%s\nZ:%s\n", musl, apkQ1(muslBody), kn, apkQ1(pub))
		return [][]tfile{append([]tfile{
			osRel("alpine", "3.24.4"),
			{path: "lib/ld-musl.so.1", body: muslBody},
			{path: "lib/apk/db/installed", body: db},
			{path: "etc/apk/keys/" + kn, body: pub},
			{path: "var/cache/apk/APKINDEX.0123abcd.tar.gz", body: index},
			{path: "var/log/apk.log", body: "log " + musl},
		}, extra...)}
	}
	old := img("1.2.5-r23", "musl-old", string(apkIndex(t, key, kn, "P:musl\nV:1.2.5-r23\n")))
	newIdx := string(apkIndex(t, key, kn, "P:musl\nV:1.2.6-r3\n"))

	u, r := runSynthetic(t, "alpine", nil, nil, old, img("1.2.6-r3", "musl-new", newIdx), nil)
	check(t, u, r, model.RouteReview, []string{codeArchiveNotVerified}, map[string]int{"package": 1, "normalized": 2, "package-db": 1})

	// A corrupted index cache does not verify.
	bad := []byte(newIdx)
	bad[len(bad)-20] ^= 0xff
	u, r = runSynthetic(t, "alpine", nil, nil, old, img("1.2.6-r3", "musl-new", string(bad)), nil)
	check(t, u, r, model.RouteHuman, []string{codeArchiveNotVerified, codeUnexplainedFiles}, nil)

	// Rebuilt package (same version, new checksum) is a change, not noise.
	m := img("1.2.5-r23", "musl-rebuilt", string(apkIndex(t, key, kn, "x")))
	m[0][2].body = strings.Replace(m[0][2].body, "C:Q1abc=", "C:Q1def=", 1)
	u, r = runSynthetic(t, "alpine", nil, nil, old, m, nil)
	if len(u.Results) != 1 || len(u.Results[0].Changed) != 1 || !u.Results[0].Changed[0].Rebuilt || r != model.RouteReview {
		t.Errorf("rebuilt: route %s %+v %s", r, u.Results[0].Changed, codes(u.Findings))
	}

	if _, err := verifyAPKIndex([]byte(newIdx), func(string) ([]byte, bool) { return nil, false }); err == nil {
		t.Error("verified without a key")
	}
}

func TestOSVDelta(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Queries []struct {
				Package struct{ Name, Ecosystem string }
				Version string
			}
		}
		json.NewDecoder(r.Body).Decode(&q)
		var res []map[string]any
		for _, x := range q.Queries {
			got = append(got, x.Package.Ecosystem+"/"+x.Package.Name+"@"+x.Version)
			var vulns []map[string]string
			switch x.Version {
			case "1.0":
				vulns = []map[string]string{{"id": "CVE-OLD"}, {"id": "CVE-BOTH"}}
			case "1.1":
				vulns = []map[string]string{{"id": "CVE-BOTH"}, {"id": "CVE-NEW"}}
			}
			res = append(res, map[string]any{"vulns": vulns})
		}
		json.NewEncoder(w).Encode(map[string]any{"results": res})
	}))
	defer srv.Close()
	osv := &osvClient{http: srv.Client(), url: srv.URL}
	old := [][]tfile{debImage("1.0", "foo1", "foo1", "20000")}
	u, r := runSynthetic(t, "debian", nil, nil, old, [][]tfile{debImage("1.1", "foo2", "foo2", "20000")}, osv)
	if r != model.RouteHuman || !strings.Contains(codes(u.Findings), codeOSVIntroduced) {
		t.Errorf("route %s %s", r, codes(u.Findings))
	}
	d := u.Results[0].OSV
	if !slices.Equal(got, []string{"Debian:13/foo@1.0", "Debian:13/foo@1.1"}) || len(d.Fixed["CVE-OLD"]) != 1 || len(d.Introduced["CVE-NEW"]) != 1 || d.Fixed["CVE-BOTH"] != nil {
		t.Errorf("queries %v delta %+v", got, d)
	}
}

func TestNormalizers(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		ok   bool
	}{
		{"root:*:20000:0:99999:7:::\nbin:*:20000::::::\n", "root:*:20010:0:99999:7:::\nbin:*:20010::::::\n", true},
		{"root:*:20000:0:99999:7:::\n", "root:$6$hash:20000:0:99999:7:::\n", false},
		{"root:*:20000:0:99999:7:::\n", "root:*:20000:0:99999:7:::\nevil::0:0:::::\n", false},
		{"root:*:20000:0:99999:7:::\n", "root:*:x:0:99999:7:::\n", false},
	} {
		if got := onlyFieldDiffers([]byte(tc.a), []byte(tc.b), ':', 2); got != tc.ok {
			t.Errorf("%q -> %q: %v", tc.a, tc.b, got)
		}
	}
	if !onlyKeysDiffer([]byte("name: ubuntu\ncreated: 'a'\n"), []byte("name: ubuntu\ncreated: 'b'\n"), ":", "created") ||
		onlyKeysDiffer([]byte("name: ubuntu\n"), []byte("name: evil\n"), ":", "created") {
		t.Error("onlyKeysDiffer")
	}
}

func TestSanitize(t *testing.T) {
	if got := sanitize("a\x1b[31mb\nc‮d"); got != "a?[31mb c?d" {
		t.Errorf("%q", got)
	}
}

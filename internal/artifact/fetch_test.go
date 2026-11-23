package artifact

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/gh"
)

// The recorded fixtures in testdata are real, public artifacts, fetched
// once from the three sources the package uses and stored unchanged:
//
//	npm      https://registry.npmjs.org/isarray/-/isarray-<version>.tgz
//	         integrity: "dist.integrity" of https://registry.npmjs.org/isarray
//	gomod    https://proxy.golang.org/rsc.io/quote/@v/<version>.zip
//	         hash: https://sum.golang.org/lookup/rsc.io/quote@<version>
//	actions  https://api.github.com/repos/dtolnay/rust-toolchain/tarball/<commit>
//
// Each hash below is the one its authority reported, not one computed
// from the stored file, so a test that verifies a fixture checks this
// package's hashing against the real thing.
var (
	recordedNPM = Pair{
		Ecosystem: allow.NPM, Name: "isarray", From: "2.0.4", To: "2.0.5",
		Old: Ref{Kind: NPMTarball, Name: "isarray", Version: "2.0.4",
			Hash: "sha512-GMxXOiUirWg1xTKRipM0Ek07rX+ubx4nNVElTJdNLYmNO/2YrDkgJGw9CljXn+r4EWiDQg/8lsRdHyg2PJuUaA=="},
		New: Ref{Kind: NPMTarball, Name: "isarray", Version: "2.0.5",
			Hash: "sha512-xHjhDr3cNBK0BzdUJSPXZntQUx/mwMS5Rw4A7lPJ90XGAO6ISP/ePDNuo0vhqOZU+UD5JoodwCAAoZQd3FeAKw=="},
	}
	recordedModule = Pair{
		Ecosystem: allow.GoModules, Name: "rsc.io/quote", From: "v1.5.1", To: "v1.5.2",
		Old: Ref{Kind: GoModuleZip, Name: "rsc.io/quote", Version: "v1.5.1", Hash: "h1:ptSemFtffEBvMed43o25vSUpcTVcqxfXU8Jv0sfFVJs="},
		New: Ref{Kind: GoModuleZip, Name: "rsc.io/quote", Version: "v1.5.2", Hash: "h1:w5fcysjrx7yqtD/aO+QwRjYZOKnaM9Uh2b40tElTs3Y="},
	}
	// The two commits are neighbours on the repository's master branch
	// and carry no tag; the versions are labels made up for the test.
	recordedAction = Pair{
		Ecosystem: allow.GitHubActions, Name: "dtolnay/rust-toolchain", From: "v0.0.1", To: "v0.0.2",
		Old: Ref{Kind: ActionTarball, Name: "dtolnay/rust-toolchain", Version: "v0.0.1", Hash: "683b588c487a69d01f6c6ddf40f036ff682cc2c8"},
		New: Ref{Kind: ActionTarball, Name: "dtolnay/rust-toolchain", Version: "v0.0.2", Hash: "245fd7ab067fa10d00f4c3c5fb238e6ec0874e77"},
	}
)

// recordedFile is the testdata file a recorded Ref was stored as.
func recordedFile(ref Ref) string {
	switch ref.Kind {
	case NPMTarball:
		return filepath.Join("testdata", "npm", ref.Name+"-"+ref.Version+".tgz")
	case GoModuleZip:
		return filepath.Join("testdata", "gomod", strings.ReplaceAll(ref.Name, "/", "-")+"-"+ref.Version+".zip")
	}
	return filepath.Join("testdata", "actions", strings.ReplaceAll(ref.Name, "/", "-")+"-"+ref.Hash+".tar.gz")
}

// route is the recorded answer to one URL.
type route struct {
	status   int    // 200 when zero
	location string // the Location of a redirect
	file     string // the body, from testdata
	body     []byte // or the body itself
	failures int    // answer 503 this many times first
}

// replay is an http.RoundTripper that answers from recorded routes and
// fails the test on any request it has no route for: a test that passes
// made no request to the network.
type replay struct {
	t      *testing.T
	routes map[string]*route

	mu   sync.Mutex
	seen []*http.Request
}

func (r *replay) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, req)
	rt, ok := r.routes[req.URL.String()]
	if !ok {
		r.t.Errorf("unexpected request: %s %s", req.Method, req.URL)
		return nil, errors.New("replay: no route")
	}
	resp := &http.Response{StatusCode: rt.status, Header: http.Header{}, Request: req, Body: http.NoBody, ContentLength: -1}
	switch {
	case rt.failures > 0:
		rt.failures--
		resp.StatusCode = http.StatusServiceUnavailable
	case rt.location != "":
		resp.Header.Set("Location", rt.location)
	default:
		body := rt.body
		if rt.file != "" {
			var err error
			if body, err = os.ReadFile(rt.file); err != nil {
				r.t.Fatal(err)
			}
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}
	if resp.StatusCode == 0 {
		resp.StatusCode = http.StatusOK
	}
	return resp, nil
}

// urls lists the URLs requested, in order.
func (r *replay) urls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var urls []string
	for _, req := range r.seen {
		urls = append(urls, req.URL.String())
	}
	return urls
}

// replayReader is the Preparer New returns, on a replayed network.
func replayReader(t *testing.T, routes map[string]*route, github *gh.Client) (*reader, *replay) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	rp := &replay{t: t, routes: routes}
	p, err := New(Options{Scratch: t.TempDir(), HTTP: &http.Client{Transport: rp}, GitHub: github})
	if err != nil {
		t.Fatal(err)
	}
	r := p.(*reader)
	r.fetch.(*netFetcher).retryDelay = time.Millisecond
	return r, rp
}

const (
	npmOldURL      = "https://registry.npmjs.org/isarray/-/isarray-2.0.4.tgz"
	npmNewURL      = "https://registry.npmjs.org/isarray/-/isarray-2.0.5.tgz"
	actionOldURL   = "https://api.github.com/repos/dtolnay/rust-toolchain/tarball/683b588c487a69d01f6c6ddf40f036ff682cc2c8"
	actionNewURL   = "https://api.github.com/repos/dtolnay/rust-toolchain/tarball/245fd7ab067fa10d00f4c3c5fb238e6ec0874e77"
	codeloadOldURL = "https://codeload.github.com/dtolnay/rust-toolchain/legacy.tar.gz/683b588c487a69d01f6c6ddf40f036ff682cc2c8"
	codeloadNewURL = "https://codeload.github.com/dtolnay/rust-toolchain/legacy.tar.gz/245fd7ab067fa10d00f4c3c5fb238e6ec0874e77"
)

func npmRoutes() map[string]*route {
	return map[string]*route{
		npmOldURL: {file: recordedFile(recordedNPM.Old)},
		npmNewURL: {file: recordedFile(recordedNPM.New)},
	}
}

func actionRoutes() map[string]*route {
	return map[string]*route{
		actionOldURL:   {status: http.StatusFound, location: codeloadOldURL},
		actionNewURL:   {status: http.StatusFound, location: codeloadNewURL},
		codeloadOldURL: {file: recordedFile(recordedAction.Old)},
		codeloadNewURL: {file: recordedFile(recordedAction.New)},
	}
}

func TestURLs(t *testing.T) {
	for _, tt := range []struct{ name, version, want string }{
		{"isarray", "2.0.5", npmNewURL},
		{"@tailwindcss/oxide", "4.1.0", "https://registry.npmjs.org/@tailwindcss/oxide/-/oxide-4.1.0.tgz"},
		{"JSONStream", "1.3.5-rc.1", "https://registry.npmjs.org/JSONStream/-/JSONStream-1.3.5-rc.1.tgz"},
	} {
		if got := npmTarballURL(tt.name, tt.version); got != tt.want {
			t.Errorf("npmTarballURL(%q, %q) = %q, want %q", tt.name, tt.version, got, tt.want)
		}
	}
	if got := gh.DefaultBaseURL + actionTarballPath("dtolnay/rust-toolchain", recordedAction.Old.Hash); got != actionOldURL {
		t.Errorf("action tarball URL %q, want %q", got, actionOldURL)
	}
}

// checkRecordedNPM is what the isarray 2.0.4 to 2.0.5 update must read
// as, replayed or live.
func checkRecordedNPM(t *testing.T, got Prepared) {
	t.Helper()
	all := text(got)
	for _, want := range []string{
		"== file: LICENSE (added)\n",
		"+MIT License\n",
		"== file: README.md (changed)\n",
		"-## License\n",
		"== file: package.json (changed)\n",
		"-  \"version\": \"2.0.4\",\n+  \"version\": \"2.0.5\",\n",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("the text lacks %q:\n%s", want, all)
		}
	}
	if strings.Contains(all, "== file: index.js") {
		t.Errorf("index.js did not change between the two versions, but it is shown:\n%s", all)
	}
	if got.State != allow.ReadFull || len(got.Unread) != 0 || len(got.Chunks) != 1 {
		t.Errorf("state %q, unread %v, %d chunks; want a full read in one chunk", got.State, unreadPaths(got), len(got.Chunks))
	}
}

func TestRecordedNPM(t *testing.T) {
	r, rp := replayReader(t, npmRoutes(), nil)
	got, err := r.Prepare(context.Background(), recordedNPM, roomy)
	if err != nil {
		t.Fatal(err)
	}
	checkRecordedNPM(t, got)
	if want := []string{npmOldURL, npmNewURL}; !reflect.DeepEqual(rp.urls(), want) {
		t.Errorf("requests %v, want %v", rp.urls(), want)
	}
}

// checkRecordedAction is what the recorded dtolnay/rust-toolchain update
// must read as, replayed or live.
func checkRecordedAction(t *testing.T, got Prepared) {
	t.Helper()
	all := text(got)
	if strings.Count(all, "== file: ") != 1 || !strings.HasPrefix(all, "== file: .github/workflows/ci.yml (changed)\n@@ ") {
		t.Errorf("want exactly the one changed file, .github/workflows/ci.yml:\n%s", all)
	}
	if !strings.Contains(all, "\n-") || strings.Contains(all, "pax_global_header") || strings.Contains(all, "dtolnay-rust-toolchain-") {
		t.Errorf("text:\n%s", all)
	}
	if got.State != allow.ReadFull || len(got.Unread) != 0 {
		t.Errorf("state %q, unread %v", got.State, unreadPaths(got))
	}
}

func TestRecordedAction(t *testing.T) {
	github := gh.New("the-job-token")
	r, rp := replayReader(t, actionRoutes(), github)
	got, err := r.Prepare(context.Background(), recordedAction, roomy)
	if err != nil {
		t.Fatal(err)
	}
	checkRecordedAction(t, got)
	if want := []string{actionOldURL, codeloadOldURL, actionNewURL, codeloadNewURL}; !reflect.DeepEqual(rp.urls(), want) {
		t.Errorf("requests %v, want %v", rp.urls(), want)
	}
	// The token goes to the API and stays there.
	for _, req := range rp.seen {
		auth := req.Header.Get("Authorization")
		switch req.URL.Host {
		case "api.github.com":
			if auth != "Bearer the-job-token" {
				t.Errorf("%s: Authorization %q", req.URL, auth)
			}
		default:
			if auth != "" {
				t.Errorf("%s: the token was sent to another host", req.URL)
			}
		}
	}
}

func TestActionWithoutAToken(t *testing.T) {
	r, rp := replayReader(t, actionRoutes(), nil)
	if _, err := r.Prepare(context.Background(), recordedAction, roomy); err != nil {
		t.Fatal(err)
	}
	for _, req := range rp.seen {
		if req.Header.Get("Authorization") != "" {
			t.Errorf("%s: an Authorization header without a token", req.URL)
		}
	}
}

// checkRecordedModule is what the rsc.io/quote v1.5.1 to v1.5.2 update
// must read as, from a directory or live.
func checkRecordedModule(t *testing.T, got Prepared) {
	t.Helper()
	// v1.5.2 adds one file to v1.5.1 and changes nothing else.
	want := `== file: buggy/buggy_test.go (added)
@@ -0,0 +1,11 @@
+// Copyright 2018 The Go Authors. All rights reserved.
+// Use of this source code is governed by a BSD-style
+// license that can be found in the LICENSE file.
+
+package buggy
+
+import "testing"
+
+func Test(t *testing.T) {
+	t.Fatal("buggy!")
+}
`
	if all := text(got); all != want {
		t.Errorf("text:\n%s\nwant:\n%s", all, want)
	}
	if got.State != allow.ReadFull || len(got.Unread) != 0 {
		t.Errorf("state %q, unread %v", got.State, unreadPaths(got))
	}
}

// The go command itself downloads the recorded module, from a directory
// laid out as a module proxy. Only the proxy and the checksum database
// differ from production: GOPROXY is the directory, and the checksum
// database, which cannot be recorded, is off. The hashes are the real
// ones, so the zip the go command hands over is checked against what
// sum.golang.org says.
func TestRecordedGoModule(t *testing.T) {
	zips := map[Ref][]byte{}
	for _, ref := range []Ref{recordedModule.Old, recordedModule.New} {
		zipped, err := os.ReadFile(recordedFile(ref))
		if err != nil {
			t.Fatal(err)
		}
		zips[ref] = zipped
	}
	r := newReader(t, directoryProxy(t, zips))
	got, err := r.Prepare(context.Background(), recordedModule, roomy)
	if err != nil {
		t.Fatal(err)
	}
	checkRecordedModule(t, got)
	if ents, _ := os.ReadDir(r.scratch); len(ents) != 0 {
		t.Errorf("the module cache was left behind: %v", ents)
	}

	// The same module under a hash it does not have: the go command's
	// own report is compared first.
	wrong := recordedModule
	wrong.New.Hash = recordedModule.Old.Hash
	if _, err := r.Prepare(context.Background(), wrong, roomy); !errors.Is(err, ErrHashMismatch) {
		t.Errorf("error %v, want ErrHashMismatch", err)
	}
	// A version the proxy does not have.
	missing := recordedModule
	missing.To, missing.New.Version = "v1.5.3", "v1.5.3"
	if _, err := r.Prepare(context.Background(), missing, roomy); err == nil || errors.Is(err, ErrHashMismatch) {
		t.Errorf("error %v, want a download error", err)
	}
}

// directoryProxy is a fetcher that runs the real go command against a
// directory laid out as a module proxy and holding the given module
// zips, with the checksum database off.
func directoryProxy(t *testing.T, zips map[Ref][]byte) *netFetcher {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go command is not installed")
	}
	proxy := t.TempDir()
	for ref, zipped := range zips {
		dir := filepath.Join(proxy, ref.Name, "@v")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		zr, err := zip.NewReader(bytes.NewReader(zipped), int64(len(zipped)))
		if err != nil {
			t.Fatal(err)
		}
		gomod, err := zr.Open(ref.Name + "@" + ref.Version + "/go.mod")
		if err != nil {
			t.Fatal(err)
		}
		mod, _ := io.ReadAll(gomod)
		gomod.Close()
		for name, content := range map[string][]byte{
			ref.Version + ".zip":  zipped,
			ref.Version + ".mod":  mod,
			ref.Version + ".info": []byte(`{"Version":"` + ref.Version + `","Time":"2018-02-14T00:00:00Z"}`),
		} {
			if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return &netFetcher{goBin: goBin, goProxy: "file://" + filepath.ToSlash(proxy), goSumDB: "off"}
}

// What the go command does with a module whose go.mod asks for a newer
// Go than the one installed. With GOTOOLCHAIN=local, which keeps it from
// downloading and running another toolchain, go 1.27 refuses to download
// the module at all. For the gate that is an error from Prepare, so the
// update goes to a person until the gate's own Go is as new as the
// dependency asks for. The test pins that reading and tells whoever
// upgrades Go if it changes.
func TestGoModuleNewerThanTheToolchain(t *testing.T) {
	oldZip := moduleZip(t, "example.com/future", "v1.0.0", map[string]string{
		"go.mod": "module example.com/future\n\ngo 1.21\n", "a.go": "package future\n"})
	newZip := moduleZip(t, "example.com/future", "v1.1.0", map[string]string{
		"go.mod": "module example.com/future\n\ngo 1.999\n", "a.go": "package future\n\nvar X = 1\n"})
	p := Pair{Ecosystem: allow.GoModules, Name: "example.com/future", From: "v1.0.0", To: "v1.1.0",
		Old: Ref{Kind: GoModuleZip, Name: "example.com/future", Version: "v1.0.0", Hash: h1(t, oldZip)},
		New: Ref{Kind: GoModuleZip, Name: "example.com/future", Version: "v1.1.0", Hash: h1(t, newZip)}}
	r := newReader(t, directoryProxy(t, map[Ref][]byte{p.Old: oldZip, p.New: newZip}))
	got, err := r.Prepare(context.Background(), p, roomy)
	switch {
	case err == nil:
		// A go command that downloads it anyway: then it must read.
		t.Logf("this go command downloads a module that asks for go 1.999")
		if got.State != allow.ReadFull || !strings.Contains(text(got), "+var X = 1\n") {
			t.Errorf("state %q, text:\n%s", got.State, text(got))
		}
	case errors.Is(err, ErrHashMismatch) || errors.Is(err, ErrUnsafeArchive) || errors.Is(err, ErrBadRef):
		t.Errorf("error %v: want the go command's own refusal", err)
	case !strings.Contains(err.Error(), "requires go"):
		t.Errorf("error %v: want the go command's \"requires go >= 1.999\"", err)
	}
}

func TestGoEnvInheritsNothing(t *testing.T) {
	t.Setenv("GOFLAGS", "-insecure")
	t.Setenv("GOPROXY", "https://proxy.example")
	t.Setenv("GONOSUMDB", "*")
	t.Setenv("GONOSUMCHECK", "1")
	t.Setenv("GOPRIVATE", "*")
	t.Setenv("GOINSECURE", "*")
	f := &netFetcher{goProxy: goProxy, goSumDB: goSumDB}
	env := f.goEnv("/scratch", "/scratch/home")
	got := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		if _, dup := got[k]; dup {
			t.Errorf("%s is set twice", k)
		}
		got[k] = v
	}
	for k, want := range map[string]string{
		"GOPROXY": "https://proxy.golang.org", "GOSUMDB": "sum.golang.org", "GOFLAGS": "-mod=mod -modcacherw",
		"GONOSUMDB": "", "GONOSUMCHECK": "", "GOPRIVATE": "", "GOINSECURE": "", "GONOPROXY": "",
		"GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local", "GOVCS": "*:off",
	} {
		if v, ok := got[k]; !ok || v != want {
			t.Errorf("%s = %q (set: %v), want %q", k, v, ok, want)
		}
	}
}

func TestDownloadFailures(t *testing.T) {
	other, err := os.ReadFile(recordedFile(recordedNPM.Old))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		pair     Pair
		routes   func() map[string]*route
		github   *gh.Client
		wantErr  error // nil: any error that is not one of the package's
		requests int
	}{
		{"npm: not found is final", recordedNPM, func() map[string]*route {
			r := npmRoutes()
			r[npmOldURL] = &route{status: http.StatusNotFound}
			return r
		}, nil, nil, 1},
		{"npm: 503 three times is unavailable", recordedNPM, func() map[string]*route {
			r := npmRoutes()
			r[npmOldURL].failures = 3
			return r
		}, nil, ErrUnavailable, 3},
		{"npm: 429 three times is unavailable", recordedNPM, func() map[string]*route {
			r := npmRoutes()
			r[npmNewURL] = &route{status: http.StatusTooManyRequests}
			return r
		}, nil, ErrUnavailable, 4},
		{"action: 502 from the download host is unavailable", recordedAction, func() map[string]*route {
			r := actionRoutes()
			r[codeloadOldURL] = &route{status: http.StatusBadGateway}
			return r
		}, nil, ErrUnavailable, 6},
		{"npm: a redirect is refused", recordedNPM, func() map[string]*route {
			r := npmRoutes()
			r[npmOldURL] = &route{status: http.StatusFound, location: "https://codeload.github.com/x/y/legacy.tar.gz/z"}
			return r
		}, nil, errRedirect, 1},
		{"npm: other bytes than the lockfile's", recordedNPM, func() map[string]*route {
			r := npmRoutes()
			r[npmNewURL] = &route{body: other}
			return r
		}, nil, ErrHashMismatch, 2},
		{"action: a redirect to another host is refused", recordedAction, func() map[string]*route {
			r := actionRoutes()
			r[actionOldURL].location = "https://codeload.example.com/x"
			return r
		}, nil, errRedirect, 1},
		{"action: a redirect to http is refused", recordedAction, func() map[string]*route {
			r := actionRoutes()
			r[actionOldURL].location = strings.Replace(codeloadOldURL, "https://", "http://", 1)
			return r
		}, nil, errRedirect, 1},
		{"action: the tarball of another commit", recordedAction, func() map[string]*route {
			r := actionRoutes()
			r[codeloadNewURL].file = recordedFile(recordedAction.Old)
			return r
		}, nil, ErrHashMismatch, 4},
		{"action: a tarball that names no commit", recordedAction, func() map[string]*route {
			r := actionRoutes()
			r[codeloadOldURL] = &route{body: other}
			return r
		}, nil, ErrHashMismatch, 2},
		{"action: forbidden is final", recordedAction, func() map[string]*route {
			r := actionRoutes()
			r[actionOldURL] = &route{status: http.StatusForbidden}
			return r
		}, nil, nil, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, rp := replayReader(t, tt.routes(), tt.github)
			_, err := r.Prepare(context.Background(), tt.pair, roomy)
			switch {
			case err == nil:
				t.Fatal("prepared a read; want an error")
			case tt.wantErr != nil && !errors.Is(err, tt.wantErr):
				t.Errorf("error %v, want %v", err, tt.wantErr)
			case tt.wantErr == nil && (errors.Is(err, ErrHashMismatch) || errors.Is(err, ErrUnsafeArchive) || errors.Is(err, ErrBadRef)):
				t.Errorf("error %v: a failed download is none of the package's refusals", err)
			}
			// Only a failure that was retried to the end is a wait. An
			// answer that arrived (404, 403, a redirect, other bytes) must
			// not be waited out.
			if got := errors.Is(err, ErrUnavailable); got != (tt.wantErr == ErrUnavailable) {
				t.Errorf("error %v: unavailable is %v", err, got)
			}
			if got := len(rp.urls()); got != tt.requests {
				t.Errorf("%d requests %v, want %d", got, rp.urls(), tt.requests)
			}
		})
	}
}

// The caller's context ending is the caller's error, whatever the
// download was doing: it is in none of the package's classes, so nobody
// reads it as "the registry is down, wait".
func TestCallerContextIsNoClass(t *testing.T) {
	routes := npmRoutes()
	routes[npmOldURL].failures = 3
	r, _ := replayReader(t, routes, nil)
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel while the fetcher waits between two attempts.
	r.fetch.(*netFetcher).retryDelay = time.Hour
	time.AfterFunc(50*time.Millisecond, cancel)
	_, err := r.Prepare(ctx, recordedNPM, roomy)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v, want the context's", err)
	}
	for _, class := range []error{ErrUnavailable, ErrHashMismatch, ErrUnsafeArchive, ErrBadRef} {
		if errors.Is(err, class) {
			t.Errorf("a cancelled Prepare is %v", class)
		}
	}
}

// What a failed fetch is: the caller's own error when the caller gave up,
// a refusal when it is one however late it arrived, a wait when the
// download's time ran out, and otherwise nothing this package names.
func TestFetchError(t *testing.T) {
	plain := errors.New("go mod download: exit status 1")
	mismatch := hashMismatch(recordedNPM.New, "the tarball is other bytes")
	for _, tc := range []struct {
		name      string
		err       error
		callerErr error
		timedOut  bool
		want      error // the class; nil for none of the package's
	}{
		{"a hash mismatch", mismatch, nil, false, ErrHashMismatch},
		{"a hash mismatch found after the time ran out", mismatch, nil, true, ErrHashMismatch},
		{"an unsafe archive found after the time ran out", unsafeArchive("a symbolic link"), nil, true, ErrUnsafeArchive},
		{"a bad reference after the time ran out", badRef("kind %q", "x"), nil, true, ErrBadRef},
		{"retries used up", fmt.Errorf("%w: HTTP 503", ErrUnavailable), nil, false, ErrUnavailable},
		{"retries used up as the time ran out", fmt.Errorf("%w: HTTP 503", ErrUnavailable), nil, true, ErrUnavailable},
		{"the go command killed when the time ran out", plain, nil, true, ErrUnavailable},
		{"the go command failed", plain, nil, false, nil},
		{"the caller gave up", plain, context.Canceled, true, context.Canceled},
		{"the caller gave up on a download that was failing", fmt.Errorf("%w: HTTP 503", ErrUnavailable), context.DeadlineExceeded, true, context.DeadlineExceeded},
	} {
		got := fetchError(tc.err, tc.callerErr, tc.timedOut)
		for _, class := range []error{ErrHashMismatch, ErrUnsafeArchive, ErrBadRef, ErrUnavailable, context.Canceled, context.DeadlineExceeded} {
			if errors.Is(got, class) != (class == tc.want) {
				t.Errorf("%s: %v: errors.Is(%v) is %v", tc.name, got, class, errors.Is(got, class))
			}
		}
	}
}

// The go command's errors are text. One exact shape of it is read as the
// module proxy not answering; everything else is left alone.
func TestGoProxyOutage(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       bool
	}{
		{"503", "github.com/fsnotify/fsnotify@v1.5.4: reading https://proxy.golang.org/github.com/fsnotify/fsnotify/@v/v1.5.4.zip: 503 Service Unavailable", true},
		{"500 with the server's text", "example.com/m@v1.0.0: reading https://proxy.golang.org/example.com/m/@v/v1.0.0.info: 500 Internal Server Error\n\tserver response: oops", true},
		{"429", "example.com/m@v1.0.0: reading https://proxy.golang.org/example.com/m/@v/v1.0.0.zip: 429 Too Many Requests", true},
		{"no response", `golang.org/x/text@v0.3.3: Get "https://proxy.golang.org/golang.org/x/text/@v/v0.3.3.info": dial tcp: i/o timeout`, true},
		{"no response from another host", `example.com/m@v1.0.0: Get "https://example.com/m?go-get=1": dial tcp: i/o timeout`, false},
		{"a quoted URL that only starts like the proxy's", `example.com/m@v1.0.0: Get "https://proxy.golang.org.evil.example/m": EOF`, false},
		// The recorded answer for a version that does not exist.
		{"404", "github.com/fsnotify/fsnotify@v1.5.99: reading https://proxy.golang.org/github.com/fsnotify/fsnotify/@v/v1.5.99.info: 404 Not Found\n\tserver response: not found: github.com/fsnotify/fsnotify@v1.5.99: invalid version: unknown revision v1.5.99", false},
		{"410", "example.com/m@v1.0.0: reading https://proxy.golang.org/example.com/m/@v/v1.0.0.info: 410 Gone", false},
		// The recorded answer for a module that fails the checksum database.
		{"checksum mismatch", "github.com/fsnotify/fsnotify@v1.5.4: verifying go.mod: checksum mismatch\n\tdownloaded: h1:KOil/w6cxr3ALagyF6SIPYeoV9XN+Pjkp5hICIRMzgM=\n\tsum.golang.org: h1:OVB6XrOHzAwXMpEM7uPOzcehqUV2UqJxmVXmkdnm1bU=\n\nSECURITY ERROR\n", false},
		{"a 503 quoted in a 404's text", "example.com/m@v1.0.0: reading https://proxy.golang.org/example.com/m/@v/v1.0.0.info: 404 Not Found\n\tserver response: example.com/m@v1.0.0: reading https://proxy.golang.org/x: 503 Service Unavailable", false},
		{"another host", "example.com/m@v1.0.0: reading https://proxy.golang.org.evil.example/example.com/m/@v/v1.0.0.zip: 503 Service Unavailable", false},
		{"plain http", "example.com/m@v1.0.0: reading http://proxy.golang.org/example.com/m/@v/v1.0.0.zip: 503 Service Unavailable", false},
		{"not at the start", "go: example.com/m@v1.0.0: reading https://proxy.golang.org/example.com/m/@v/v1.0.0.zip: 503 Service Unavailable", false},
		{"a status that only starts with 5", "example.com/m@v1.0.0: reading https://proxy.golang.org/example.com/m/@v/v1.0.0.zip: 5030 Odd", false},
		{"empty", "", false},
	} {
		if got := goProxyOutageRE.MatchString(tc.text); got != tc.want {
			t.Errorf("%s: outage is %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestDownloadRetries(t *testing.T) {
	routes := npmRoutes()
	routes[npmOldURL].failures = 2
	r, rp := replayReader(t, routes, nil)
	got, err := r.Prepare(context.Background(), recordedNPM, roomy)
	if err != nil {
		t.Fatal(err)
	}
	checkRecordedNPM(t, got)
	if want := []string{npmOldURL, npmOldURL, npmOldURL, npmNewURL}; !reflect.DeepEqual(rp.urls(), want) {
		t.Errorf("requests %v, want %v", rp.urls(), want)
	}
}

func TestNewChecksTheGitHubRoot(t *testing.T) {
	for _, base := range []string{"http://api.github.com/", "https://ghe.example.com/api/v3", "ftp://x/", ""} {
		if _, err := New(Options{GitHub: &gh.Client{BaseURL: base}}); err == nil {
			t.Errorf("New took the GitHub API root %q", base)
		}
	}
	if _, err := New(Options{GitHub: &gh.Client{BaseURL: "https://ghe.example.com/api/v3/"}}); err != nil {
		t.Errorf("New refused a GitHub Enterprise API root: %v", err)
	}
}

// The live test fetches the recorded updates from the real services and
// expects exactly what the recordings give. It runs only when asked:
//
//	DEP_REVIEW_LIVE=1 go test ./internal/artifact/ -run TestLive -v
func TestLive(t *testing.T) {
	if os.Getenv("DEP_REVIEW_LIVE") == "" {
		t.Skip("set DEP_REVIEW_LIVE=1 to fetch from the module proxy, the npm registry and GitHub")
	}
	var github *gh.Client
	if token := os.Getenv("GH_TOKEN"); token != "" {
		github = gh.New(token)
	}
	p, err := New(Options{Scratch: t.TempDir(), GitHub: github})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("npm", func(t *testing.T) {
		got, err := p.Prepare(context.Background(), recordedNPM, roomy)
		if err != nil {
			t.Fatal(err)
		}
		checkRecordedNPM(t, got)
		replayed, _ := replayReader(t, npmRoutes(), nil)
		want, err := replayed.Prepare(context.Background(), recordedNPM, roomy)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("live and recorded differ (%v):\n%s\nrecorded:\n%s", err, text(got), text(want))
		}
		t.Logf("key %s", got.Key)
	})
	t.Run("gomod", func(t *testing.T) {
		got, err := p.Prepare(context.Background(), recordedModule, roomy)
		if err != nil {
			t.Fatal(err)
		}
		checkRecordedModule(t, got)
		t.Logf("key %s\n%s", got.Key, text(got))
	})
	t.Run("actions", func(t *testing.T) {
		got, err := p.Prepare(context.Background(), recordedAction, roomy)
		if err != nil {
			t.Fatal(err)
		}
		checkRecordedAction(t, got)
		replayed, _ := replayReader(t, actionRoutes(), nil)
		want, err := replayed.Prepare(context.Background(), recordedAction, roomy)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("live and recorded differ (%v):\n%s\nrecorded:\n%s", err, text(got), text(want))
		}
		t.Logf("key %s", got.Key)
	})
}

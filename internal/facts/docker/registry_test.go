package docker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/facts"
)

// The registries' failure modes, which cannot be recorded on demand, are
// played by fakeRegistry. The answers a healthy registry gives are in
// testdata/recorded (recorded_test.go).

// fakeAnswer is one answer of fakeRegistry.
type fakeAnswer struct {
	status int
	header map[string]string
	body   string
	// err is a transport failure in place of an answer.
	err error
}

// fakeRegistry answers each request ("METHOD URL") from its list for
// that request, in order; the last answer repeats. A request with no
// list fails the test.
type fakeRegistry struct {
	t       *testing.T
	answers map[string][]fakeAnswer
	asked   []string
	// bearer is the Authorization header of each request, in order.
	bearer []string
}

func (f *fakeRegistry) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.Method + " " + req.URL.String()
	f.asked = append(f.asked, key)
	f.bearer = append(f.bearer, req.Header.Get("Authorization"))
	list := f.answers[key]
	if len(list) == 0 {
		f.t.Errorf("unexpected request: %s", key)
		return nil, fmt.Errorf("unexpected request: %s", key)
	}
	ans := list[0]
	if len(list) > 1 {
		f.answers[key] = list[1:]
	}
	if ans.err != nil {
		return nil, ans.err
	}
	return response(req, ans.status, ans.header, []byte(ans.body)), nil
}

// count is how often key was asked.
func (f *fakeRegistry) count(key string) int {
	n := 0
	for _, asked := range f.asked {
		if asked == key {
			n++
		}
	}
	return n
}

// The requests for golang:1.27 and for distroless static:nonroot.
const (
	hubTokenURL = "GET https://auth.docker.io/token?scope=repository%3Alibrary%2Fgolang%3Apull&service=registry.docker.io"
	hubHeadURL  = "HEAD https://registry-1.docker.io/v2/library/golang/manifests/1.27"
	hubTagURL   = "GET https://hub.docker.com/v2/repositories/library/golang/tags/1.27"
	gcrHeadURL  = "HEAD https://gcr.io/v2/distroless/static/manifests/nonroot"
	gcrListURL  = "GET https://gcr.io/v2/distroless/static/tags/list"
)

var (
	okToken = fakeAnswer{status: 200, body: `{"token":"t0ken"}`}
	okHead  = fakeAnswer{status: 200, header: map[string]string{"Docker-Content-Digest": digestB}}
	okTag   = fakeAnswer{status: 200, body: `{"name":"1.27","digest":"` + digestB + `","tag_last_pushed":"2026-11-10T18:33:44.343824Z"}`}
	okList  = fakeAnswer{status: 200, body: gcrListBody(`"1787335936959"`, `"nonroot"`)}
)

// gcrListBody is a tag list whose entry for digestB has the given
// timeUploadedMs and tags, both written as JSON.
func gcrListBody(uploadedMs, tags string) string {
	return `{"name":"distroless/static","tags":["nonroot"],"manifest":{` +
		`"` + digestA + `":{"tag":[],"timeUploadedMs":"1700000000000","timeCreatedMs":"0"},` +
		`"` + digestB + `":{"tag":[` + tags + `],"timeUploadedMs":` + uploadedMs + `,"timeCreatedMs":"0"}}}`
}

// healthyHub and healthyGCR answer everything well; a test replaces the
// answer it is about.
func healthyHub(t *testing.T) *fakeRegistry {
	return &fakeRegistry{t: t, answers: map[string][]fakeAnswer{
		hubTokenURL: {okToken}, hubHeadURL: {okHead}, hubTagURL: {okTag},
	}}
}

func healthyGCR(t *testing.T) *fakeRegistry {
	return &fakeRegistry{t: t, answers: map[string][]fakeAnswer{
		gcrHeadURL: {okHead}, gcrListURL: {okList},
	}}
}

// oneLine is a Dockerfile whose single FROM line moves from one image
// reference to another.
func oneLine(from, to string) []facts.File {
	return []facts.File{dockerfile("Dockerfile", "FROM "+from+"\n", "FROM "+to+"\n")}
}

var (
	golangRefresh     = oneLine("golang:1.27@"+digestA, "golang:1.27@"+digestB)
	distrolessRefresh = oneLine("gcr.io/distroless/static:nonroot@"+digestA, "gcr.io/distroless/static:nonroot@"+digestB)
)

// gatherWith runs the gatherer against a fake registry, without waiting
// between tries. It returns the waits that were asked for.
func gatherWith(t *testing.T, reg http.RoundTripper, files []facts.File) (facts.Result, []time.Duration, error) {
	t.Helper()
	var waits []time.Duration
	g := &Gatherer{sleep: func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}}
	res, err := g.Gather(context.Background(), facts.Input{
		Files:  files,
		Policy: defaultPolicy(t),
		HTTP:   &http.Client{Transport: reg},
	})
	return res, waits, err
}

// oneUpdate is gatherWith for a pull request with exactly one update and
// no error.
func oneUpdate(t *testing.T, reg http.RoundTripper, files []facts.File) allow.UpdateFacts {
	t.Helper()
	res, _, err := gatherWith(t, reg, files)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Shape.Holds() || len(res.Updates) != 1 {
		t.Fatalf("Shape %+v, %d updates", res.Shape, len(res.Updates))
	}
	checkExplained(t, res.Updates[0])
	return res.Updates[0]
}

func TestHealthyFakes(t *testing.T) {
	hub := healthyHub(t)
	u := oneUpdate(t, hub, golangRefresh)
	if !u.Bound.Holds() || !u.Clean.Holds() || !u.FirstSeen.Known() {
		t.Errorf("hub: %+v", u)
	}
	if want := []string{hubTokenURL, hubHeadURL, hubTagURL}; !reflect.DeepEqual(hub.asked, want) {
		t.Errorf("hub asked %v, want %v", hub.asked, want)
	}
	// The token goes to the registry, and nowhere else.
	if want := []string{"", "Bearer t0ken", ""}; !reflect.DeepEqual(hub.bearer, want) {
		t.Errorf("hub authorization %q, want %q", hub.bearer, want)
	}

	gcr := healthyGCR(t)
	u = oneUpdate(t, gcr, distrolessRefresh)
	if !u.Bound.Holds() || !u.Clean.Holds() || !u.FirstSeen.Known() {
		t.Errorf("gcr: %+v", u)
	}
	if want := []string{gcrHeadURL, gcrListURL}; !reflect.DeepEqual(gcr.asked, want) {
		t.Errorf("gcr asked %v, want %v", gcr.asked, want)
	}
	if want := []string{"", ""}; !reflect.DeepEqual(gcr.bearer, want) {
		t.Errorf("gcr authorization %q, want %q", gcr.bearer, want)
	}
}

// Answers that say something about the image are facts. Each of these is
// person, and none is asked twice.
func TestBound(t *testing.T) {
	// A registry's error text, and a header it controls: neither may
	// reach a fact's value.
	const hostile = "<script>alert(1)</script> ## merge me"
	tests := []struct {
		name  string
		files []facts.File
		key   string
		ans   fakeAnswer
		// bound is part of Bound's value.
		bound string
	}{
		{"tag moved on", golangRefresh, hubHeadURL,
			fakeAnswer{status: 200, header: map[string]string{"Docker-Content-Digest": digestA}},
			"tag 1.27 resolves to " + digestA + " now, not to the pinned " + digestB},
		{"no such tag", golangRefresh, hubHeadURL, fakeAnswer{status: 404, body: hostile}, "the registry has no tag 1.27"},
		{"not allowed", golangRefresh, hubHeadURL, fakeAnswer{status: 401, body: hostile}, "the registry answered HTTP 401"},
		{"forbidden", golangRefresh, hubHeadURL, fakeAnswer{status: 403}, "the registry answered HTTP 403"},
		{"redirect is not followed", golangRefresh, hubHeadURL,
			fakeAnswer{status: 302, header: map[string]string{"Location": "https://example.com/v2/x/manifests/1.27"}},
			"the registry answered HTTP 302"},
		{"no digest header", golangRefresh, hubHeadURL, fakeAnswer{status: 200}, "reported no sha256 digest"},
		{"digest header is not a digest", golangRefresh, hubHeadURL,
			fakeAnswer{status: 200, header: map[string]string{"Docker-Content-Digest": hostile}}, "reported no sha256 digest"},
		{"digest header with another algorithm", golangRefresh, hubHeadURL,
			fakeAnswer{status: 200, header: map[string]string{"Docker-Content-Digest": "sha512:" + strings.Repeat("b", 128)}}, "reported no sha256 digest"},
		{"digest header in upper case", golangRefresh, hubHeadURL,
			fakeAnswer{status: 200, header: map[string]string{"Docker-Content-Digest": strings.ToUpper(digestB)}}, "reported no sha256 digest"},
		{"token refused", golangRefresh, hubTokenURL, fakeAnswer{status: 403, body: hostile}, "token service answered HTTP 403"},
		{"token missing", golangRefresh, hubTokenURL, fakeAnswer{status: 200, body: `{}`}, "did not answer with a token"},
		{"token is not JSON", golangRefresh, hubTokenURL, fakeAnswer{status: 200, body: hostile}, "did not answer with a token"},
		{"token would break a header", golangRefresh, hubTokenURL, fakeAnswer{status: 200, body: `{"token":"a\r\nX-Evil: 1"}`}, "did not answer with a token"},
		{"token too large", golangRefresh, hubTokenURL,
			fakeAnswer{status: 200, body: `{"token":"` + strings.Repeat("a", maxTokenBytes) + `"}`}, "did not answer with a token"},
		{"gcr tag moved on", distrolessRefresh, gcrHeadURL,
			fakeAnswer{status: 200, header: map[string]string{"Docker-Content-Digest": digestA}}, "tag nonroot resolves to " + digestA},
		{"gcr no such tag", distrolessRefresh, gcrHeadURL, fakeAnswer{status: 404}, "the registry has no tag nonroot"},
		{"gcr wants credentials", distrolessRefresh, gcrHeadURL, fakeAnswer{status: 401}, "the registry answered HTTP 401"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := healthyHub(t)
			if tc.key == gcrHeadURL {
				reg = healthyGCR(t)
			}
			reg.answers[tc.key] = []fakeAnswer{tc.ans}
			res, waits, err := gatherWith(t, reg, tc.files)
			if err != nil {
				t.Fatal(err)
			}
			u := res.Updates[0]
			checkExplained(t, u)
			if u.Bound.OK || !strings.Contains(u.Bound.Value, tc.bound) {
				t.Errorf("Bound: %+v, want it not to hold and to say %q", u.Bound, tc.bound)
			}
			// With no Bound nothing else from the registry holds, and
			// nothing more is asked.
			if u.Clean.OK || u.FirstSeen.Known() {
				t.Errorf("Clean %+v, FirstSeen %+v", u.Clean, u.FirstSeen)
			}
			if reg.count(tc.key) != 1 || len(waits) != 0 {
				t.Errorf("asked %v, waited %v: a definitive answer is not asked again", reg.asked, waits)
			}
			if last := reg.asked[len(reg.asked)-1]; last != tc.key {
				t.Errorf("asked %s after the failed %s", last, tc.key)
			}
			for _, v := range []string{u.Bound.Value, u.Clean.Value, u.FirstSeen.Value} {
				if strings.Contains(v, "script") || strings.Contains(v, "merge me") || strings.Contains(v, "example.com") {
					t.Errorf("registry text reached a value: %q", v)
				}
			}
			d := decide(res, defaultPolicy(t), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
			if d.Outcome != allow.Person || d.Reasons[0] != allow.ReasonNotBound {
				t.Errorf("decision %s %v, want person, not_bound first", d.Outcome, d.Reasons)
			}
		})
	}
}

// FirstSeen is a time only when the registry's own clock said so about
// the pinned digest. Everything else is unknown, which is person: a
// placeholder read as a time would be decades old and satisfy every age.
func TestFirstSeen(t *testing.T) {
	hubTag := func(body string) fakeAnswer { return fakeAnswer{status: 200, body: body} }
	hubPushed := func(pushed string) fakeAnswer {
		return hubTag(`{"name":"1.27","digest":"` + digestB + `","tag_last_pushed":` + pushed + `}`)
	}
	gcrUploaded := func(ms string) fakeAnswer {
		return fakeAnswer{status: 200, body: gcrListBody(ms, `"nonroot"`)}
	}
	tests := []struct {
		name  string
		files []facts.File
		key   string
		ans   fakeAnswer
		// seen is the expected time; empty means unknown, and why must
		// then be part of the value.
		seen string
		why  string
	}{
		{name: "hub", files: golangRefresh, key: hubTagURL, ans: okTag, seen: "2026-11-10T18:33:44.343824Z"},
		{name: "hub, with an offset", files: golangRefresh, key: hubTagURL, ans: hubPushed(`"2026-11-10T20:33:44+02:00"`), seen: "2026-11-10T18:33:44Z"},
		{name: "hub, the tag at another digest", files: golangRefresh, key: hubTagURL,
			ans: hubTag(`{"name":"1.27","digest":"` + digestA + `","tag_last_pushed":"2020-01-01T00:00:00Z"}`), why: "not at the pinned digest"},
		{name: "hub, no digest", files: golangRefresh, key: hubTagURL,
			ans: hubTag(`{"name":"1.27","digest":null,"tag_last_pushed":"2020-01-01T00:00:00Z"}`), why: "no sha256 digest"},
		{name: "hub, digest is not a digest", files: golangRefresh, key: hubTagURL,
			ans: hubTag(`{"name":"1.27","digest":"<script>","tag_last_pushed":"2020-01-01T00:00:00Z"}`), why: "no sha256 digest"},
		{name: "hub, another tag", files: golangRefresh, key: hubTagURL,
			ans: hubTag(`{"name":"1.26","digest":"` + digestB + `","tag_last_pushed":"2020-01-01T00:00:00Z"}`), why: "another tag"},
		{name: "hub, time null", files: golangRefresh, key: hubTagURL, ans: hubPushed(`null`), why: "no usable tag_last_pushed"},
		{name: "hub, time missing", files: golangRefresh, key: hubTagURL, ans: hubTag(`{"name":"1.27","digest":"` + digestB + `"}`), why: "no usable tag_last_pushed"},
		{name: "hub, time empty", files: golangRefresh, key: hubTagURL, ans: hubPushed(`""`), why: "no usable tag_last_pushed"},
		{name: "hub, time is year 1", files: golangRefresh, key: hubTagURL, ans: hubPushed(`"0001-01-01T00:00:00Z"`), why: "no usable tag_last_pushed"},
		{name: "hub, time is the epoch", files: golangRefresh, key: hubTagURL, ans: hubPushed(`"1970-01-01T00:00:00Z"`), why: "no usable tag_last_pushed"},
		{name: "hub, time is not a time", files: golangRefresh, key: hubTagURL, ans: hubPushed(`"yesterday"`), why: "no usable tag_last_pushed"},
		{name: "hub, time is a date", files: golangRefresh, key: hubTagURL, ans: hubPushed(`"2026-11-10"`), why: "no usable tag_last_pushed"},
		{name: "hub, time is a number", files: golangRefresh, key: hubTagURL, ans: hubPushed(`1787335936`), why: "could not be read"},
		{name: "hub, not JSON", files: golangRefresh, key: hubTagURL, ans: hubTag(`<html>`), why: "could not be read"},
		{name: "hub, empty", files: golangRefresh, key: hubTagURL, ans: hubTag(``), why: "could not be read"},
		{name: "hub, too large", files: golangRefresh, key: hubTagURL,
			ans: hubTag(`{"name":"1.27","digest":"` + digestB + `","tag_last_pushed":"2020-01-01T00:00:00Z","pad":"` + strings.Repeat("a", maxHubTagBytes) + `"}`), why: "could not be read"},
		{name: "hub, no such tag", files: golangRefresh, key: hubTagURL, ans: fakeAnswer{status: 404, body: `{"message":"<script>"}`}, why: "Docker Hub answered HTTP 404"},
		{name: "hub, redirect", files: golangRefresh, key: hubTagURL,
			ans: fakeAnswer{status: 301, header: map[string]string{"Location": "https://example.com/"}}, why: "Docker Hub answered HTTP 301"},

		{name: "gcr", files: distrolessRefresh, key: gcrListURL, ans: okList, seen: "2026-08-21T18:12:16.959Z"},
		{name: "gcr, zero", files: distrolessRefresh, key: gcrListURL, ans: gcrUploaded(`"0"`), why: "no usable timeUploadedMs"},
		{name: "gcr, year 1", files: distrolessRefresh, key: gcrListURL, ans: gcrUploaded(`"-62135596800000"`), why: "no usable timeUploadedMs"},
		{name: "gcr, one millisecond", files: distrolessRefresh, key: gcrListURL, ans: gcrUploaded(`"1"`), why: "no usable timeUploadedMs"},
		{name: "gcr, seconds for milliseconds", files: distrolessRefresh, key: gcrListURL, ans: gcrUploaded(`"1787335936"`), why: "no usable timeUploadedMs"},
		{name: "gcr, empty", files: distrolessRefresh, key: gcrListURL, ans: gcrUploaded(`""`), why: "no usable timeUploadedMs"},
		{name: "gcr, not a number", files: distrolessRefresh, key: gcrListURL, ans: gcrUploaded(`"soon"`), why: "no usable timeUploadedMs"},
		{name: "gcr, overflow", files: distrolessRefresh, key: gcrListURL, ans: gcrUploaded(`"99999999999999999999"`), why: "no usable timeUploadedMs"},
		{name: "gcr, a JSON number", files: distrolessRefresh, key: gcrListURL, ans: gcrUploaded(`1787335936959`), why: "could not be read"},
		{name: "gcr, digest not in the list", files: distrolessRefresh, key: gcrListURL,
			ans: fakeAnswer{status: 200, body: `{"manifest":{"` + digestA + `":{"tag":["nonroot"],"timeUploadedMs":"1787335936959"}}}`}, why: "no manifest with the pinned digest"},
		{name: "gcr, empty list", files: distrolessRefresh, key: gcrListURL, ans: fakeAnswer{status: 200, body: `{}`}, why: "no manifest with the pinned digest"},
		{name: "gcr, not JSON", files: distrolessRefresh, key: gcrListURL, ans: fakeAnswer{status: 200, body: `<html>`}, why: "could not be read"},
		{name: "gcr, no list", files: distrolessRefresh, key: gcrListURL, ans: fakeAnswer{status: 404}, why: "answered HTTP 404 for its tag list"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := healthyHub(t)
			if tc.key == gcrListURL {
				reg = healthyGCR(t)
			}
			reg.answers[tc.key] = []fakeAnswer{tc.ans}
			res, _, err := gatherWith(t, reg, tc.files)
			if err != nil {
				t.Fatal(err)
			}
			u := res.Updates[0]
			checkExplained(t, u)
			if !u.Bound.Holds() {
				t.Fatalf("Bound: %+v", u.Bound)
			}
			if strings.Contains(u.FirstSeen.Value, "script") {
				t.Errorf("registry text reached the value: %q", u.FirstSeen.Value)
			}
			far := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
			d := decide(res, defaultPolicy(t), far)
			if tc.seen == "" {
				if u.FirstSeen.Known() || u.FirstSeen.OK || !u.FirstSeen.Time.IsZero() {
					t.Fatalf("FirstSeen is known: %+v", u.FirstSeen)
				}
				if !strings.Contains(u.FirstSeen.Value, tc.why) {
					t.Errorf("FirstSeen says %q, want it to say %q", u.FirstSeen.Value, tc.why)
				}
				// However long one waits.
				if d.Outcome != allow.Person || !contains(d.Reasons, allow.ReasonFirstSeenUnknown) {
					t.Errorf("decision %s %v, want person with first_seen_unknown", d.Outcome, d.Reasons)
				}
				return
			}
			if !u.FirstSeen.Known() || !u.FirstSeen.Time.Equal(mustTime(t, tc.seen)) {
				t.Fatalf("FirstSeen %+v, want %s", u.FirstSeen, tc.seen)
			}
			if d.Outcome != allow.Merge {
				t.Errorf("decision %s %v, want merge", d.Outcome, d.Reasons)
			}
		})
	}
}

func contains(reasons []allow.Reason, r allow.Reason) bool {
	for _, have := range reasons {
		if have == r {
			return true
		}
	}
	return false
}

// A larger list than the limit is not read, and that is not an error.
func TestGCRListTooLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates more than 64 MB")
	}
	reg := healthyGCR(t)
	reg.answers[gcrListURL] = []fakeAnswer{{status: 200, body: `{"pad":"` + strings.Repeat("a", maxGCRListBytes) + `"}`}}
	u := oneUpdate(t, reg, distrolessRefresh)
	if u.FirstSeen.Known() || !strings.Contains(u.FirstSeen.Value, "larger than 64 MB") || u.Clean.OK {
		t.Errorf("FirstSeen %+v, Clean %+v", u.FirstSeen, u.Clean)
	}
}

// GCR's deprecation mark is the tag deprecated-public-image-<the
// manifest's own digest in hex>, and only that.
func TestGCRDeprecated(t *testing.T) {
	hexB := strings.TrimPrefix(digestB, "sha256:")
	hexA := strings.TrimPrefix(digestA, "sha256:")
	tests := []struct {
		name  string
		tags  string
		clean bool
	}{
		{"no mark", `"nonroot","nonroot-0170310d2620046d308a2b1cc1d2a4303fa71946"`, true},
		{"no tags at all", ``, true},
		{"marked", `"deprecated-public-image-` + hexB + `","nonroot"`, false},
		{"marked, last", `"nonroot","deprecated-public-image-` + hexB + `"`, false},
		// Tags that are not the mark of this manifest. GCR's other
		// marker, on a manifest its tag has left, is not a deprecation.
		{"another manifest's mark", `"deprecated-public-image-` + hexA + `","nonroot"`, true},
		{"the prefix alone", `"deprecated-public-image-","nonroot"`, true},
		{"update available", `"update-available-` + hexB + `","nonroot"`, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := healthyGCR(t)
			reg.answers[gcrListURL] = []fakeAnswer{{status: 200, body: gcrListBody(`"1787335936959"`, tc.tags)}}
			res, _, err := gatherWith(t, reg, distrolessRefresh)
			if err != nil {
				t.Fatal(err)
			}
			u := res.Updates[0]
			checkExplained(t, u)
			if u.Clean.OK != tc.clean {
				t.Errorf("Clean: %+v, want %v", u.Clean, tc.clean)
			}
			// The mark does not change what else is known.
			if !u.Bound.Holds() || !u.FirstSeen.Known() {
				t.Errorf("Bound %+v, FirstSeen %+v", u.Bound, u.FirstSeen)
			}
			d := decide(res, defaultPolicy(t), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
			want, reasons := allow.Merge, []allow.Reason(nil)
			if !tc.clean {
				want, reasons = allow.Person, []allow.Reason{allow.ReasonNotClean}
			}
			if d.Outcome != want || !reflect.DeepEqual(d.Reasons, reasons) {
				t.Errorf("decision %s %v, want %s %v", d.Outcome, d.Reasons, want, reasons)
			}
		})
	}
}

// A registry that cannot be asked is tried again. One that still has no
// answer leaves what depended on it not established, which is person:
// the run does not fail, and nothing else it learned is lost.
func TestTransient(t *testing.T) {
	down := errors.New("connection refused: <script>")
	tests := []struct {
		key string
		// What still holds when key cannot be asked, and the reasons
		// allow.Decide then gives.
		bound, clean bool
		reasons      []allow.Reason
	}{
		{hubTokenURL, false, false, []allow.Reason{allow.ReasonNotBound, allow.ReasonNotClean, allow.ReasonFirstSeenUnknown}},
		{hubHeadURL, false, false, []allow.Reason{allow.ReasonNotBound, allow.ReasonNotClean, allow.ReasonFirstSeenUnknown}},
		{hubTagURL, true, true, []allow.Reason{allow.ReasonFirstSeenUnknown}},
		{gcrHeadURL, false, false, []allow.Reason{allow.ReasonNotBound, allow.ReasonNotClean, allow.ReasonFirstSeenUnknown}},
		{gcrListURL, true, false, []allow.Reason{allow.ReasonNotClean, allow.ReasonFirstSeenUnknown}},
	}
	for _, tc := range tests {
		key := tc.key
		files := golangRefresh
		registry := healthyHub
		if strings.Contains(key, "gcr.io") {
			files, registry = distrolessRefresh, healthyGCR
		}
		good := registry(t).answers[key][0]

		for _, bad := range []fakeAnswer{{status: 429}, {status: 500}, {status: 502}, {status: 503}, {status: 504}, {err: down}} {
			name := fmt.Sprintf("%s/%d", strings.SplitN(key, "?", 2)[0], bad.status)

			t.Run(name+"/twice, then an answer", func(t *testing.T) {
				reg := registry(t)
				reg.answers[key] = []fakeAnswer{bad, bad, good}
				res, waits, err := gatherWith(t, reg, files)
				if err != nil {
					t.Fatal(err)
				}
				u := res.Updates[0]
				if !u.Bound.Holds() || !u.Clean.Holds() || !u.FirstSeen.Known() {
					t.Errorf("facts: %+v", u)
				}
				if reg.count(key) != 3 || !reflect.DeepEqual(waits, []time.Duration{time.Second, 2 * time.Second}) {
					t.Errorf("asked %d times, waited %v", reg.count(key), waits)
				}
			})

			t.Run(name+"/every time", func(t *testing.T) {
				reg := registry(t)
				reg.answers[key] = []fakeAnswer{bad}
				res, waits, err := gatherWith(t, reg, files)
				if err != nil {
					t.Fatalf("the run failed: %v", err)
				}
				if !res.Shape.Holds() || len(res.Updates) != 1 {
					t.Fatalf("Shape %+v, %d updates", res.Shape, len(res.Updates))
				}
				u := res.Updates[0]
				checkExplained(t, u)
				if u.Bound.OK != tc.bound || u.Clean.OK != tc.clean || u.FirstSeen.Known() {
					t.Errorf("Bound %+v, Clean %+v, FirstSeen %+v", u.Bound, u.Clean, u.FirstSeen)
				}
				if reg.count(key) != maxTries || len(waits) != maxTries-1 {
					t.Errorf("asked %d times, waited %v", reg.count(key), waits)
				}
				if last := reg.asked[len(reg.asked)-1]; last != key {
					t.Errorf("asked %s after giving up on %s", last, key)
				}

				// The value says that the registry was not asked, with the
				// status when there was one, and never the error's text.
				said := u.Bound.Value + "\n" + u.Clean.Value + "\n" + u.FirstSeen.Value
				want := fmt.Sprintf("could not be asked (HTTP %d, %d tries)", bad.status, maxTries)
				if bad.err != nil {
					want = fmt.Sprintf("could not be reached (%d tries)", maxTries)
				}
				if !strings.Contains(said, want) {
					t.Errorf("the values do not say %q:\n%s", want, said)
				}
				if strings.Contains(said, "refused") || strings.Contains(said, "script") || strings.Contains(said, "not established: not established") {
					t.Errorf("the values:\n%s", said)
				}

				d := decide(res, defaultPolicy(t), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
				if d.Outcome != allow.Person || !reflect.DeepEqual(d.Reasons, tc.reasons) {
					t.Errorf("decision %s %v, want person %v", d.Outcome, d.Reasons, tc.reasons)
				}
			})
		}
	}
}

// The one failure of the run itself: its context ended. There is no
// result then, whichever request was under way.
func TestContextEnds(t *testing.T) {
	for _, key := range []string{hubTokenURL, hubHeadURL, hubTagURL, gcrHeadURL, gcrListURL} {
		files, reg := golangRefresh, healthyHub(t)
		if strings.Contains(key, "gcr.io") {
			files, reg = distrolessRefresh, healthyGCR(t)
		}
		ctx, cancel := context.WithCancel(context.Background())
		rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method+" "+req.URL.String() == key {
				cancel()
				return nil, ctx.Err()
			}
			return reg.RoundTrip(req)
		})
		res, err := New().Gather(ctx, facts.Input{Files: files, Policy: defaultPolicy(t), HTTP: &http.Client{Transport: rt}})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("%s: error %v, want the context's", key, err)
		}
		if !reflect.DeepEqual(res, facts.Result{}) {
			t.Errorf("%s: a result beside the error: %+v", key, res)
		}
	}

	// While waiting to try again.
	ctx, cancel := context.WithCancel(context.Background())
	reg := healthyHub(t)
	reg.answers[hubHeadURL] = []fakeAnswer{{status: 503}}
	g := &Gatherer{sleep: func(ctx context.Context, d time.Duration) error {
		cancel()
		return ctx.Err()
	}}
	_, err := g.Gather(ctx, facts.Input{Files: golangRefresh, Policy: defaultPolicy(t), HTTP: &http.Client{Transport: reg}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v, want the context's", err)
	}
	if reg.count(hubHeadURL) != 1 {
		t.Errorf("asked %d times after the context ended", reg.count(hubHeadURL))
	}

	// Already ended before the first request.
	reg = healthyHub(t)
	reg.answers[hubTokenURL] = []fakeAnswer{{err: context.Canceled}}
	_, err = New().Gather(ctx, facts.Input{Files: golangRefresh, Policy: defaultPolicy(t), HTTP: &http.Client{Transport: reg}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v, want the context's", err)
	}
}

// Nothing is asked when there is nothing the gate could ask well: a
// registry it does not know, a pin without a tag, a Shape that does not
// hold.
func TestNotAsked(t *testing.T) {
	tests := []struct {
		name  string
		files []facts.File
		// bound is part of Bound's value; empty means Shape must not hold
		// and there are no updates.
		bound string
		name2 string
	}{
		{"ghcr.io", oneLine("ghcr.io/example/app:1.2@"+digestA, "ghcr.io/example/app:1.3@"+digestB),
			"ghcr.io is not a registry the gate knows how to ask", "ghcr.io/example/app"},
		{"quay.io", oneLine("quay.io/prometheus/prometheus:3.1@"+digestA, "quay.io/prometheus/prometheus:3.2@"+digestB),
			"quay.io is not a registry", "quay.io/prometheus/prometheus"},
		{"a private registry with a port", oneLine("registry.example.com:5000/app:1@"+digestA, "registry.example.com:5000/app:2@"+digestB),
			"registry.example.com:5000 is not a registry", "registry.example.com:5000/app"},
		{"an alias of Docker Hub", oneLine("index.docker.io/library/golang:1.26@"+digestA, "index.docker.io/library/golang:1.27@"+digestB),
			"index.docker.io is not a registry", "index.docker.io/library/golang"},
		{"localhost", oneLine("localhost/app:1@"+digestA, "localhost/app:2@"+digestB),
			"localhost is not a registry", "localhost/app"},
		{"no tag at head", oneLine("golang:1.27@"+digestA, "golang@"+digestB), "pinned without a tag", "docker.io/library/golang"},
		{"no tag at either", oneLine("golang@"+digestA, "golang@"+digestB), "pinned without a tag", "docker.io/library/golang"},
		{name: "shape does not hold", files: []facts.File{dockerfile("Dockerfile", "FROM golang:1.26@"+digestA+"\nRUN a\n", "FROM golang:1.27@"+digestB+"\nRUN b\n")}},
		{name: "not a Dockerfile", files: []facts.File{dockerfile("go.mod", "a\n", "b\n")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := &fakeRegistry{t: t} // any request fails the test
			res, _, err := gatherWith(t, reg, tc.files)
			if err != nil {
				t.Fatal(err)
			}
			if len(reg.asked) != 0 {
				t.Errorf("asked %v", reg.asked)
			}
			far := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
			if tc.bound == "" {
				if res.Shape.Holds() || !res.Shape.Gathered() || len(res.Updates) != 0 || len(res.Artifacts) != 0 {
					t.Errorf("result: %+v", res)
				}
				if d := decide(res, defaultPolicy(t), far); d.Outcome != allow.Person || d.Reasons[0] != allow.ReasonShape {
					t.Errorf("decision %s %v", d.Outcome, d.Reasons)
				}
				return
			}
			if !res.Shape.Holds() || len(res.Updates) != 1 {
				t.Fatalf("Shape %+v, %d updates", res.Shape, len(res.Updates))
			}
			u := res.Updates[0]
			checkExplained(t, u)
			if u.Name != tc.name2 {
				t.Errorf("name %q, want %q", u.Name, tc.name2)
			}
			if u.Bound.OK || !strings.Contains(u.Bound.Value, tc.bound) || u.Clean.OK || u.FirstSeen.Known() {
				t.Errorf("Bound %+v, Clean %+v, FirstSeen %+v", u.Bound, u.Clean, u.FirstSeen)
			}
			if d := decide(res, defaultPolicy(t), far); d.Outcome != allow.Person || !contains(d.Reasons, allow.ReasonNotBound) {
				t.Errorf("decision %s %v", d.Outcome, d.Reasons)
			}
		})
	}
}

// From and To name the tag and the digest, so a refresh has two
// different versions and a line without a tag still has a To.
func TestVersions(t *testing.T) {
	tests := []struct {
		from, to         string
		wantFrom, wantTo string
	}{
		{"golang:1.26@" + digestA, "golang:1.27@" + digestB, "1.26@" + digestA, "1.27@" + digestB},
		{"golang:1.27@" + digestA, "golang:1.27@" + digestB, "1.27@" + digestA, "1.27@" + digestB},
		{"golang@" + digestA, "golang:1.27@" + digestB, digestA, "1.27@" + digestB},
	}
	for _, tc := range tests {
		u := oneUpdate(t, healthyHub(t), oneLine(tc.from, tc.to))
		if u.From != tc.wantFrom || u.To != tc.wantTo {
			t.Errorf("%s to %s: From %q To %q, want %q %q", tc.from, tc.to, u.From, u.To, tc.wantFrom, tc.wantTo)
		}
	}
	// A tag added to an untagged pin is bound like any other, and is not
	// an increase: there was no version to increase from.
	u := oneUpdate(t, healthyHub(t), oneLine("golang@"+digestA, "golang:1.27@"+digestB))
	if !u.Bound.Holds() || u.Increase.OK {
		t.Errorf("Bound %+v, Increase %+v", u.Bound, u.Increase)
	}
}

// Known is the list and nothing else: an image is in the Dockerfile at
// the base commit by construction, and that does not make it known.
func TestKnownIsListed(t *testing.T) {
	grafana := &fakeRegistry{t: t, answers: map[string][]fakeAnswer{
		"GET https://auth.docker.io/token?scope=repository%3Agrafana%2Fgrafana%3Apull&service=registry.docker.io": {okToken},
		"HEAD https://registry-1.docker.io/v2/grafana/grafana/manifests/1.27":                                     {okHead},
		"GET https://hub.docker.com/v2/repositories/grafana/grafana/tags/1.27":                                    {okTag},
	}}
	files := oneLine("grafana/grafana:1.26@"+digestA, "grafana/grafana:1.27@"+digestB)

	u := oneUpdate(t, grafana, files)
	if u.Name != "docker.io/grafana/grafana" || u.Listed.OK || u.Known.OK || u.NewName.OK {
		t.Errorf("unlisted: %+v", u)
	}
	if !u.Listed.Gathered() || !u.Known.Gathered() || !u.NewName.Gathered() {
		t.Errorf("not gathered: %+v", u)
	}

	// The owner lists the publisher: the same pull request is now known.
	policy := defaultPolicy(t)
	policy.Listed[allow.Docker] = append(policy.Listed[allow.Docker], "docker.io/grafana/")
	grafana.asked = nil
	res, err := New().Gather(context.Background(), facts.Input{Files: files, Policy: policy, HTTP: &http.Client{Transport: grafana}})
	if err != nil {
		t.Fatal(err)
	}
	u = res.Updates[0]
	if !u.Listed.Holds() || !u.Known.Holds() || u.NewName.OK {
		t.Errorf("listed: %+v", u)
	}
	if d := decide(res, policy, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)); d.Outcome != allow.Merge {
		t.Errorf("decision %s %v", d.Outcome, d.Reasons)
	}

	// No list at all.
	res, err = New().Gather(context.Background(), facts.Input{Files: golangRefresh, HTTP: &http.Client{Transport: healthyHub(t)}})
	if err != nil {
		t.Fatal(err)
	}
	if u := res.Updates[0]; u.Listed.OK || u.Known.OK || !u.Listed.Gathered() || !u.Known.Gathered() {
		t.Errorf("zero policy: %+v", u)
	}
}

// One token per Docker Hub repository and one tag list per GCR
// repository, however many tags of it the pull request moves.
func TestAskedOncePerRepository(t *testing.T) {
	hub := healthyHub(t)
	hub.answers["HEAD https://registry-1.docker.io/v2/library/golang/manifests/1.27-alpine"] = []fakeAnswer{okHead}
	hub.answers["GET https://hub.docker.com/v2/repositories/library/golang/tags/1.27-alpine"] = []fakeAnswer{
		{status: 200, body: `{"name":"1.27-alpine","digest":"` + digestB + `","tag_last_pushed":"2026-11-16T07:23:27.867505Z"}`}}
	res, _, err := gatherWith(t, hub, []facts.File{dockerfile("Dockerfile",
		"FROM golang:1.27@"+digestA+" AS build\nFROM golang:1.27-alpine@"+digestA+"\n",
		"FROM golang:1.27@"+digestB+" AS build\nFROM golang:1.27-alpine@"+digestB+"\n")})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Updates) != 2 || !res.Updates[0].Bound.Holds() || !res.Updates[1].Bound.Holds() {
		t.Fatalf("updates: %+v", res.Updates)
	}
	if hub.count(hubTokenURL) != 1 {
		t.Errorf("token asked %d times", hub.count(hubTokenURL))
	}

	gcr := healthyGCR(t)
	gcr.answers["HEAD https://gcr.io/v2/distroless/static/manifests/debug"] = []fakeAnswer{
		{status: 200, header: map[string]string{"Docker-Content-Digest": digestA}}}
	res, _, err = gatherWith(t, gcr, []facts.File{dockerfile("Dockerfile",
		"FROM gcr.io/distroless/static:nonroot@"+digestA+"\nFROM gcr.io/distroless/static:debug@"+digestB+"\n",
		"FROM gcr.io/distroless/static:nonroot@"+digestB+"\nFROM gcr.io/distroless/static:debug@"+digestA+"\n")})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Updates) != 2 || !res.Updates[0].FirstSeen.Known() || !res.Updates[1].FirstSeen.Known() {
		t.Fatalf("updates: %+v", res.Updates)
	}
	if res.Updates[0].FirstSeen.Time.Equal(res.Updates[1].FirstSeen.Time) {
		t.Errorf("both updates have the same upload time")
	}
	if gcr.count(gcrListURL) != 1 {
		t.Errorf("tag list asked %d times", gcr.count(gcrListURL))
	}

	// A list that could not be read is not asked for again either.
	gcr = healthyGCR(t)
	gcr.answers["HEAD https://gcr.io/v2/distroless/static/manifests/debug"] = []fakeAnswer{
		{status: 200, header: map[string]string{"Docker-Content-Digest": digestA}}}
	gcr.answers[gcrListURL] = []fakeAnswer{{status: 404}}
	res, _, err = gatherWith(t, gcr, []facts.File{dockerfile("Dockerfile",
		"FROM gcr.io/distroless/static:nonroot@"+digestA+"\nFROM gcr.io/distroless/static:debug@"+digestB+"\n",
		"FROM gcr.io/distroless/static:nonroot@"+digestB+"\nFROM gcr.io/distroless/static:debug@"+digestA+"\n")})
	if err != nil {
		t.Fatal(err)
	}
	if gcr.count(gcrListURL) != 1 || res.Updates[0].FirstSeen.Known() || res.Updates[1].FirstSeen.Known() {
		t.Errorf("tag list asked %d times; %+v", gcr.count(gcrListURL), res.Updates)
	}
}

// The caller's client is used as it is and left as it was.
func TestClient(t *testing.T) {
	_, err := New().Gather(context.Background(), facts.Input{Files: golangRefresh, Policy: defaultPolicy(t)})
	if err == nil {
		t.Error("no error without an HTTP client")
	}
	// Without a client and without a Shape there is nothing to ask, and
	// so nothing to fail.
	res, err := New().Gather(context.Background(), facts.Input{Files: []facts.File{dockerfile("go.mod", "a\n", "b\n")}})
	if err != nil || res.Shape.Holds() {
		t.Errorf("result %+v, error %v", res, err)
	}

	followed := false
	client := &http.Client{
		Transport: healthyHub(t),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			followed = true
			return nil
		},
	}
	before := fmt.Sprintf("%p", client.CheckRedirect)
	client.Transport.(*fakeRegistry).answers[hubHeadURL] = []fakeAnswer{
		{status: 307, header: map[string]string{"Location": "https://registry-1.docker.io/v2/library/golang/manifests/1.26"}}}
	if _, err := New().Gather(context.Background(), facts.Input{Files: golangRefresh, Policy: defaultPolicy(t), HTTP: client}); err != nil {
		t.Fatal(err)
	}
	if followed {
		t.Error("the caller's redirect policy was consulted: a redirect was about to be followed")
	}
	if after := fmt.Sprintf("%p", client.CheckRedirect); after != before {
		t.Error("the caller's client was changed")
	}
}

// Every request names the same client and asks for JSON or a manifest;
// none carries anything about the repository the gate runs for.
func TestRequestHeaders(t *testing.T) {
	var seen []http.Header
	reg := healthyHub(t)
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		seen = append(seen, req.Header.Clone())
		if req.Body != nil && req.Body != http.NoBody {
			t.Errorf("%s %s has a body", req.Method, req.URL)
		}
		return reg.RoundTrip(req)
	})
	res, err := New().Gather(context.Background(), facts.Input{
		Repo: "owner/private-repo", Base: strings.Repeat("a", 40), Head: strings.Repeat("b", 40),
		Files: golangRefresh, Policy: defaultPolicy(t), HTTP: &http.Client{Transport: rt},
	})
	if err != nil || len(res.Updates) != 1 {
		t.Fatalf("result %+v, error %v", res, err)
	}
	if len(seen) != 3 {
		t.Fatalf("%d requests", len(seen))
	}
	for i, h := range seen {
		if h.Get("User-Agent") != userAgent {
			t.Errorf("request %d: User-Agent %q", i, h.Get("User-Agent"))
		}
		for name, values := range h {
			for _, v := range values {
				if strings.Contains(v, "private-repo") || strings.Contains(v, "owner") {
					t.Errorf("request %d: header %s carries the repository: %q", i, name, v)
				}
			}
		}
	}
	if got := seen[1].Get("Accept"); got != acceptManifests {
		t.Errorf("manifest Accept %q", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// brokenBody fails in the middle of a body.
type brokenBody struct{}

func (brokenBody) Read([]byte) (int, error) { return 0, errors.New("connection reset") }
func (brokenBody) Close() error             { return nil }

// A body that breaks off is a registry that could not be asked: tried
// again, and never read as a short answer.
func TestBodyBreaksOff(t *testing.T) {
	reg := healthyHub(t)
	broken := 2
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		resp, err := reg.RoundTrip(req)
		if err == nil && req.URL.Host == "hub.docker.com" && broken > 0 {
			broken--
			resp.Body = brokenBody{}
		}
		return resp, err
	})
	res, waits, err := gatherWith(t, rt, golangRefresh)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Updates[0].FirstSeen.Known() || len(waits) != 2 || reg.count(hubTagURL) != 3 {
		t.Errorf("FirstSeen %+v, waited %v, asked %d times", res.Updates[0].FirstSeen, waits, reg.count(hubTagURL))
	}

	// Every time: the time is unknown, the rest stands, and the error's
	// text is not shown.
	broken = maxTries
	reg = healthyHub(t)
	res, _, err = gatherWith(t, rt, golangRefresh)
	if err != nil {
		t.Fatal(err)
	}
	u := res.Updates[0]
	if !u.Bound.Holds() || !u.Clean.Holds() || u.FirstSeen.Known() {
		t.Errorf("Bound %+v, Clean %+v, FirstSeen %+v", u.Bound, u.Clean, u.FirstSeen)
	}
	if want := "Docker Hub could not be reached (3 tries)"; u.FirstSeen.Value != want {
		t.Errorf("FirstSeen says %q, want %q", u.FirstSeen.Value, want)
	}
}

func TestSleepCtx(t *testing.T) {
	if err := sleepCtx(context.Background(), time.Millisecond); err != nil {
		t.Errorf("a wait that ran out: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := sleepCtx(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("a wait whose context ended: %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Error("the wait did not end with its context")
	}
}

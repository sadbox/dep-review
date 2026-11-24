package gomod

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Where the index is read from (spec section 11, amendment 61): the time
// in the Last-Modified header of the proxy's answer for the version's
// go.mod, and only failing that the commit time.
//
// The late tag of these tests is golang.org/x/mod v0.2.0. Its commit is
// dated 2020-01-02T17:33:45Z and the proxy first cached the version eight
// days later. testdata has the three index pages that follow the commit
// time, none of which has the version, the proxy's answer for its go.mod,
// and the index page that starts a second before that answer's
// Last-Modified.
const (
	lateCommit = "2020-01-02T17:33:45Z"
	lateSeen   = "2020-01-10T18:01:31.477154Z"
)

func TestStoredRecorded(t *testing.T) {
	fixtures := &indexFixtures{t: t, stored: true}
	ix := &index{client: &http.Client{Transport: fixtures}}
	at, ok := ix.stored(context.Background(), "golang.org/x/mod", "v0.2.0")
	if !ok || !at.Equal(ts("2020-01-10T18:01:31Z")) {
		t.Errorf("stored = %v, %v; want the header's 2020-01-10T18:01:31Z", at, ok)
	}
	// A version the proxy does not have.
	if at, ok := ix.stored(context.Background(), "golang.org/x/mod", "v0.2.1"); ok || !at.IsZero() {
		t.Errorf("stored = %v, %v for a version the proxy answers 404 for", at, ok)
	}
	want := []string{"/golang.org/x/mod/@v/v0.2.0.mod", "/golang.org/x/mod/@v/v0.2.1.mod"}
	if !reflect.DeepEqual(fixtures.proxied, want) {
		t.Errorf("the proxy was asked for %q, want %q", fixtures.proxied, want)
	}
}

// TestStored checks which answers of the proxy are a place to start, and
// that the request is the go command's.
func TestStored(t *testing.T) {
	const when = "Tue, 09 Jan 2024 10:00:00 GMT"
	tests := []struct {
		name   string
		status int
		header string // Last-Modified; "-" for none
		fail   bool   // no response at all
		want   string // RFC 3339, or empty for no place to start
	}{
		{"a time", 200, when, false, "2024-01-09T10:00:00Z"},
		{"no header", 200, "-", false, ""},
		{"an empty header", 200, "", false, ""},
		{"not a time", 200, "yesterday", false, ""},
		{"a time in another form than HTTP's", 200, "2024-01-09T10:00:00Z", false, ""},
		{"not found, whatever the header", 404, when, false, ""},
		{"gone", 410, when, false, ""},
		{"not modified", 304, when, false, ""},
		{"a server error", 500, when, false, ""},
		{"too many requests", 429, when, false, ""},
		{"no response", 0, "", true, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var asked []string
			client := &http.Client{Transport: roundTrip(func(req *http.Request) (*http.Response, error) {
				asked = append(asked, req.Method+" "+req.URL.String())
				if tc.fail {
					return nil, fmt.Errorf("dial tcp: no route to host")
				}
				resp := respond(req, tc.status, "module github.com/Azure/azure-sdk-for-go\n")
				if tc.header != "-" {
					resp.Header.Set("Last-Modified", tc.header)
				}
				return resp, nil
			})}
			ix := &index{client: client}
			// x/mod's escaping: an upper-case letter is "!" and its lower case.
			at, ok := ix.stored(context.Background(), "github.com/Azure/azure-sdk-for-go", "v68.0.0+incompatible")
			if tc.want == "" && (ok || !at.IsZero()) {
				t.Errorf("stored = %v, %v; want no place to start", at, ok)
			}
			if tc.want != "" && (!ok || !at.Equal(ts(tc.want))) {
				t.Errorf("stored = %v, %v; want %s", at, ok, tc.want)
			}
			if want := []string{"GET https://proxy.golang.org/github.com/!azure/azure-sdk-for-go/@v/v68.0.0+incompatible.mod"}; !reflect.DeepEqual(asked, want) {
				t.Errorf("requests %q, want %q", asked, want)
			}
		})
	}

	t.Run("a path x/mod will not escape is not asked about", func(t *testing.T) {
		client := &http.Client{Transport: roundTrip(func(req *http.Request) (*http.Response, error) {
			t.Errorf("unexpected request %s", req.URL)
			return nil, fmt.Errorf("unexpected request")
		})}
		ix := &index{client: client}
		for _, target := range [][2]string{{"example.com/m!", "v1.0.0"}, {"example.com/m", "v1.0.0!"}} {
			if at, ok := ix.stored(context.Background(), target[0], target[1]); ok || !at.IsZero() {
				t.Errorf("stored(%q) = %v, %v", target, at, ok)
			}
		}
	})
}

// TestSeenAtStoredRecorded: a tag cut long after its commit is found on
// the one page the proxy's header points at, and its date is the index
// line's, not the header's whole second.
func TestSeenAtStoredRecorded(t *testing.T) {
	fixtures := &indexFixtures{t: t, stored: true}
	ix := &index{client: &http.Client{Transport: fixtures}, url: defaultIndexURL, limit: 100, perVersion: 3, left: 4}
	f := seenFact(context.Background(), ix, "golang.org/x/mod", "v0.2.0", ts(lateCommit), testNow)
	if !f.Known() || !f.Time.Equal(ts(lateSeen)) || f.Source != sourceIndex {
		t.Errorf("FirstSeen = %+v, want the index's %s", f, lateSeen)
	}
	if want := []string{"2020-01-10T18:01:30Z"}; !reflect.DeepEqual(fixtures.requests, want) || ix.left != 3 {
		t.Errorf("index requests %v with %d pages left, want %v and 3", fixtures.requests, ix.left, want)
	}
}

// TestSeenBudgetShared is a real run's failure in small: a late tag
// read from its commit time uses up its own pages without being found,
// and what is left of the run's pages does not reach the last version.
// Read from where the proxy stored each, every version is dated with a
// page to spare. Both readings are run: without the proxy's answers the
// reader does what it always did.
func TestSeenBudgetShared(t *testing.T) {
	versions := []struct{ path, version, commit string }{
		{"golang.org/x/mod", "v0.2.0", lateCommit},
		{"golang.org/x/text", "v0.3.3", "2020-06-16T18:28:43Z"},
		{"golang.org/x/mod", "v0.5.1", "2021-09-22T20:26:12Z"},
	}
	gather := func(stored bool) ([]string, *index) {
		fixtures := &indexFixtures{t: t, stored: stored}
		ix := &index{client: &http.Client{Transport: fixtures}, url: defaultIndexURL, limit: 100, perVersion: 3, left: 4}
		var got []string
		for _, v := range versions {
			f := seenFact(context.Background(), ix, v.path, v.version, ts(v.commit), testNow)
			if f.Unavailable {
				t.Errorf("%s@%s: %+v", v.path, v.version, f)
			}
			if f.Known() {
				got = append(got, f.Time.UTC().Format(time.RFC3339Nano))
			} else {
				got = append(got, f.Value)
			}
		}
		return got, ix
	}

	got, ix := gather(true)
	want := []string{lateSeen, "2020-06-16T18:50:19.600867Z", "2021-09-22T20:29:37.75807Z"}
	if !reflect.DeepEqual(got, want) || ix.left != 1 {
		t.Errorf("from where the proxy stored them, with %d pages left:\n%q\nwant, with 1 left:\n%q", ix.left, got, want)
	}

	got, ix = gather(false)
	want = []string{
		"not established: not in the 3 index pages after 2020-01-02T17:23:45Z (read up to 2020-01-02T21:47:04Z); the proxy gave no Last-Modified to start at",
		"2020-06-16T18:50:19.600867Z",
		"not established: not looked up: this run's index budget was spent on other versions; the proxy gave no Last-Modified to start at",
	}
	if !reflect.DeepEqual(got, want) || ix.left != 0 {
		t.Errorf("from the commit times, with %d pages left:\n%q\nwant, with 0 left:\n%q", ix.left, got, want)
	}
}

// pointed is a proxy that answers every go.mod request with status and,
// when lastModified is not empty, that header, in front of an index whose
// pages are given by their since. A since that is not in pages gets the
// status 503. asked collects the sinces the index was asked for.
func pointed(t *testing.T, status int, lastModified string, pages map[string]string, asked *[]string) *http.Client {
	return &http.Client{Transport: roundTrip(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "proxy.golang.org":
			if status == 0 {
				return nil, fmt.Errorf("dial tcp: no route to host")
			}
			resp := respond(req, status, "module example.com/m\n")
			if lastModified != "" {
				resp.Header.Set("Last-Modified", lastModified)
			}
			return resp, nil
		case "index.golang.org":
			since := req.URL.Query().Get("since")
			*asked = append(*asked, since)
			if page, ok := pages[since]; ok {
				return respond(req, http.StatusOK, page), nil
			}
			return respond(req, http.StatusServiceUnavailable, ""), nil
		}
		t.Errorf("unexpected request %s", req.URL)
		return nil, fmt.Errorf("unexpected request")
	})}
}

// TestSeenFactPointer: the header says where to look and nothing more.
// The update is example.com/m v1.0.0 with a commit dated 2024-01-01
// 00:00:00, so the reading from the commit time starts at 23:50:00 the
// day before. A page holds three lines.
func TestSeenFactPointer(t *testing.T) {
	const (
		fromCommit = "2023-12-31T23:50:00Z"
		header     = "Tue, 09 Jan 2024 10:00:00 GMT"
		fromHeader = "2024-01-09T09:59:59Z"
	)
	other := func(timestamp string) string { return line("example.com/other", "v1.0.0", timestamp) }
	target := func(timestamp string) string { return line("example.com/m", "v1.0.0", timestamp) }
	// The index's end, as far as these tests go: a page that is not full.
	nothing := other("2024-01-09T09:59:59.5Z")

	tests := []struct {
		name   string
		status int
		header string
		pages  map[string]string
		// want is the index's time; empty when there is none. why is then
		// the whole text of the fact, and wait says it is unavailable.
		want  string
		why   string
		wait  bool
		asked []string
	}{
		{
			name: "found where the proxy points: the line's time, not the header's second", status: 200, header: header,
			pages: map[string]string{fromHeader: nothing + target("2024-01-09T10:00:00.25Z")},
			want:  "2024-01-09T10:00:00.25Z", asked: []string{fromHeader},
		},
		{
			name: "on the second page from there", status: 200, header: header,
			pages: map[string]string{
				fromHeader:               other("2024-01-09T09:59:59.1Z") + other("2024-01-09T09:59:59.2Z") + other("2024-01-09T09:59:59.3Z"),
				"2024-01-09T09:59:59.3Z": other("2024-01-09T09:59:59.3Z") + target("2024-01-09T10:00:00.25Z"),
			},
			want: "2024-01-09T10:00:00.25Z", asked: []string{fromHeader, "2024-01-09T09:59:59.3Z"},
		},
		{
			name: "not on the two pages from there: the commit time is read from, and no third page", status: 200, header: header,
			pages: map[string]string{
				fromHeader:               other("2024-01-09T09:59:59.1Z") + other("2024-01-09T09:59:59.2Z") + other("2024-01-09T09:59:59.3Z"),
				"2024-01-09T09:59:59.3Z": other("2024-01-09T09:59:59.3Z") + other("2024-01-09T09:59:59.4Z") + other("2024-01-09T09:59:59.6Z"),
				"2024-01-09T09:59:59.6Z": other("2024-01-09T09:59:59.6Z") + target("2024-01-09T10:00:00.25Z"),
				fromCommit:               target("2024-01-01T00:20:00Z"),
			},
			want: "2024-01-01T00:20:00Z", asked: []string{fromHeader, "2024-01-09T09:59:59.3Z", fromCommit},
		},
		{
			name: "the header is later than the line: found from the commit time", status: 200, header: header,
			pages: map[string]string{fromHeader: nothing, fromCommit: target("2024-01-01T00:20:00Z")},
			want:  "2024-01-01T00:20:00Z", asked: []string{fromHeader, fromCommit},
		},
		{
			name: "where the proxy points there is only another version, and another module", status: 200, header: header,
			pages: map[string]string{
				fromHeader: line("example.com/m", "v1.0.1", "2024-01-09T10:00:00.25Z") + other("2024-01-09T10:00:00.25Z"),
				fromCommit: other("2024-01-01T00:20:00Z"),
			},
			why:   "not established: not in the index between 2023-12-31T23:50:00Z and its end; nor from the proxy's Last-Modified, 2024-01-09T10:00:00Z",
			asked: []string{fromHeader, fromCommit},
		},
		{
			name: "the index does not answer where the proxy points: a wait, and no other read", status: 200, header: header,
			pages: map[string]string{fromCommit: target("2024-01-01T00:20:00Z")},
			why:   "the index did not answer: status 503", wait: true, asked: []string{fromHeader},
		},
		{
			name: "the index does not answer from the commit time either: a wait", status: 200, header: header,
			pages: map[string]string{fromHeader: nothing},
			why:   "the index did not answer: status 503", wait: true, asked: []string{fromHeader, fromCommit},
		},
		{
			name: "the line where the proxy points is dated in the future", status: 200, header: "Mon, 23 Nov 2026 10:00:00 GMT",
			pages: map[string]string{"2026-11-23T09:59:59Z": target("2026-11-23T10:00:00.5Z")},
			why:   "not established: the index dates it 2026-11-23T10:00:00Z, which is in the future", asked: []string{"2026-11-23T09:59:59Z"},
		},
		{
			name: "no header: read from the commit time, as before", status: 200,
			pages: map[string]string{fromCommit: target("2024-01-01T00:20:00Z")},
			want:  "2024-01-01T00:20:00Z", asked: []string{fromCommit},
		},
		{
			name: "no header, and not found from the commit time", status: 200,
			pages: map[string]string{fromCommit: other("2024-01-01T00:20:00Z")},
			why:   "not established: not in the index between 2023-12-31T23:50:00Z and its end; the proxy gave no Last-Modified to start at",
			asked: []string{fromCommit},
		},
		{
			name: "a header that is not a time", status: 200, header: "yesterday",
			pages: map[string]string{fromCommit: target("2024-01-01T00:20:00Z")},
			want:  "2024-01-01T00:20:00Z", asked: []string{fromCommit},
		},
		{
			name: "the proxy answers 500: not a wait", status: 500, header: header,
			pages: map[string]string{fromCommit: other("2024-01-01T00:20:00Z")},
			why:   "not established: not in the index between 2023-12-31T23:50:00Z and its end; the proxy gave no Last-Modified to start at",
			asked: []string{fromCommit},
		},
		{
			name: "the proxy does not answer: not a wait", status: 0,
			pages: map[string]string{fromCommit: target("2024-01-01T00:20:00Z")},
			want:  "2024-01-01T00:20:00Z", asked: []string{fromCommit},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var asked []string
			ix := &index{client: pointed(t, tc.status, tc.header, tc.pages, &asked), url: defaultIndexURL, limit: 3, perVersion: 2, left: 10}
			f := seenFact(context.Background(), ix, "example.com/m", "v1.0.0", ts("2024-01-01T00:00:00Z"), testNow)
			if tc.want != "" {
				if !f.Known() || !f.Time.Equal(ts(tc.want)) || f.Source != sourceIndex {
					t.Errorf("FirstSeen = %+v, want the index's %s", f, tc.want)
				}
			} else if f.Known() || !f.Time.IsZero() || f.Value != tc.why || f.Unavailable != tc.wait || (f.Source == sourceIndex) != tc.wait {
				// A wait names the index as the source that did not answer;
				// a time nothing established has no source.
				t.Errorf("FirstSeen = %+v, want no time, %q and unavailable = %v", f, tc.why, tc.wait)
			}
			if !reflect.DeepEqual(asked, tc.asked) {
				t.Errorf("the index was asked from %v, want %v", asked, tc.asked)
			}
		})
	}
}

// TestGatherAtStored gathers for the pull request of TestGather with the
// proxy's recorded answers behind it. The dates are the ones the reading
// from the commit times finds there, each now from one page: the one that
// starts a second before the proxy's time for the version.
func TestGatherAtStored(t *testing.T) {
	in, fixtures, _ := input(t, pr(baseMod, headMod, baseSum, headSum))
	fixtures.stored = true
	res, err := gatherer(goFixtures(t)).Gather(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	mod, text := find(t, res, "golang.org/x/mod"), find(t, res, "golang.org/x/text")
	if want := ts("2021-09-22T20:29:37.75807Z"); !mod.FirstSeen.Known() || !mod.FirstSeen.Time.Equal(want) || mod.FirstSeen.Source != sourceIndex {
		t.Errorf("x/mod FirstSeen = %+v, want %v", mod.FirstSeen, want)
	}
	if want := ts("2019-05-31T18:28:44.591758Z"); !mod.NameCreated.Known() || !mod.NameCreated.Time.Equal(want) ||
		!strings.Contains(mod.NameCreated.Value, "v0.1.0") {
		t.Errorf("x/mod NameCreated = %+v, want %v", mod.NameCreated, want)
	}
	if want := ts("2020-06-16T18:50:19.600867Z"); !text.FirstSeen.Known() || !text.FirstSeen.Time.Equal(want) || text.FirstSeen.Source != sourceIndex {
		t.Errorf("x/text FirstSeen = %+v, want %v", text.FirstSeen, want)
	}
	wantProxied := []string{"/golang.org/x/mod/@v/v0.5.1.mod", "/golang.org/x/mod/@v/v0.1.0.mod", "/golang.org/x/text/@v/v0.3.3.mod"}
	if !reflect.DeepEqual(fixtures.proxied, wantProxied) {
		t.Errorf("the proxy was asked for %q, want %q", fixtures.proxied, wantProxied)
	}
	wantIndex := []string{"2021-09-22T20:29:36Z", "2019-05-31T18:28:43Z", "2020-06-16T18:50:18Z"}
	if !reflect.DeepEqual(fixtures.requests, wantIndex) {
		t.Errorf("the index was asked from %q, want %q", fixtures.requests, wantIndex)
	}
}

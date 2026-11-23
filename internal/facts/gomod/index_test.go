package gomod

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The files in testdata/index are pages of https://index.golang.org/index
// as it answered on 2026-11-22, unedited. The file name is the request:
// its "since" (with "-" for ":") and its "limit". They were recorded with
// limit=100 to keep them small; the gatherer asks for 2000.

//
// The files in testdata/proxy are answers of https://proxy.golang.org on
// 2026-11-23 for a version's go.mod, head and body, as "curl --http1.1 -i"
// wrote them. The file's path is the request's.

// indexFixtures answers index requests from testdata/index and counts
// them. A page that was not recorded is a 404.
//
// The proxy is asked where to start reading (index.stored). It answers
// from testdata/proxy when stored is set. Without it the proxy has no
// version (404), and every lookup starts at the commit time, as all of
// them did before amendment 61: the tests that leave it unset hold that
// reading to what it was.
type indexFixtures struct {
	t        *testing.T
	requests []string
	stored   bool
	// proxied are the paths the proxy was asked for.
	proxied []string
}

func (f *indexFixtures) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" && req.URL.Host == "proxy.golang.org" && req.Method == http.MethodGet {
		f.proxied = append(f.proxied, req.URL.Path)
		data, err := os.ReadFile(filepath.Join("testdata", "proxy", filepath.FromSlash(req.URL.Path)))
		if err != nil || !f.stored {
			return respond(req, http.StatusNotFound, "not found"), nil
		}
		return http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), req)
	}
	if req.URL.Scheme != "https" || req.URL.Host != "index.golang.org" || req.URL.Path != "/index" || req.Method != http.MethodGet {
		f.t.Errorf("unexpected request: %s %s", req.Method, req.URL)
		return nil, fmt.Errorf("unexpected request")
	}
	q := req.URL.Query()
	f.requests = append(f.requests, q.Get("since"))
	name := strings.ReplaceAll(q.Get("since"), ":", "-") + "_" + q.Get("limit") + ".jsonl"
	data, err := os.ReadFile(filepath.Join("testdata", "index", name))
	if err != nil {
		return respond(req, http.StatusNotFound, "not recorded: "+name), nil
	}
	return respond(req, http.StatusOK, string(data)), nil
}

// roundTrip adapts a function to http.RoundTripper, for answers the real
// index does not give.
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func respond(req *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Request: req, Header: http.Header{}}
}

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestFirstSeenRecorded(t *testing.T) {
	tests := []struct {
		name          string
		path, version string
		since         string
		perVersion    int
		left          int
		want          string // RFC 3339, or empty for not found
		why           string // substring of the reason when not found
		pages         int
		leftAfter     int
	}{
		{"on the first page", "golang.org/x/text", "v0.3.3", "2020-06-16T18:18:43Z", 50, 150,
			"2020-06-16T18:50:19.600867Z", "", 1, 149},
		{"on the second page", "golang.org/x/mod", "v0.5.1", "2021-09-22T20:16:12Z", 50, 150,
			"2021-09-22T20:29:37.75807Z", "", 2, 148},
		{"the earliest version of a module", "golang.org/x/mod", "v0.1.0", "2019-05-31T18:14:31Z", 50, 150,
			"2019-05-31T18:28:44.591758Z", "", 1, 149},
		{"beyond the pages allowed for one version", "golang.org/x/mod", "v0.5.1", "2021-09-22T20:16:12Z", 1, 150,
			"", "not in the 1 index pages after 2021-09-22T20:16:12Z", 1, 149},
		{"the run's budget is spent", "golang.org/x/mod", "v0.5.1", "2021-09-22T20:16:12Z", 50, 1,
			"", "not in the 1 index pages after 2021-09-22T20:16:12Z (read up to 2021-09-22T20:26:43Z) that were read before this run's index budget was spent", 1, 0},
		{"the run's budget was spent before this version", "golang.org/x/mod", "v0.5.1", "2021-09-22T20:16:12Z", 50, 0,
			"", "not looked up: this run's index budget was spent on other versions", 0, 0},
		{"another version of the same module is not a match", "golang.org/x/text", "v0.3.4", "2020-06-16T18:18:43Z", 1, 150,
			"", "not in the 1 index pages", 1, 149},
		{"the path is matched exactly, including case", "golang.org/x/Text", "v0.3.3", "2020-06-16T18:18:43Z", 1, 150,
			"", "not in the 1 index pages", 1, 149},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixtures := &indexFixtures{t: t}
			ix := &index{client: &http.Client{Transport: fixtures}, url: defaultIndexURL, limit: 100, perVersion: tc.perVersion, left: tc.left}
			seen, why, _ := ix.firstSeen(context.Background(), tc.path, tc.version, ts(tc.since), tc.perVersion)
			if tc.want == "" {
				if !seen.IsZero() || !strings.Contains(why, tc.why) {
					t.Errorf("seen = %v, why = %q; want not found with %q", seen, why, tc.why)
				}
			} else if !seen.Equal(ts(tc.want)) || why != "" {
				t.Errorf("seen = %v, why = %q; want %s", seen, why, tc.want)
			}
			if len(fixtures.requests) != tc.pages || ix.left != tc.leftAfter {
				t.Errorf("%d requests %v, %d pages left; want %d and %d", len(fixtures.requests), fixtures.requests, ix.left, tc.pages, tc.leftAfter)
			}
		})
	}
}

// TestFirstSeenPaging checks that the second request starts at the last
// timestamp of the first page, which the index includes again.
func TestFirstSeenPaging(t *testing.T) {
	fixtures := &indexFixtures{t: t}
	ix := &index{client: &http.Client{Transport: fixtures}, url: defaultIndexURL, limit: 100, perVersion: 50, left: 150}
	ix.firstSeen(context.Background(), "golang.org/x/mod", "v0.5.1", ts("2021-09-22T20:16:12Z"), ix.perVersion)
	want := []string{"2021-09-22T20:16:12Z", "2021-09-22T20:26:43.140844Z"}
	if strings.Join(fixtures.requests, " ") != strings.Join(want, " ") {
		t.Errorf("requests = %v, want %v", fixtures.requests, want)
	}
}

// TestFirstSeenSharesPages checks that two versions with the same commit
// time, as the modules of one repository released together have, read
// the index once.
func TestFirstSeenSharesPages(t *testing.T) {
	fixtures := &indexFixtures{t: t}
	ix := &index{client: &http.Client{Transport: fixtures}, url: defaultIndexURL, limit: 100, perVersion: 50, left: 150}
	since := ts("2021-09-22T20:16:12Z")
	first, _, _ := ix.firstSeen(context.Background(), "golang.org/x/mod", "v0.5.1", since, ix.perVersion)
	again, why, _ := ix.firstSeen(context.Background(), "golang.org/x/mod", "v0.5.1", since, ix.perVersion)
	if first.IsZero() || !again.Equal(first) {
		t.Errorf("first %v, again %v (%s)", first, again, why)
	}
	if len(fixtures.requests) != 2 || ix.left != 148 {
		t.Errorf("%d requests, %d pages left; want 2 and 148", len(fixtures.requests), ix.left)
	}
	// A page that is already here is not charged to a spent budget.
	ix.left = 0
	if spent, why, _ := ix.firstSeen(context.Background(), "golang.org/x/mod", "v0.5.1", since, ix.perVersion); !spent.Equal(first) {
		t.Errorf("with no budget left: %v (%s)", spent, why)
	}
}

func line(path, version, timestamp string) string {
	return fmt.Sprintf(`{"Path":%q,"Version":%q,"Timestamp":%q}`+"\n", path, version, timestamp)
}

func TestFirstSeenBadIndex(t *testing.T) {
	since := ts("2024-01-01T00:00:00Z")
	target := line("example.com/m", "v1.0.0", "2024-01-01T00:00:05Z")
	other := line("example.com/other", "v1.0.0", "2024-01-01T00:00:03Z")
	tests := []struct {
		name   string
		status int
		body   string
		want   string // RFC 3339, or empty
		why    string
	}{
		{"found", 200, other + target, "2024-01-01T00:00:05Z", ""},
		{"a short page is the end of the index", 200, other, "", "and its end"},
		{"an empty page is the end of the index", 200, "", "", "and its end"},
		{"server error", 500, "", "", "the index did not answer: status 500"},
		{"bad request", 400, "400 bad request\n", "", "could not be read: status 400"},
		{"not JSON", 200, "<html>\n", "", "could not be read: line 1 is not JSON"},
		{"a line without a version", 200, line("example.com/m", "", "2024-01-01T00:00:05Z"), "", "not in the documented form or order"},
		{"a timestamp that is not a time", 200, line("example.com/m", "v1.0.0", "yesterday"), "", "not in the documented form or order"},
		{"a line from before the request's since", 200, line("example.com/m", "v1.0.0", "2023-12-31T23:59:59Z"), "", "not in the documented form or order"},
		{"lines out of order after the match", 200, target + other, "", "not in the documented form or order"},
		{"lines out of order before the match", 200, line("example.com/x", "v1.0.0", "2024-01-01T00:00:09Z") + target, "", "not in the documented form or order"},
		{"the same version twice: the first counts", 200, target + line("example.com/m", "v1.0.0", "2024-01-01T00:00:07Z"), "2024-01-01T00:00:05Z", ""},
		{"more lines than asked for", 200, other + other + other + target, "", "more than the limit asked for"},
		{"a full page that does not advance", 200, strings.Repeat(line("example.com/other", "v1.0.0", "2024-01-01T00:00:00Z"), 3), "", "does not advance"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTrip(func(req *http.Request) (*http.Response, error) {
				return respond(req, tc.status, tc.body), nil
			})}
			ix := &index{client: client, url: defaultIndexURL, limit: 3, perVersion: 2, left: 10}
			seen, why, _ := ix.firstSeen(context.Background(), "example.com/m", "v1.0.0", since, ix.perVersion)
			if tc.want == "" {
				if !seen.IsZero() || !strings.Contains(why, tc.why) {
					t.Errorf("seen = %v, why = %q; want not found with %q", seen, why, tc.why)
				}
			} else if !seen.Equal(ts(tc.want)) {
				t.Errorf("seen = %v, why = %q; want %s", seen, why, tc.want)
			}
		})
	}
}

func TestFirstSeenTransportError(t *testing.T) {
	client := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("dial tcp: no route to host")
	})}
	ix := &index{client: client, url: defaultIndexURL, limit: 3, perVersion: 2, left: 10}
	seen, why, down := ix.firstSeen(context.Background(), "example.com/m", "v1.0.0", ts("2024-01-01T00:00:00Z"), ix.perVersion)
	if !seen.IsZero() || !strings.Contains(why, "the index did not answer: ") || !down {
		t.Errorf("seen = %v, why = %q, down = %v", seen, why, down)
	}
}

// An index that was asked and did not answer is told apart from every
// answer it gave: only the first is worth asking again.
// A pseudo-version carries its commit's time, and the proxy's .info for
// it repeats that time: both are the publisher's to set. FirstSeen is
// the index's own timestamp or nothing (spec section 11, amendment 24).
// With nothing, the publish job dates the pin from its own first
// evaluation of it (amendment 38).
func TestFirstSeenOfAPseudoVersion(t *testing.T) {
	const (
		name    = "google.golang.org/genproto/googleapis/rpc"
		version = "v0.0.0-20240101000000-aaaaaaaaaaaa"
	)
	commit := ts("2024-01-01T00:00:00Z")
	for _, tc := range []struct {
		name string
		page string
		// want is the index's time; empty when the version is not found.
		want string
	}{
		{"cached by the proxy nine hours after the commit", line("example.com/other", "v1.0.0", "2024-01-01T00:00:03Z") + line(name, version, "2024-01-01T09:30:00Z"), "2024-01-01T09:30:00Z"},
		{"not in the index pages read", line("example.com/other", "v1.0.0", "2024-01-01T00:00:03Z"), ""},
		{"only another commit of the same module is there", line(name, "v0.0.0-20240101000000-bbbbbbbbbbbb", "2024-01-01T09:30:00Z"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTrip(func(req *http.Request) (*http.Response, error) {
				return respond(req, http.StatusOK, tc.page), nil
			})}
			ix := &index{client: client, url: defaultIndexURL, limit: 3, perVersion: 2, left: 10}
			f := seenFact(context.Background(), ix, name, version, commit, testNow)
			if f.Time.Equal(commit) {
				t.Fatalf("FirstSeen is the commit's time: %+v", f)
			}
			switch {
			case tc.want == "" && (f.Known() || f.Unavailable):
				t.Errorf("FirstSeen = %+v, want a time that was not established", f)
			case tc.want != "" && (!f.Known() || !f.Time.Equal(ts(tc.want)) || f.Source != sourceIndex):
				t.Errorf("FirstSeen = %+v, want the index's %s", f, tc.want)
			}
		})
	}
}

func TestFirstSeenDown(t *testing.T) {
	other := line("example.com/other", "v1.0.0", "2024-01-01T00:00:03Z")
	for _, tc := range []struct {
		name   string
		status int
		body   string
		down   bool
	}{
		{"500", 500, "", true},
		{"502", 502, "", true},
		{"503", 503, "", true},
		{"429", 429, "", true},
		{"400", 400, "400 bad request\n", false},
		{"404", 404, "", false},
		{"403", 403, "", false},
		{"not JSON", 200, "<html>\n", false},
		{"not in the index", 200, other, false},
		{"lines out of order", 200, line("example.com/x", "v1.0.0", "2023-01-01T00:00:00Z"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTrip(func(req *http.Request) (*http.Response, error) {
				return respond(req, tc.status, tc.body), nil
			})}
			ix := &index{client: client, url: defaultIndexURL, limit: 3, perVersion: 2, left: 10}
			seen, why, down := ix.firstSeen(context.Background(), "example.com/m", "v1.0.0", ts("2024-01-01T00:00:00Z"), ix.perVersion)
			if !seen.IsZero() || why == "" || down != tc.down {
				t.Errorf("seen = %v, why = %q, down = %v; want down = %v", seen, why, down, tc.down)
			}
			// And the fact built from it.
			ix = &index{client: client, url: defaultIndexURL, limit: 3, perVersion: 2, left: 10}
			f := seenFact(context.Background(), ix, "example.com/m", "v1.0.0", ts("2024-01-01T00:10:00Z"), testNow)
			// Unavailable names the index as its source; a time nothing
			// established has none.
			if f.Known() || f.Unavailable != tc.down || (f.Source != "") != tc.down {
				t.Errorf("fact %+v, want unavailable = %v", f, tc.down)
			}
		})
	}
}

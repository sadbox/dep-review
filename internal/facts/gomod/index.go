package gomod

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/mod/module"

	"github.com/sadbox/dep-review/internal/facts"
)

// The Go module index (index.golang.org) is a feed of every module
// version proxy.golang.org has cached, in the order it first cached them,
// each with the proxy's own clock at that moment. That is the first-seen
// time the gate wants: a version's commit time is whatever the publisher
// wrote into the commit. The feed has no lookup by module and is read
// forward from a point in time. Two things say where to start, and
// neither is ever the answer: the time the proxy says it stored the
// version at (stored), and failing that the commit time. A start that is
// wrong makes the version impossible to find, which leaves it to the
// publish job's own clock, and never makes it look older: the time is the
// one on the feed's own line for exactly that module and version.

const (
	// defaultIndexURL is the feed.
	defaultIndexURL = "https://index.golang.org/index"
	// indexPageLimit is the most lines the index returns for one request.
	// It answers 400 to a larger limit.
	indexPageLimit = 2000
	// indexPagesPerVersion is how far the gatherer reads forward from a
	// version's commit time before it gives up. In November 2026 the
	// index grew by 2000 lines every 40 to 55 minutes, and 50 pages
	// reached 30 hours past their start. A tag the proxy first served
	// later than that after its commit is not found this way, and the
	// growth of the index only shortens the window.
	indexPagesPerVersion = 50
	// indexPagesAtStored is how far it reads forward from the time the
	// proxy says it stored the version at. The line is at that second or
	// nowhere near: on 58 of 58 versions checked on 2026-11-23 it was
	// among the first five lines, and at most 64 lines shared one second.
	indexPagesAtStored = 2
	// indexPagesPerRun bounds all the reading of one Gather. A version
	// that is not found is dated by the publish job's own clock, which
	// is never too early, so there is no point in reading on for long.
	indexPagesPerRun = 150
	// indexStartMargin is how far before the commit time the reading
	// starts, for a committer whose clock runs a little fast.
	indexStartMargin = 10 * time.Minute
	// indexStoredMargin is how far before the proxy's time the reading
	// starts: the header has whole seconds, and nothing says whether it
	// was cut or rounded to them.
	indexStoredMargin = time.Second
	// indexRequestTimeout bounds one request, whatever the client allows.
	indexRequestTimeout = time.Minute
	// maxIndexPage bounds one response. A full page is about 250 KB.
	maxIndexPage = 8 << 20
	// proxyURL is where the go command gets a module version's files.
	proxyURL = "https://proxy.golang.org/"
	// maxModFile is how much of a go.mod is read off the connection.
	maxModFile = 1 << 20

	sourceIndex = "index.golang.org (when proxy.golang.org first cached the version)"
)

// index reads the module index.
type index struct {
	client *http.Client
	// url and limit are the feed and its page size; tests replay pages
	// recorded with a smaller limit.
	url   string
	limit int
	// perVersion and left are the page budgets: for one lookup from a
	// commit time, and what remains for this run.
	perVersion int
	left       int
	// pages is every page this run has fetched, by its since. Modules that
	// are released together from one commit have the same commit time and
	// so read the same pages; a page that is already here costs nothing.
	pages map[string][]indexEntry
}

// indexEntry is one line of the feed.
type indexEntry struct {
	Path      string
	Version   string
	Timestamp string
}

// errIndexDown is the error of a page the index was asked for and did not
// deliver: no response, a 429 or a 5xx. That says nothing about the
// version, unlike a page that came back in a form this package does not
// know.
var errIndexDown = errors.New("the index did not answer")

// stored asks proxy.golang.org for path@version's go.mod, the request the
// go command makes, and returns the time in the answer's Last-Modified
// header. On every version it was checked for, that was the second the
// index dates the version at (spec section 11, amendment 61). Nothing
// documents it, so it is only ever where to start reading the index: no
// header, one that is not a time, any status but 200 and a proxy that
// does not answer all return false, and none of them is waited for.
func (ix *index) stored(ctx context.Context, path, version string) (time.Time, bool) {
	escapedPath, err := module.EscapePath(path)
	if err != nil {
		return time.Time{}, false
	}
	escapedVersion, err := module.EscapeVersion(version)
	if err != nil {
		return time.Time{}, false
	}
	ctx, cancel := context.WithTimeout(ctx, indexRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxyURL+escapedPath+"/@v/"+escapedVersion+".mod", nil)
	if err != nil {
		return time.Time{}, false
	}
	resp, err := ix.client.Do(req)
	if err != nil {
		return time.Time{}, false
	}
	defer resp.Body.Close()
	// The go.mod itself is not looked at; reading it leaves the
	// connection fit for the next request, and a failed read costs only
	// that.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxModFile))
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, false
	}
	at, err := http.ParseTime(resp.Header.Get("Last-Modified"))
	return at, err == nil
}

// firstSeen returns when the proxy first cached path@version, reading
// the index forward from since for at most pages pages. When the version
// is not found, or the index cannot be read, the time is zero and why
// says what happened; down is then set when the index was asked and did
// not answer, so that asking again may find the version.
func (ix *index) firstSeen(ctx context.Context, path, version string, since time.Time, pages int) (seen time.Time, why string, down bool) {
	start := since
	for page := 1; ; page++ {
		if page > pages {
			return time.Time{}, fmt.Sprintf("not in the %d index pages after %s (read up to %s)",
				pages, start.UTC().Format(time.RFC3339), since.UTC().Format(time.RFC3339)), false
		}
		key := since.UTC().Format(time.RFC3339Nano)
		entries, fetched := ix.pages[key]
		if !fetched {
			if ix.left <= 0 && page == 1 {
				return time.Time{}, "not looked up: this run's index budget was spent on other versions", false
			}
			if ix.left <= 0 {
				return time.Time{}, fmt.Sprintf("not in the %d index pages after %s (read up to %s) that were read before this run's index budget was spent",
					page-1, start.UTC().Format(time.RFC3339), since.UTC().Format(time.RFC3339)), false
			}
			ix.left--
			var err error
			if entries, err = ix.page(ctx, since); errors.Is(err, errIndexDown) {
				return time.Time{}, facts.Show(err.Error()), true
			} else if err != nil {
				return time.Time{}, "the index could not be read: " + facts.Show(err.Error()), false
			}
			if ix.pages == nil {
				ix.pages = map[string][]indexEntry{}
			}
			ix.pages[key] = entries
		}
		// The whole page is checked before anything in it is believed:
		// the feed is in time order from since on, and in anything else
		// "first" would mean nothing.
		last := since
		var found time.Time
		for _, e := range entries {
			t, err := time.Parse(time.RFC3339Nano, e.Timestamp)
			if err != nil || e.Path == "" || e.Version == "" || t.Before(last) {
				return time.Time{}, "the index returned a line that is not in the documented form or order", false
			}
			last = t
			if found.IsZero() && e.Path == path && e.Version == version {
				found = t
			}
		}
		if !found.IsZero() {
			return found, "", false
		}
		if len(entries) < ix.limit {
			return time.Time{}, fmt.Sprintf("not in the index between %s and its end", start.UTC().Format(time.RFC3339)), false
		}
		if !last.After(since) {
			// A full page of one timestamp: asking again would return
			// the same page.
			return time.Time{}, "the index does not advance past " + since.UTC().Format(time.RFC3339Nano), false
		}
		// since is inclusive, so the next page starts with the last line
		// of this one. That costs one line and loses none.
		since = last
	}
}

// page fetches one page of the feed.
func (ix *index) page(ctx context.Context, since time.Time) ([]indexEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, indexRequestTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("since", since.UTC().Format(time.RFC3339Nano))
	q.Set("limit", strconv.Itoa(ix.limit))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ix.url+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := ix.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errIndexDown, err) //nolint:errorlint // errIndexDown is the only class; the transport's error is text
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, fmt.Errorf("%w: status %d", errIndexDown, resp.StatusCode)
	default:
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIndexPage+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errIndexDown, err) //nolint:errorlint // errIndexDown is the only class; the transport's error is text
	}
	if len(body) > maxIndexPage {
		return nil, fmt.Errorf("page larger than %d bytes", maxIndexPage)
	}

	var entries []indexEntry
	lines := bufio.NewScanner(bytes.NewReader(body))
	lines.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for lines.Scan() {
		if len(lines.Bytes()) == 0 {
			continue
		}
		var e indexEntry
		if err := json.Unmarshal(lines.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("line %d is not JSON", len(entries)+1)
		}
		entries = append(entries, e)
	}
	if err := lines.Err(); err != nil {
		return nil, err
	}
	if len(entries) > ix.limit {
		return nil, fmt.Errorf("page has %d lines, more than the limit asked for", len(entries))
	}
	return entries, nil
}

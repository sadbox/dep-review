package actions

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/advisory"
	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/gh"
)

// canned is an answer a test gives in place of the recorded one. Status 0
// is no answer at all: the connection fails.
type canned struct {
	status int
	body   string
}

// replay is the network of these tests: an http.RoundTripper that answers
// from testdata/github, where record.sh put GitHub's real answers. The
// file is the request path: GET repos/o/r/x is repos/o/r/x.json, or
// repos/o/r/x.404.json for a recorded 404. A test overrides single paths
// to say what GitHub would have answered in a case that cannot be
// recorded (a moved tag, a draft release). A request with neither a
// recording nor an override fails the test.
type replay struct {
	t        *testing.T
	override map[string]canned

	mu   sync.Mutex
	seen []string
}

func (r *replay) RoundTrip(req *http.Request) (*http.Response, error) {
	path := strings.TrimPrefix(req.URL.Path, "/")
	r.mu.Lock()
	r.seen = append(r.seen, req.Method+" "+path)
	r.mu.Unlock()

	if req.Method != http.MethodGet {
		r.t.Errorf("the gatherer sent %s %s; it may only GET", req.Method, path)
		return nil, errors.New("replay: not a GET")
	}
	if c, ok := r.override[path]; ok {
		if c.status == 0 {
			return nil, errors.New("replay: connection reset")
		}
		return response(req, c.status, []byte(c.body)), nil
	}
	file := filepath.Join("testdata", "github", filepath.FromSlash(path))
	if body, err := os.ReadFile(file + ".json"); err == nil {
		return response(req, http.StatusOK, body), nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		r.t.Errorf("replay: %v", err)
	}
	if body, err := os.ReadFile(file + ".404.json"); err == nil {
		return response(req, http.StatusNotFound, body), nil
	}
	r.t.Errorf("replay: no recording and no override for GET %s", path)
	return nil, errors.New("replay: no recording")
}

func response(req *http.Request, status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}
}

// requested reports whether any request's path contains part.
func (r *replay) requested(part string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.seen {
		if strings.Contains(s, part) {
			return true
		}
	}
	return false
}

// client returns a GitHub client that talks to r and never retries or
// sleeps, so an unanswered request fails at once.
func (r *replay) client() *gh.Client {
	c := gh.New("")
	c.HTTP = &http.Client{Transport: r}
	c.MaxRetries = 0
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	return c
}

// advisories is a fixed advisory.Checker.
type advisories struct {
	result advisory.Result
	// byName is the answer for a query under one name, where it is not
	// result.
	byName map[string]advisory.Result
	err    error
	asked  []advisory.Query
}

func (a *advisories) Check(_ context.Context, q advisory.Query) (advisory.Result, error) {
	a.asked = append(a.asked, q)
	if r, ok := a.byName[q.Name]; ok {
		return r, a.err
	}
	return a.result, a.err
}

// noAdvisories answers that the database has nothing on the update.
func noAdvisories() *advisories {
	return &advisories{result: advisory.Result{
		SecurityFix:   allow.No("no advisory names this update as the fix", "advisories"),
		NoMalware:     allow.Yes("no malware advisory", "advisories"),
		NoNewAdvisory: allow.Yes("no new advisory", "advisories"),
	}}
}

// testPolicy is the embedded default policy's ages and Actions list,
// written out so the tests do not depend on internal/config.
func testPolicy() allow.Policy {
	return allow.Policy{
		MinAge:       72 * time.Hour,
		UnreadAge:    14 * 24 * time.Hour,
		MajorAge:     14 * 24 * time.Hour,
		NewNameAge:   365 * 24 * time.Hour,
		WaitDeadline: 7 * 24 * time.Hour,
		FastPath:     true,
		Companions:   allow.RideAlong,
		Listed:       map[string][]string{allow.GitHubActions: {"actions/", "github/", "docker/"}},
	}
}

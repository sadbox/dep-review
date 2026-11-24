package docker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The registries are reached through facts.Input.HTTP, and that client's
// transport is the seam. Tests replay answers recorded from the real
// registries (testdata/recorded, one file per request). Running
//
//	DEP_REVIEW_DOCKER_RECORD=1 go test ./internal/facts/docker/ -run TestRecorded
//
// asks the real registries instead and rewrites the files. Tags move, so
// after recording again the digests and times in recordedCases have to be
// brought up to date by hand; the test says which.
//
// A recording keeps only what the gatherer reads, and nothing about who
// recorded it:
//   - of the headers, Content-Type and Docker-Content-Digest (the others
//     carry the recorder's IP address, cookies and trace IDs);
//   - no body of an answer that is not a 200;
//   - a placeholder for the pull token;
//   - of Docker Hub's tag document, the three fields that are read;
//   - of GCR's tag list (megabytes), the manifests that carry a tag or a
//     digest the test cases name.

const (
	fixtureDir = "testdata/recorded"
	recordEnv  = "DEP_REVIEW_DOCKER_RECORD"
)

// exchange is one recorded request and the part of its answer that is
// kept.
type exchange struct {
	Method string            `json:"method"`
	URL    string            `json:"url"`
	Note   string            `json:"note,omitempty"`
	Status int               `json:"status"`
	Header map[string]string `json:"header,omitempty"`
	Body   json.RawMessage   `json:"body,omitempty"`
}

var unsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

// fixtureFile is where the answer to one request is kept.
func fixtureFile(method, rawURL string) string {
	name := unsafeFileChars.ReplaceAllString(strings.TrimPrefix(rawURL, "https://"), "_")
	return filepath.Join(fixtureDir, method+"_"+name+".json")
}

// replayer answers from the recorded files and notes what was asked.
type replayer struct {
	asked []string
}

func (r *replayer) RoundTrip(req *http.Request) (*http.Response, error) {
	r.asked = append(r.asked, req.Method+" "+req.URL.String())
	raw, err := os.ReadFile(fixtureFile(req.Method, req.URL.String()))
	if err != nil {
		return nil, fmt.Errorf("no recorded answer (set %s=1 to record): %w", recordEnv, err)
	}
	var ex exchange
	if err := json.Unmarshal(raw, &ex); err != nil {
		return nil, fmt.Errorf("recorded answer for %s %s: %w", req.Method, req.URL, err)
	}
	if ex.Method != req.Method || ex.URL != req.URL.String() {
		return nil, fmt.Errorf("recorded answer is for %s %s, not %s %s", ex.Method, ex.URL, req.Method, req.URL)
	}
	return response(req, ex.Status, ex.Header, ex.Body), nil
}

// response builds a transport's answer.
func response(req *http.Request, status int, header map[string]string, body []byte) *http.Response {
	resp := &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
		Body:       http.NoBody,
		Request:    req,
	}
	for k, v := range header {
		resp.Header.Set(k, v)
	}
	if req.Method != http.MethodHead && len(body) > 0 {
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}
	return resp
}

// recorder asks the real registries and writes what replayer reads.
type recorder struct {
	next http.RoundTripper
	// keepGCR names the tags and digests whose entries of a GCR tag list
	// are kept.
	keepGCR map[string]bool
}

// recordedHosts is every host the gatherer may ask. A request anywhere
// else fails the recording.
var recordedHosts = map[string]bool{
	"auth.docker.io":       true,
	"registry-1.docker.io": true,
	"hub.docker.com":       true,
	"gcr.io":               true,
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" || !recordedHosts[req.URL.Host] {
		return nil, fmt.Errorf("the gatherer asked %s, which is not one of its registries", req.URL)
	}
	resp, err := r.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))

	ex := exchange{Method: req.Method, URL: req.URL.String(), Status: resp.StatusCode, Header: map[string]string{}}
	for _, h := range []string{"Content-Type", "Docker-Content-Digest"} {
		if v := resp.Header.Get(h); v != "" {
			ex.Header[h] = v
		}
	}
	if resp.StatusCode == http.StatusOK && req.Method == http.MethodGet {
		ex.Body, ex.Note, err = r.keep(req.URL, body)
		if err != nil {
			return nil, fmt.Errorf("recording %s: %w", req.URL, err)
		}
	}
	out, err := json.MarshalIndent(ex, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(fixtureFile(req.Method, req.URL.String()), append(out, '\n'), 0o644); err != nil {
		return nil, err
	}
	return resp, nil
}

// keep reduces a 200 body to what is written to the fixture.
func (r *recorder) keep(u *url.URL, body []byte) (kept json.RawMessage, note string, err error) {
	switch u.Host {
	case "auth.docker.io":
		return json.RawMessage(`{"token": "recorded-anonymous-token"}`), "the pull token is replaced by a placeholder", nil

	case "hub.docker.com":
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, "", err
		}
		out := map[string]json.RawMessage{}
		for _, k := range []string{"name", "digest", "tag_last_pushed"} {
			if v, ok := doc[k]; ok {
				out[k] = v
			}
		}
		kept, err = json.Marshal(out)
		return kept, "reduced to the three fields that are read", err

	case "gcr.io":
		var doc struct {
			Name     string                     `json:"name"`
			Manifest map[string]json.RawMessage `json:"manifest"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, "", err
		}
		total := len(doc.Manifest)
		for digest, raw := range doc.Manifest {
			var m struct {
				Tag []string `json:"tag"`
			}
			if err := json.Unmarshal(raw, &m); err != nil {
				return nil, "", err
			}
			wanted := r.keepGCR[digest]
			for _, tag := range m.Tag {
				wanted = wanted || r.keepGCR[tag]
			}
			if !wanted {
				delete(doc.Manifest, digest)
			}
		}
		kept, err = json.Marshal(doc)
		note = fmt.Sprintf("trimmed: %d of the list's %d manifests are kept, and its \"tags\" and \"child\" arrays are dropped", len(doc.Manifest), total)
		return kept, note, err
	}
	return nil, "", fmt.Errorf("no rule for what to keep of an answer from %s", u.Host)
}

package docker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/facts"
)

// liveEnv turns on the test that asks the real registries. It is for
// finding out that a registry changed its answers; the recorded tests
// cannot notice that.
const liveEnv = "DEP_REVIEW_DOCKER_LIVE"

// liveDigest asks a registry which digest a tag has now, with code that
// shares nothing with the gatherer's.
func liveDigest(t *testing.T, registry, repo, tag string) string {
	t.Helper()
	client := &http.Client{Timeout: time.Minute}
	host, bearer := registry, ""
	if registry == "docker.io" {
		host = "registry-1.docker.io"
		q := url.Values{"service": {"registry.docker.io"}, "scope": {"repository:" + repo + ":pull"}}
		resp, err := client.Get("https://auth.docker.io/token?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var doc struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil || doc.Token == "" {
			t.Fatalf("no token for %s: %v", repo, err)
		}
		bearer = doc.Token
	}
	req, err := http.NewRequest(http.MethodHead, "https://"+host+"/v2/"+repo+"/manifests/"+tag, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", acceptManifests)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	digest := resp.Header.Get("Docker-Content-Digest")
	if resp.StatusCode != http.StatusOK || !digestRe.MatchString(digest) {
		t.Fatalf("%s/%s:%s: HTTP %d, digest %q", registry, repo, tag, resp.StatusCode, digest)
	}
	return digest
}

func TestLive(t *testing.T) {
	if os.Getenv(liveEnv) == "" {
		t.Skipf("set %s=1 to ask the real registries", liveEnv)
	}
	now := time.Now()
	tests := []struct {
		written  string // the image as a Dockerfile names it
		registry string
		repo     string
		tag      string
		// clean is whether Clean is expected to hold. For the deprecated
		// distroless repository it is only logged: the mark is GCR's to
		// take away.
		clean bool
	}{
		{"golang", "docker.io", "library/golang", "latest", true},
		{"golang", "docker.io", "library/golang", "1-bookworm", true},
		{"node", "docker.io", "library/node", "lts-bookworm-slim", true},
		{"gcr.io/distroless/static-debian13", "gcr.io", "distroless/static-debian13", "nonroot", true},
		{"gcr.io/distroless/static-debian12", "gcr.io", "distroless/static-debian12", "nonroot", false},
	}
	for _, tc := range tests {
		t.Run(tc.written+":"+tc.tag, func(t *testing.T) {
			current := liveDigest(t, tc.registry, tc.repo, tc.tag)
			in := facts.Input{
				Policy: defaultPolicy(t),
				HTTP:   &http.Client{},
				Now:    func() time.Time { return now },
			}

			// A refresh to the digest the tag has now.
			in.Files = oneLine(tc.written+":"+tc.tag+"@"+digestA, tc.written+":"+tc.tag+"@"+current)
			res, err := New().Gather(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			if !res.Shape.Holds() || len(res.Updates) != 1 {
				t.Fatalf("Shape %+v, %d updates", res.Shape, len(res.Updates))
			}
			u := res.Updates[0]
			checkExplained(t, u)
			t.Logf("%s", summarise(u))
			t.Logf("Clean: %s", u.Clean.Value)
			if u.Name != tc.registry+"/"+tc.repo || !u.Listed.Holds() || !u.Known.Holds() || !u.Increase.Holds() || !u.Bound.Holds() {
				t.Errorf("facts: %+v", u)
			}
			if tc.clean && !u.Clean.Holds() {
				t.Errorf("Clean: %+v", u.Clean)
			}
			if tc.registry == "gcr.io" {
				// GCR dates the manifest, not the tag: no time, and the
				// upload in the value (spec section 11, amendment 49).
				if u.FirstSeen.Known() || u.FirstSeen.Unavailable || u.FirstSeen.Source == "" || !strings.Contains(u.FirstSeen.Value, "dates the upload of the pinned manifest (20") {
					t.Errorf("FirstSeen: %+v", u.FirstSeen)
				}
			} else if !u.FirstSeen.Known() || u.FirstSeen.Time.After(now.Add(5*time.Minute)) || u.FirstSeen.Time.Before(now.AddDate(-3, 0, 0)) {
				t.Errorf("FirstSeen: %+v", u.FirstSeen)
			}

			// A pin the tag does not have.
			in.Files = oneLine(tc.written+":"+tc.tag+"@"+current, tc.written+":"+tc.tag+"@"+digestA)
			res, err = New().Gather(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			u = res.Updates[0]
			if u.Bound.OK || !strings.Contains(u.Bound.Value, "resolves to "+current) || u.Clean.OK || u.FirstSeen.Known() {
				t.Errorf("facts for a pin the tag does not have: %+v", u)
			}
		})
	}
}

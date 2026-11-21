package docker

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/fetch"
)

func recordSleeps(a *analyzer) *[]time.Duration {
	var got []time.Duration
	a.reg.sleep = func(_ context.Context, d time.Duration) error {
		got = append(got, d)
		return nil
	}
	return &got
}

// Docker Hub answers 429 on shared runner IPs. A short burst is retried,
// honouring Retry-After up to a cap.
func TestRegistryRetriesRateLimit(t *testing.T) {
	golang := imageRef{Registry: "docker.io", Repo: "library/golang"}
	path := "/v2/library/golang/manifests/" + dgB
	for _, tc := range []struct {
		name       string
		code       int
		retryAfter string
		wantSleeps []time.Duration
	}{
		{"429 with Retry-After", http.StatusTooManyRequests, "7", []time.Duration{7 * time.Second, 7 * time.Second}},
		{"Retry-After capped", http.StatusTooManyRequests, "3600", []time.Duration{time.Minute, time.Minute}},
		{"503 without Retry-After", http.StatusServiceUnavailable, "", []time.Duration{2 * time.Second, 4 * time.Second}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRegistry(t)
			f.throttle[path], f.throttleCode, f.retryAfter = 2, tc.code, tc.retryAfter
			a := f.analyzer(nil)
			sleeps := recordSleeps(a)
			if _, doc, _, err := a.reg.manifest(context.Background(), golang, dgB); err != nil || !doc.isIndex() {
				t.Fatalf("%v", err)
			}
			if !slices.Equal(*sleeps, tc.wantSleeps) {
				t.Errorf("sleeps %v, want %v", *sleeps, tc.wantSleeps)
			}
		})
	}
}

// Still limited after maxTries: an infrastructure error for the whole
// fetch (the PR stays pending), never a finding about the image.
func TestRegistryRateLimitIsInfrastructure(t *testing.T) {
	f := newFakeRegistry(t)
	f.throttle["/v2/library/golang/manifests/"+dgA] = -1 // always
	a := f.analyzer(nil)
	sleeps := recordSleeps(a)
	cl, src := loadCase(t, filepath.Join("testdata/cases", "golang-digest-noop"))
	res, err := run(context.Background(), fetch.Env{Class: cl, Evidence: newMemWriter()}, src, a)
	if !errors.Is(err, errRateLimited) || len(res.Findings) != 0 {
		t.Fatalf("err %v findings %s", err, codes(res.Findings))
	}
	if n := f.hits["GET /v2/library/golang/manifests/"+dgA]; n != 1+maxTries || len(*sleeps) != maxTries-1 {
		t.Errorf("%d requests, %d sleeps", n, len(*sleeps))
	}
}

func TestRetryDelay(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", time.Now().Add(30*time.Second).UTC().Format(http.TimeFormat))
	if d := retryDelay(h, 1); d < 25*time.Second || d > 30*time.Second {
		t.Errorf("HTTP date: %v", d)
	}
	h.Set("Retry-After", "garbage")
	if d := retryDelay(h, 2); d != 4*time.Second {
		t.Errorf("garbage: %v", d)
	}
	h.Set("Retry-After", "-5")
	if d := retryDelay(h, 1); d != 2*time.Second {
		t.Errorf("negative: %v", d)
	}
}

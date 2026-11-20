package ecoutil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"time"
)

// Download limits. Every fetch is bounded in time and size.
const (
	MetadataLimit   = 32 << 20  // registry JSON documents
	ArtifactLimit   = 256 << 20 // a tarball, wheel or sdist
	RequestTimeout  = 3 * time.Minute
	maxAttempts     = 4
	firstRetryDelay = time.Second
)

// ErrNotFound is returned for an HTTP 404 or 410.
var ErrNotFound = errors.New("not found")

// HTTPError is a non-retryable, non-404 status.
type HTTPError struct {
	URL    string
	Status int
}

func (e *HTTPError) Error() string { return fmt.Sprintf("GET %s: HTTP %d", e.URL, e.Status) }

// CheckHost refuses any URL that is not https on one of hosts.
func CheckHost(raw string, hosts ...string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.User != nil || !slices.Contains(hosts, u.Host) {
		return fmt.Errorf("%q is not an https URL on %v", raw, hosts)
	}
	return nil
}

// Get fetches url into w, retrying on network errors and 5xx with backoff.
// It fails once more than limit bytes arrive. A retry restarts the body, so
// w must tolerate being reset: reset is called before each attempt.
func Get(ctx context.Context, c *http.Client, rawURL string, limit int64, w io.Writer, reset func() error, header http.Header) error {
	delay := firstRetryDelay
	var last error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
			delay *= 2
		}
		if err := reset(); err != nil {
			return err
		}
		retry, err := getOnce(ctx, c, rawURL, limit, w, header)
		if err == nil {
			return nil
		}
		last = err
		if !retry {
			return err
		}
	}
	return fmt.Errorf("after %d attempts: %w", maxAttempts, last)
}

func getOnce(ctx context.Context, c *http.Client, rawURL string, limit int64, w io.Writer, header http.Header) (retry bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("User-Agent", "dep-review")
	resp, err := c.Do(req)
	if err != nil {
		return true, fmt.Errorf("GET %s: %w", rawURL, err) // Get stops retrying once its ctx is done
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return false, fmt.Errorf("GET %s: %w", rawURL, ErrNotFound)
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
		return true, &HTTPError{rawURL, resp.StatusCode}
	default:
		return false, &HTTPError{rawURL, resp.StatusCode}
	}
	if resp.ContentLength > limit {
		return false, fmt.Errorf("GET %s: %d bytes exceeds limit %d", rawURL, resp.ContentLength, limit)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return true, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	if n > limit {
		return false, fmt.Errorf("GET %s: body exceeds limit %d", rawURL, limit)
	}
	return false, nil
}

// GetBytes fetches a small document into memory.
func GetBytes(ctx context.Context, c *http.Client, rawURL string, limit int64, header http.Header) ([]byte, error) {
	var buf limitedBuffer
	err := Get(ctx, c, rawURL, limit, &buf, func() error { buf.b = buf.b[:0]; return nil }, header)
	return buf.b, err
}

type limitedBuffer struct{ b []byte }

func (l *limitedBuffer) Write(p []byte) (int, error) { l.b = append(l.b, p...); return len(p), nil }

// GetFile downloads rawURL to dst (created fresh; must be under Scratch).
func GetFile(ctx context.Context, c *http.Client, rawURL, dst string, limit int64) error {
	f, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	reset := func() error {
		if err := f.Truncate(0); err != nil {
			return err
		}
		_, err := f.Seek(0, io.SeekStart)
		return err
	}
	if err := Get(ctx, c, rawURL, limit, f, reset, nil); err != nil {
		return err
	}
	return f.Close()
}

// NewClient returns the HTTP client fetchers use: bounded, and following
// redirects only to https.
func NewClient() *http.Client {
	return &http.Client{
		Timeout: RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to non-https %s", req.URL)
			}
			return nil
		},
	}
}

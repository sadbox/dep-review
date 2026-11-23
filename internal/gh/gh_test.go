package gh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/fetch"
)

var _ fetch.GitHub = (*Client)(nil)

// testClient returns a client against srv that records its sleeps instead
// of sleeping.
func testClient(srv *httptest.Server) (*Client, *[]time.Duration) {
	c := New("tok")
	c.BaseURL = srv.URL + "/"
	c.HTTP = srv.Client()
	c.MaxRetries = 3
	var mu sync.Mutex
	var sleeps []time.Duration
	c.Sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		defer mu.Unlock()
		sleeps = append(sleeps, d)
		return ctx.Err()
	}
	return c, &sleeps
}

func TestRetries(t *testing.T) {
	type resp struct {
		status int
		header map[string]string
		body   string
	}
	tests := []struct {
		name      string
		method    string
		responses []resp
		wantCalls int
		wantCode  int // 0 = success
		minSleep  time.Duration
	}{
		{"get 502 then ok", "GET", []resp{{502, nil, ""}, {200, nil, `{"n":1}`}}, 2, 0, 0},
		{"get 500 forever", "GET", []resp{{500, nil, `{"message":"boom"}`}}, 4, 500, 0},
		{"post 502 not retried", "POST", []resp{{502, nil, ""}, {200, nil, `{}`}}, 1, 502, 0},
		{"post 429 retried", "POST", []resp{{429, map[string]string{"Retry-After": "7"}, ""}, {201, nil, `{"n":1}`}}, 2, 0, 7 * time.Second},
		{"secondary rate limit", "PUT", []resp{{403, nil, `{"message":"You have exceeded a secondary rate limit."}`}, {200, nil, `{}`}}, 2, 0, 0},
		{"primary rate limit", "GET", []resp{{403, map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "0"}, ""}, {200, nil, `{}`}}, 2, 0, 0},
		{"plain 403 not retried", "GET", []resp{{403, nil, `{"message":"Resource not accessible by integration"}`}}, 1, 403, 0},
		{"404", "GET", []resp{{404, nil, `{"message":"Not Found"}`}}, 1, 404, 0},
		{"405 merge", "PUT", []resp{{405, nil, `{"message":"Pull Request is not mergeable"}`}}, 1, 405, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			calls := 0
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				i := calls
				calls++
				mu.Unlock()
				if r.Method != tt.method {
					t.Errorf("method %s", r.Method)
				}
				if r.Header.Get("Authorization") != "Bearer tok" {
					t.Errorf("auth header %q", r.Header.Get("Authorization"))
				}
				if i >= len(tt.responses) {
					i = len(tt.responses) - 1
				}
				for k, v := range tt.responses[i].header {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tt.responses[i].status)
				io.WriteString(w, tt.responses[i].body)
			}))
			defer srv.Close()
			c, sleeps := testClient(srv)
			var out map[string]any
			var err error
			switch tt.method {
			case "GET":
				err = c.Get(context.Background(), "x", &out)
			case "POST":
				err = c.Post(context.Background(), "x", map[string]string{"a": "b"}, &out)
			case "PUT":
				err = c.Put(context.Background(), "x", map[string]string{"a": "b"}, &out)
			}
			if calls != tt.wantCalls {
				t.Errorf("calls = %d, want %d", calls, tt.wantCalls)
			}
			if got := StatusCode(err); got != tt.wantCode {
				t.Errorf("status = %d (%v), want %d", got, err, tt.wantCode)
			}
			if tt.minSleep > 0 && (len(*sleeps) == 0 || (*sleeps)[0] < tt.minSleep) {
				t.Errorf("sleeps = %v, want >= %v", *sleeps, tt.minSleep)
			}
		})
	}
}

func TestErrorMessage(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(409)
		io.WriteString(w, `{"message":"Head branch was modified"}`)
	}))
	defer srv.Close()
	c, _ := testClient(srv)
	err := c.Put(context.Background(), "repos/o/r/pulls/1/merge", nil, nil)
	if !strings.Contains(err.Error(), "409 Head branch was modified") {
		t.Fatal(err)
	}
}

func TestErrNotFound(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/missing":
			w.WriteHeader(404)
		case "/forbidden":
			w.WriteHeader(403)
		case "/gone":
			w.WriteHeader(410)
		}
	}))
	defer srv.Close()
	c, _ := testClient(srv)
	for path, want := range map[string]bool{"missing": true, "forbidden": false, "gone": false} {
		err := c.Get(context.Background(), path, nil)
		if got := errors.Is(fmt.Errorf("wrapped: %w", err), ErrNotFound); got != want {
			t.Errorf("%s: errors.Is(ErrNotFound) = %v, want %v (%v)", path, got, want, err)
		}
	}
}

func TestPagination(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("per_page") != "100" {
			t.Errorf("per_page missing: %s", r.URL)
		}
		page := r.URL.Query().Get("page")
		switch page {
		case "", "1":
			w.Header().Set("Link", fmt.Sprintf(`<%s/items?per_page=100&page=2>; rel="next", <%s/items?per_page=100&page=3>; rel="last"`, srv.URL, srv.URL))
			io.WriteString(w, `[{"n":1},{"n":2}]`)
		case "2":
			w.Header().Set("Link", fmt.Sprintf(`<%s/items?per_page=100&page=3>; rel="next"`, srv.URL))
			io.WriteString(w, `[{"n":3}]`)
		case "3":
			io.WriteString(w, `[{"n":4}]`)
		}
	}))
	defer srv.Close()
	c, _ := testClient(srv)
	got, err := List[struct{ N int }](context.Background(), c, "items")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got[3].N != 4 {
		t.Fatalf("got %+v", got)
	}
}

func TestPaginationRefusesForeignHost(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://evil.example/items?page=2>; rel="next"`)
		io.WriteString(w, `[]`)
	}))
	defer srv.Close()
	c, _ := testClient(srv)
	if _, err := List[json.RawMessage](context.Background(), c, "items"); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("err = %v", err)
	}
}

func TestTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(block)
	c, _ := testClient(srv)
	c.Timeout = 50 * time.Millisecond
	c.MaxRetries = 1
	start := time.Now()
	if err := c.Get(context.Background(), "slow", nil); err == nil {
		t.Fatal("want timeout error")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("timeout not applied")
	}
}

func TestValid(t *testing.T) {
	for _, s := range []string{"sadbox/dep-review", "Espresso-Aficionados/sprobot", "a/b.c_d"} {
		if !ValidRepo(s) {
			t.Errorf("ValidRepo(%q) = false", s)
		}
	}
	for _, s := range []string{"", "a", "a/b/c", "../x", "a/..", "a/b?x", "a/b c", "a/b\n"} {
		if ValidRepo(s) {
			t.Errorf("ValidRepo(%q) = true", s)
		}
	}
	if !ValidSHA(strings.Repeat("a", 40)) || ValidSHA(strings.Repeat("A", 40)) || ValidSHA("abc") {
		t.Error("ValidSHA")
	}
}

// Unavailable tells "GitHub did not answer" from every answer GitHub
// gave, after the client's own retries.
func TestUnavailable(t *testing.T) {
	type resp struct {
		status int
		header map[string]string
		body   string
	}
	for _, tc := range []struct {
		name string
		resp resp
		want bool
	}{
		{"500", resp{500, nil, `{"message":"boom"}`}, true},
		{"502", resp{502, nil, ""}, true},
		{"503", resp{503, nil, ""}, true},
		{"429", resp{429, nil, ""}, true},
		{"secondary rate limit", resp{403, nil, `{"message":"You have exceeded a secondary rate limit."}`}, true},
		{"primary rate limit", resp{403, map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "0"}, `{"message":"API rate limit exceeded"}`}, true},
		{"a 403 with retry-after", resp{403, map[string]string{"Retry-After": "1"}, ""}, true},
		{"plain 403", resp{403, nil, `{"message":"Resource not accessible by integration"}`}, false},
		{"a 403 whose text only mentions a rate limit", resp{403, nil, `{"message":"Repository access blocked; see the rate limit documentation"}`}, false},
		{"404", resp{404, nil, `{"message":"Not Found"}`}, false},
		{"401", resp{401, nil, `{"message":"Bad credentials"}`}, false},
		{"422", resp{422, nil, `{"message":"Validation Failed"}`}, false},
		{"a 200 that is not JSON", resp{200, nil, `<html>`}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tc.resp.header {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tc.resp.status)
				io.WriteString(w, tc.resp.body)
			}))
			defer srv.Close()
			c, _ := testClient(srv)
			var out struct{ N int }
			err := c.Get(context.Background(), "x", &out)
			if err == nil {
				t.Fatal("no error")
			}
			if got := Unavailable(err); got != tc.want {
				t.Errorf("Unavailable(%v) = %v, want %v", err, got, tc.want)
			}
			if got := Unavailable(fmt.Errorf("advisory: asking: %w", err)); got != tc.want {
				t.Errorf("wrapped: Unavailable = %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("nothing listening", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		c, _ := testClient(srv)
		srv.Close()
		if err := c.Get(context.Background(), "x", nil); err == nil || !Unavailable(err) {
			t.Errorf("Unavailable(%v) is false", err)
		}
	})
	t.Run("an attempt that times out", func(t *testing.T) {
		release := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
		defer srv.Close()
		defer close(release)
		c, _ := testClient(srv)
		c.Timeout, c.MaxRetries = 50*time.Millisecond, 0
		if err := c.Get(context.Background(), "x", nil); err == nil || !Unavailable(err) {
			t.Errorf("Unavailable(%v) is false", err)
		}
	})
	for _, err := range []error{nil, errors.New("github: bad path"), context.Canceled, ErrNotFound} {
		if Unavailable(err) {
			t.Errorf("Unavailable(%v) is true", err)
		}
	}
}

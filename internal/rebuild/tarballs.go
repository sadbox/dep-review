package rebuild

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sadbox/dep-review/internal/strictjson"
)

// Caps on the locked tarballs the job downloads.
const (
	MaxTarball  = 64 << 20
	MaxTarballs = 1 << 30
	maxPackages = 5000
)

// tarball is one locked package archive: its registry URL and sha512.
type tarball struct {
	url    string
	sha512 []byte
}

// lockedTarballs lists the distinct tarballs a lockfile Scripts accepted
// pins. Two entries with one URL must pin one digest.
func lockedTarballs(lock []byte) ([]tarball, error) {
	var lf struct {
		Packages map[string]struct {
			Resolved  string `json:"resolved"`
			Integrity string `json:"integrity"`
		} `json:"packages"`
	}
	if err := strictjson.Unmarshal(lock, &lf); err != nil {
		return nil, err
	}
	byURL := map[string][]byte{}
	for k, e := range lf.Packages {
		if k == "" || e.Resolved == "" {
			continue
		}
		var sum []byte
		for _, h := range strings.Fields(e.Integrity) {
			if b, ok := strings.CutPrefix(h, "sha512-"); ok {
				d, err := base64.StdEncoding.DecodeString(b)
				if err == nil && len(d) == sha512.Size {
					sum = d
				}
			}
		}
		if sum == nil {
			return nil, notRebuildable("a locked package has no valid sha512 integrity")
		}
		if prev, ok := byURL[e.Resolved]; ok && !bytes.Equal(prev, sum) {
			return nil, notRebuildable("two locked packages pin one tarball to different digests")
		}
		byURL[e.Resolved] = sum
	}
	if len(byURL) > maxPackages {
		return nil, notRebuildable("the lockfile pins too many packages")
	}
	var out []tarball
	for _, u := range slices.Sorted(mapKeys(byURL)) {
		out = append(out, tarball{u, byURL[u]})
	}
	return out, nil
}

func mapKeys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// fetchTarballs downloads every tarball (each URL already matched
// resolvedRe: registry.npmjs.org over HTTPS), checks its sha512 and
// returns the files to seed npm's cache with, named by the URL's sha256.
func fetchTarballs(ctx context.Context, client *http.Client, tbs []tarball) (map[string][]byte, error) {
	out := map[string][]byte{}
	var mu sync.Mutex
	var total int64
	var firstErr error
	for _, tb := range tbs {
		if !resolvedRe.MatchString(tb.url) {
			return nil, notRebuildable("a locked package is not a registry.npmjs.org tarball")
		}
	}
	// Four in flight: at most MaxTarballs plus 4 x MaxTarball held.
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, tb := range tbs {
		wg.Add(1)
		sem <- struct{}{}
		go func(tb tarball) {
			defer wg.Done()
			defer func() { <-sem }()
			data, err := getTarball(ctx, client, tb.url)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				if sum := sha512.Sum512(data); !bytes.Equal(sum[:], tb.sha512) {
					err = fmt.Errorf("%s does not match its locked sha512", tb.url)
				}
			}
			if err == nil {
				total += int64(len(data))
				if total > MaxTarballs {
					err = errors.New("the locked tarballs are too large")
				}
			}
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			h := sha256.Sum256([]byte(tb.url))
			out["tgz/"+hex.EncodeToString(h[:])+".tgz"] = data
		}(tb)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

func getTarball(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		var data []byte
		if data, err = getOnce(ctx, client, url); err == nil {
			return data, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * time.Second):
		}
	}
	return nil, err
}

func getOnce(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxTarball+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxTarball {
		return nil, fmt.Errorf("%s is larger than %d bytes", url, MaxTarball)
	}
	return data, nil
}

// registryClient follows no redirect off registry.npmjs.org.
func registryClient() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" || req.URL.Host != "registry.npmjs.org" || len(via) > 3 {
				return errors.New("redirect off the registry")
			}
			return nil
		},
	}
}

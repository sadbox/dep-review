package docker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeRegistry serves recorded fixtures from testdata/registry/docker.io
// plus in-memory blobs, behind the anonymous bearer-token flow.
type fakeRegistry struct {
	t     *testing.T
	srv   *httptest.Server
	mu    sync.Mutex
	blobs map[string][]byte // repo + "@" + digest -> bytes (overrides files)
	tags  map[string]string // repo + ":" + tag -> digest (overrides files)
	// tamper, if set, rewrites a response body before it is sent.
	tamper func(path string, b []byte) []byte
	hits   map[string]int
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	f := &fakeRegistry{t: t, blobs: map[string][]byte{}, tags: map[string]string{}, hits: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRegistry) analyzer(hist tagHistory) *analyzer {
	reg := newRegistry(f.srv.Client(), 1<<30)
	reg.endpoint = func(string) string { return f.srv.URL }
	host := strings.TrimPrefix(f.srv.URL, "http://")
	reg.realmOK = func(u *url.URL) bool { return u.Host == host }
	return &analyzer{reg: reg, hist: hist, maxParallel: 2}
}

func (f *fakeRegistry) put(repo string, b []byte) string {
	d := sha256Digest(b)
	f.mu.Lock()
	f.blobs[repo+"@"+d] = b
	f.mu.Unlock()
	return d
}

func (f *fakeRegistry) get(repo, ref string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if b, ok := f.blobs[repo+"@"+ref]; ok {
		return b, true
	}
	b, err := os.ReadFile(filepath.Join("testdata/registry/docker.io", filepath.FromSlash(repo), strings.TrimPrefix(ref, "sha256:")))
	return b, err == nil
}

func (f *fakeRegistry) tag(repo, tag string) (string, bool) {
	f.mu.Lock()
	d, ok := f.tags[repo+":"+tag]
	f.mu.Unlock()
	if ok {
		return d, d != ""
	}
	b, err := os.ReadFile(filepath.Join("testdata/registry/docker.io", filepath.FromSlash(repo), "tags", tag))
	return strings.TrimSpace(string(b)), err == nil
}

func (f *fakeRegistry) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.hits[r.Method+" "+r.URL.Path]++
	f.mu.Unlock()
	if r.URL.Path == "/token" {
		if r.Header.Get("Authorization") != "" {
			http.Error(w, "credentials sent", http.StatusBadRequest)
			return
		}
		scope := r.URL.Query().Get("scope")
		repo := strings.TrimSuffix(strings.TrimPrefix(scope, "repository:"), ":pull")
		json.NewEncoder(w).Encode(map[string]string{"token": "tok-" + repo})
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/v2/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	var repo, kind, ref string
	for _, k := range []string{"/manifests/", "/blobs/"} {
		if i := strings.LastIndex(rest, k); i >= 0 {
			repo, kind, ref = rest[:i], strings.Trim(k, "/"), rest[i+len(k):]
		}
	}
	if repo == "" {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("Authorization") != "Bearer tok-"+repo {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="fake",scope="repository:%s:pull"`, f.srv.URL, repo))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if kind == "manifests" && !strings.HasPrefix(ref, "sha256:") {
		d, ok := f.tag(repo, ref)
		if !ok {
			http.NotFound(w, r)
			return
		}
		ref = d
	}
	b, ok := f.get(repo, ref)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if f.tamper != nil {
		b = f.tamper(r.URL.Path, b)
	}
	if kind == "manifests" {
		var m struct {
			MediaType string `json:"mediaType"`
		}
		json.Unmarshal(b, &m)
		w.Header().Set("Content-Type", m.MediaType)
		w.Header().Set("Docker-Content-Digest", ref)
	}
	if r.Method == http.MethodHead {
		return
	}
	w.Write(b)
}

// --- synthetic images ---

type tfile struct {
	path string
	typ  byte // 0 or 'f' regular, 'd' dir, 'l' symlink, 'h' hardlink
	body string
	link string
	mode int64
}

func tarGz(t *testing.T, files []tfile) (gz []byte, diffID string) {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, f := range files {
		h := &tar.Header{Name: f.path, Mode: f.mode, Uname: "root"}
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		switch f.typ {
		case 'd':
			h.Typeflag, h.Mode = tar.TypeDir, 0o755
		case 'l':
			h.Typeflag, h.Linkname = tar.TypeSymlink, f.link
		case 'h':
			h.Typeflag, h.Linkname = tar.TypeLink, f.link
		default:
			h.Typeflag, h.Size = tar.TypeReg, int64(len(f.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			tw.Write([]byte(f.body))
		}
	}
	tw.Close()
	s := sha256.Sum256(raw.Bytes())
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	zw.Write(raw.Bytes())
	zw.Close()
	return out.Bytes(), "sha256:" + hex.EncodeToString(s[:])
}

// image stores a single-platform image made of layers and returns its
// manifest descriptor.
func (f *fakeRegistry) image(repo, plat string, env []string, layers ...[]tfile) descriptor {
	f.t.Helper()
	os, arch, _ := splitPlatform(plat)
	var lds []descriptor
	var diffIDs []string
	for _, l := range layers {
		gz, did := tarGz(f.t, l)
		lds = append(lds, descriptor{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: f.put(repo, gz), Size: int64(len(gz))})
		diffIDs = append(diffIDs, did)
	}
	cfg, _ := json.Marshal(map[string]any{
		"architecture": arch, "os": os,
		"config": map[string]any{"Env": env, "Cmd": []string{"sh"}},
		"rootfs": map[string]any{"type": "layers", "diff_ids": diffIDs},
	})
	cd := descriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: f.put(repo, cfg), Size: int64(len(cfg))}
	m, _ := json.Marshal(manifestDoc{SchemaVersion: 2, MediaType: mtOCIManifest, Config: &cd, Layers: lds})
	return descriptor{MediaType: mtOCIManifest, Digest: f.put(repo, m), Size: int64(len(m)), Platform: &ociPlatform{OS: os, Architecture: arch}}
}

func (f *fakeRegistry) index(repo string, ms ...descriptor) string {
	b, _ := json.Marshal(manifestDoc{SchemaVersion: 2, MediaType: mtOCIIndex, Manifests: ms})
	return f.put(repo, b)
}

type fakeHistory map[string]bool

func (h fakeHistory) indexDigests(_ context.Context, image, tag string) (map[string]bool, bool, error) {
	return h, len(h) > 0, nil
}

func newSHA256() hash.Hash { return sha256.New() }

package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
	modzip "golang.org/x/mod/zip"

	"github.com/sadbox/dep-review/internal/allow"
)

// roomy is a budget no test artifact comes near.
var roomy = Limits{ChunkBytes: 1 << 20, MaxChunks: 4}

// tarEntry is one entry of a tar built by a test.
type tarEntry struct {
	name string
	typ  byte // tar.TypeReg when zero
	body string
	link string
	pax  map[string]string
}

// buildTar writes entries as a tar, end-of-archive marker included.
func buildTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: 0o644, Linkname: e.link, PAXRecords: e.pax}
		switch e.typ {
		case 0:
			h.Typeflag = tar.TypeReg
			h.Size = int64(len(e.body))
		case tar.TypeDir:
			h.Mode = 0o755
		case tar.TypeXGlobalHeader:
			// The Writer takes nothing but records for one of these.
			h = &tar.Header{Typeflag: tar.TypeXGlobalHeader, PAXRecords: e.pax}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatalf("tar header %q: %v", e.name, err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipped(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fileEntries turns path -> content into sorted tar entries under top.
func fileEntries(top string, files map[string]string) []tarEntry {
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var entries []tarEntry
	for _, name := range names {
		entries = append(entries, tarEntry{name: top + "/" + name, body: files[name]})
	}
	return entries
}

// npmTarball is a tarball as npm pack writes it: everything under
// "package/".
func npmTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	return gzipped(t, buildTar(t, fileEntries("package", files)))
}

// actionTarball is a tarball as GitHub serves it: git archive's global
// header with the commit first, then everything under one directory.
func actionTarball(t *testing.T, commit string, files map[string]string) []byte {
	t.Helper()
	entries := []tarEntry{{name: "pax_global_header", typ: tar.TypeXGlobalHeader, pax: map[string]string{"comment": commit}}}
	entries = append(entries, fileEntries("owner-repo-"+commit[:7], files)...)
	return gzipped(t, buildTar(t, entries))
}

// moduleZip is a module zip as the go command's own code writes it.
func moduleZip(t *testing.T, path, version string, files map[string]string) []byte {
	t.Helper()
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var zfiles []modzip.File
	for _, name := range names {
		zfiles = append(zfiles, memFile{name, []byte(files[name])})
	}
	var buf bytes.Buffer
	if err := modzip.Create(&buf, module.Version{Path: path, Version: version}, zfiles); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// memFile is a modzip.File held in memory.
type memFile struct {
	name string
	data []byte
}

func (f memFile) Path() string                 { return f.name }
func (f memFile) Lstat() (os.FileInfo, error)  { return memInfo{f}, nil }
func (f memFile) Open() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(f.data)), nil }

// memInfo is the os.FileInfo of a memFile: a regular file.
type memInfo struct{ f memFile }

func (i memInfo) Name() string       { return path.Base(i.f.name) }
func (i memInfo) Size() int64        { return int64(len(i.f.data)) }
func (i memInfo) Mode() os.FileMode  { return 0o644 }
func (i memInfo) ModTime() time.Time { return time.Time{} }
func (i memInfo) IsDir() bool        { return false }
func (i memInfo) Sys() any           { return nil }

// integrity is the lockfile integrity of a tarball.
func integrity(b []byte) string {
	sum := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

// h1 is the go.sum hash of a module zip.
func h1(t *testing.T, zip []byte) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "m.zip")
	if err := os.WriteFile(name, zip, 0o600); err != nil {
		t.Fatal(err)
	}
	sum, err := dirhash.HashZip(name, dirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}
	return sum
}

// fakeFetcher serves archives from memory, by Ref.
type fakeFetcher map[Ref][]byte

func (f fakeFetcher) fetch(_ context.Context, ref Ref, dir string) (string, error) {
	b, ok := f[ref]
	if !ok {
		return "", fmt.Errorf("fakeFetcher: no archive for %+v", ref)
	}
	out, err := os.CreateTemp(dir, "fake-*")
	if err != nil {
		return "", err
	}
	defer out.Close()
	if _, err := out.Write(b); err != nil {
		return "", err
	}
	return out.Name(), nil
}

// newReader is a reader that fetches from f and works under a test
// directory.
func newReader(t *testing.T, f fetcher) *reader {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	return &reader{scratch: t.TempDir(), git: git, fetch: f, limits: defaultExtractLimits, read: defaultReadLimits}
}

// npmPair is an update of the npm package "demo" from 1.0.0 to 1.0.1 with
// the given files, and a fetcher that serves both tarballs. A nil oldFiles
// makes it a new name.
func npmPair(t *testing.T, oldFiles, newFiles map[string]string) (Pair, fakeFetcher) {
	t.Helper()
	f := fakeFetcher{}
	p := Pair{Ecosystem: allow.NPM, Name: "demo", To: "1.0.1"}
	after := npmTarball(t, newFiles)
	p.New = Ref{Kind: NPMTarball, Name: "demo", Version: "1.0.1", Hash: integrity(after)}
	f[p.New] = after
	if oldFiles != nil {
		before := npmTarball(t, oldFiles)
		p.From = "1.0.0"
		p.Old = Ref{Kind: NPMTarball, Name: "demo", Version: "1.0.0", Hash: integrity(before)}
		f[p.Old] = before
	}
	return p, f
}

// prepareNPM prepares the read of an npm update built from two file sets.
func prepareNPM(t *testing.T, oldFiles, newFiles map[string]string, lim Limits) Prepared {
	t.Helper()
	p, f := npmPair(t, oldFiles, newFiles)
	got, err := newReader(t, f).Prepare(context.Background(), p, lim)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return got
}

// text is every chunk of a prepared read, joined.
func text(p Prepared) string {
	var b strings.Builder
	for _, c := range p.Chunks {
		b.WriteString(c.Text)
	}
	return b.String()
}

// unreadPaths lists the paths of p.Unread.
func unreadPaths(p Prepared) []string {
	paths := []string{}
	for _, u := range p.Unread {
		paths = append(paths, u.Path)
	}
	return paths
}

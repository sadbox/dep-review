package docker

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
)

// Layers are streamed through gzip and archive/tar and reduced to a file
// manifest (path, type, mode, owner, size, hashes) plus the bytes of a few
// small files the analysis needs (package databases, os-release, /etc).
// Nothing is written to disk and nothing is executed.

const (
	maxLayerBytes        = 2 << 30  // compressed
	maxLayerUncompressed = 8 << 30  // per layer
	maxCaptureFile       = 32 << 20 // one captured file
	maxCaptureEtc        = 64 << 10 // /etc files captured for evidence
	maxCaptureTotal      = 256 << 20
	maxEntriesPerLayer   = 500_000
)

// errZstd marks a zstd-compressed layer: the standard library has no zstd
// reader, so these go to a human.
var errZstd = errors.New("zstd-compressed layer")

// errUnsupportedLayer marks foreign/non-distributable or unknown layers.
var errUnsupportedLayer = errors.New("unsupported layer")

type entry struct {
	Type   byte // f d l h c b p
	Mode   int64
	UID    int
	GID    int
	Size   int64
	SHA256 string
	MD5    string
	SHA1   string
	Link   string
	Dev    [2]int64
	Xattr  bool
	Layer  int
}

func (e *entry) typeName() string {
	switch e.Type {
	case 'f':
		return "file"
	case 'd':
		return "dir"
	case 'l':
		return "symlink"
	case 'h':
		return "hardlink"
	case 'c':
		return "char-device"
	case 'b':
		return "block-device"
	case 'p':
		return "fifo"
	}
	return "unknown"
}

type layerResult struct {
	Digest    string
	DiffID    string
	Entries   map[string]*entry
	Whiteouts []string
	Opaque    []string
	Captured  map[string][]byte
	Anomalies []string
}

// captureRe selects files whose contents are kept in memory.
var captureRe = regexp.MustCompile(`^(?:` +
	`var/lib/dpkg/status|var/lib/dpkg/status\.d/[^/]+|var/lib/dpkg/info/[^/]+\.(?:list|md5sums|conffiles)|` +
	`(?:usr/)?lib/apk/db/installed|` +
	`etc/os-release|usr/lib/os-release|usr/local/go/VERSION|\.rock/[^/]+` +
	`)$`)

func shouldCapture(p string, size int64) bool {
	if captureRe.MatchString(p) {
		return size <= maxCaptureFile
	}
	if apkIndexRe.MatchString(p) {
		return size <= maxAPKIndex
	}
	if strings.HasPrefix(p, "usr/share/apk/keys/") {
		return size <= maxCaptureEtc
	}
	return strings.HasPrefix(p, "etc/") && size <= maxCaptureEtc
}

func normPath(name string) (string, bool) {
	name = strings.TrimLeft(name, "/")
	parts := strings.Split(name, "/")
	out := parts[:0]
	for _, p := range parts {
		switch p {
		case "", ".":
		case "..":
			return "", false
		default:
			out = append(out, p)
		}
	}
	return strings.Join(out, "/"), true
}

// readLayer reduces one layer stream (already digest-verifying) to a
// layerResult. It reads r to EOF so the verifier runs.
func readLayer(r io.Reader, mediaType string, idx int, captureBudget *int64) (*layerResult, error) {
	var dec io.Reader
	br := bufio.NewReaderSize(r, 1<<20)
	switch {
	case strings.Contains(mediaType, "zstd"):
		return nil, errZstd
	case strings.HasSuffix(mediaType, "gzip"):
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("layer %d: %w", idx, err)
		}
		defer gz.Close()
		dec = gz
	case strings.HasSuffix(mediaType, ".tar") || strings.HasSuffix(mediaType, "rootfs.diff.tar"):
		// Sniff: some registries label gzip layers as plain tar.
		if b, _ := br.Peek(2); bytes.Equal(b, []byte{0x1f, 0x8b}) {
			gz, err := gzip.NewReader(br)
			if err != nil {
				return nil, fmt.Errorf("layer %d: %w", idx, err)
			}
			defer gz.Close()
			dec = gz
		} else {
			dec = br
		}
	default:
		return nil, fmt.Errorf("layer %d: media type %q: %w", idx, mediaType, errUnsupportedLayer)
	}
	diff := sha256.New()
	lim := &io.LimitedReader{R: dec, N: maxLayerUncompressed + 1}
	tr := tar.NewReader(io.TeeReader(lim, diff))
	lr := &layerResult{Entries: map[string]*entry{}, Captured: map[string][]byte{}}
	buf := make([]byte, 1<<20)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("layer %d: tar: %w", idx, err)
		}
		if len(lr.Entries) > maxEntriesPerLayer {
			return nil, fmt.Errorf("layer %d: more than %d entries: %w", idx, maxEntriesPerLayer, errTooLarge)
		}
		p, ok := normPath(h.Name)
		if !ok {
			lr.Anomalies = append(lr.Anomalies, fmt.Sprintf("path with ..: %q", h.Name))
			continue
		}
		if p == "" {
			continue
		}
		dir, base := path.Split(p)
		dir = strings.TrimSuffix(dir, "/")
		if base == ".wh..wh..opq" {
			lr.Opaque = append(lr.Opaque, dir)
			continue
		}
		if w, ok := strings.CutPrefix(base, ".wh."); ok {
			lr.Whiteouts = append(lr.Whiteouts, path.Join(dir, w))
			continue
		}
		e := &entry{Mode: h.Mode & 0o7777, UID: h.Uid, GID: h.Gid, Layer: idx}
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			e.Type = 'f'
		case tar.TypeDir:
			e.Type = 'd'
		case tar.TypeSymlink:
			e.Type, e.Link = 'l', h.Linkname
		case tar.TypeLink:
			e.Type = 'h'
			e.Link, _ = normPath(h.Linkname)
		case tar.TypeChar:
			e.Type, e.Dev = 'c', [2]int64{h.Devmajor, h.Devminor}
		case tar.TypeBlock:
			e.Type, e.Dev = 'b', [2]int64{h.Devmajor, h.Devminor}
		case tar.TypeFifo:
			e.Type = 'p'
		default:
			lr.Anomalies = append(lr.Anomalies, fmt.Sprintf("unsupported tar type %q for %s", h.Typeflag, p))
			continue
		}
		for k := range h.PAXRecords {
			if strings.HasPrefix(k, "SCHILY.xattr.") || strings.HasPrefix(k, "LIBARCHIVE.xattr.") {
				e.Xattr = true
			}
		}
		if e.Type == 'f' {
			e.Size = h.Size
			s256, m5, s1 := sha256.New(), md5.New(), sha1.New()
			w := io.MultiWriter(s256, m5, s1)
			var keep *bytes.Buffer
			if shouldCapture(p, h.Size) && *captureBudget >= h.Size {
				keep = bytes.NewBuffer(make([]byte, 0, h.Size))
				w = io.MultiWriter(w, keep)
				*captureBudget -= h.Size
			}
			if _, err := io.CopyBuffer(w, tr, buf); err != nil {
				return nil, fmt.Errorf("layer %d: %s: %w", idx, p, err)
			}
			e.SHA256 = hex.EncodeToString(s256.Sum(nil))
			e.MD5 = hex.EncodeToString(m5.Sum(nil))
			e.SHA1 = hex.EncodeToString(s1.Sum(nil))
			if keep != nil {
				lr.Captured[p] = keep.Bytes()
			}
		}
		lr.Entries[p] = e
	}
	// Drain: tar padding, gzip trailer, then the compressed stream itself
	// so the digest check at EOF runs.
	if _, err := io.Copy(io.Discard, io.TeeReader(lim, diff)); err != nil {
		return nil, fmt.Errorf("layer %d: %w", idx, err)
	}
	if lim.N <= 0 {
		return nil, fmt.Errorf("layer %d: uncompressed size over %d: %w", idx, int64(maxLayerUncompressed), errTooLarge)
	}
	if _, err := io.Copy(io.Discard, br); err != nil {
		return nil, fmt.Errorf("layer %d: %w", idx, err)
	}
	lr.DiffID = "sha256:" + hex.EncodeToString(diff.Sum(nil))
	// Hard links inside the layer take their target's content.
	for _, e := range lr.Entries {
		if e.Type == 'h' {
			if t := lr.Entries[e.Link]; t != nil && t.Type == 'f' {
				e.Size, e.SHA256, e.MD5, e.SHA1 = t.Size, t.SHA256, t.MD5, t.SHA1
			}
		}
	}
	for p, e := range lr.Entries {
		if e.Type == 'h' {
			if b, ok := lr.Captured[e.Link]; ok {
				lr.Captured[p] = b
			}
		}
	}
	return lr, nil
}

// rootfs is the effective filesystem after applying layers in order.
type rootfs struct {
	Files    map[string]*entry
	Captured map[string][]byte
}

// compose applies layers with OCI whiteout semantics.
func compose(layers []*layerResult) *rootfs {
	fs := &rootfs{Files: map[string]*entry{}, Captured: map[string][]byte{}}
	for _, l := range layers {
		del := func(pred func(string) bool) {
			for k := range fs.Files {
				if pred(k) {
					delete(fs.Files, k)
					delete(fs.Captured, k)
				}
			}
		}
		if len(l.Opaque) > 0 || len(l.Whiteouts) > 0 {
			opq := map[string]bool{}
			for _, d := range l.Opaque {
				opq[d] = true
			}
			wh := map[string]bool{}
			for _, w := range l.Whiteouts {
				wh[w] = true
			}
			del(func(k string) bool {
				if wh[k] {
					return true
				}
				for d := path.Dir(k); ; d = path.Dir(d) {
					if d == "." {
						d = ""
					}
					if wh[d] || (opq[d] && l.Entries[k] == nil) {
						return true
					}
					if d == "" {
						return false
					}
				}
			})
		}
		for p, e := range l.Entries {
			if old := fs.Files[p]; old != nil && old.Type == 'd' && e.Type != 'd' {
				pre := p + "/"
				del(func(k string) bool { return strings.HasPrefix(k, pre) })
			}
			delete(fs.Captured, p)
			if e.Type == 'h' && e.SHA256 == "" {
				if t := fs.Files[e.Link]; t != nil && t.Type == 'f' {
					c := *e
					c.Size, c.SHA256, c.MD5, c.SHA1 = t.Size, t.SHA256, t.MD5, t.SHA1
					e = &c
					if b, ok := fs.Captured[e.Link]; ok {
						fs.Captured[p] = b
					}
				}
			}
			fs.Files[p] = e
			if b, ok := l.Captured[p]; ok {
				fs.Captured[p] = b
			}
		}
	}
	return fs
}

// canon resolves symlinked directory components (usrmerge: /bin -> usr/bin)
// so package file lists and the rootfs agree on paths.
func (fs *rootfs) canon(p string) string {
	p = strings.TrimPrefix(path.Clean("/"+p), "/")
	for depth := 0; depth < 16; depth++ {
		parts := strings.Split(p, "/")
		changed := false
		for i := 0; i < len(parts)-1; i++ {
			pre := strings.Join(parts[:i+1], "/")
			e := fs.Files[pre]
			if e == nil || e.Type != 'l' {
				continue
			}
			t := e.Link
			var base string
			if strings.HasPrefix(t, "/") {
				base = t
			} else {
				base = path.Join(path.Dir("/"+pre), t)
			}
			p = strings.TrimPrefix(path.Clean(path.Join(base, strings.Join(parts[i+1:], "/"))), "/")
			changed = true
			break
		}
		if !changed {
			return p
		}
	}
	return p
}

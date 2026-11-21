package ecoutil

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
)

// Extraction limits, against archive bombs.
const (
	MaxExtractBytes = 1 << 30
	MaxExtractFiles = 100_000
	MaxEntryBytes   = 256 << 20
)

// Tree is an extracted archive.
type Tree struct {
	Dir      string   // absolute directory holding the files
	Files    []string // relative slash paths of regular files, sorted
	Rejected []string // entries not extracted, with the reason
}

// ExtractTarGz extracts a gzip-compressed tar into dir (created; must not
// exist). See ExtractTar.
func ExtractTarGz(archive, dir string, stripFirst bool) (*Tree, error) {
	f, err := os.Open(archive)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(bufio.NewReader(f))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", archive, err)
	}
	defer zr.Close()
	return ExtractTar(zr, dir, stripFirst)
}

// ExtractTar extracts only regular files and directories. Symlinks, hard
// links, devices, FIFOs, absolute paths, ".." elements and duplicate names
// are not extracted and are listed in Tree.Rejected; the caller decides what
// that means. With stripFirst the first path element ("package/" in npm
// tarballs, "name-1.0/" in sdists) is removed.
func ExtractTar(r io.Reader, dir string, stripFirst bool) (*Tree, error) {
	x, err := newExtractor(dir)
	if err != nil {
		return nil, err
	}
	defer x.root.Close()
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar: %w", err)
		}
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeRegA:
			if err := x.file(h.Name, stripFirst, h.Size, tr); err != nil {
				return nil, err
			}
		case tar.TypeDir:
			x.mkdir(h.Name, stripFirst)
		default:
			x.reject(h.Name, fmt.Sprintf("tar entry type %q (link, device or other special file)", h.Typeflag))
		}
	}
	if why := trailingData(r); why != "" {
		x.reject("(end of archive)", why)
	}
	return x.tree(), nil
}

// maxTrailing bounds how much is read past the end-of-archive marker.
const maxTrailing = 16 << 20

// trailingData reports anything but zero padding after the tar
// end-of-archive marker. archive/tar stops at the marker, but other
// extractors (GNU tar --ignore-zeros, Python's tarfile with ignore_zeros)
// keep reading, so a second archive appended there would install files
// the gate never saw.
func trailingData(r io.Reader) string {
	buf := make([]byte, 32<<10)
	var n int64
	for {
		k, err := r.Read(buf)
		for _, b := range buf[:k] {
			if b != 0 {
				return "data after the end-of-archive marker (a second archive or appended bytes)"
			}
		}
		n += int64(k)
		switch {
		case errors.Is(err, io.EOF):
			return ""
		case err != nil:
			return "unreadable data after the end-of-archive marker: " + err.Error()
		case n > maxTrailing:
			return fmt.Sprintf("more than %d bytes after the end-of-archive marker", maxTrailing)
		}
	}
}

// ExtractZip extracts a zip (wheel, sdist .zip) with the same rules as
// ExtractTar.
func ExtractZip(archive, dir string, stripFirst bool) (*Tree, error) {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", archive, err)
	}
	defer zr.Close()
	x, err := newExtractor(dir)
	if err != nil {
		return nil, err
	}
	defer x.root.Close()
	for _, f := range zr.File {
		mode := f.Mode()
		switch {
		case mode.IsDir():
			x.mkdir(f.Name, stripFirst)
		case mode.IsRegular():
			if f.UncompressedSize64 > MaxEntryBytes {
				x.reject(f.Name, "entry too large")
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("%s: %s: %w", archive, f.Name, err)
			}
			err = x.file(f.Name, stripFirst, int64(f.UncompressedSize64), rc)
			rc.Close()
			if err != nil {
				return nil, err
			}
		default:
			x.reject(f.Name, fmt.Sprintf("zip entry mode %v (symlink or special file)", mode))
		}
	}
	return x.tree(), nil
}

type extractor struct {
	dir      string
	root     *os.Root
	files    []string
	seen     map[string]bool // lower-cased, so case-insensitive filesystems cannot merge two entries
	rejected []string
	total    int64
}

func newExtractor(dir string) (*extractor, error) {
	if err := os.Mkdir(dir, 0o755); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &extractor{dir: dir, root: root, seen: map[string]bool{}}, nil
}

func (x *extractor) reject(name, why string) {
	x.rejected = append(x.rejected, fmt.Sprintf("%q: %s", name, why))
}

// SafeRel validates an archive entry name and returns its cleaned relative
// path, or "" and the reason it is unsafe.
func SafeRel(name string, stripFirst bool) (string, string) {
	switch {
	case name == "":
		return "", "empty name"
	case strings.ContainsAny(name, "\x00\\"):
		return "", "NUL or backslash in name"
	case strings.HasPrefix(name, "/"):
		return "", "absolute path"
	case len(name) >= 2 && name[1] == ':':
		return "", "drive-letter path"
	}
	for _, el := range strings.Split(strings.TrimSuffix(name, "/"), "/") {
		if el == ".." {
			return "", `".." element`
		}
	}
	rel := path.Clean(name)
	if stripFirst {
		_, rest, ok := strings.Cut(rel, "/")
		if !ok {
			return "", "" // the top-level directory itself
		}
		rel = rest
	}
	if rel == "." || rel == "" {
		return "", ""
	}
	return rel, ""
}

func (x *extractor) mkdir(name string, stripFirst bool) {
	rel, why := SafeRel(name, stripFirst)
	if why != "" {
		x.reject(name, why)
		return
	}
	if rel == "" {
		return
	}
	if err := x.root.MkdirAll(rel, 0o755); err != nil {
		x.reject(name, err.Error())
	}
}

func (x *extractor) file(name string, stripFirst bool, size int64, r io.Reader) error {
	rel, why := SafeRel(name, stripFirst)
	if why != "" || rel == "" {
		if why == "" {
			why = "file at the top-level position"
		}
		x.reject(name, why)
		return nil
	}
	key := strings.ToLower(rel)
	if x.seen[key] {
		x.reject(name, "duplicate entry (or differs only in case)")
		return nil
	}
	if len(x.files) >= MaxExtractFiles {
		return fmt.Errorf("archive has more than %d files", MaxExtractFiles)
	}
	if size > MaxEntryBytes || x.total+size > MaxExtractBytes {
		return fmt.Errorf("archive expands beyond %d bytes", MaxExtractBytes)
	}
	if d := path.Dir(rel); d != "." {
		if err := x.root.MkdirAll(d, 0o755); err != nil {
			x.reject(name, err.Error())
			return nil
		}
	}
	f, err := x.root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		x.reject(name, err.Error())
		return nil
	}
	n, err := io.Copy(f, io.LimitReader(r, size+1))
	cerr := f.Close()
	if err != nil {
		return fmt.Errorf("extracting %s: %w", name, err)
	}
	if cerr != nil {
		return cerr
	}
	if n > size {
		return fmt.Errorf("extracting %s: entry longer than its header says", name)
	}
	x.total += n
	x.seen[key] = true
	x.files = append(x.files, rel)
	return nil
}

func (x *extractor) tree() *Tree {
	sort.Strings(x.files)
	return &Tree{Dir: x.dir, Files: x.files, Rejected: x.rejected}
}

// ReadFile reads rel from t, or returns nil if t lacks it.
func (t *Tree) ReadFile(rel string) []byte {
	if t == nil {
		return nil
	}
	root, err := os.OpenRoot(t.Dir)
	if err != nil {
		return nil
	}
	defer root.Close()
	b, err := root.ReadFile(rel)
	if err != nil {
		return nil
	}
	return b
}

// Has reports whether t contains rel.
func (t *Tree) Has(rel string) bool {
	if t == nil {
		return false
	}
	i := sort.SearchStrings(t.Files, rel)
	return i < len(t.Files) && t.Files[i] == rel
}

// DirTree lists the regular files under dir (e.g. a Go module cache
// directory) as a Tree. Symlinks and special files are listed in Rejected.
func DirTree(dir string) (*Tree, error) {
	t := &Tree{Dir: dir}
	err := fs.WalkDir(os.DirFS(dir), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
		case d.Type().IsRegular():
			t.Files = append(t.Files, p)
		default:
			t.Rejected = append(t.Rejected, fmt.Sprintf("%q: %v", p, d.Type()))
		}
		return nil
	})
	sort.Strings(t.Files)
	return t, err
}

package artifact

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"

	"golang.org/x/mod/module"
	modzip "golang.org/x/mod/zip"
)

func unsafeArchive(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnsafeArchive, fmt.Sprintf(format, args...))
}

// extractLimits bound one extracted artifact, against archive bombs.
type extractLimits struct {
	// entries is the most archive entries of any kind.
	entries int
	// bytes is the most the regular files may add up to.
	bytes int64
}

// defaultExtractLimits is far above any artifact the gate reads: the go
// command's own limit for a module is 500 MiB, and of fourteen widely
// used actions the largest tarball extracts to 16 MB in 133 entries.
var defaultExtractLimits = extractLimits{entries: 100_000, bytes: 1 << 30}

// maxTrailing bounds how much is read after a tar's end marker while
// checking that it is only padding.
const maxTrailing = 16 << 20

// file is one regular file of an extracted artifact.
type file struct {
	size int64
	sum  [sha256.Size]byte
}

// tree is one extracted artifact: a directory that holds regular files
// and directories only, and what the files are. The zero tree is "no
// artifact" (the old side of a new name) and has no files.
type tree struct {
	// root is the directory. Every later read goes through it, so even
	// a bug in this package cannot read outside the artifact.
	root *os.Root
	// files is every regular file, by its slash-separated path.
	files map[string]file
}

func (t *tree) close() {
	if t != nil && t.root != nil {
		t.root.Close()
	}
}

// fs is the tree for an Inspect function: nil for "no artifact", which
// has no directory to open.
func (t *tree) fs() fs.FS {
	if t.root == nil {
		return nil
	}
	return t.root.FS()
}

// extractTarGz extracts a gzip-compressed tar into dir, which must not
// exist. The first path element of every entry is dropped, as npm and the
// Actions runner do ("package/", "owner-repo-1234567/").
//
// It is strict where they are lenient. Anything but a regular file or a
// directory, any name it would have to reinterpret, a repeated name, and
// anything after the end-of-archive marker is an error for the whole
// archive, not an entry to skip: an archive that two extractors can read
// differently is one where the model and the consumer would see different
// files.
func extractTarGz(archive, dir string, lim extractLimits) (*tree, error) {
	f, err := os.Open(archive)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(bufio.NewReader(f))
	if err != nil {
		return nil, unsafeArchive("not a gzip stream: %v", err)
	}
	defer zr.Close()

	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	x := &extraction{root: root, lim: lim, files: map[string]file{}, seen: map[string]bool{}}
	if err := x.all(zr); err != nil {
		root.Close()
		return nil, err
	}
	return &tree{root: root, files: x.files}, nil
}

// all extracts every entry of the tar in r and checks what follows it.
func (x *extraction) all(r io.Reader) error {
	tr := tar.NewReader(r)
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return unsafeArchive("reading the archive: %v", err)
		}
		if n >= x.lim.entries {
			return unsafeArchive("more than %d entries", x.lim.entries)
		}
		if err := x.entry(n, h, tr); err != nil {
			return err
		}
	}
	return onlyPadding(r)
}

// extraction is the state of one tar being extracted.
type extraction struct {
	root  *os.Root
	lim   extractLimits
	files map[string]file
	// seen holds the lower-cased path of every file written. Two names
	// that differ only in case are one file on a case-insensitive file
	// system and two on another; refusing them keeps the result the same
	// everywhere.
	seen  map[string]bool
	total int64
}

// entry handles the n-th tar entry.
func (x *extraction) entry(n int, h *tar.Header, content io.Reader) error {
	if h.Typeflag == tar.TypeXGlobalHeader {
		// git archive writes exactly one, first, holding the commit ID
		// as "comment" (see tarballCommit). archive/tar does not apply
		// a global header to the entries after it and other extractors
		// do, so any other record in it would be read two ways.
		if n != 0 {
			return unsafeArchive("%q: a global header that is not the first entry", h.Name)
		}
		for key := range h.PAXRecords {
			if key != "comment" {
				return unsafeArchive("%q: global header sets %q", h.Name, key)
			}
		}
		return nil
	}
	for key := range h.PAXRecords {
		if strings.HasPrefix(key, "GNU.sparse.") {
			return unsafeArchive("%q: a sparse file", h.Name)
		}
	}
	rel, err := entryPath(h.Name)
	if err != nil {
		return unsafeArchive("%q: %v", h.Name, err)
	}
	switch h.Typeflag {
	case tar.TypeDir:
		if rel == "" {
			return nil // the top-level directory itself
		}
		if err := x.root.MkdirAll(rel, 0o700); err != nil {
			return unsafeArchive("%q: %v", h.Name, err)
		}
		return nil
	case tar.TypeReg:
		return x.file(h.Name, rel, h.Size, content)
	case tar.TypeSymlink:
		return unsafeArchive("%q: a symbolic link", h.Name)
	case tar.TypeLink:
		return unsafeArchive("%q: a hard link", h.Name)
	}
	return unsafeArchive("%q: entry type %q (a device, a pipe or another special file)", h.Name, h.Typeflag)
}

// entryPath checks an entry's name and returns its path below the
// top-level directory, or "" for the top-level directory itself.
func entryPath(name string) (string, error) {
	switch {
	case name == "":
		return "", errors.New("empty name")
	case strings.ContainsRune(name, 0):
		return "", errors.New("NUL in the name")
	case strings.Contains(name, `\`):
		// A path separator to some extractors and a letter to others.
		return "", errors.New("backslash in the name")
	case strings.HasPrefix(name, "/"):
		return "", errors.New("absolute path")
	case len(name) >= 2 && name[1] == ':':
		return "", errors.New("drive-letter path")
	}
	for _, element := range strings.Split(name, "/") {
		if element == ".." {
			return "", errors.New(`".." in the path`)
		}
	}
	_, rest, _ := strings.Cut(path.Clean(name), "/")
	return rest, nil
}

// file writes one regular file.
func (x *extraction) file(name, rel string, size int64, content io.Reader) error {
	if rel == "" {
		return unsafeArchive("%q: a file where the top-level directory should be", name)
	}
	key := strings.ToLower(rel)
	if x.seen[key] {
		return unsafeArchive("%q: the name occurs twice (or two names differ only in case)", name)
	}
	if size < 0 || size > x.lim.bytes-x.total {
		return unsafeArchive("more than %d bytes", x.lim.bytes)
	}
	if dir := path.Dir(rel); dir != "." {
		if err := x.root.MkdirAll(dir, 0o700); err != nil {
			return unsafeArchive("%q: %v", name, err)
		}
	}
	// O_EXCL: never write through anything that is already there.
	f, err := x.root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return unsafeArchive("%q: %v", name, err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(content, size+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return unsafeArchive("%q: %v", name, err)
	}
	if n != size {
		return unsafeArchive("%q: %d bytes where the header says %d", name, n, size)
	}
	x.total += n
	x.seen[key] = true
	x.files[rel] = file{size: n, sum: [sha256.Size]byte(h.Sum(nil))}
	return nil
}

// onlyPadding reads what follows a tar's end-of-archive marker and
// refuses anything but zero bytes. archive/tar stops at the marker; GNU
// tar with --ignore-zeros and other extractors go on, so a second archive
// appended there would give them files the gate never saw.
func onlyPadding(r io.Reader) error {
	buf := make([]byte, 32<<10)
	var total int64
	for {
		n, err := r.Read(buf)
		for _, b := range buf[:n] {
			if b != 0 {
				return unsafeArchive("data after the end-of-archive marker")
			}
		}
		total += int64(n)
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case err != nil:
			return unsafeArchive("after the end-of-archive marker: %v", err)
		case total > maxTrailing:
			return unsafeArchive("more than %d bytes after the end-of-archive marker", maxTrailing)
		}
	}
}

// unzipModule extracts a Go module zip into dir, which must not exist.
//
// The go command's own code does it (golang.org/x/mod/zip), so the tree
// is the one a build would see and the rules are the go command's: every
// name under "module@version/", valid and clean; no two names equal
// under case folding; nothing but regular files written, whatever mode an
// entry claims.
func unzipModule(archive, dir string, m module.Version, lim extractLimits) (*tree, error) {
	// Counted first, so a zip over the limits is not written out at all.
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return nil, unsafeArchive("not a zip file: %v", err)
	}
	entries := len(zr.File)
	var total uint64
	for _, f := range zr.File {
		total += f.UncompressedSize64
		if total > uint64(lim.bytes) {
			break
		}
	}
	zr.Close()
	if entries > lim.entries {
		return nil, unsafeArchive("more than %d entries", lim.entries)
	}
	if total > uint64(lim.bytes) {
		return nil, unsafeArchive("more than %d bytes", lim.bytes)
	}

	if err := modzip.Unzip(dir, m, archive); err != nil {
		return nil, unsafeArchive("%v", err)
	}
	return readTree(dir, lim)
}

// readTree lists and hashes a directory something else extracted. Only
// regular files and directories may be in it.
func readTree(dir string, lim extractLimits) (*tree, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	t := &tree{root: root, files: map[string]file{}}
	var total int64
	err = fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return nil
		case !d.Type().IsRegular():
			return unsafeArchive("%q: not a regular file", p)
		case len(t.files) >= lim.entries:
			return unsafeArchive("more than %d files", lim.entries)
		}
		f, err := root.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(f, lim.bytes-total+1))
		if err != nil {
			return err
		}
		total += n
		if total > lim.bytes {
			return unsafeArchive("more than %d bytes", lim.bytes)
		}
		t.files[p] = file{size: n, sum: [sha256.Size]byte(h.Sum(nil))}
		return nil
	})
	if err != nil {
		root.Close()
		return nil, err
	}
	return t, nil
}

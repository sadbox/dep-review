package artifact

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/mod/module"
)

// rawEntry is a tar entry written byte by byte, for the shapes
// archive/tar's Writer refuses to produce.
func rawEntry(name string, typ byte, body string) []byte {
	block := make([]byte, 512)
	copy(block[0:100], name)
	copy(block[100:108], "0000644\x00")
	copy(block[108:116], "0000000\x00")
	copy(block[116:124], "0000000\x00")
	copy(block[124:136], fmt.Sprintf("%011o\x00", len(body)))
	copy(block[136:148], "00000000000\x00")
	block[156] = typ
	copy(block[257:263], "ustar\x00")
	copy(block[263:265], "00")
	if typ == tar.TypeGNUSparse {
		// Only the GNU format has this type; its magic is "ustar  ".
		copy(block[257:265], "ustar  \x00")
	}
	setChecksum(block)
	out := append(block, body...)
	if pad := len(body) % 512; pad != 0 {
		out = append(out, make([]byte, 512-pad)...)
	}
	return out
}

// setChecksum fills in a tar header block's checksum, which counts its
// own field as spaces.
func setChecksum(block []byte) {
	copy(block[148:156], "        ")
	sum := 0
	for _, b := range block[:512] {
		sum += int(b)
	}
	copy(block[148:156], fmt.Sprintf("%06o\x00 ", sum))
}

// endMarker is a tar's end: two blocks of zeros.
var endMarker = make([]byte, 1024)

// paxRecord is one record of a PAX extended header.
func paxRecord(key, value string) string {
	// "<length> key=value\n", where the length counts its own digits.
	rest := " " + key + "=" + value + "\n"
	n := len(rest) + 1
	for n != len(fmt.Sprint(n))+len(rest) {
		n = len(fmt.Sprint(n)) + len(rest)
	}
	return fmt.Sprint(n) + rest
}

func TestExtractTarGzRefusesUnsafeArchives(t *testing.T) {
	ok := tarEntry{name: "package/index.js", body: "ok\n"}
	outside := filepath.Join(t.TempDir(), "outside")
	global := func(records map[string]string) tarEntry {
		return tarEntry{name: "pax_global_header", typ: tar.TypeXGlobalHeader, pax: records}
	}
	tests := []struct {
		name    string
		archive func(t *testing.T) []byte
		want    string // part of the error
	}{
		{"absolute path", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: outside, body: "x"}}))
		}, "absolute path"},
		{"dot-dot first", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "../outside", body: "x"}}))
		}, `".." in the path`},
		{"dot-dot inside", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "package/a/../../../outside", body: "x"}}))
		}, "not a clean path"},
		{"dot-dot that stays inside is refused too", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "package/a/../b.js", body: "x"}}))
		}, "not a clean path"},
		{"dot-dot directory", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "package/../..", typ: tar.TypeDir}}))
		}, "not a clean path"},
		{"symbolic link", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "package/link", typ: tar.TypeSymlink, link: outside}}))
		}, "a symbolic link"},
		{"symbolic link, then a file through it", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{
				{name: "package/dir", typ: tar.TypeSymlink, link: filepath.Dir(outside)},
				{name: "package/dir/outside", body: "x"},
			}))
		}, "a symbolic link"},
		{"relative symbolic link inside the archive", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "package/main.js", typ: tar.TypeSymlink, link: "index.js"}}))
		}, "a symbolic link"},
		{"hard link", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "package/copy.js", typ: tar.TypeLink, link: "package/index.js"}}))
		}, "a hard link"},
		{"character device", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "package/null", typ: tar.TypeChar}}))
		}, "special file"},
		{"block device", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "package/disk", typ: tar.TypeBlock}}))
		}, "special file"},
		{"named pipe", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "package/pipe", typ: tar.TypeFifo}}))
		}, "special file"},
		{"GNU sparse file", func(t *testing.T) []byte {
			return gzipped(t, append(buildTarOpen(t, []tarEntry{ok}), append(rawEntry("package/sparse", tar.TypeGNUSparse, ""), endMarker...)...))
		}, "entry type 'S'"},
		{"PAX sparse file", func(t *testing.T) []byte {
			records := paxRecord("GNU.sparse.major", "1") + paxRecord("GNU.sparse.minor", "0") +
				paxRecord("GNU.sparse.name", "package/sparse") + paxRecord("GNU.sparse.realsize", "4")
			raw := buildTarOpen(t, []tarEntry{ok})
			raw = append(raw, rawEntry("PaxHeaders/sparse", tar.TypeXHeader, records)...)
			raw = append(raw, rawEntry("package/GNUSparseFile.0/sparse", tar.TypeReg, "1\n0\n4\n"+strings.Repeat("\x00", 506)+"abcd")...)
			return gzipped(t, append(raw, endMarker...))
		}, ""},
		{"same name twice", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "package/index.js", body: "second\n"}}))
		}, "occurs twice"},
		{"names that differ only in case", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "package/INDEX.js", body: "second\n"}}))
		}, "occurs twice"},
		// Directories too (amendment 72): what is beside what must not
		// depend on whether the file system ignores case.
		{"directories that differ only in case", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "package/Sub/binding.gyp", body: "{}\n"}, {name: "package/sub/package.json", body: "{}\n"}}))
		}, "differ only in case"},
		{"directories that differ only in case, two levels down", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "package/node_modules/Inner/binding.gyp", body: "{}\n"}, {name: "package/node_modules/inner/package.json", body: "{}\n"}}))
		}, "differ only in case"},
		{"directories that differ only in a dot at the end", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "package/sub./binding.gyp", body: "{}\n"}, {name: "package/sub/package.json", body: "{}\n"}}))
		}, "differ only in case"},
		{"files that differ only in a dot at the end", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "package/index.js.", body: "second\n"}}))
		}, "occurs twice"},
		{"a directory that differs from a file only in case", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "package/Readme", body: "x\n"}, {name: "package/readme/x.js", body: "y\n"}}))
		}, "a file and a directory"},
		{"a file that differs from a directory only in case", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "package/lib/x.js", body: "y\n"}, {name: "package/LIB", body: "x\n"}}))
		}, "a file and a directory"},
		{"a directory spelled with a dotless i beside its plain spelling", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "package/l\u0131b/a.js", body: "x\n"}, {name: "package/lib/b.js", body: "y\n"}}))
		}, "differ only in case"},
		// A name that is not in clean form is never rewritten: npm drops
		// the first element of the name as it stands, so "./package/x" is
		// "package/x" to npm and would be "x" here.
		{"a second name for a file, once cleaned", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "package/./index.js", body: "second\n"}}))
		}, "not a clean path"},
		{"a leading ./ that would hide a second package.json", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{
				{name: "package/package.json", body: "{}\n"},
				{name: "./package/package.json", body: "{\"scripts\":{\"install\":\"evil\"}}\n"},
			}))
		}, "not a clean path"},
		{"a leading ./ on every name", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{{name: "./package/index.js", body: "ok\n"}}))
		}, "not a clean path"},
		{"a doubled slash", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{{name: "package//index.js", body: "ok\n"}}))
		}, "not a clean path"},
		{"a doubled slash at the start", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{{name: "//package/index.js", body: "ok\n"}}))
		}, "absolute path"},
		{"a directory named .", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{{name: "./", typ: tar.TypeDir}, ok}))
		}, "not a clean path"},
		{"a directory with two trailing slashes", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "package/lib//", typ: tar.TypeDir}}))
		}, "not a clean path"},
		{"a file whose name ends in a slash", func(t *testing.T) []byte {
			return gzipped(t, append(buildTarOpen(t, []tarEntry{ok}), append(rawEntry("package/lib.js/", tar.TypeReg, "x\n"), endMarker...)...))
		}, "not a clean path"},
		{"same name under two top-level directories", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "other/index.js", body: "second\n"}}))
		}, "occurs twice"},
		{"a file where a directory is", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{{name: "package/a/b.js", body: "x"}, {name: "package/a", body: "x"}}))
		}, ""},
		{"a directory where a file is", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{{name: "package/a", body: "x"}, {name: "package/a/b.js", body: "x"}}))
		}, ""},
		{"a file outside the top-level directory", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "loose.js", body: "x"}}))
		}, "top-level directory"},
		{"backslash", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: `package\..\..\outside`, body: "x"}}))
		}, "backslash"},
		{"drive letter", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, {name: "C:/outside", body: "x"}}))
		}, "drive-letter"},
		{"a second archive after the end marker", func(t *testing.T) []byte {
			return gzipped(t, append(buildTar(t, []tarEntry{ok}), buildTar(t, []tarEntry{{name: "package/hidden.js", body: "evil()\n"}})...))
		}, "after the end-of-archive marker"},
		{"bytes after the end marker", func(t *testing.T) []byte {
			return gzipped(t, append(buildTar(t, []tarEntry{ok}), "not zeros"...))
		}, "after the end-of-archive marker"},
		{"a second gzip member holding another archive", func(t *testing.T) []byte {
			return append(gzipped(t, buildTar(t, []tarEntry{ok})), gzipped(t, buildTar(t, []tarEntry{{name: "package/hidden.js", body: "evil()\n"}}))...)
		}, "after the end-of-archive marker"},
		{"bytes after the gzip stream", func(t *testing.T) []byte {
			return append(gzipped(t, buildTar(t, []tarEntry{ok})), "not gzip"...)
		}, "after the end-of-archive marker"},
		{"a global header that is not first", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{ok, global(map[string]string{"comment": "x"})}))
		}, "not the first entry"},
		{"two global headers", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{global(map[string]string{"comment": "x"}), global(map[string]string{"comment": "y"}), ok}))
		}, "not the first entry"},
		{"a global header that renames", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{global(map[string]string{"path": "package/evil.js"}), ok}))
		}, "global header sets"},
		{"a global header that sets a size", func(t *testing.T) []byte {
			return gzipped(t, buildTar(t, []tarEntry{global(map[string]string{"comment": "x", "size": "1"}), ok}))
		}, "global header sets"},
		{"cut short", func(t *testing.T) []byte {
			raw := buildTar(t, []tarEntry{{name: "package/index.js", body: strings.Repeat("x", 4096)}})
			return gzipped(t, raw[:1024])
		}, ""},
		{"not gzip", func(t *testing.T) []byte {
			return buildTar(t, []tarEntry{ok})
		}, "not a gzip stream"},
		{"not a tar", func(t *testing.T) []byte {
			return gzipped(t, bytes.Repeat([]byte("garbage "), 200))
		}, "reading the archive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := t.TempDir()
			archive := filepath.Join(parent, "archive.tgz")
			if err := os.WriteFile(archive, tt.archive(t), 0o600); err != nil {
				t.Fatal(err)
			}
			tree, err := extractTarGz(archive, filepath.Join(parent, "out"), defaultExtractLimits)
			if err == nil {
				tree.close()
				t.Fatalf("extracted, files %v; want an error", fileNames(tree))
			}
			if !errors.Is(err, ErrUnsafeArchive) {
				t.Errorf("error %v is not ErrUnsafeArchive", err)
			}
			t.Logf("refused: %v", err)
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not say %q", err, tt.want)
			}
			if _, err := os.Lstat(outside); err == nil {
				t.Errorf("%s was written, outside the extraction directory", outside)
			}
			// Whatever was written before the bad entry is regular
			// files and directories inside out/, nothing else anywhere.
			ents, err := os.ReadDir(parent)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range ents {
				if e.Name() != "archive.tgz" && e.Name() != "out" {
					t.Errorf("%s was written beside the extraction directory", e.Name())
				}
			}
			filepath.WalkDir(filepath.Join(parent, "out"), func(p string, d fs.DirEntry, err error) error {
				if err == nil && !d.IsDir() && !d.Type().IsRegular() {
					t.Errorf("%s is a %v", p, d.Type())
				}
				return nil
			})
		})
	}
}

// buildTarOpen is buildTar without the end-of-archive marker, to append
// raw entries to.
func buildTarOpen(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	raw := buildTar(t, entries)
	return raw[:len(raw)-len(endMarker)]
}

func fileNames(t *tree) []string {
	var names []string
	for name := range t.files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func TestExtractTarGzLimits(t *testing.T) {
	many := []tarEntry{}
	for i := range 6 {
		many = append(many, tarEntry{name: fmt.Sprintf("package/%d.js", i), body: "x"})
	}
	tests := []struct {
		name    string
		archive []byte
		lim     extractLimits
		want    string
	}{
		{"too many entries", gzipped(t, buildTar(t, many)), extractLimits{entries: 5, bytes: 1 << 20}, "more than 5 entries"},
		{"directories count as entries", gzipped(t, buildTar(t, []tarEntry{
			{name: "package/", typ: tar.TypeDir}, {name: "package/a/", typ: tar.TypeDir}, {name: "package/b/", typ: tar.TypeDir},
		})), extractLimits{entries: 2, bytes: 1 << 20}, "more than 2 entries"},
		{"too many bytes in all", gzipped(t, buildTar(t, []tarEntry{
			{name: "package/a.js", body: strings.Repeat("a", 600)}, {name: "package/b.js", body: strings.Repeat("b", 600)},
		})), extractLimits{entries: 100, bytes: 1000}, "more than 1000 bytes"},
		{"one entry that claims too many bytes", gzipped(t, append(rawEntryOfSize("package/big.js", 1<<32), endMarker...)),
			extractLimits{entries: 100, bytes: 1 << 20}, "more than 1048576 bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := t.TempDir()
			archive := filepath.Join(parent, "archive.tgz")
			if err := os.WriteFile(archive, tt.archive, 0o600); err != nil {
				t.Fatal(err)
			}
			tree, err := extractTarGz(archive, filepath.Join(parent, "out"), tt.lim)
			if err == nil {
				tree.close()
				t.Fatal("extracted; want an error")
			}
			if !errors.Is(err, ErrUnsafeArchive) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q: want ErrUnsafeArchive saying %q", err, tt.want)
			}
		})
	}
}

// rawEntryOfSize is the header of a regular file that claims size bytes
// and brings none.
func rawEntryOfSize(name string, size int64) []byte {
	block := rawEntry(name, tar.TypeReg, "")
	copy(block[124:136], fmt.Sprintf("%011o\x00", size))
	setChecksum(block)
	return block
}

func TestExtractTarGzAcceptsWhatRegistriesServe(t *testing.T) {
	commit := strings.Repeat("ab", 20)
	raw := buildTar(t, []tarEntry{
		{name: "pax_global_header", typ: tar.TypeXGlobalHeader, pax: map[string]string{"comment": commit}},
		{name: "owner-repo-abababa/", typ: tar.TypeDir},
		{name: "owner-repo-abababa/dist/", typ: tar.TypeDir},
		{name: "owner-repo-abababa/dist/index.js", body: "run()\n"},
		{name: "owner-repo-abababa/dist/", typ: tar.TypeDir}, // a directory may come twice
		{name: "owner-repo-abababa/action.yml", body: "name: x\n"},
		{name: "owner-repo-abababa/no/dir/entry/first.txt", body: ""},
		{name: "owner-repo-abababa/with space/" + u(0xE9) + ".txt", body: "accent\n"},
		{name: "owner-repo-abababa/" + strings.Repeat("long/", 30) + "name.txt", body: "pax path\n"},
	})
	// Padding after the end marker, as tar writes to fill its record.
	raw = append(raw, make([]byte, 8192)...)
	parent := t.TempDir()
	archive := filepath.Join(parent, "archive.tgz")
	if err := os.WriteFile(archive, gzipped(t, raw), 0o600); err != nil {
		t.Fatal(err)
	}
	tree, err := extractTarGz(archive, filepath.Join(parent, "out"), defaultExtractLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer tree.close()
	want := map[string]string{
		"dist/index.js":                          "run()\n",
		"action.yml":                             "name: x\n",
		"no/dir/entry/first.txt":                 "",
		"with space/" + u(0xE9) + ".txt":         "accent\n",
		strings.Repeat("long/", 30) + "name.txt": "pax path\n",
	}
	if len(tree.files) != len(want) {
		t.Errorf("files %v, want %d of them", fileNames(tree), len(want))
	}
	for name, content := range want {
		f, ok := tree.files[name]
		if !ok {
			t.Errorf("%s is missing", name)
			continue
		}
		if f.size != int64(len(content)) || f.sum != sha256.Sum256([]byte(content)) {
			t.Errorf("%s: recorded size %d and hash do not match the content", name, f.size)
		}
		got, err := tree.root.ReadFile(name)
		if err != nil || string(got) != content {
			t.Errorf("%s: read %q, %v; want %q", name, got, err, content)
		}
	}
}

func TestEntryPath(t *testing.T) {
	tests := []struct {
		name    string
		dir     bool
		want    string
		wantErr bool
	}{
		{"package/index.js", false, "index.js", false},
		{"package/lib/a.js", false, "lib/a.js", false},
		{"package/", true, "", false},
		{"package", true, "", false},
		{"package", false, "", false},
		{"package/lib/", true, "lib", false},
		{"package/...", false, "...", false},
		{"package/..a", false, "..a", false},
		// Not in clean form: refused, not rewritten.
		{"./package/lib/a.js", false, "", true},
		{"package//lib/a.js", false, "", true},
		{"package/./a.js", false, "", true},
		{"package/lib/", false, "", true},
		{"package/lib//", true, "", true},
		{".", true, "", true},
		{"./", true, "", true},
		{"", false, "", true},
		{"/", true, "", true},
		{"/etc/passwd", false, "", true},
		{"//package/a.js", false, "", true},
		{"..", true, "", true},
		{"../x", false, "", true},
		{"package/..", true, "", true},
		{"package/../x", false, "", true},
		{"package/a/../../..", false, "", true},
		{`package\x`, false, "", true},
		{"package/a\x00b", false, "", true},
		{"C:/x", false, "", true},
		{"C:x", false, "", true},
	}
	for _, tt := range tests {
		got, err := entryPath(tt.name, tt.dir)
		if got != tt.want || (err != nil) != tt.wantErr {
			t.Errorf("entryPath(%q, dir %v) = %q, %v; want %q, error %v", tt.name, tt.dir, got, err, tt.want, tt.wantErr)
		}
	}
}

// zipEntry is one entry of a zip built by a test.
type zipEntry struct {
	name string
	body string
	mode fs.FileMode
}

func buildZip(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {
			h.SetMode(e.mode)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestUnzipModule(t *testing.T) {
	m := module.Version{Path: "example.com/mod", Version: "v1.2.3"}
	const prefix = "example.com/mod@v1.2.3/"
	gomod := zipEntry{name: prefix + "go.mod", body: "module example.com/mod\n"}
	tests := []struct {
		name    string
		entries []zipEntry
		lim     extractLimits
		want    string // "" when the zip is fine
	}{
		{"a plain module", []zipEntry{gomod, {name: prefix + "a/a.go", body: "package a\n"}}, defaultExtractLimits, ""},
		{"a name outside the module's directory", []zipEntry{gomod, {name: "other.com/mod@v1.2.3/a.go", body: "x"}}, defaultExtractLimits, "does not have prefix"},
		{"an absolute path", []zipEntry{gomod, {name: "/etc/passwd", body: "x"}}, defaultExtractLimits, "does not have prefix"},
		{"dot-dot", []zipEntry{gomod, {name: prefix + "../../outside", body: "x"}}, defaultExtractLimits, `invalid path element ".."`},
		{"backslash", []zipEntry{gomod, {name: prefix + `a\..\b.go`, body: "x"}}, defaultExtractLimits, "invalid char"},
		{"names that differ only in case", []zipEntry{gomod, {name: prefix + "a.go", body: "x"}, {name: prefix + "A.go", body: "y"}}, defaultExtractLimits, "case-insensitive file name collision"},
		{"the same name twice", []zipEntry{gomod, {name: prefix + "a.go", body: "x"}, {name: prefix + "a.go", body: "y"}}, defaultExtractLimits, "unzip"},
		{"too many entries", []zipEntry{gomod, {name: prefix + "a.go", body: "x"}, {name: prefix + "b.go", body: "y"}}, extractLimits{entries: 2, bytes: 1 << 20}, "more than 2 entries"},
		{"too many bytes", []zipEntry{gomod, {name: prefix + "a.go", body: strings.Repeat("x", 2000)}}, extractLimits{entries: 100, bytes: 1000}, "more than 1000 bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := t.TempDir()
			archive := filepath.Join(parent, "m.zip")
			if err := os.WriteFile(archive, buildZip(t, tt.entries), 0o600); err != nil {
				t.Fatal(err)
			}
			tree, err := unzipModule(archive, filepath.Join(parent, "out"), m, tt.lim)
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				tree.close()
				if got := fileNames(tree); strings.Join(got, " ") != "a/a.go go.mod" {
					t.Errorf("files %v", got)
				}
				return
			}
			if err == nil {
				tree.close()
				t.Fatalf("extracted, files %v; want an error", fileNames(tree))
			}
			if !errors.Is(err, ErrUnsafeArchive) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q: want ErrUnsafeArchive saying %q", err, tt.want)
			}
			if ents, _ := os.ReadDir(parent); len(ents) > 2 {
				t.Errorf("something was written beside the extraction directory: %v", ents)
			}
		})
	}
}

// A zip entry marked as a symbolic link is written by the go command as
// a regular file holding the link's text, and so it is here: no link is
// ever made, and the model is shown that text like any other file.
func TestUnzipModuleNeverMakesALink(t *testing.T) {
	m := module.Version{Path: "example.com/mod", Version: "v1.2.3"}
	const prefix = "example.com/mod@v1.2.3/"
	parent := t.TempDir()
	archive := filepath.Join(parent, "m.zip")
	zipped := buildZip(t, []zipEntry{
		{name: prefix + "go.mod", body: "module example.com/mod\n"},
		{name: prefix + "link", body: "/etc/passwd", mode: fs.ModeSymlink | 0o777},
	})
	if err := os.WriteFile(archive, zipped, 0o600); err != nil {
		t.Fatal(err)
	}
	tree, err := unzipModule(archive, filepath.Join(parent, "out"), m, defaultExtractLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer tree.close()
	info, err := os.Lstat(filepath.Join(parent, "out", "link"))
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("link: %v, %v; want a regular file", info, err)
	}
	if got, _ := tree.root.ReadFile("link"); string(got) != "/etc/passwd" {
		t.Errorf("link holds %q", got)
	}
}

// readTree is given a directory someone else filled. A symbolic link in
// it is refused, not followed.
func TestReadTreeRefusesALink(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link")); err != nil {
		t.Skipf("cannot make a symbolic link here: %v", err)
	}
	tree, err := readTree(dir, defaultExtractLimits)
	if err == nil {
		tree.close()
		t.Fatal("read a tree with a symbolic link in it")
	}
	if !errors.Is(err, ErrUnsafeArchive) {
		t.Errorf("error %v is not ErrUnsafeArchive", err)
	}
}

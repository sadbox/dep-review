package ecoutil

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sadbox/dep-review/internal/model"
)

func TestExtractTarRejectsUnsafe(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	reg := func(name, body string) {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	reg("package/package.json", "{}")
	reg("package/lib/index.js", "ok")
	tw.WriteHeader(&tar.Header{Name: "package/link", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink})
	tw.WriteHeader(&tar.Header{Name: "package/hard", Linkname: "package/package.json", Typeflag: tar.TypeLink})
	tw.WriteHeader(&tar.Header{Name: "package/dev", Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 3})
	tw.WriteHeader(&tar.Header{Name: "package/fifo", Typeflag: tar.TypeFifo})
	reg("package/../../escape", "x")
	reg("/abs/path", "x")
	reg("package/LIB/INDEX.JS", "case collision")
	reg("package/lib/index.js", "duplicate")
	reg(`package\..\win`, "x")
	tw.Close()
	zw.Close()
	arc := filepath.Join(t.TempDir(), "p.tgz")
	os.WriteFile(arc, buf.Bytes(), 0o644)

	parent := t.TempDir()
	tree, err := ExtractTarGz(arc, filepath.Join(parent, "out"), true)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"lib/index.js", "package.json"}; !slices.Equal(tree.Files, want) {
		t.Errorf("Files = %q, want %q", tree.Files, want)
	}
	if len(tree.Rejected) != 9 {
		t.Errorf("Rejected (%d) = %q", len(tree.Rejected), tree.Rejected)
	}
	if got := string(tree.ReadFile("lib/index.js")); got != "ok" {
		t.Errorf("duplicate overwrote the first entry: %q", got)
	}
	err = filepath.WalkDir(parent, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 || (!d.IsDir() && !d.Type().IsRegular()) {
			t.Errorf("special file written: %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(parent, "escape")); err == nil {
		t.Error("escaped the extraction directory")
	}
}

func TestExtractZipRejectsSymlink(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("pkg/__init__.py")
	w.Write([]byte("x = 1\n"))
	h := &zip.FileHeader{Name: "pkg/link"}
	h.SetMode(fs.ModeSymlink | 0o777)
	w, _ = zw.CreateHeader(h)
	w.Write([]byte("/etc/passwd"))
	w, _ = zw.Create("../evil.py")
	w.Write([]byte("x"))
	zw.Close()
	arc := filepath.Join(t.TempDir(), "p.whl")
	os.WriteFile(arc, buf.Bytes(), 0o644)
	tree, err := ExtractZip(arc, filepath.Join(t.TempDir(), "out"), false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(tree.Files, []string{"pkg/__init__.py"}) || len(tree.Rejected) != 2 {
		t.Errorf("Files %q Rejected %q", tree.Files, tree.Rejected)
	}
}

func TestTypeOf(t *testing.T) {
	tests := []struct {
		from, to string
		want     model.UpdateType
	}{
		{"v1.21.0", "v1.21.1", model.Patch},
		{"1.21.0", "1.22.0", model.Minor},
		{"v0.47.0", "v0.48.0", model.Minor},
		{"v1.9.9", "v2.0.0", model.Major},
		{"26.2", "26.3", model.Minor},
		{"2.21.6", "2.21.6.1", model.Patch},
		{"v2.0.0+incompatible", "v2.0.1+incompatible", model.Patch},
		{"v0.0.0-20240101000000-abcdefabcdef", "v0.0.0-20250101000000-abcdefabcdef", model.Unknown},
		{"1.0.0", "1.0.1-rc.1", model.Unknown},
		{"1.2.0", "1.1.0", model.Unknown},
		{"1.2.0", "1.2.0", model.Unknown},
		{"", "1.0.0", model.Unknown},
		{"latest", "1.0.0", model.Unknown},
	}
	for _, tt := range tests {
		if got := TypeOf(tt.from, tt.to); got != tt.want {
			t.Errorf("TypeOf(%q, %q) = %s, want %s", tt.from, tt.to, got, tt.want)
		}
	}
}

func TestPair(t *testing.T) {
	tests := []struct {
		removed, added, kept []string
		pairs                [][2]string
		gone                 []string
	}{
		{[]string{"1.0.0"}, []string{"1.0.1"}, nil, [][2]string{{"1.0.0", "1.0.1"}}, nil},
		{nil, []string{"2.0.0"}, nil, [][2]string{{"", "2.0.0"}}, nil},
		{nil, []string{"2.0.0"}, []string{"1.0.0"}, [][2]string{{"1.0.0", "2.0.0"}}, nil},
		{[]string{"4.3.4"}, nil, []string{"4.3.5"}, nil, []string{"4.3.4"}},
		{[]string{"1.10.0", "1.9.0"}, []string{"1.9.1", "1.10.1"}, nil, [][2]string{{"1.9.0", "1.9.1"}, {"1.10.0", "1.10.1"}}, nil},
	}
	for _, tt := range tests {
		pairs, gone := Pair(tt.removed, tt.added, tt.kept)
		if !slices.Equal(pairs, tt.pairs) || !slices.Equal(gone, tt.gone) {
			t.Errorf("Pair(%v, %v, %v) = %v, %v; want %v, %v", tt.removed, tt.added, tt.kept, pairs, gone, tt.pairs, tt.gone)
		}
	}
}

func TestDiffTrees(t *testing.T) {
	parent := t.TempDir()
	write := func(p, s string) {
		os.MkdirAll(filepath.Dir(filepath.Join(parent, p)), 0o755)
		os.WriteFile(filepath.Join(parent, p), []byte(s), 0o644)
	}
	write("m@v1/a.go", "package a\n")
	write("m@v1/vendor/x.go", "package x\n")
	write("m@v1/same.txt", "same\n")
	write("m@v2/a.go", "package a // changed\n")
	write("m@v2/new file.go", "package a\n")
	write("m@v2/same.txt", "same\n")
	write("m@v2/bin.dat", "\x00\x01\x02")
	diffs, cut, err := DiffTrees(context.Background(), t.TempDir(), parent, "m@v1", "m@v2")
	if err != nil || cut {
		t.Fatal(err, cut)
	}
	var paths []string
	for _, d := range diffs {
		paths = append(paths, d.Path)
		if !bytes.HasPrefix(d.Body, []byte("diff --git ")) {
			t.Errorf("%s: body %q", d.Path, d.Body)
		}
	}
	if want := []string{"a.go", "bin.dat", "new file.go", "vendor/x.go"}; !slices.Equal(paths, want) {
		t.Errorf("paths = %q, want %q", paths, want)
	}
	text, kept := JoinDiffs(diffs, func(p string) bool { return strings.HasPrefix(p, "vendor/") })
	if slices.Contains(kept, "vendor/x.go") || !bytes.Contains(text, []byte("Binary files")) || !bytes.Contains(text, []byte("+package a // changed")) {
		t.Errorf("joined diff:\n%s", text)
	}
	// A new tree diffs against nothing.
	diffs, _, err = DiffTrees(context.Background(), t.TempDir(), parent, "", "m@v2")
	if err != nil || len(diffs) != 4 {
		t.Errorf("new-tree diff: %v, %d files", err, len(diffs))
	}
}

func TestGetRetriesAndLimits(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/flaky":
			if calls.Add(1) < 3 {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			w.Write([]byte("ok"))
		case "/big":
			w.Write(bytes.Repeat([]byte("x"), 100))
		case "/gone":
			http.NotFound(w, r)
		case "/forbidden":
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	if b, err := GetBytes(ctx, srv.Client(), srv.URL+"/flaky", 10, nil); err != nil || string(b) != "ok" || calls.Load() != 3 {
		t.Errorf("flaky: %q %v after %d calls", b, err, calls.Load())
	}
	if _, err := GetBytes(ctx, srv.Client(), srv.URL+"/big", 10, nil); err == nil {
		t.Error("size limit not enforced")
	}
	if _, err := GetBytes(ctx, srv.Client(), srv.URL+"/gone", 10, nil); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("404: %v", err)
	}
	if _, err := GetBytes(ctx, srv.Client(), srv.URL+"/forbidden", 10, nil); err == nil {
		t.Error("403 accepted")
	}
	dst := filepath.Join(t.TempDir(), "f")
	if err := GetFile(ctx, srv.Client(), srv.URL+"/big", dst, 1000); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(dst); st.Size() != 100 {
		t.Errorf("GetFile size %d", st.Size())
	}
}

func TestCheckHost(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://registry.npmjs.org/x/-/x-1.tgz":        true,
		"http://registry.npmjs.org/x/-/x-1.tgz":         false,
		"https://registry.npmjs.org.evil.example/x":     false,
		"https://user@registry.npmjs.org/x":             false,
		"https://registry.npmjs.org:8443/x":             false,
		"git+ssh://git@github.com/registry.npmjs.org/x": false,
	} {
		if got := CheckHost(raw, "registry.npmjs.org") == nil; got != ok {
			t.Errorf("CheckHost(%q) = %v, want %v", raw, got, ok)
		}
	}
}

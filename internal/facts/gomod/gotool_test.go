package gomod

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/module"
)

// The files in testdata/go are what go 1.27.4 printed on 2026-11-22 for
// the command named in each test, run the way goCommand runs it against
// proxy.golang.org and sum.golang.org, for public modules. The only edit
// is the scratch directory in the file paths, which is "/scratch".
//
// Three of them needed a proxy that misbehaves, which the real one does
// not do on request. For those GOPROXY pointed at a local forwarder to
// proxy.golang.org that altered one response:
//
//	download_tampered.json           one line appended to fsnotify@v1.5.4's go.mod
//	list_versions_unloadable.json    404 for the go.mod of fsnotify's latest version
//	list_retracted_unloadable.json   the same, for "go list -m -u -retracted"
//
// Three more were printed on 2026-11-23, for a pseudo-version of a module
// with no tagged version (google.golang.org/genproto/googleapis/rpc):
// download_pseudo.json, list_pseudo.json and list_versions_tagless.json.
// For such a module the version list is the path and nothing else: no
// version and no error. That stays so behind the same forwarder answering
// 404 for the go.mod of the module's latest version, or for its @latest:
// "go list -m -versions" and "go list -m -u -retracted" for an older
// pseudo-version then print what they print without it, so nothing shows
// that the retractions of a module with no tagged version were not read.

// fakeTool replays recorded output of the go command.
type fakeTool struct {
	t *testing.T
	// files maps a command line, without the leading "go", to a file in
	// testdata/go.
	files map[string]string
	// inline maps a command line to output written in the test, for
	// answers the real services cannot be made to give.
	inline map[string]string
	// errs maps a command line to the error the go command exits with.
	errs map[string]error
	// calls is every command line run.
	calls []string
}

// scratchDir is the directory in the recorded output's file paths.
func (f *fakeTool) scratchDir() string { return "/scratch" }

func (f *fakeTool) run(ctx context.Context, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	line := strings.Join(args, " ")
	f.calls = append(f.calls, line)
	if out, ok := f.inline[line]; ok {
		return []byte(out), f.errs[line]
	}
	file, ok := f.files[line]
	if !ok {
		if err, ok := f.errs[line]; ok {
			return nil, err
		}
		f.t.Errorf("unexpected command: go %s", line)
		return nil, errors.New("unexpected command")
	}
	return fixture(f.t, "go", file), f.errs[line]
}

func fixture(t *testing.T, dir, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mv(path, version string) module.Version { return module.Version{Path: path, Version: version} }

func TestDownload(t *testing.T) {
	ctx := context.Background()
	exit1 := errors.New("exit status 1")

	t.Run("two modules", func(t *testing.T) {
		tool := &fakeTool{t: t, files: map[string]string{
			"mod download -json -- golang.org/x/mod@v0.5.1 golang.org/x/text@v0.3.3": "download.json",
		}}
		got, err := download(ctx, tool, []module.Version{mv("golang.org/x/mod", "v0.5.1"), mv("golang.org/x/text", "v0.3.3")})
		if err != nil {
			t.Fatal(err)
		}
		if d := got[mv("golang.org/x/text", "v0.3.3")]; d.Sum != hText033 || d.GoModSum != hText033Mod || d.Error != "" {
			t.Errorf("x/text = %+v", d)
		}
		if d := got[mv("golang.org/x/mod", "v0.5.1")]; d.Sum != hMod051 || d.GoModSum != hMod051Mod || d.Error != "" {
			t.Errorf("x/mod = %+v", d)
		}
	})

	t.Run("one version does not exist", func(t *testing.T) {
		line := "mod download -json -- github.com/fsnotify/fsnotify@v1.5.4 github.com/fsnotify/fsnotify@v1.5.99"
		tool := &fakeTool{t: t, files: map[string]string{line: "download_missing.json"}, errs: map[string]error{line: exit1}}
		got, err := download(ctx, tool, []module.Version{mv("github.com/fsnotify/fsnotify", "v1.5.4"), mv("github.com/fsnotify/fsnotify", "v1.5.99")})
		if err != nil {
			t.Fatalf("a module that failed is a result, not an error: %v", err)
		}
		if d := got[mv("github.com/fsnotify/fsnotify", "v1.5.4")]; d.Sum == "" || d.Error != "" {
			t.Errorf("v1.5.4 = %+v", d)
		}
		if d := got[mv("github.com/fsnotify/fsnotify", "v1.5.99")]; !strings.Contains(d.Error, "404 Not Found") || d.Sum != "" {
			t.Errorf("v1.5.99 = %+v", d)
		}
	})

	t.Run("the checksum database disagrees", func(t *testing.T) {
		line := "mod download -json -- github.com/fsnotify/fsnotify@v1.5.4"
		tool := &fakeTool{t: t, files: map[string]string{line: "download_tampered.json"}, errs: map[string]error{line: exit1}}
		got, err := download(ctx, tool, []module.Version{mv("github.com/fsnotify/fsnotify", "v1.5.4")})
		if err != nil {
			t.Fatal(err)
		}
		d := got[mv("github.com/fsnotify/fsnotify", "v1.5.4")]
		if !strings.Contains(d.Error, "SECURITY ERROR") || d.Sum != "" || d.GoModSum != "" {
			t.Errorf("tampered = %+v", d)
		}
	})

	t.Run("the command fails outright", func(t *testing.T) {
		line := "mod download -json -- golang.org/x/text@v0.3.3"
		tool := &fakeTool{t: t, errs: map[string]error{line: errors.New("exec: go: not found")}}
		if _, err := download(ctx, tool, []module.Version{mv("golang.org/x/text", "v0.3.3")}); err == nil {
			t.Error("no error")
		}
	})

	t.Run("output that is not JSON", func(t *testing.T) {
		line := "mod download -json -- golang.org/x/text@v0.3.3"
		tool := &fakeTool{t: t, inline: map[string]string{line: "go: something else\n"}}
		if _, err := download(ctx, tool, []module.Version{mv("golang.org/x/text", "v0.3.3")}); err == nil {
			t.Error("no error")
		}
	})

	// The go command's reason can name a file of its module cache, which
	// is in the scratch directory: x/mod/zip words a zip it will not
	// unpack as "unzip <file>: ...". The reason is shown on the pull
	// request, without the directory.
	t.Run("a reason that names a file in the scratch directory", func(t *testing.T) {
		line := "mod download -json -- example.com/m@v1.0.0"
		tool := &fakeTool{t: t, errs: map[string]error{line: exit1}, inline: map[string]string{line: `{"Path":"example.com/m","Version":"v1.0.0",` +
			`"Error":"example.com/m@v1.0.0: unzip /scratch/gopath/pkg/mod/cache/download/example.com/m/@v/v1.0.0.zip: malformed file path"}`}}
		got, err := download(ctx, tool, []module.Version{mv("example.com/m", "v1.0.0")})
		if err != nil {
			t.Fatal(err)
		}
		const want = "example.com/m@v1.0.0: unzip (scratch)/gopath/pkg/mod/cache/download/example.com/m/@v/v1.0.0.zip: malformed file path"
		if d := got[mv("example.com/m", "v1.0.0")]; d.Error != want {
			t.Errorf("Error = %q, want %q", d.Error, want)
		}
		f := goFailure("go mod download failed", got[mv("example.com/m", "v1.0.0")].Error, sourceDownload)
		if f.OK || f.Value != "go mod download failed: "+want {
			t.Errorf("the fact made from it = %+v", f)
		}
	})

	t.Run("a module reported twice is not reported", func(t *testing.T) {
		line := "mod download -json -- golang.org/x/text@v0.3.3"
		one := `{"Path":"golang.org/x/text","Version":"v0.3.3","Sum":"` + hText033 + `","GoModSum":"` + hText033Mod + `"}`
		tool := &fakeTool{t: t, inline: map[string]string{line: one + "\n" + strings.Replace(one, hText033, hText032, 1) + "\n"}}
		got, err := download(ctx, tool, []module.Version{mv("golang.org/x/text", "v0.3.3")})
		if err != nil || len(got) != 0 {
			t.Errorf("got %v, %v", got, err)
		}
	})
}

func TestList(t *testing.T) {
	ctx := context.Background()
	fsnotify := "github.com/fsnotify/fsnotify"

	t.Run("retraction and deprecation", func(t *testing.T) {
		tool := &fakeTool{t: t, files: map[string]string{
			"list -m -e -u -retracted -json -- github.com/fsnotify/fsnotify@v1.5.3 github.com/fsnotify/fsnotify@v1.5.4 github.com/fsnotify/fsnotify@v1.5.99 github.com/golang/protobuf@v1.5.4 google.golang.org/grpc@v1.74.0": "list_retracted.json",
		}}
		got, err := list(ctx, tool, []string{"-u", "-retracted"}, []module.Version{
			mv(fsnotify, "v1.5.3"), mv(fsnotify, "v1.5.4"), mv(fsnotify, "v1.5.99"),
			mv("github.com/golang/protobuf", "v1.5.4"), mv("google.golang.org/grpc", "v1.74.0"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if l := got[mv(fsnotify, "v1.5.3")]; len(l.Retracted) != 1 || !strings.Contains(l.Retracted[0], "incorrect branch") || l.Error != nil {
			t.Errorf("retracted version = %+v", l)
		}
		if l := got[mv(fsnotify, "v1.5.4")]; len(l.Retracted) != 0 || l.Deprecated != "" || l.Error != nil || l.Time == nil ||
			!l.Time.Equal(time.Date(2022, 4, 27, 2, 6, 9, 0, time.UTC)) {
			t.Errorf("good version = %+v", l)
		}
		if l := got[mv(fsnotify, "v1.5.99")]; l.Error == nil || !strings.Contains(l.Error.Err, "404 Not Found") || l.Time != nil {
			t.Errorf("missing version = %+v", l)
		}
		if l := got[mv("github.com/golang/protobuf", "v1.5.4")]; !strings.Contains(l.Deprecated, "google.golang.org/protobuf") {
			t.Errorf("deprecated module = %+v", l)
		}
		if l := got[mv("google.golang.org/grpc", "v1.74.0")]; len(l.Retracted) == 0 {
			t.Errorf("retracted by an interval = %+v", l)
		}
	})

	t.Run("versions without the retracted ones", func(t *testing.T) {
		tool := &fakeTool{t: t, files: map[string]string{
			"list -m -e -versions -json -- github.com/fsnotify/fsnotify github.com/golang/protobuf google.golang.org/grpc": "list_versions_retracted.json",
		}}
		got, err := list(ctx, tool, []string{"-versions"}, []module.Version{mv(fsnotify, ""), mv("github.com/golang/protobuf", ""), mv("google.golang.org/grpc", "")})
		if err != nil {
			t.Fatal(err)
		}
		versions := got[mv(fsnotify, "")].Versions
		if slices.Contains(versions, "v1.5.3") || slices.Contains(versions, "v1.5.0") || !slices.Contains(versions, "v1.5.4") {
			t.Errorf("fsnotify versions = %v", versions)
		}
		if v := got[mv("google.golang.org/grpc", "")].Versions; slices.Contains(v, "v1.74.0") || !slices.Contains(v, "v1.74.2") {
			t.Errorf("grpc versions leave out the retracted interval: %v", v)
		}
	})

	t.Run("retractions that cannot be loaded are an error on the version list", func(t *testing.T) {
		tool := &fakeTool{t: t, files: map[string]string{
			"list -m -e -versions -json -- github.com/fsnotify/fsnotify": "list_versions_unloadable.json",
		}}
		got, err := list(ctx, tool, []string{"-versions"}, []module.Version{mv(fsnotify, "")})
		if err != nil {
			t.Fatal(err)
		}
		if l := got[mv(fsnotify, "")]; l.Error == nil || !strings.Contains(l.Error.Err, "loading module retractions") || len(l.Versions) != 0 {
			t.Errorf("got %+v", l)
		}
	})

	t.Run("a reason that names a file in the scratch directory", func(t *testing.T) {
		line := "list -m -e -u -retracted -json -- example.com/m@v1.0.0"
		tool := &fakeTool{t: t, inline: map[string]string{line: `{"Path":"example.com/m","Version":"v1.0.0",` +
			`"Error":{"Err":"example.com/m@v1.0.0: open /scratch/gopath/pkg/mod/cache/download/example.com/m/@v/v1.0.0.info: permission denied"}}`}}
		got, err := list(ctx, tool, []string{"-u", "-retracted"}, []module.Version{mv("example.com/m", "v1.0.0")})
		if err != nil {
			t.Fatal(err)
		}
		const want = "example.com/m@v1.0.0: open (scratch)/gopath/pkg/mod/cache/download/example.com/m/@v/v1.0.0.info: permission denied"
		if l := got[mv("example.com/m", "v1.0.0")]; l.Error == nil || l.Error.Err != want {
			t.Errorf("Error = %+v, want %q", l.Error, want)
		}
	})

	t.Run("the command fails", func(t *testing.T) {
		line := "list -m -e -versions -json -- github.com/fsnotify/fsnotify"
		tool := &fakeTool{t: t, errs: map[string]error{line: errors.New("exit status 2")}}
		if _, err := list(ctx, tool, []string{"-versions"}, []module.Version{mv(fsnotify, "")}); err == nil {
			t.Error("no error")
		}
	})
}

// The paths and versions of a go.mod become arguments of the go command
// as they are, so what must never get there has to be refused where the
// file is read: parseMod runs module.Check and the canonical-version
// check on every require.
func TestHostileRequiresDoNotParse(t *testing.T) {
	for _, tc := range []struct{ path, version string }{
		{"-modfile=/etc/passwd", "v1.0.0"},
		{"-json", "v1.0.0"},
		{"all", "v1.0.0"},
		{"example.com/...", "v1.0.0"},
		{"example.com/m", "latest"},
		{"example.com/m", "v1.0"},
		{"example.com/m", "v1.0.0@v2.0.0"},
		{"example.com/m v1.0.0", "v1.0.0"},
		{"example.com/m", "v1.0.0 -x"},
		{"example.com/m/v2", "v1.0.0"},
		{"../escape", "v1.0.0"},
		{"", "v1.0.0"},
	} {
		mod := "module example.com/app\n\ngo 1.22\n\nrequire " + strconv.Quote(tc.path) + " " + tc.version + "\n"
		if m, err := parseMod([]byte(mod)); err == nil {
			t.Errorf("require %q %s parsed: %+v", tc.path, tc.version, m.requires)
		}
	}
	// And what does parse is passed on unchanged.
	got := goArgs([]module.Version{mv("golang.org/x/text", "v0.3.3"), mv("golang.org/x/text", ""), mv("github.com/Azure/azure-sdk-for-go", "v68.0.0+incompatible")})
	want := []string{"golang.org/x/text@v0.3.3", "golang.org/x/text", "github.com/Azure/azure-sdk-for-go@v68.0.0+incompatible"}
	if !slices.Equal(got, want) {
		t.Errorf("goArgs = %q, want %q", got, want)
	}
}

// TestGoCommandEnvironment runs the real go command, which needs no
// network for "go env", and checks that it sees the gatherer's settings
// and none of the caller's.
func TestGoCommandEnvironment(t *testing.T) {
	bin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command on PATH")
	}
	// What a hostile or merely unusual environment could set.
	t.Setenv("GOPROXY", "direct")
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GONOSUMDB", "*")
	t.Setenv("GONOSUMCHECK", "1")
	t.Setenv("GOPRIVATE", "*")
	t.Setenv("GOINSECURE", "*")
	t.Setenv("GOFLAGS", "-insecure")
	t.Setenv("GOTOOLCHAIN", "go1.99.0")
	t.Setenv("GOVCS", "*:all")

	scratch := t.TempDir()
	c, err := newGoCommand(bin, scratch)
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.run(context.Background(), "env", "-json")
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]string
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"GOPROXY":     "https://proxy.golang.org",
		"GOSUMDB":     "sum.golang.org",
		"GONOSUMDB":   "",
		"GONOPROXY":   "",
		"GOPRIVATE":   "",
		"GOINSECURE":  "",
		"GOFLAGS":     "-mod=mod -modcacherw",
		"GOTOOLCHAIN": "local",
		"GOVCS":       "*:off",
		"GOWORK":      "off",
		"GOMODCACHE":  filepath.Join(scratch, "gopath", "pkg", "mod"),
		"GOTELEMETRY": "off",
	}
	for k, v := range want {
		if env[k] != v {
			t.Errorf("%s = %q, want %q", k, env[k], v)
		}
	}
	// The go command works in the empty scratch module, which requires
	// nothing and has no go.sum.
	if gomod, _ := filepath.EvalSymlinks(env["GOMOD"]); gomod == "" || filepath.Base(filepath.Dir(gomod)) != "work" {
		t.Errorf("GOMOD = %q, want the scratch module's go.mod", env["GOMOD"])
	}
	if _, err := os.Stat(filepath.Join(scratch, "work", "go.sum")); !os.IsNotExist(err) {
		t.Errorf("the scratch module has a go.sum: %v", err)
	}
}

func TestGoCommandTimeout(t *testing.T) {
	bin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command on PATH")
	}
	c, err := newGoCommand(bin, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.run(ctx, "env", "-json"); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestCappedBuffer(t *testing.T) {
	b := &cappedBuffer{max: 5}
	for _, s := range []string{"abc", "de"} {
		if n, err := b.Write([]byte(s)); n != len(s) || err != nil {
			t.Fatalf("Write(%q) = %d, %v", s, n, err)
		}
	}
	// Exactly the cap is not over it.
	if string(b.b) != "abcde" || b.over {
		t.Errorf("buffer = %q, over = %v", b.b, b.over)
	}
	// A write past the cap is taken and dropped, never refused: the
	// writer is a child's pipe.
	for _, s := range []string{"fg", "h"} {
		if n, err := b.Write([]byte(s)); n != len(s) || err != nil {
			t.Fatalf("Write(%q) = %d, %v", s, n, err)
		}
	}
	if string(b.b) != "abcde" || !b.over {
		t.Errorf("buffer = %q, over = %v", b.b, b.over)
	}
	// A write that straddles the cap keeps what fits.
	c := &cappedBuffer{max: 5}
	c.Write([]byte("abc"))
	c.Write([]byte("defg"))
	if string(c.b) != "abcde" || !c.over {
		t.Errorf("buffer = %q, over = %v", c.b, c.over)
	}
}

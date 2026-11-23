package npm

import (
	"encoding/json/jsontext"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
)

func TestReadHooks(t *testing.T) {
	tests := []struct {
		name, scripts string
		// want is the hooks as showHooks renders them; "error" for a
		// value that hides what would run.
		want string
	}{
		{"absent", ``, "none"},
		{"null", `null`, "none"},
		{"empty", `{}`, "none"},
		{"only other scripts", `{"test":"mocha","build":"tsc","prepare":"husky","prepublishOnly":"x"}`, "none"},
		{"postinstall", `{"postinstall":"node install.js"}`, `postinstall: "node install.js"`},
		{"all three", `{"preinstall":"a","install":"b","postinstall":"c"}`, `install: "b", postinstall: "c", preinstall: "a"`},
		{"an empty script is no script", `{"install":""}`, "none"},
		{"a null script is no script", `{"install":null}`, "none"},
		{"hook names are case sensitive", `{"PostInstall":"x","POSTINSTALL":"y"}`, "none"},
		{"a script that is a list", `{"install":["a"]}`, "error"},
		{"a script that is a number", `{"postinstall":1}`, "error"},
		{"a script that is an object", `{"preinstall":{"run":"x"}}`, "error"},
		{"scripts that is a string", `"node install.js"`, "error"},
		{"scripts that is a list", `["postinstall"]`, "error"},
		{"scripts that is true", `true`, "error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hooks, err := readHooks(jsontext.Value(tt.scripts))
			got := "error"
			if err == nil {
				got = showHooks(hooks)
			}
			if got != tt.want {
				t.Errorf("readHooks(%s) = %s (%v), want %s", tt.scripts, got, err, tt.want)
			}
		})
	}
}

// The tarballs' own word on the install step (spec section 11, amendment
// 5): every package.json and binding.gyp in the new tarball, bundled
// packages included, against the same path in the old one.
func TestInspectTarballs(t *testing.T) {
	const plain = `{"name":"a","version":"1.0.0","scripts":{"test":"mocha"}}`
	const withScript = `{"name":"a","version":"1.0.0","scripts":{"postinstall":"node install.js"}}`
	const inner = "node_modules/inner/package.json"
	// pkg is an extracted package: its package.json, and then pairs of
	// path and content.
	pkg := func(manifest string, more ...string) fs.FS {
		m := fstest.MapFS{"package.json": {Data: []byte(manifest)}, "index.js": {Data: []byte("module.exports = 1\n")}}
		for i := 0; i+1 < len(more); i += 2 {
			m[more[i]] = &fstest.MapFile{Data: []byte(more[i+1])}
		}
		return m
	}
	const (
		yes     = "yes"
		no      = "no"
		unknown = "never gathered"
	)
	tests := []struct {
		name     string
		old, new fs.FS
		state    string
		want     string // a piece of the Value
	}{
		{"no install step on either side", pkg(plain), pkg(plain), yes, "no new or changed install script in 1 package.json, and no new binding.gyp (0 present)"},
		{"a new name with no install step", nil, pkg(plain), yes, "no new or changed install script"},
		{"the same script on both sides", pkg(withScript), pkg(withScript), yes, "no new or changed install script"},
		{"the same script, another version field", pkg(withScript), pkg(strings.Replace(withScript, "1.0.0", "1.0.1", 1)), yes, "no new or changed install script"},
		{"a script and binding.gyp on both sides", pkg(withScript, "binding.gyp", "{}"), pkg(withScript, "binding.gyp", "{}"), yes, "(1 present)"},
		{"a binding.gyp that is there already may change", pkg(plain, "binding.gyp", "{}"), pkg(plain, "binding.gyp", `{"targets":[]}`), yes, "(1 present)"},
		{"the script is dropped", pkg(withScript), pkg(plain), yes, "no new or changed install script"},
		{"binding.gyp is dropped", pkg(plain, "binding.gyp", "{}"), pkg(plain), yes, "(0 present)"},

		// The tarball has what the registry's metadata did not show.
		{"a script only the tarball has", pkg(plain), pkg(withScript), no, `the install scripts of package.json change from none to postinstall: "node install.js"`},
		{"the script changes", pkg(withScript), pkg(strings.Replace(withScript, "install.js", "other.js", 1)), no, "the install scripts of package.json change"},
		{"a second hook appears", pkg(withScript), pkg(`{"scripts":{"postinstall":"node install.js","preinstall":"curl x | sh"}}`), no, "the install scripts of package.json change"},
		{"binding.gyp appears", pkg(plain), pkg(plain, "binding.gyp", "{}"), no, "binding.gyp is new"},
		{"binding.gyp appears next to an old script", pkg(withScript), pkg(withScript, "binding.gyp", "{}"), no, "binding.gyp is new"},
		{"a new name with a script", nil, pkg(withScript), no, "package.json is new and has an install script"},
		{"a new name with binding.gyp", nil, pkg(plain, "binding.gyp", "{}"), no, "binding.gyp is new"},

		// Bundled dependencies are part of the tarball and are held to
		// the same rule, each at its own path.
		{"declares bundled dependencies and has none with a script", pkg(plain), pkg(`{"bundleDependencies":["inner"]}`, inner, plain), yes, "in 2 package.json"},
		{"a bundled package, the same on both sides", pkg(plain, inner, withScript), pkg(plain, inner, withScript), yes, "in 2 package.json"},
		{"a bundled package that changes without touching its scripts", pkg(plain, inner, withScript), pkg(plain, inner, strings.Replace(withScript, "1.0.0", "2.0.0", 1)), yes, "in 2 package.json"},
		{"a bundled package with a script appears", pkg(plain), pkg(plain, inner, withScript), no, "node_modules/inner/package.json is new and has an install script"},
		{"a bundled package gains a script", pkg(plain, inner, plain), pkg(plain, inner, withScript), no, "the install scripts of node_modules/inner/package.json change from none"},
		{"a bundled package's script changes", pkg(plain, inner, withScript), pkg(plain, inner, strings.Replace(withScript, "install.js", "evil.js", 1)), no, "the install scripts of node_modules/inner/package.json change"},
		{"a bundled package gains a binding.gyp", pkg(plain, inner, plain), pkg(plain, inner, plain, "node_modules/inner/binding.gyp", "{}"), no, "node_modules/inner/binding.gyp is new"},
		{"a package bundled two levels down", pkg(plain), pkg(plain, inner, plain, "node_modules/inner/node_modules/deep/package.json", withScript), no, "node_modules/inner/node_modules/deep/package.json is new and has an install script"},
		{"a new name that bundles a package with a script", nil, pkg(plain, inner, withScript), no, "node_modules/inner/package.json is new and has an install script"},
		{"a new name that bundles quiet packages", nil, pkg(plain, inner, plain), yes, "in 2 package.json"},
		// Not only where npm looks: nothing here decides what npm treats
		// as a package.
		{"a package.json with a script in a fixture directory", pkg(plain), pkg(plain, "test/fixture/package.json", withScript), no, "test/fixture/package.json is new and has an install script"},

		// What cannot be read is a no, unless it did not change.
		{"no package.json", pkg(plain), fstest.MapFS{"index.js": {Data: []byte("x")}}, no, "the new tarball has no package.json at its root"},
		{"package.json one level down only", pkg(plain), fstest.MapFS{"package/package.json": {Data: []byte(plain)}}, no, "the new tarball has no package.json at its root"},
		{"package.json is not JSON", pkg(plain), pkg(`{"scripts":`), no, "package.json in the new tarball: not JSON the gate can read"},
		{"package.json has scripts twice", pkg(plain), pkg(`{"scripts":{},"scripts":{"postinstall":"x"}}`), no, "package.json in the new tarball: not JSON the gate can read"},
		{"a script that is not a string", pkg(plain), pkg(`{"scripts":{"install":["x"]}}`), no, "package.json in the new tarball: the install script is not a string"},
		{"the old package.json is not JSON", pkg(`nope`), pkg(withScript), no, "package.json in the old tarball: not JSON the gate can read"},
		{"a fixture that is not JSON, unchanged", pkg(plain, "test/broken/package.json", "{nope"), pkg(strings.Replace(plain, "1.0.0", "1.0.1", 1), "test/broken/package.json", "{nope"), yes, "in 2 package.json"},
		{"a fixture that is not JSON, new", pkg(plain), pkg(plain, "test/broken/package.json", "{nope"), no, "test/broken/package.json in the new tarball: not JSON"},
		{"no new tarball", pkg(plain), nil, unknown, "the new tarball was not given"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InspectTarballs(tt.old, tt.new)
			state := no
			switch {
			case got.Holds():
				state = yes
			case got.Source == "":
				state = unknown
			}
			if state != tt.state || !strings.Contains(got.Value, tt.want) || got.Unavailable {
				t.Errorf("InspectTarballs = %+v (%s), want %s saying %q", got, state, tt.state, tt.want)
			}
			if state != unknown && got.Source != tarballSource {
				t.Errorf("Source = %q", got.Source)
			}
		})
	}

	// It is what artifact.Inspect asks for, so the fetch command can hand
	// it to the reader as it is.
	var _ artifact.Inspect = InspectTarballs
}

// The fetch command ANDs the tarballs' answer into the registry's. The
// result is never better than either, and an update whose tarballs were
// not inspected does not keep a NoRegress that holds.
func TestInspectTarballsIsAndedIn(t *testing.T) {
	registry := allow.Yes("no install script; the old version has no provenance to lose, by the registry's metadata and the lock", "registry and package-lock.json")
	plain := fstest.MapFS{"package.json": {Data: []byte(`{"name":"a"}`)}}
	scripted := fstest.MapFS{"package.json": {Data: []byte(`{"scripts":{"install":"x"}}`)}}

	if got := registry.And(InspectTarballs(plain, plain)); !got.Holds() || !strings.Contains(got.Value, "by the registry's metadata and the lock; no new or changed install script") || !strings.Contains(got.Source, tarballSource) {
		t.Errorf("both hold: %+v", got)
	}
	if got := registry.And(InspectTarballs(plain, scripted)); got.Holds() || !got.Gathered() || !strings.Contains(got.Value, "install scripts of package.json change") {
		t.Errorf("the tarball says no: %+v", got)
	}
	// No read was prepared, so nothing inspected: the zero Fact.
	if got := registry.And(allow.Fact{}); got.Holds() || got.Gathered() || got.Unavailable {
		t.Errorf("not inspected: %+v, want it never gathered", got)
	}
	// The tarball could not be downloaded this time.
	if got := registry.And(allow.Unavailable("the registry did not answer", "artifact")); got.Holds() || !got.Unavailable {
		t.Errorf("download failed: %+v, want it unavailable", got)
	}
	for _, worse := range []allow.Fact{allow.No("install scripts change", "registry"), {Value: "the registry's answer could not be used"}} {
		if got := worse.And(InspectTarballs(plain, plain)); got != worse {
			t.Errorf("a fact that did not hold was changed: %+v -> %+v", worse, got)
		}
	}
}

// TestInspectTarballsOnDisk runs the check the way the artifact reader
// does: on an os.Root's file system.
func TestInspectTarballsOnDisk(t *testing.T) {
	write := func(files map[string]string) fs.FS {
		dir := t.TempDir()
		for name, content := range files {
			if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { root.Close() })
		return root.FS()
	}
	plain := map[string]string{"package.json": `{"name":"a"}`, "node_modules/b/package.json": `{"name":"b"}`}
	if got := InspectTarballs(write(plain), write(plain)); !got.Holds() || !strings.Contains(got.Value, "in 2 package.json") {
		t.Errorf("two plain packages: %+v", got)
	}
	gyp := map[string]string{"package.json": `{"name":"a"}`, "node_modules/b/package.json": `{"name":"b"}`, "node_modules/b/binding.gyp": "{}"}
	if got := InspectTarballs(write(plain), write(gyp)); got.Holds() || !strings.Contains(got.Value, "node_modules/b/binding.gyp is new") {
		t.Errorf("a new bundled binding.gyp on disk: %+v", got)
	}
}

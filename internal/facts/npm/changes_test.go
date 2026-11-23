package npm

import (
	"strings"
	"testing"

	json "encoding/json/v2"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
)

// reg builds a registry entry at a lock path, with a hash that stands for
// "the bytes of this name and version", and a Fixed that stands for what
// the lock says of them.
func reg(lockPath, name, version string) node {
	return node{
		Path: lockPath, Name: name, Version: version,
		Resolved:  artifact.NPMTarballURL(name, version),
		Integrity: "sha512-" + name + "@" + version,
		Fixed:     "integrity=sha512-" + name + "@" + version + "\n",
	}
}

// shrinkwrapped is n as the lock has it when the entry has a
// "hasShrinkwrap" member: the flag, and the member in Fixed.
func shrinkwrapped(n node) node {
	n.HasShrinkwrap = true
	n.Fixed = "hasShrinkwrap=true\n" + n.Fixed
	return n
}

func tree(nodes ...node) map[string]node {
	out := map[string]node{}
	for _, n := range nodes {
		out[n.Path] = n
	}
	return out
}

func TestDiffTrees(t *testing.T) {
	bundledIn := func(lockPath, name, version string) node {
		return node{Path: lockPath, Name: name, Version: version, InBundle: true}
	}
	tests := []struct {
		name       string
		base, head map[string]node
		// want is the updates as "name from->to", joined by ", ".
		want string
		// problem is a piece of the one Shape problem expected; empty
		// for none.
		problem string
	}{
		{
			name: "one version moves at its path",
			base: tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/b", "b", "2.0.0")),
			head: tree(reg("node_modules/a", "a", "1.0.1"), reg("node_modules/b", "b", "2.0.0")),
			want: "a 1.0.0->1.0.1",
		},
		{
			name: "nothing moves",
			base: tree(reg("node_modules/a", "a", "1.0.0")),
			head: tree(reg("node_modules/a", "a", "1.0.0")),
			want: "",
		},
		{
			name: "a package is removed",
			base: tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/b", "b", "2.0.0")),
			head: tree(reg("node_modules/a", "a", "1.0.0")),
			want: "",
		},
		{
			name: "a new name",
			base: tree(reg("node_modules/a", "a", "1.0.0")),
			head: tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/n", "n", "0.1.0")),
			want: "n (new)->0.1.0",
		},
		{
			name: "two copies move together",
			base: tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/x/node_modules/a", "a", "1.0.0")),
			head: tree(reg("node_modules/a", "a", "1.0.1"), reg("node_modules/x/node_modules/a", "a", "1.0.1")),
			want: "a 1.0.0->1.0.1",
		},
		{
			// One update has one From. Which of the two this is an update
			// of is not the gate's to choose.
			name:    "two paths with different old versions move to one new version",
			base:    tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/x/node_modules/a", "a", "1.1.0")),
			head:    tree(reg("node_modules/a", "a", "1.2.0"), reg("node_modules/x/node_modules/a", "a", "1.2.0")),
			problem: "a@1.2.0 does not replace one version of a at the same lock paths",
		},
		{
			// By name: 1.1.0 was already in the base lock, so moving it
			// to the top is not a new version of anything.
			name: "a nested copy is hoisted over an older one",
			base: tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/x/node_modules/a", "a", "1.1.0")),
			head: tree(reg("node_modules/a", "a", "1.1.0")),
			want: "",
		},
		{
			name: "a downgrade at a path is shown as one",
			base: tree(reg("node_modules/a", "a", "3.0.0")),
			head: tree(reg("node_modules/a", "a", "2.0.0")),
			want: "a 3.0.0->2.0.0",
		},
		{
			// A version at a path the base lock did not have replaced
			// nothing there, whatever else the base had of the name.
			name:    "a new nested copy at a new version",
			base:    tree(reg("node_modules/a", "a", "1.0.0")),
			head:    tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/x/node_modules/a", "a", "2.0.0")),
			problem: "a@2.0.0 does not replace one version of a at the same lock paths",
		},
		{
			name:    "a copy at a new path where one base version is gone",
			base:    tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/x/node_modules/a", "a", "3.0.0")),
			head:    tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/y/node_modules/a", "a", "2.0.0")),
			problem: "a@2.0.0 does not replace one version of a at the same lock paths",
		},
		{
			name:    "one copy replaces a version at its path and a second copy is at a new path",
			base:    tree(reg("node_modules/a", "a", "1.0.0")),
			head:    tree(reg("node_modules/a", "a", "1.0.1"), reg("node_modules/x/node_modules/a", "a", "1.0.1")),
			problem: "a@1.0.1 does not replace one version of a at the same lock paths",
		},
		{
			name:    "a version takes the path of another package",
			base:    tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/b", "b", "1.0.0")),
			head:    tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/b", "a", "2.0.0")),
			problem: "a@2.0.0 does not replace one version of a at the same lock paths",
		},
		{
			name:    "a version takes the path of a bundled entry",
			base:    tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/w", "w", "1.0.0"), bundledIn("node_modules/w/node_modules/a", "a", "1.0.0")),
			head:    tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/w", "w", "1.0.1"), reg("node_modules/w/node_modules/a", "a", "2.0.0")),
			problem: "a@2.0.0 does not replace one version of a at the same lock paths",
		},
		{
			name: "a second copy of an established version at a new path is no update",
			base: tree(reg("node_modules/a", "a", "1.0.0")),
			head: tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/x/node_modules/a", "a", "1.0.0")),
			want: "",
		},
		{
			name: "a second copy of an established version with another hash",
			base: tree(reg("node_modules/a", "a", "1.0.0")),
			head: tree(reg("node_modules/a", "a", "1.0.0"), func() node {
				n := reg("node_modules/x/node_modules/a", "a", "1.0.0")
				n.Integrity, n.Fixed = "sha512-other", "integrity=sha512-other\n"
				return n
			}()),
			problem: "a@1.0.0 at node_modules/x/node_modules/a keeps its version",
		},
		{
			name: "an established version reappears under another name",
			base: tree(reg("node_modules/a", "a", "1.0.0")),
			head: tree(reg("node_modules/a", "a", "1.0.0"), func() node {
				n := reg("node_modules/a", "a", "1.0.0")
				n.Path = "node_modules/alias"
				return n
			}()),
			problem: "a@1.0.0 at node_modules/alias keeps its version",
		},
		{
			name: "an established version gains the install-script flag",
			base: tree(reg("node_modules/a", "a", "1.0.0")),
			head: tree(func() node {
				n := reg("node_modules/a", "a", "1.0.0")
				n.HasInstallScript = true
				n.Fixed = "hasInstallScript=true\n" + n.Fixed
				return n
			}()),
			problem: "a@1.0.0 at node_modules/a keeps its version",
		},
		{
			// npm ci installs what is below such a package as the
			// npm-shrinkwrap.json in its tarball says, and ran a
			// postinstall that only that file's entry for a dependency
			// had. Nothing the gate reads is that file.
			name:    "a new version that brings a shrinkwrap",
			base:    tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/a/node_modules/b", "b", "1.0.0")),
			head:    tree(shrinkwrapped(reg("node_modules/a", "a", "1.0.1")), reg("node_modules/a/node_modules/b", "b", "1.0.0")),
			problem: "a@1.0.1 is marked as bringing an npm-shrinkwrap.json (hasShrinkwrap)",
		},
		{
			name:    "a new version that brings a shrinkwrap, as the old one did",
			base:    tree(shrinkwrapped(reg("node_modules/a", "a", "1.0.0"))),
			head:    tree(shrinkwrapped(reg("node_modules/a", "a", "1.0.1"))),
			problem: "a@1.0.1 is marked as bringing an npm-shrinkwrap.json (hasShrinkwrap)",
		},
		{
			name:    "one of two copies of a new version brings a shrinkwrap",
			base:    tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/x/node_modules/a", "a", "1.0.0")),
			head:    tree(reg("node_modules/a", "a", "1.0.1"), shrinkwrapped(reg("node_modules/x/node_modules/a", "a", "1.0.1"))),
			problem: "a@1.0.1 is marked as bringing an npm-shrinkwrap.json (hasShrinkwrap)",
		},
		{
			name:    "a new name that brings a shrinkwrap",
			base:    tree(reg("node_modules/a", "a", "1.0.0")),
			head:    tree(reg("node_modules/a", "a", "1.0.0"), shrinkwrapped(reg("node_modules/n", "n", "0.1.0"))),
			problem: "n@0.1.0 is marked as bringing an npm-shrinkwrap.json (hasShrinkwrap)",
		},
		{
			// The version is the base lock's, and so are its integrity and
			// its flag: the shrinkwrap in that tarball is the one that is
			// installed today.
			name: "a version that keeps its shrinkwrap while another package moves",
			base: tree(shrinkwrapped(reg("node_modules/a", "a", "1.0.0")), reg("node_modules/b", "b", "2.0.0")),
			head: tree(shrinkwrapped(reg("node_modules/a", "a", "1.0.0")), reg("node_modules/b", "b", "2.0.1")),
			want: "b 2.0.0->2.0.1",
		},
		{
			name:    "an established version gains the shrinkwrap flag",
			base:    tree(reg("node_modules/a", "a", "1.0.0")),
			head:    tree(shrinkwrapped(reg("node_modules/a", "a", "1.0.0"))),
			problem: "a@1.0.0 at node_modules/a keeps its version",
		},
		{
			// A bundled entry under a bundler that moves is compared with
			// nothing, so this one flag is refused there.
			name:    "a bundled entry that brings a shrinkwrap, under a bundler that moves",
			base:    tree(reg("node_modules/w", "w", "1.0.0"), bundledIn("node_modules/w/node_modules/t", "t", "2.0.0")),
			head:    tree(reg("node_modules/w", "w", "1.0.1"), shrinkwrapped(bundledIn("node_modules/w/node_modules/t", "t", "2.0.0"))),
			problem: "the bundled node_modules/w/node_modules/t is marked as bringing an npm-shrinkwrap.json (hasShrinkwrap), inside w@1.0.1",
		},
		{
			name:    "a bundled entry that brings a shrinkwrap, under a new name",
			base:    tree(reg("node_modules/a", "a", "1.0.0")),
			head:    tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/w", "w", "1.0.0"), shrinkwrapped(bundledIn("node_modules/w/node_modules/t", "t", "2.0.0"))),
			problem: "the bundled node_modules/w/node_modules/t is marked as bringing an npm-shrinkwrap.json (hasShrinkwrap), inside w@1.0.0",
		},
		{
			name: "a bundled entry that keeps its shrinkwrap inside a package that does not change",
			base: tree(reg("node_modules/w", "w", "1.0.0"), shrinkwrapped(bundledIn("node_modules/w/node_modules/t", "t", "2.0.0")), reg("node_modules/b", "b", "2.0.0")),
			head: tree(reg("node_modules/w", "w", "1.0.0"), shrinkwrapped(bundledIn("node_modules/w/node_modules/t", "t", "2.0.0")), reg("node_modules/b", "b", "2.0.1")),
			want: "b 2.0.0->2.0.1",
		},
		{
			name:    "a bundled entry gains the shrinkwrap flag inside a package that does not change",
			base:    tree(reg("node_modules/w", "w", "1.0.0"), bundledIn("node_modules/w/node_modules/t", "t", "2.0.0")),
			head:    tree(reg("node_modules/w", "w", "1.0.0"), shrinkwrapped(bundledIn("node_modules/w/node_modules/t", "t", "2.0.0"))),
			problem: "the bundled node_modules/w/node_modules/t changes inside w@1.0.0",
		},
		{
			name: "a bundler moves with what it bundles",
			base: tree(reg("node_modules/w", "w", "1.0.0"), bundledIn("node_modules/w/node_modules/t", "t", "2.0.0")),
			head: tree(reg("node_modules/w", "w", "1.0.1"), bundledIn("node_modules/w/node_modules/t", "t", "2.1.0"), bundledIn("node_modules/w/node_modules/@s/u", "@s/u", "1.0.0")),
			want: "w 1.0.0->1.0.1",
		},
		{
			// A bundled entry is its bundler's bytes. One that names a
			// source or a hash of its own is not, whether or not its
			// bundler moves.
			name: "a bundled entry with a source of its own, under a bundler that moves",
			base: tree(reg("node_modules/w", "w", "1.0.0"), bundledIn("node_modules/w/node_modules/t", "t", "2.0.0")),
			head: tree(reg("node_modules/w", "w", "1.0.1"), func() node {
				n := bundledIn("node_modules/w/node_modules/t", "t", "2.1.0")
				n.Resolved = artifact.NPMTarballURL("t", "2.1.0")
				return n
			}()),
			problem: "node_modules/w/node_modules/t is marked as bundled and has a source or a hash of its own",
		},
		{
			name: "a bundled entry with a hash of its own, under a bundler that moves",
			base: tree(reg("node_modules/w", "w", "1.0.0"), bundledIn("node_modules/w/node_modules/t", "t", "2.0.0")),
			head: tree(reg("node_modules/w", "w", "1.0.1"), func() node {
				n := bundledIn("node_modules/w/node_modules/t", "t", "2.1.0")
				n.Integrity = "sha512-t@2.1.0"
				return n
			}()),
			problem: "node_modules/w/node_modules/t is marked as bundled and has a source or a hash of its own",
		},
		{
			name: "a bundled entry with a source of its own, the same at base",
			base: tree(reg("node_modules/w", "w", "1.0.0"), func() node {
				n := bundledIn("node_modules/w/node_modules/t", "t", "2.0.0")
				n.Resolved, n.Integrity = artifact.NPMTarballURL("t", "2.0.0"), "sha512-t@2.0.0"
				return n
			}()),
			head: tree(reg("node_modules/w", "w", "1.0.0"), func() node {
				n := bundledIn("node_modules/w/node_modules/t", "t", "2.0.0")
				n.Resolved, n.Integrity = artifact.NPMTarballURL("t", "2.0.0"), "sha512-t@2.0.0"
				return n
			}()),
			problem: "node_modules/w/node_modules/t is marked as bundled and has a source or a hash of its own",
		},
		{
			name:    "a bundled entry changes inside a package that does not",
			base:    tree(reg("node_modules/w", "w", "1.0.0"), bundledIn("node_modules/w/node_modules/t", "t", "2.0.0")),
			head:    tree(reg("node_modules/w", "w", "1.0.0"), bundledIn("node_modules/w/node_modules/t", "t", "2.1.0")),
			problem: "the bundled node_modules/w/node_modules/t changes inside w@1.0.0",
		},
		{
			name:    "a bundled entry disappears from a package that does not change",
			base:    tree(reg("node_modules/w", "w", "1.0.0"), bundledIn("node_modules/w/node_modules/t", "t", "2.0.0")),
			head:    tree(reg("node_modules/w", "w", "1.0.0")),
			problem: "the bundled node_modules/w/node_modules/t disappears from w@1.0.0",
		},
		{
			name:    "an entry marked bundled at the top level",
			base:    tree(reg("node_modules/a", "a", "1.0.0")),
			head:    tree(reg("node_modules/a", "a", "1.0.0"), bundledIn("node_modules/t", "t", "2.0.0")),
			problem: "node_modules/t is marked as bundled but is inside no package",
		},
		{
			// A bundled name is not a dependency the base lock has a
			// source for, so the same name from the registry is new.
			name: "a name that was only bundled at base is a new name",
			base: tree(reg("node_modules/w", "w", "1.0.0"), bundledIn("node_modules/w/node_modules/t", "t", "2.0.0")),
			head: tree(reg("node_modules/w", "w", "1.0.0"), bundledIn("node_modules/w/node_modules/t", "t", "2.0.0"), reg("node_modules/t", "t", "2.0.0")),
			want: "t (new)->2.0.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updates, problems := diffTrees(tt.base, tt.head)
			if tt.problem != "" {
				if len(problems) != 1 || !strings.Contains(problems[0], tt.problem) {
					t.Fatalf("problems = %q, want one saying %q", problems, tt.problem)
				}
				return
			}
			if len(problems) != 0 {
				t.Fatalf("problems = %q, want none", problems)
			}
			var got []string
			for _, u := range updates {
				s := u.Name + " " + orNew(u.From) + "->" + u.To
				if u.NewName != (u.From == "") {
					t.Errorf("%s: NewName = %v with From %q", u.Name, u.NewName, u.From)
				}
				if len(u.New) == 0 || (u.From != "" && len(u.Old) == 0) {
					t.Errorf("%s: %d old and %d new lock entries", s, len(u.Old), len(u.New))
				}
				got = append(got, s)
			}
			if g := strings.Join(got, ", "); g != tt.want {
				t.Errorf("updates:\n got %s\nwant %s", g, tt.want)
			}
		})
	}
}

func TestSameButRanges(t *testing.T) {
	const base = `{"name":"app","version":"1.0.0","scripts":{"build":"x"},
		"dependencies":{"a":"^1.0.0","b":"2.0.0","c":"~3.1"},"devDependencies":{"d":">=4.0.0"}}`
	moved := map[string]bool{"a": true, "b": true, "c": true, "d": true}
	tests := []struct {
		name string
		head string
		// want is a piece of the difference reported; empty for none.
		want string
	}{
		{"identical", base, ""},
		{"key order does not matter", `{"version":"1.0.0","name":"app","scripts":{"build":"x"},"devDependencies":{"d":">=4.0.0"},"dependencies":{"c":"~3.1","b":"2.0.0","a":"^1.0.0"}}`, ""},
		{"caret range moves", strings.Replace(base, `"a":"^1.0.0"`, `"a":"^1.2.0"`, 1), ""},
		{"exact version moves", strings.Replace(base, `"b":"2.0.0"`, `"b":"2.0.1"`, 1), ""},
		{"short tilde range moves", strings.Replace(base, `"c":"~3.1"`, `"c":"~3.2"`, 1), ""},
		{"dev range moves", strings.Replace(base, `"d":">=4.0.0"`, `"d":">=4.1.0"`, 1), ""},
		{"operator changes", strings.Replace(base, `"a":"^1.0.0"`, `"a":"~1.2.0"`, 1), "by more than its version"},
		{"range becomes a union", strings.Replace(base, `"a":"^1.0.0"`, `"a":"^1.0.0 || ^2.0.0"`, 1), "by more than its version"},
		{"range becomes an alias", strings.Replace(base, `"b":"2.0.0"`, `"b":"npm:other@2.0.1"`, 1), "by more than its version"},
		{"range becomes a git reference", strings.Replace(base, `"b":"2.0.0"`, `"b":"github:x/y#2.0.1"`, 1), "by more than its version"},
		{"range becomes a tag", strings.Replace(base, `"b":"2.0.0"`, `"b":"latest"`, 1), "by more than its version"},
		{"range becomes a number", strings.Replace(base, `"b":"2.0.0"`, `"b":2`, 1), "by more than its version"},
		{"a dependency is added", strings.Replace(base, `"b":"2.0.0"`, `"b":"2.0.0","z":"1.0.0"`, 1), "adds z to dependencies"},
		{"a dependency is removed", strings.Replace(base, `"b":"2.0.0",`, ``, 1), "removes b from dependencies"},
		{"a dependency changes section", strings.Replace(strings.Replace(base, `"b":"2.0.0",`, ``, 1), `"d":">=4.0.0"`, `"d":">=4.0.0","b":"2.0.0"`, 1), "from dependencies"},
		{"a script changes", strings.Replace(base, `"build":"x"`, `"build":"y"`, 1), "changes scripts"},
		{"a key is added", strings.Replace(base, `"name":"app",`, `"name":"app","overrides":{"a":"9.9.9"},`, 1), "adds overrides"},
		{"a key is removed", strings.Replace(base, `"scripts":{"build":"x"},`, ``, 1), "removes scripts"},
		{"a section is added", strings.Replace(base, `"name":"app",`, `"name":"app","optionalDependencies":{"a":"1.0.0"},`, 1), "adds optionalDependencies"},
		{"a section becomes a list", strings.Replace(base, `"devDependencies":{"d":">=4.0.0"}`, `"devDependencies":["d"]`, 1), "changes devDependencies"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b, h map[string]any
			if err := json.Unmarshal([]byte(base), &b); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(tt.head), &h); err != nil {
				t.Fatal(err)
			}
			got := sameButRanges(b, h, moved)
			if tt.want == "" && got != "" {
				t.Errorf("sameButRanges = %q, want no difference", got)
			}
			if tt.want != "" && !strings.Contains(got, tt.want) {
				t.Errorf("sameButRanges = %q, want it to say %q", got, tt.want)
			}
		})
	}

	t.Run("a range may move only for a package the lock moves", func(t *testing.T) {
		var b, h map[string]any
		if err := json.Unmarshal([]byte(base), &b); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(strings.Replace(base, `"a":"^1.0.0"`, `"a":"^1.2.0"`, 1)), &h); err != nil {
			t.Fatal(err)
		}
		if got := sameButRanges(b, h, map[string]bool{"b": true}); !strings.Contains(got, "a package the lock does not move") {
			t.Errorf("sameButRanges = %q", got)
		}
	})
}

// Indirect is read from the lock's root entry (spec section 11, amendment
// 23): a package the root names in none of its dependency maps, at head
// or at base, under its own name or the name it is installed as.
func TestDeclared(t *testing.T) {
	root := func(s string) map[string]any {
		var m map[string]any
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	plain := root(`{"name":"app","dependencies":{"a":"^1.0.0"},"devDependencies":{"b":"^2.0.0"}}`)
	moved := func(name string, paths ...string) update {
		u := update{Name: name, From: "1.0.0", To: "2.0.0"}
		for _, p := range paths {
			u.Old = append(u.Old, reg(p, name, "1.0.0"))
			u.New = append(u.New, reg(p, name, "2.0.0"))
		}
		return u
	}
	tests := []struct {
		name       string
		u          update
		base, head map[string]any
		want       string // "" for a package the root does not declare
	}{
		{"a dependency of a dependency", moved("deep", "node_modules/deep"), plain, plain, ""},
		{"nested under its parent", moved("deep", "node_modules/a/node_modules/deep"), plain, plain, ""},
		{"a new name the root does not declare", update{Name: "deep", To: "1.0.0", NewName: true, New: []node{reg("node_modules/deep", "deep", "1.0.0")}}, plain, plain, ""},
		{"in dependencies", moved("a", "node_modules/a"), plain, plain, "in dependencies at head"},
		{"in devDependencies", moved("b", "node_modules/b"), plain, plain, "in devDependencies at head"},
		{"in optionalDependencies", moved("c", "node_modules/c"), plain, root(`{"optionalDependencies":{"c":"^1.0.0"}}`), "in optionalDependencies at head"},
		{"in peerDependencies", moved("c", "node_modules/c"), plain, root(`{"peerDependencies":{"c":"*"}}`), "in peerDependencies at head"},
		{"declared at base only", moved("c", "node_modules/c"), root(`{"dependencies":{"c":"^1.0.0"}}`), plain, "in dependencies at base"},
		{"a root with no dependencies at all", moved("deep", "node_modules/deep"), root(`{"name":"app"}`), root(`{"name":"app"}`), ""},
		// The same name as a declared package, at another place in the
		// tree, is still the declared name: the gate does not say which
		// copy the root's range picks.
		{"a second copy of a declared name, nested", moved("a", "node_modules/x/node_modules/a"), plain, plain, "in dependencies at head"},
		// An alias is declared under the name it is installed as.
		{"declared under an alias", moved("real", "node_modules/alias"), plain, root(`{"dependencies":{"alias":"npm:real@^1.0.0"}}`), "in dependencies at head"},
		// Names are compared exactly.
		{"a name that only resembles a declared one", moved("a-b", "node_modules/a-b"), plain, plain, ""},
		{"a scope is part of the name", moved("@a/a", "node_modules/@a/a"), plain, plain, ""},
		// A map that cannot be read declares everything.
		{"dependencies is a list", moved("deep", "node_modules/deep"), plain, root(`{"dependencies":["deep"]}`), "dependencies at head is not an object"},
		{"devDependencies is null at base", moved("deep", "node_modules/deep"), root(`{"devDependencies":null}`), plain, "devDependencies at base is not an object"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := declared(tt.u, tt.base, tt.head); got != tt.want {
				t.Errorf("declared = %q, want %q", got, tt.want)
			}
			if f := indirectFact(tt.u, tt.base, tt.head); !f.Gathered() || f.OK != (tt.want == "") || !strings.Contains(f.Value, tt.want) {
				t.Errorf("Indirect = %+v, want a gathered %v saying %q", f, tt.want == "", tt.want)
			}
		})
	}
	// An update nobody looked the root entries up for is not indirect:
	// the fact has to be made, it is never what is left over.
	if f := lockFacts(moved("deep", "node_modules/deep"), testPolicy(), "npm").Indirect; f != (allow.Fact{}) {
		t.Errorf("Indirect of an update without one = %+v, want no fact at all", f)
	}
}

func TestInstalledName(t *testing.T) {
	tests := map[string]string{
		"node_modules/a":                        "a",
		"node_modules/@s/a":                     "@s/a",
		"node_modules/x/node_modules/a":         "a",
		"node_modules/x/node_modules/@s/a":      "@s/a",
		"packages/a":                            "",
		"":                                      "",
		"not_node_modules/a":                    "",
		"packages/x/node_modules/a":             "a",
		"node_modules/x/not_node_modules/thing": "",
	}
	for lockPath, want := range tests {
		if got := installedName(lockPath); got != want {
			t.Errorf("installedName(%q) = %q, want %q", lockPath, got, want)
		}
	}
}

func TestBundler(t *testing.T) {
	nodes := tree(
		reg("node_modules/w", "w", "1.0.0"),
		node{Path: "node_modules/w/node_modules/t", Name: "t", Version: "1.0.0", InBundle: true},
		node{Path: "node_modules/w/node_modules/t/node_modules/u", Name: "u", Version: "1.0.0", InBundle: true},
	)
	for lockPath, want := range map[string]string{
		"node_modules/w/node_modules/t":                "node_modules/w",
		"node_modules/w/node_modules/t/node_modules/u": "node_modules/w",
		"node_modules/w":                               "",
		"node_modules/z/node_modules/t":                "",
	} {
		got, ok := bundler(nodes, lockPath)
		if got.Path != want || ok != (want != "") {
			t.Errorf("bundler(%q) = %q, %v; want %q", lockPath, got.Path, ok, want)
		}
	}
}

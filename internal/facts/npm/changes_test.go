package npm

import (
	"strings"
	"testing"

	json "encoding/json/v2"
)

// reg builds a registry entry at a lock path, with a hash that stands for
// "the bytes of this name and version".
func reg(lockPath, name, version string) node {
	return node{
		Path: lockPath, Name: name, Version: version,
		Resolved:  tarballURL(name, version),
		Integrity: "sha512-" + name + "@" + version,
	}
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
			name: "two paths with different old versions move to one new version",
			base: tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/x/node_modules/a", "a", "1.1.0")),
			head: tree(reg("node_modules/a", "a", "1.2.0"), reg("node_modules/x/node_modules/a", "a", "1.2.0")),
			want: "a 1.0.0->1.2.0, a 1.1.0->1.2.0",
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
			name: "a new nested copy is measured against the one version the base had",
			base: tree(reg("node_modules/a", "a", "1.0.0")),
			head: tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/x/node_modules/a", "a", "2.0.0")),
			want: "a 1.0.0->2.0.0",
		},
		{
			name: "a copy at a new path replaces the one base version that is gone",
			base: tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/x/node_modules/a", "a", "3.0.0")),
			head: tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/y/node_modules/a", "a", "2.0.0")),
			want: "a 3.0.0->2.0.0",
		},
		{
			// Nothing says which of 1.0.0 and 3.0.0 the new 2.0.0 stands
			// in for, so it is measured against the highest.
			name: "a copy at a new path with nothing gone is measured against the highest base version",
			base: tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/x/node_modules/a", "a", "3.0.0")),
			head: tree(reg("node_modules/a", "a", "1.0.0"), reg("node_modules/x/node_modules/a", "a", "3.0.0"), reg("node_modules/y/node_modules/a", "a", "2.0.0")),
			want: "a 3.0.0->2.0.0",
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
				n.Integrity = "sha512-other"
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
				return n
			}()),
			problem: "a@1.0.0 at node_modules/a keeps its version",
		},
		{
			name: "a bundler moves with what it bundles",
			base: tree(reg("node_modules/w", "w", "1.0.0"), bundledIn("node_modules/w/node_modules/t", "t", "2.0.0")),
			head: tree(reg("node_modules/w", "w", "1.0.1"), bundledIn("node_modules/w/node_modules/t", "t", "2.1.0"), bundledIn("node_modules/w/node_modules/@s/u", "@s/u", "1.0.0")),
			want: "w 1.0.0->1.0.1 bundles @s/u,t",
		},
		{
			name: "a bundler only declares that it bundles",
			base: tree(reg("node_modules/w", "w", "1.0.0")),
			head: tree(func() node {
				n := reg("node_modules/w", "w", "1.0.1")
				n.Bundles = true
				return n
			}()),
			want: "w 1.0.0->1.0.1 bundles (declared)",
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
				if len(u.Bundled) > 0 {
					s += " bundles " + strings.Join(u.Bundled, ",")
				}
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

func TestUnpairedFrom(t *testing.T) {
	tests := []struct {
		base, head []string
		want       string
	}{
		{[]string{"1.0.0"}, []string{"1.0.0", "2.0.0"}, "1.0.0"},
		{[]string{"1.0.0", "3.0.0"}, []string{"1.0.0", "2.0.0"}, "3.0.0"},
		{[]string{"1.0.0", "3.0.0"}, []string{"1.0.0", "2.0.0", "3.0.0"}, "3.0.0"},
		{[]string{"1.2.0", "1.10.0", "1.9.0"}, []string{"2.0.0"}, "1.10.0"},
		// A version that cannot be ranked is chosen, so Increase fails.
		{[]string{"1.0.0", "not-a-version"}, []string{"2.0.0"}, "not-a-version"},
	}
	for _, tt := range tests {
		if got := unpairedFrom(tt.base, tt.head); got != tt.want {
			t.Errorf("unpairedFrom(%v, %v) = %q, want %q", tt.base, tt.head, got, tt.want)
		}
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

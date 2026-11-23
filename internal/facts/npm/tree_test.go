package npm

import (
	"encoding/json/jsontext"
	"strings"
	"testing"
)

func recordedTree(t *testing.T, name, side string) (map[string]node, []string) {
	t.Helper()
	rec := readRecorded(t, name, side)
	return readTree(side, lsOutput{Stdout: rec.Stdout, Exit: rec.Exit})
}

func TestReadTreeRecorded(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		nodes, problems := recordedTree(t, "plain", "head")
		if len(problems) != 0 {
			t.Fatalf("problems: %q", problems)
		}
		want := node{
			Path: "node_modules/core-js", Name: "core-js", Version: "3.38.1",
			Resolved:         "https://registry.npmjs.org/core-js/-/core-js-3.38.1.tgz",
			Integrity:        "sha512-OP35aUorbU3Zvlx7pjsFdu1rGNnD4pgw/CWoYzRY3t2EzoVT7shKHY1dlAy3f41cGIO7ZDPQimhGFTlEYkG/Hw==",
			HasInstallScript: true,
		}
		if got := nodes["node_modules/core-js"]; got != want {
			t.Errorf("core-js:\n got %+v\nwant %+v", got, want)
		}
		if len(nodes) != 5 {
			t.Errorf("%d nodes, want 5", len(nodes))
		}
		// @kurkle/color is printed below chart.js, and is still keyed by
		// its own lock path.
		if got := nodes["node_modules/@kurkle/color"]; got.Name != "@kurkle/color" || got.Version != "0.3.4" {
			t.Errorf("@kurkle/color = %+v", got)
		}
	})

	t.Run("bundled", func(t *testing.T) {
		nodes, problems := recordedTree(t, "bundled", "head")
		if len(problems) != 0 {
			t.Fatalf("problems: %q", problems)
		}
		parent := nodes["node_modules/@tailwindcss/oxide-wasm32-wasi"]
		if parent.InBundle || !parent.Bundles || parent.Integrity == "" {
			t.Errorf("bundler = %+v, want a registry entry that declares bundled dependencies", parent)
		}
		inside := nodes["node_modules/@tailwindcss/oxide-wasm32-wasi/node_modules/tslib"]
		if !inside.InBundle || inside.Resolved != "" || inside.Integrity != "" || inside.Version != "2.8.1" {
			t.Errorf("bundled entry = %+v, want inBundle with no source or hash", inside)
		}
	})

	// What npm prints for the sources the gate has no rule for.
	t.Run("special", func(t *testing.T) {
		nodes, problems := recordedTree(t, "special", "head")
		alias := nodes["node_modules/aliased"]
		if alias.Name != "is-number" || installedName(alias.Path) == alias.Name {
			t.Errorf("alias = %+v, want the real package's name at the alias's path", alias)
		}
		git := nodes["node_modules/gitdep"]
		if !strings.HasPrefix(git.Resolved, "git+ssh://") || git.Integrity != "" {
			t.Errorf("git dependency = %+v", git)
		}
		// The workspace is a link to packages/a, which npm reports as
		// extraneous when the directory is not there; the lock's own
		// "packages/a" entry is never printed.
		if len(problems) == 0 || !strings.Contains(strings.Join(problems, "\n"), "extraneous") {
			t.Errorf("problems = %q, want the workspace link reported", problems)
		}
		lock, problem := readLock(loadCase(t, "special").headLock)
		if problem != "" {
			t.Fatal(problem)
		}
		notPrinted, notInLock := unlisted(lock, nodes)
		if len(notPrinted) != 1 || notPrinted[0] != "packages/a" || len(notInLock) != 0 {
			t.Errorf("unlisted = %q, %q; want packages/a not printed", notPrinted, notInLock)
		}
	})

	// npm copies unknown lock fields into its output. The reader takes
	// "integrity" and nothing that only looks like it.
	t.Run("casekeys", func(t *testing.T) {
		rec := readRecorded(t, "casekeys", "head")
		if !strings.Contains(string(rec.Stdout), `"Integrity": "sha512-AAAA`) {
			t.Fatal("the recorded output no longer has the look-alike field; the case tests nothing")
		}
		nodes, problems := recordedTree(t, "casekeys", "head")
		if len(problems) != 0 {
			t.Fatalf("problems: %q", problems)
		}
		plain, _ := recordedTree(t, "plain", "head")
		if nodes["node_modules/chart.js"] != plain["node_modules/chart.js"] {
			t.Errorf("chart.js read as %+v, want the same as without the look-alike fields: %+v", nodes["node_modules/chart.js"], plain["node_modules/chart.js"])
		}
	})

	// npm prints only what the root reaches: the extra entry is not there.
	t.Run("unreachable", func(t *testing.T) {
		nodes, problems := recordedTree(t, "unreachable", "head")
		if len(problems) != 0 {
			t.Fatalf("problems: %q", problems)
		}
		if _, ok := nodes["node_modules/zzz"]; ok {
			t.Fatal("npm now prints an entry nothing depends on; the lock-key check may no longer be needed")
		}
		lock, _ := readLock(loadCase(t, "unreachable").headLock)
		notPrinted, _ := unlisted(lock, nodes)
		if len(notPrinted) != 1 || notPrinted[0] != "node_modules/zzz" {
			t.Errorf("not printed = %q, want node_modules/zzz", notPrinted)
		}
	})
}

func TestReadTreeProblems(t *testing.T) {
	const root = `"name":"app","version":"1.0.0","path":"/scratch/project"`
	entry := func(lockPath, extra string) string {
		name := installedName(lockPath)
		return `"` + name + `":{"name":"` + name + `","version":"1.0.0","path":"/scratch/project/` + lockPath + `"` + extra + `}`
	}
	tests := []struct {
		name string
		out  lsOutput
		// want is a piece of a problem; empty means no problem at all.
		want string
	}{
		{"clean", lsOutput{Stdout: []byte(`{` + root + `,"dependencies":{` + entry("node_modules/a", "") + `}}`)}, ""},
		{"no dependencies", lsOutput{Stdout: []byte(`{` + root + `}`)}, ""},
		{"truncated", lsOutput{Stdout: []byte(`{`), Truncated: true}, "printed more than"},
		{"not JSON", lsOutput{Stdout: []byte(`npm error`), Exit: 1}, "did not print a tree the gate can read"},
		{"empty", lsOutput{Exit: 1}, "did not print a tree the gate can read"},
		{"duplicate name", lsOutput{Stdout: []byte(`{` + root + `,"version":"2.0.0"}`)}, "did not print a tree the gate can read"},
		{"error object", lsOutput{Stdout: []byte(`{"error":{"code":"ENOLOCK","summary":"This command requires an existing lockfile."}}`), Exit: 1}, "npm ls failed: ENOLOCK"},
		{"error object with an odd code", lsOutput{Stdout: []byte(`{"error":{"code":"<b>hi</b>"}}`), Exit: 1}, "npm ls failed: an error without a code"},
		{"exit status alone", lsOutput{Stdout: []byte(`{` + root + `}`), Exit: 1}, "npm ls exited with status 1"},
		{"problems at the root", lsOutput{Stdout: []byte(`{` + root + `,"problems":["extraneous: x@1.0.0 /scratch/project/node_modules/x"]}`)}, "npm reports problems with the lock"},
		{"no project path", lsOutput{Stdout: []byte(`{"name":"app"}`)}, "printed no project path"},
		{"missing dependency", lsOutput{Stdout: []byte(`{` + root + `,"dependencies":{"a":{"required":"^1.0.0","missing":true}}}`)}, "the dependency a is missing from the lock"},
		{"extraneous", lsOutput{Stdout: []byte(`{` + root + `,"dependencies":{` + entry("node_modules/a", `,"extraneous":true`) + `}}`)}, "node_modules/a is extraneous"},
		{"invalid", lsOutput{Stdout: []byte(`{` + root + `,"dependencies":{` + entry("node_modules/a", `,"invalid":"\"2.0.0\" from the root project"`) + `}}`)}, "node_modules/a does not satisfy what depends on it"},
		{"scripts in the entry", lsOutput{Stdout: []byte(`{` + root + `,"dependencies":{` + entry("node_modules/a", `,"scripts":{"postinstall":"x"}`) + `}}`)}, "node_modules/a carries scripts"},
		{"path outside the project", lsOutput{Stdout: []byte(`{` + root + `,"dependencies":{"a":{"name":"a","version":"1.0.0","path":"/scratch/outside"}}}`)}, "outside the project"},
		{"path with the project as a mere prefix", lsOutput{Stdout: []byte(`{` + root + `,"dependencies":{"a":{"name":"a","version":"1.0.0","path":"/scratch/project-other/node_modules/a"}}}`)}, "outside the project"},
		{"no version", lsOutput{Stdout: []byte(`{` + root + `,"dependencies":{"a":{"name":"a","path":"/scratch/project/node_modules/a"}}}`)}, "has no name or version"},
		{"null dependency", lsOutput{Stdout: []byte(`{` + root + `,"dependencies":{"a":null}}`)}, "npm printed no package for the dependency a"},
		{"a flag that is not a boolean", lsOutput{Stdout: []byte(`{` + root + `,"dependencies":{` + entry("node_modules/a", `,"inBundle":"yes"`) + `}}`)}, "did not print a tree the gate can read"},
		{"a name that is not a string", lsOutput{Stdout: []byte(`{` + root + `,"dependencies":{"a":{"name":["a"],"version":"1.0.0","path":"/scratch/project/node_modules/a"}}}`)}, "did not print a tree the gate can read"},
		{"one path printed twice, differently", lsOutput{Stdout: []byte(`{` + root + `,"dependencies":{` +
			entry("node_modules/a", `,"dependencies":{`+entry("node_modules/b", `,"integrity":"sha512-one"`)+`}`) + `,` +
			entry("node_modules/b", `,"integrity":"sha512-two"`) + `}}`)}, "npm printed node_modules/b twice with different contents"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, problems := readTree("head", tt.out)
			joined := strings.Join(problems, "\n")
			if tt.want == "" && len(problems) != 0 {
				t.Errorf("problems = %q, want none", problems)
			}
			if tt.want != "" && !strings.Contains(joined, tt.want) {
				t.Errorf("problems = %q, want one saying %q", problems, tt.want)
			}
			for _, p := range problems {
				if !strings.HasPrefix(p, "head: ") {
					t.Errorf("problem %q does not say which side it is about", p)
				}
			}
		})
	}

	// The same path printed twice with the same contents is how npm
	// prints a package two others depend on.
	t.Run("one path printed twice, the same", func(t *testing.T) {
		out := lsOutput{Stdout: []byte(`{` + root + `,"dependencies":{` +
			entry("node_modules/a", `,"overridden":false,"dependencies":{`+entry("node_modules/b", "")+`}`) + `,` +
			entry("node_modules/b", `,"overridden":false`) + `}}`)}
		nodes, problems := readTree("head", out)
		if len(problems) != 0 || len(nodes) != 2 {
			t.Errorf("nodes = %v, problems = %q", nodes, problems)
		}
	})
}

func TestReadLock(t *testing.T) {
	tests := []struct {
		name string
		lock string
		// want is a piece of the problem; empty means the lock is read.
		want string
	}{
		{"version 3", `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/a":{"version":"1.0.0"}}}`, ""},
		{"version 2", `{"lockfileVersion":2,"packages":{"":{"name":"app"}},"dependencies":{}}`, ""},
		{"version 1", `{"lockfileVersion":1,"dependencies":{}}`, `lockfileVersion "1"`},
		{"version 4", `{"lockfileVersion":4,"packages":{"":{}}}`, `lockfileVersion "4"`},
		{"version as a string", `{"lockfileVersion":"3","packages":{"":{}}}`, "lockfileVersion"},
		{"version as a float", `{"lockfileVersion":3.0,"packages":{"":{}}}`, "lockfileVersion"},
		{"no version", `{"packages":{"":{}}}`, "lockfileVersion"},
		{"no packages", `{"lockfileVersion":3}`, "no root entry"},
		{"no root entry", `{"lockfileVersion":3,"packages":{"node_modules/a":{}}}`, "no root entry"},
		{"root entry is not an object", `{"lockfileVersion":3,"packages":{"":[]}}`, "root entry is not an object"},
		{"root entry is null", `{"lockfileVersion":3,"packages":{"":null}}`, "root entry is not an object"},
		{"duplicate lockfileVersion", `{"lockfileVersion":1,"lockfileVersion":3,"packages":{"":{}}}`, "not JSON the gate can read"},
		{"duplicate package key", `{"lockfileVersion":3,"packages":{"":{},"node_modules/a":{},"node_modules/a":{}}}`, "not JSON the gate can read"},
		{"a yarn.lock", "# yarn lockfile v1\n\nleft-pad@1.3.0:\n  version \"1.3.0\"\n", "not JSON the gate can read"},
		{"truncated", `{"lockfileVersion":3,`, "not JSON the gate can read"},
		{"trailing data", `{"lockfileVersion":3,"packages":{"":{}}} {}`, "not JSON the gate can read"},
		{"an array", `[]`, "not JSON the gate can read"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lock, problem := readLock([]byte(tt.lock))
			if tt.want == "" {
				if problem != "" {
					t.Fatalf("problem = %q, want the lock to be read", problem)
				}
				if lock.Version != 2 && lock.Version != 3 {
					t.Errorf("Version = %d", lock.Version)
				}
				return
			}
			if !strings.Contains(problem, tt.want) {
				t.Errorf("problem = %q, want it to say %q", problem, tt.want)
			}
		})
	}

	lock, problem := readLock([]byte(`{"lockfileVersion":3,"packages":{"node_modules/b":{},"":{"dependencies":{"a":"1"}},"node_modules/a":{}}}`))
	if problem != "" {
		t.Fatal(problem)
	}
	if got := strings.Join(lock.Keys, " "); got != "node_modules/a node_modules/b" {
		t.Errorf("Keys = %q, want the sorted keys without the root's", got)
	}
	if _, ok := lock.Root["dependencies"]; !ok {
		t.Errorf("Root = %v, want the root entry", lock.Root)
	}
}

func TestPresentAndDeclaresBundle(t *testing.T) {
	tests := []struct {
		raw             string
		present, bundle bool
	}{
		{"", false, false},
		{"null", false, false},
		{"false", false, false},
		{"[]", true, false},
		{"[ ]", true, false},
		{"true", true, true},
		{`["a"]`, true, true},
		{`"a"`, true, true},
		{"{}", true, true},
		{"0", true, true},
	}
	for _, tt := range tests {
		if got := present(jsontext.Value(tt.raw)); got != tt.present {
			t.Errorf("present(%q) = %v, want %v", tt.raw, got, tt.present)
		}
		if got := declaresBundle(jsontext.Value(tt.raw)); got != tt.bundle {
			t.Errorf("declaresBundle(%q) = %v, want %v", tt.raw, got, tt.bundle)
		}
	}
}

package npm

import (
	"encoding/json/jsontext"
	"maps"
	"slices"
	"strings"
	"testing"
)

// recordedTree reads a case's recorded npm output beside the lock it was
// made from, as readChangeSet does. A lock the gate does not read (the
// lockv1, casekeys and lockscripts cases) leaves every Fixed empty.
func recordedTree(t *testing.T, name, side string) (map[string]node, []string) {
	t.Helper()
	rec := readRecorded(t, name, side)
	c := loadCase(t, name)
	lock, _ := readLock(map[string][]byte{"base": c.baseLock, "head": c.headLock}[side])
	return readTree(side, lsOutput{Stdout: rec.Stdout, Exit: rec.Exit}, lock)
}

func TestReadTreeRecorded(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		nodes, problems := recordedTree(t, "plain", "head")
		if len(problems) != 0 {
			t.Fatalf("problems: %q", problems)
		}
		const resolved = "https://registry.npmjs.org/core-js/-/core-js-3.38.1.tgz"
		const integrity = "sha512-OP35aUorbU3Zvlx7pjsFdu1rGNnD4pgw/CWoYzRY3t2EzoVT7shKHY1dlAy3f41cGIO7ZDPQimhGFTlEYkG/Hw=="
		want := node{
			Path: "node_modules/core-js", Name: "core-js", Version: "3.38.1",
			Resolved: resolved, Integrity: integrity, HasInstallScript: true,
			// The members that decide what is installed, by name, in the
			// lock's own JSON. "dev", "funding" and "license" are not
			// among them.
			Fixed: "hasInstallScript=true\nintegrity=\"" + integrity + "\"\nresolved=\"" + resolved + "\"\nversion=\"3.38.1\"\n",
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
		if parent.InBundle || !strings.Contains(parent.Fixed, `bundleDependencies=["@napi-rs/wasm-runtime","@emnapi/core",`) || parent.Integrity == "" {
			t.Errorf("bundler = %+v, want a registry entry that declares bundled dependencies", parent)
		}
		inside := nodes["node_modules/@tailwindcss/oxide-wasm32-wasi/node_modules/tslib"]
		if !inside.InBundle || inside.Resolved != "" || inside.Integrity != "" || inside.Version != "2.8.1" || inside.Fixed != "inBundle=true\nversion=\"2.8.1\"\n" {
			t.Errorf("bundled entry = %+v, want inBundle with no source or hash", inside)
		}
	})

	// What npm prints for the sources the gate has no rule for.
	t.Run("special", func(t *testing.T) {
		nodes, problems := recordedTree(t, "special", "head")
		alias := nodes["node_modules/aliased"]
		if alias.Name != "is-number" || installedName(alias.Path) == alias.Name || !strings.Contains(alias.Fixed, `name="is-number"`) {
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

	// npm copies unknown lock fields into its output, which is why the
	// lock's own set of members is closed. The reader of npm's output
	// takes "integrity" and nothing that only looks like it.
	t.Run("casekeys", func(t *testing.T) {
		rec := readRecorded(t, "casekeys", "head")
		if !strings.Contains(string(rec.Stdout), `"Integrity": "sha512-AAAA`) {
			t.Fatal("the recorded output no longer has the look-alike field; the case tests nothing")
		}
		if _, problem := readLock(loadCase(t, "casekeys").headLock); !strings.Contains(problem, "node_modules/chart.js has a member npm does not write, Integrity") {
			t.Errorf("readLock = %q, want the look-alike member refused", problem)
		}
		nodes, problems := readTree("head", lsOutput{Stdout: rec.Stdout, Exit: rec.Exit}, lockFile{})
		if len(problems) != 0 {
			t.Fatalf("problems: %q", problems)
		}
		plain, _ := readTree("head", lsOutput{Stdout: readRecorded(t, "plain", "head").Stdout}, lockFile{})
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
		{"error object", lsOutput{Stdout: []byte(`{"error":{"code":"ENOLOCK","summary":"This command requires an existing lockfile."}}`), Exit: 1}, `npm ls failed: "{\"code\":\"ENOLOCK\",`},
		{"exit status alone", lsOutput{Stdout: []byte(`{` + root + `}`), Exit: 1}, "npm ls exited with status 1"},
		{"problems at the root", lsOutput{Stdout: []byte(`{` + root + `,"problems":["extraneous: x@1.0.0 /scratch/project/node_modules/x"]}`)}, "npm reports problems with the lock"},
		{"no project path", lsOutput{Stdout: []byte(`{"name":"app"}`)}, "printed no project path"},
		{"missing dependency", lsOutput{Stdout: []byte(`{` + root + `,"dependencies":{"a":{"required":"^1.0.0","missing":true}}}`)}, "the dependency a is missing from the lock"},
		{"extraneous", lsOutput{Stdout: []byte(`{` + root + `,"dependencies":{` + entry("node_modules/a", `,"extraneous":true`) + `}}`)}, "node_modules/a is extraneous"},
		{"invalid", lsOutput{Stdout: []byte(`{` + root + `,"dependencies":{` + entry("node_modules/a", `,"invalid":"\"2.0.0\" from the root project"`) + `}}`)}, "node_modules/a does not satisfy what depends on it"},
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
			_, problems := readTree("head", tt.out, lockFile{})
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
		nodes, problems := readTree("head", out, lockFile{})
		if len(problems) != 0 || len(nodes) != 2 {
			t.Errorf("nodes = %v, problems = %q", nodes, problems)
		}
	})
}

// npm names the packages of a broken tree by absolute path. The problem
// that quotes npm becomes the Shape fact's Value, which is shown on the
// pull request, so the run's scratch directory is taken out of it.
func TestReadTreeHidesTheScratchDirectory(t *testing.T) {
	// A directory of the length a runner has, which is most of the 160
	// bytes a quoted text keeps.
	const (
		scratch = "/var/folders/zz/0123456789abcdefghijklmnopqrstuv/T/dep-review-npm-1234567890"
		project = scratch + "/project"
		lockKey = "node_modules/@example/plugin/node_modules/widget"
	)
	failed := func(projectPath, mention string) lsOutput {
		return lsOutput{Exit: 1, Scratch: scratch, Stdout: []byte(`{"name":"app","version":"1.0.0","path":"` + projectPath + `",` +
			`"problems":["invalid: widget@1.0.0 ` + mention + `/` + lockKey + `"],` +
			`"error":{"code":"ELSPROBLEMS","summary":"invalid: widget@1.0.0 ` + mention + `/` + lockKey + `","detail":"see ` + scratch + `/home/cache/_logs"}}`)}
	}
	tests := []struct {
		name string
		out  lsOutput
	}{
		{"npm prints the directory as the gate made it", failed(project, project)},
		// A temporary directory behind a symbolic link has two names, and
		// npm may print the other one for the root and for every path.
		{"npm prints another spelling of the directory", failed("/private"+project, "/private"+project)},
		{"npm prints one spelling for the root and the other in its message", failed("/private"+project, project)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, problems := readTree("base", tt.out, lockFile{})
			joined := strings.Join(problems, "\n")
			for _, trace := range []string{"dep-review-npm", "/var/folders", "/private", "0123456789abcdef"} {
				if strings.Contains(joined, trace) {
					t.Errorf("problems name the scratch directory (%s): %q", trace, problems)
				}
			}
			// What is left is the lock's own key, whole: the path no
			// longer pushes it past the cut.
			for _, want := range []string{
				`base: npm ls failed: "{\"code\":\"ELSPROBLEMS\",\"summary\":\"invalid: widget@1.0.0 ` + lockKey + `\",`,
				`base: npm reports problems with the lock: "[\"invalid: widget@1.0.0 ` + lockKey + `\"]"`,
			} {
				if !strings.Contains(joined, want) {
					t.Errorf("problems = %q, want one with %q", problems, want)
				}
			}
		})
	}

	// npm's home is in the scratch directory too, beside the project.
	t.Run("a path beside the project", func(t *testing.T) {
		out := lsOutput{Exit: 1, Scratch: scratch, Stdout: []byte(`{"error":{"code":"EACCES","summary":"open ` + scratch + `/home/cache/x"}}`)}
		_, problems := readTree("head", out, lockFile{})
		if got := strings.Join(problems, "\n"); !strings.Contains(got, `open (scratch)/home/cache/x`) || strings.Contains(got, "dep-review-npm") {
			t.Errorf("problems = %q", problems)
		}
	})

	// Recorded output has no scratch directory of this run. The root's
	// own path still says where the project was.
	t.Run("recorded output", func(t *testing.T) {
		rec := readRecorded(t, "outofsync", "head")
		_, problems := readTree("head", lsOutput{Stdout: rec.Stdout, Exit: rec.Exit}, lockFile{})
		const want = `head: npm ls failed: "{\"code\":\"ELSPROBLEMS\",\"summary\":\"invalid: chart.js@4.4.5 node_modules/chart.js\",`
		if got := strings.Join(problems, "\n"); !strings.Contains(got, want) || strings.Contains(got, scratchPath) {
			t.Errorf("problems = %q, want one with %q and none with %s", problems, want, scratchPath)
		}
	})
}

func TestHideScratch(t *testing.T) {
	const scratch, project = "/tmp/dep-review-npm-1", "/tmp/dep-review-npm-1/project"
	tests := []struct{ text, scratch, project, want string }{
		{"extraneous: x@1.0.0 " + project + "/node_modules/x", scratch, project, "extraneous: x@1.0.0 node_modules/x"},
		{"invalid: app@1.0.0 " + project, scratch, project, "invalid: app@1.0.0 (scratch)/project"},
		{"open " + scratch + "/home/cache/x", scratch, project, "open (scratch)/home/cache/x"},
		// One of the two names is enough to find the paths below the
		// project that carry it.
		{"extraneous: x@1.0.0 " + project + "/node_modules/x", scratch, "", "extraneous: x@1.0.0 node_modules/x"},
		{"extraneous: x@1.0.0 " + project + "/node_modules/x", "", project, "extraneous: x@1.0.0 node_modules/x"},
		{"extraneous: x@1.0.0 /private" + project + "/node_modules/x", scratch, "/private" + project, "extraneous: x@1.0.0 node_modules/x"},
		// Neither is known, or what npm printed for the root is no
		// absolute path: nothing is taken out.
		{"extraneous: x@1.0.0 " + project + "/node_modules/x", "", "", "extraneous: x@1.0.0 " + project + "/node_modules/x"},
		{"a/b: invalid a/b", "", "a", "a/b: invalid a/b"},
	}
	for _, tc := range tests {
		if got := hideScratch(tc.text, tc.scratch, tc.project); got != tc.want {
			t.Errorf("hideScratch(%q, %q, %q) = %q, want %q", tc.text, tc.scratch, tc.project, got, tc.want)
		}
	}
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
		{"an entry that is a list", `{"lockfileVersion":3,"packages":{"":{},"node_modules/a":[]}}`, "the lock entry node_modules/a is not an object"},
		{"an entry that is null", `{"lockfileVersion":3,"packages":{"":{},"node_modules/a":null}}`, "the lock entry node_modules/a is not an object"},
		{"an entry with a member twice", `{"lockfileVersion":3,"packages":{"":{},"node_modules/a":{"version":"1.0.0","version":"2.0.0"}}}`, "not JSON the gate can read"},
		{"an entry with scripts", `{"lockfileVersion":3,"packages":{"":{},"node_modules/a":{"version":"1.0.0","scripts":{"postinstall":"x"}}}}`, "the lock entry node_modules/a has a member npm does not write, scripts"},
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
	if got := strings.Join(slices.Sorted(maps.Keys(lock.Fixed)), " "); got != "node_modules/a node_modules/b" {
		t.Errorf("entries = %q, want every key but the root's", got)
	}
	if _, ok := lock.Root["dependencies"]; !ok {
		t.Errorf("Root = %v, want the root entry", lock.Root)
	}
}

// The lock's own set of members is closed, and one table says which of
// them an entry that keeps its version must keep: all but the eight that
// have a reason outside the package to differ.
func TestEntryKeys(t *testing.T) {
	base := map[string]string{
		"version":   `"1.0.0"`,
		"resolved":  `"https://registry.npmjs.org/a/-/a-1.0.0.tgz"`,
		"integrity": `"sha512-one"`,
		"license":   `"MIT"`,
	}
	// fixed reads a lock whose one entry is base with one member set.
	fixed := func(member, value string) (string, string) {
		entry := maps.Clone(base)
		if member != "" {
			entry[member] = value
		}
		var parts []string
		for _, k := range slices.Sorted(maps.Keys(entry)) {
			parts = append(parts, `"`+k+`":`+entry[k])
		}
		lock, problem := readLock([]byte(`{"lockfileVersion":3,"packages":{"":{},"node_modules/a":{` + strings.Join(parts, ",") + `}}}`))
		return lock.Fixed["node_modules/a"], problem
	}
	unchanged, problem := fixed("", "")
	if problem != "" || unchanged != "integrity=\"sha512-one\"\nresolved=\"https://registry.npmjs.org/a/-/a-1.0.0.tgz\"\nversion=\"1.0.0\"\n" {
		t.Fatalf("Fixed = %q, problem %q", unchanged, problem)
	}

	const (
		isProblem = "a problem"
		ignored   = "ignored"
		refused   = "not a member npm writes"
	)
	tests := []struct{ member, value, want string }{
		// What is installed, from where, and what runs.
		{"version", `"1.0.1"`, isProblem},
		{"resolved", `"https://registry.example.com/a/-/a-1.0.0.tgz"`, isProblem},
		{"integrity", `"sha512-two"`, isProblem},
		{"link", `true`, isProblem},
		{"name", `"b"`, isProblem},
		{"inBundle", `true`, isProblem},
		{"hasInstallScript", `true`, isProblem},
		{"hasShrinkwrap", `true`, isProblem},
		{"bundleDependencies", `["b"]`, isProblem},
		{"workspaces", `["packages/*"]`, isProblem},
		// What npm acts on at install without opening the tarball: the
		// executables it links, and where the package is installed at all.
		{"bin", `{"a":"cli.js"}`, isProblem},
		{"os", `["linux"]`, isProblem},
		{"cpu", `["x64"]`, isProblem},
		{"libc", `["glibc"]`, isProblem},
		// The version's own ranges, copied from its package.json like the
		// four above: one published version has one of each.
		{"dependencies", `{"b":"^1.0.0"}`, isProblem},
		{"optionalDependencies", `{"b":"^1.0.0"}`, isProblem},
		{"peerDependencies", `{"b":"^1.0.0"}`, isProblem},
		{"peerDependenciesMeta", `{"b":{"optional":true}}`, isProblem},
		{"acceptDependencies", `{"b":"^2.0.0"}`, isProblem},
		// The whole allowlist. Roles, which move when the tree around the
		// package changes.
		{"dev", `true`, ignored},
		{"optional", `true`, ignored},
		{"devOptional", `true`, ignored},
		{"peer", `true`, ignored},
		// A notice the registry adds to a version later.
		{"deprecated", `"use b"`, ignored},
		// Metadata that changes nothing that is installed or run.
		{"license", `"ISC"`, ignored},
		{"funding", `{"url":"https://example.com"}`, ignored},
		{"engines", `{"node":">=18"}`, ignored},
		// What npm does not write into an entry, and acts on when it is
		// there, or writes only into a lock that has no Shape.
		{"scripts", `{"postinstall":"node steal.js"}`, refused},
		{"gypfile", `false`, refused},
		{"extraneous", `true`, refused},
		{"devDependencies", `{"b":"^1.0.0"}`, refused},
		{"bundledDependencies", `["b"]`, refused},
		{"Integrity", `"sha512-two"`, refused},
		{"requires", `{"b":"^1.0.0"}`, refused},
		{"main", `"index.js"`, refused},
	}
	tested := map[string]bool{}
	for _, tt := range tests {
		tested[tt.member] = true
		got, problem := fixed(tt.member, tt.value)
		state := ignored
		switch {
		case problem != "":
			state = refused
			if !strings.Contains(problem, "node_modules/a has a member npm does not write, "+tt.member) {
				t.Errorf("%s: problem = %q", tt.member, problem)
			}
		case got != unchanged:
			state = isProblem
		}
		if state != tt.want {
			t.Errorf("an entry that keeps its version and changes %s: %s, want %s", tt.member, state, tt.want)
		}
	}
	allowed := 0
	for member, decides := range entryKeys {
		if !tested[member] {
			t.Errorf("%s is in the table and has no row here", member)
		}
		if !decides {
			allowed++
		}
	}
	// The allowlist does not grow by an edit to the table alone.
	if allowed != 8 {
		t.Errorf("%d members may differ on an entry that keeps its version, want the 8 named above", allowed)
	}

	// A member that must be kept is compared by what it says: one that
	// changes its value or goes away is a difference like one that is
	// new, and one that is only written in another order is none.
	cli, _ := fixed("bin", `{"a":"cli.js","b":"other.js"}`)
	reordered, _ := fixed("bin", "{\n        \"b\": \"other.js\",\n        \"a\": \"cli.js\"\n      }")
	repointed, _ := fixed("bin", `{"a":"build/steal.js","b":"other.js"}`)
	if cli != reordered || cli == repointed || cli == unchanged {
		t.Errorf("Fixed with a bin = %q, reordered %q, repointed %q; want the first two equal and the third different", cli, reordered, repointed)
	}
	// And it is this text that says whether two entries for one version
	// install the same thing.
	kept := node{Path: "node_modules/a", Name: "a", Version: "1.0.0", Fixed: cli}
	moved, gone := kept, kept
	moved.Fixed, gone.Fixed = repointed, unchanged
	if !sameInstall(kept, kept) || sameInstall(kept, moved) || sameInstall(kept, gone) {
		t.Errorf("sameInstall: same %v, repointed bin %v, bin gone %v; want true, false, false", sameInstall(kept, kept), sameInstall(kept, moved), sameInstall(kept, gone))
	}

	// How a value is laid out is not a change. What it says is.
	spread, _ := fixed("bundleDependencies", "[\n        \"b\",\n        \"c\"\n      ]")
	tight, _ := fixed("bundleDependencies", `["b","c"]`)
	other, _ := fixed("bundleDependencies", `["c","b"]`)
	if spread != tight || tight == other || tight == unchanged {
		t.Errorf("Fixed = %q, %q and %q; want the first two equal and the third different", spread, tight, other)
	}
}

func TestPresent(t *testing.T) {
	for raw, want := range map[string]bool{
		"": false, "null": false, "false": false,
		"[]": true, "true": true, `["a"]`: true, `"a"`: true, "{}": true, "0": true,
	} {
		if got := present(jsontext.Value(raw)); got != want {
			t.Errorf("present(%q) = %v, want %v", raw, got, want)
		}
	}
}

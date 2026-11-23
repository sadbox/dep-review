package npm

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/facts"
)

// TestEnvironment checks npm gets nothing of the gate's own environment.
func TestEnvironment(t *testing.T) {
	t.Setenv("NPM_TOKEN", "secret")
	t.Setenv("npm_config_registry", "https://evil.example")
	t.Setenv("NODE_OPTIONS", "--require /tmp/x.js")
	n := realNPM{path: "/usr/local/bin/npm", searchPath: "/usr/local/bin:/usr/bin:/bin"}
	var keys []string
	for _, kv := range n.env("/scratch/home") {
		key, value, _ := strings.Cut(kv, "=")
		keys = append(keys, key)
		if strings.Contains(value, "secret") || strings.Contains(value, "evil") {
			t.Errorf("%s leaks the gate's environment", kv)
		}
		if strings.HasSuffix(key, "config") && !strings.HasPrefix(value, "/scratch/home/") {
			t.Errorf("%s points outside the scratch directory", kv)
		}
	}
	want := []string{"HOME", "PATH", "npm_config_cache", "npm_config_globalconfig", "npm_config_logs_max", "npm_config_update_notifier", "npm_config_userconfig"}
	slices.Sort(keys)
	if !slices.Equal(keys, want) {
		t.Errorf("npm's environment is %v, want exactly %v", keys, want)
	}
}

// TestRealNPM runs the local npm on every case and compares its reading
// with the recorded one. A difference means this npm prints something the
// recordings do not: look before raising maxNPMMajor.
func TestRealNPM(t *testing.T) {
	n, version := realTool(t)
	t.Logf("npm %s", version)
	for _, name := range slices.Sorted(maps.Keys(caseNotes)) {
		t.Run(name, func(t *testing.T) {
			c := loadCase(t, name)
			sides := map[string][2][]byte{"base": {c.baseManifest, c.baseLock}, "head": {c.headManifest, c.headLock}}
			for side, f := range sides {
				manifest := f[0]
				if string(c.baseManifest) == string(c.headManifest) {
					manifest = nil
				}
				out, err := n.List(context.Background(), manifest, f[1])
				if err != nil {
					t.Fatalf("%s: %v", side, err)
				}
				out.Stdout = rewriteScratch(out.Stdout)
				lock, _ := readLock(f[1])
				gotNodes, gotProblems := readTree(side, out, lock)
				wantNodes, wantProblems := recordedTree(t, name, side)
				if !maps.Equal(gotNodes, wantNodes) {
					t.Errorf("%s: npm %s reads %d nodes, the recording has %d, or their contents differ", side, version, len(gotNodes), len(wantNodes))
				}
				if !slices.Equal(gotProblems, wantProblems) {
					t.Errorf("%s: problems\n got %q\nwant %q", side, gotProblems, wantProblems)
				}
			}
		})
	}
}

// TestRealNPMReadsOnlyTheScratchProject puts another project above the
// temporary directory. With no package.json of its own, npm would walk up
// to it if the gatherer did not pin the project.
func TestRealNPMReadsOnlyTheScratchProject(t *testing.T) {
	n, _ := realTool(t)
	decoy := t.TempDir()
	if err := os.WriteFile(filepath.Join(decoy, "package.json"), []byte(`{"name":"decoy","version":"9.9.9","dependencies":{"left-pad":"1.3.0"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(decoy, ".npmrc"), []byte("registry=https://evil.example/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(decoy, "node_modules"), 0o700); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(decoy, "tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmp)

	c := loadCase(t, "plain")
	out, err := n.List(context.Background(), nil, c.headLock)
	if err != nil {
		t.Fatal(err)
	}
	if out.Exit != 0 {
		t.Fatalf("npm ls exited with %d: %s", out.Exit, out.Stdout)
	}
	nodes, problems := readTree("head", out, lockFile{})
	if len(problems) != 0 || len(nodes) != 5 {
		t.Fatalf("%d nodes, problems %q; want the 5 packages of the lock", len(nodes), problems)
	}
	if strings.Contains(string(out.Stdout), "decoy") && !strings.Contains(string(out.Stdout), `"name": "fixture-plain"`) {
		t.Errorf("npm read the project above the scratch directory")
	}
	// Nothing is left behind.
	left, err := os.ReadDir(tmp)
	if err != nil || len(left) != 0 {
		t.Errorf("the scratch directory was not removed: %v %v", left, err)
	}
}

// A lock with a workspace member does not have the shape: npm cannot
// read it without the member's own package.json, which is not among the
// files the gatherer is given. Indirect rests on that. The lock's root
// entry is the only place it looks for what the repository declares, and
// a member would declare dependencies of its own.
func TestRealNPMWorkspaceHasNoShape(t *testing.T) {
	realTool(t)
	const base = `{
  "name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
  "packages": {
    "": {"name": "app", "version": "1.0.0", "workspaces": ["packages/a"]},
    "node_modules/a": {"resolved": "packages/a", "link": true},
    "node_modules/left-pad": {"version": "1.2.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.2.0.tgz", "integrity": "sha512-OLD"},
    "packages/a": {"version": "1.0.0", "dependencies": {"left-pad": "^1.2.0"}}
  }
}
`
	head := strings.NewReplacer("1.2.0\"", "1.3.0\"", "left-pad-1.2.0.tgz", "left-pad-1.3.0.tgz", "sha512-OLD", "sha512-NEW").Replace(base)
	res, err := Gatherer{}.Changes(context.Background(), []facts.File{
		{Path: "package-lock.json", BaseMode: "100644", HeadMode: "100644", Base: []byte(base), Head: []byte(head)},
	}, testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	// npm's own word for it: without the member's package.json the link
	// to it is something nothing asks for.
	if !res.Shape.Gathered() || res.Shape.OK || !strings.Contains(res.Shape.Value, "extraneous: a@1.0.0") || len(res.Updates) != 0 {
		t.Errorf("Shape = %+v with %d updates, want a gathered no that calls the member extraneous, and no update", res.Shape, len(res.Updates))
	}
}

// A bundled entry is no update and is compared with nothing while its
// bundler moves. npm reads one that names a source without a word (it
// prints the source and exits 0), so the gate refuses it.
func TestRealNPMBundledEntryWithASource(t *testing.T) {
	realTool(t)
	c := loadCase(t, "bundled")
	const key = `"node_modules/@tailwindcss/oxide-wasm32-wasi/node_modules/tslib": {`
	const source = `"resolved": "https://registry.npmjs.org/tslib/-/tslib-2.8.1.tgz", "integrity": "sha512-oJFu94HQb+KVduSUQL7wnpmqnfmLsOA/nAh6b6EH0wCEoK0/mPeXU6c3wKDV83MkOuHPRHtSXKKU99IBazS/2w==",`
	if !strings.Contains(string(c.headLock), key) {
		t.Fatal("the bundled case no longer has the entry this test edits")
	}
	c.headLock = []byte(strings.Replace(string(c.headLock), key, key+source, 1))
	res, err := Gatherer{}.Changes(context.Background(), c.files(""), testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	const want = "node_modules/@tailwindcss/oxide-wasm32-wasi/node_modules/tslib is marked as bundled and has a source or a hash of its own"
	if !res.Shape.Gathered() || res.Shape.OK || !strings.Contains(res.Shape.Value, want) || len(res.Updates) != 0 {
		t.Errorf("Shape = %+v with %d updates, want a gathered no saying %q", res.Shape, len(res.Updates), want)
	}
}

// The real npm names the package the head lock is out of sync about by
// its path in the scratch directory. The Shape fact says which package,
// and not where on this machine the gate worked.
func TestRealNPMShapeDoesNotNameTheScratchDirectory(t *testing.T) {
	realTool(t)
	res, err := Gatherer{}.Changes(context.Background(), loadCase(t, "outofsync").files(""), testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	const want = `head: npm ls failed: "{\"code\":\"ELSPROBLEMS\",\"summary\":\"invalid: chart.js@4.4.5 node_modules/chart.js\",`
	if res.Shape.OK || !strings.Contains(res.Shape.Value, want) {
		t.Errorf("Shape = %+v, want a no with %q", res.Shape, want)
	}
	tmp := os.TempDir()
	if real, err := filepath.EvalSymlinks(tmp); err == nil && strings.Contains(res.Shape.Value, real) {
		t.Errorf("Shape names the temporary directory %s: %q", real, res.Shape.Value)
	}
	if strings.Contains(res.Shape.Value, filepath.Clean(tmp)) || strings.Contains(res.Shape.Value, "dep-review-npm-") {
		t.Errorf("Shape names the scratch directory: %q", res.Shape.Value)
	}
}

// TestRealNPMGather is the whole gatherer with the real npm and the
// recorded registry: no network.
func TestRealNPMGather(t *testing.T) {
	_, version := realTool(t)
	for _, name := range []string{"plain", "lockonly"} {
		c := loadCase(t, name)
		res, err := Gatherer{}.Gather(context.Background(), facts.Input{
			Files: c.files("web/"), Policy: testPolicy(), HTTP: newFakeRegistry(t, nil), Advisories: fakeAdvisories{},
			Now: func() time.Time { return testNow },
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !res.Shape.Holds() || !strings.HasPrefix(res.Shape.Source, "npm "+version+": ") {
			t.Fatalf("%s: Shape = %+v", name, res.Shape)
		}
		if got, want := names(res), "chart.js 4.4.6->4.4.7, core-js 3.38.0->3.38.1, tailwindcss 4.3.4->4.3.5"; got != want {
			t.Errorf("%s: updates %s, want %s", name, got, want)
		}
		// What Gather returns never merges by itself: the tarballs have
		// not been looked at yet.
		if d := decide(res); d.Outcome != allow.Person || !slices.Equal(d.Reasons, []allow.Reason{allow.ReasonFactMissing}) {
			t.Errorf("%s: Decide before the fetch command's inspection = %s %v, want person [fact_missing]", name, d.Outcome, d.Reasons)
		}
		if d := decide(fetched(t, res)); d.Outcome != allow.Merge {
			t.Errorf("%s: Decide = %s %v, want merge", name, d.Outcome, d.Reasons)
		}
	}
}

func TestCappedWriter(t *testing.T) {
	c := &capped{max: 10}
	for _, chunk := range []string{"12345", "678", "90abc", "def"} {
		if n, err := c.Write([]byte(chunk)); n != len(chunk) || err != nil {
			t.Fatalf("Write(%q) = %d, %v; a capped writer never fails or stalls the writer", chunk, n, err)
		}
	}
	if got := c.buf.String(); got != "1234567890" || !c.truncated {
		t.Errorf("kept %q, truncated %v", got, c.truncated)
	}
	exact := &capped{max: 3}
	exact.Write([]byte("abc"))
	if exact.truncated {
		t.Error("output of exactly the limit counts as truncated")
	}
}

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
				gotNodes, gotProblems := readTree(side, out)
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
	nodes, problems := readTree("head", out)
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
		if d := decide(res); d.Outcome != allow.Merge {
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

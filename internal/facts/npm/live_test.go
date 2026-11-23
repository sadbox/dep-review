package npm

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/facts"
)

// TestLive runs the gatherer on the plain and bundled cases with the real
// npm against the real registry. It is off unless DEP_REVIEW_NPM_LIVE is
// set:
//
//	DEP_REVIEW_NPM_LIVE=1 go test ./internal/facts/npm/ -run TestLive -v
//
// The advisory database is not asked (that is internal/advisory's own live
// test), so Clean rests on the registry and the test's stand-in.
func TestLive(t *testing.T) {
	if os.Getenv(liveEnv) == "" {
		t.Skip("set " + liveEnv + "=1 to ask the real registry")
	}
	realTool(t)
	client := &http.Client{Timeout: 2 * time.Minute}

	t.Run("plain", func(t *testing.T) {
		c := loadCase(t, "plain")
		res, err := Gatherer{}.Gather(context.Background(), facts.Input{
			Files: c.files(""), Policy: testPolicy(), HTTP: client, Advisories: fakeAdvisories{}, Now: time.Now,
		})
		if err != nil {
			t.Fatal(err)
		}
		res = fetched(t, res)
		t.Logf("Shape: %+v", res.Shape)
		for _, u := range res.Updates {
			t.Logf("%s %s -> %s\n  Bound: %+v\n  FirstSeen: %+v\n  NameCreated: %+v\n  Clean: %+v\n  NoRegress: %+v",
				u.Name, u.From, u.To, u.Bound, u.FirstSeen, u.NameCreated, u.Clean, u.NoRegress)
		}
		if len(res.Updates) != 3 || len(res.Artifacts) != 3 {
			t.Fatalf("%d updates and %d artifacts, want 3 and 3", len(res.Updates), len(res.Artifacts))
		}
		// These versions are years or weeks old and none has been
		// withdrawn; when one is, this is where it shows.
		if d := decide(res); d.Outcome != allow.Merge {
			t.Errorf("Decide = %s %v, want merge", d.Outcome, d.Reasons)
		}
	})

	t.Run("bundled", func(t *testing.T) {
		c := loadCase(t, "bundled")
		res, err := Gatherer{}.Gather(context.Background(), facts.Input{
			Files: c.files(""), Policy: testPolicy(), HTTP: client, Advisories: fakeAdvisories{}, Now: time.Now,
		})
		if err != nil {
			t.Fatal(err)
		}
		res = fetched(t, res)
		if len(res.Updates) != 1 || !res.Updates[0].Bound.Holds() || res.Updates[0].NoRegress.OK {
			t.Errorf("updates = %+v, want one that is bound and does not pass NoRegress", res.Updates)
		}
	})
}

// liveDirEnv names a directory with base/ and head/ subdirectories, each
// holding a package.json and a package-lock.json.
const liveDirEnv = "DEP_REVIEW_NPM_LIVE_DIR"

// TestLiveDir runs the gatherer on any pair of locks with the real npm
// against the real registry, and prints what it gathered and what each
// update would come to after a full read with no veto:
//
//	DEP_REVIEW_NPM_LIVE_DIR=/path/to/pair go test ./internal/facts/npm/ -run TestLiveDir -v
func TestLiveDir(t *testing.T) {
	dir := os.Getenv(liveDirEnv)
	if dir == "" {
		t.Skip("set " + liveDirEnv + " to a directory with base/ and head/")
	}
	realTool(t)
	read := func(side, file string) []byte {
		data, err := os.ReadFile(filepath.Join(dir, side, file))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	c := testCase{
		baseManifest: read("base", "package.json"), headManifest: read("head", "package.json"),
		baseLock: read("base", "package-lock.json"), headLock: read("head", "package-lock.json"),
	}
	res, err := Gatherer{}.Gather(context.Background(), facts.Input{
		Files: c.files(""), Policy: testPolicy(), HTTP: &http.Client{Timeout: 2 * time.Minute}, Advisories: fakeAdvisories{}, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	res = fetched(t, res)
	t.Logf("Shape: ok=%v %s", res.Shape.OK, res.Shape.Value)
	d := decide(res)
	t.Logf("Decide at %s: %s %v", testNow.Format(time.DateOnly), d.Outcome, d.Reasons)
	for i, u := range res.Updates {
		t.Logf("%s %s -> %s: %s %v", u.Name, u.From, u.To, d.PerUpdate[i].Outcome, d.PerUpdate[i].Reasons)
		for what, f := range map[string]allow.Fact{"Known": u.Known, "Increase": u.Increase, "Bound": u.Bound, "Clean": u.Clean, "NoRegress": u.NoRegress} {
			if !f.Holds() {
				t.Logf("    %s: gathered=%v %s", what, f.Gathered(), f.Value)
			}
		}
	}
	t.Logf("%d updates, %d artifact pairs", len(res.Updates), len(res.Artifacts))
}

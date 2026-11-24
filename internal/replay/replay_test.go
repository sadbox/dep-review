package replay

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/config"
)

// The records under testdata are made up: example.com modules, an action
// and an image that do not exist, hashes of one repeated letter. The
// actions-own records name sadbox/ci, which the built-in policy calls the
// gate owner's own, at versions and commits it does not have. Most are
// created on 2026-01-10; go-patch-recent on 2026-03-01.
var (
	later = time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)
	// soon is before any record's min_age has passed.
	soon = time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)
	old  = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
)

// builtIn is the policy the gate ships.
func builtIn(t *testing.T) allow.Policy {
	t.Helper()
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Policy()
}

// noOwnList is the built-in policy with no repository called the gate
// owner's own: every reusable workflow is then refused, as before spec
// section 11, amendment 60.
func noOwnList(t *testing.T) allow.Policy {
	t.Helper()
	p := builtIn(t)
	p.Own = nil
	return p
}

// noOfficialImages is the built-in policy without Docker Official Images
// on the list: the kind of change the replay is there to measure.
func noOfficialImages(t *testing.T) allow.Policy {
	t.Helper()
	p := builtIn(t)
	p.Listed[allow.Docker] = []string{"gcr.io/distroless/"}
	return p
}

// answers runs the fixture and returns "outcome reasons" by record name.
func answers(t *testing.T, opt Options) map[string]string {
	t.Helper()
	results, err := Run(context.Background(), filepath.Join("testdata", "records"), opt)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range results {
		reasons := make([]string, len(r.Decision.Reasons))
		for i, reason := range r.Decision.Reasons {
			reasons[i] = string(reason)
		}
		got[r.Name] = strings.TrimSpace(string(r.Decision.Outcome) + " " + strings.Join(reasons, ","))
	}
	return got
}

func TestRun(t *testing.T) {
	// What every record comes to with the built-in policy, long after all
	// of them were created. The other cases list only what differs.
	base := map[string]string{
		"actions-major-unlisted": "person major_unlisted",
		"actions-own-lookalike":  "person shape,no_updates",
		"actions-own-major":      "person major_own",
		"actions-own-workflow":   "merge",
		"actions-pin":            "merge",
		"actions-short-tag":      "person shape,no_updates",
		"docker-listed":          "merge",
		"docker-unlisted":        "person not_known",
		"go-major-listed":        "merge",
		"go-major-unlisted":      "person major_unlisted",
		"go-new-name":            "person name_created_unknown",
		"go-other-file":          "person shape,no_updates",
		"go-others-pushed":       "person identity,fact_missing,no_updates",
		"go-patch":               "merge",
		"go-patch-recent":        "wait age",
		"uv-no-rule":             "person no_rule,fact_missing,no_updates",
	}
	for _, tc := range []struct {
		name    string
		opt     Options
		differs map[string]string
	}{
		{name: "built-in policy", opt: Options{Policy: builtIn(t), Now: later}},
		{
			// And not the own workflow: no age is asked of it.
			name: "the clock only moves merge to wait",
			opt:  Options{Policy: builtIn(t), Now: soon},
			differs: map[string]string{
				"actions-pin": "wait age", "docker-listed": "wait age", "go-major-listed": "wait age", "go-patch": "wait age",
			},
		},
		{
			name: "no own list",
			opt:  Options{Policy: noOwnList(t), Now: later},
			differs: map[string]string{
				"actions-own-workflow": "person shape,no_updates", "actions-own-major": "person shape,no_updates",
			},
		},
		{
			name:    "new names taken to be old",
			opt:     Options{Policy: builtIn(t), Now: later, NameCreated: old},
			differs: map[string]string{"go-new-name": "merge"},
		},
		{
			name:    "new names taken to be young",
			opt:     Options{Policy: builtIn(t), Now: later, NameCreated: later.AddDate(0, -6, 0)},
			differs: map[string]string{"go-new-name": "person new_name_young"},
		},
		{
			name:    "a narrower list",
			opt:     Options{Policy: noOfficialImages(t), Now: later},
			differs: map[string]string{"docker-listed": "person not_known"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := answers(t, tc.opt)
			if len(got) != len(base) {
				t.Errorf("%d results, want %d", len(got), len(base))
			}
			for name, want := range base {
				if other, ok := tc.differs[name]; ok {
					want = other
				}
				if got[name] != want {
					t.Errorf("%s: %q, want %q", name, got[name], want)
				}
			}
		})
	}
}

// What is printed: the lines, the details and the totals.
func TestPrint(t *testing.T) {
	results, err := Run(context.Background(), filepath.Join("testdata", "records"), Options{Policy: builtIn(t), Now: later})
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if err := Print(&got, results); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "records.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != string(want) {
		t.Errorf("printed:\n%s\nwant:\n%s", got.String(), want)
	}
}

// An npm record is read by npm itself, offline. The test needs an npm the
// gatherer was tested with: with none installed, or one of another major,
// it is skipped, as internal/facts/npm's own tests with the real npm are.
func TestRunNPM(t *testing.T) {
	if _, err := exec.LookPath("npm"); err != nil {
		t.Skip("npm is not installed")
	}
	results, err := Run(context.Background(), filepath.Join("testdata", "npm"), Options{Policy: builtIn(t), Now: later})
	// The gatherer's own refusal of an npm it was not tested with; the
	// check behind it is not exported.
	if err != nil && strings.Contains(err.Error(), "is not a version the gate was tested with") {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Name != "npm-plain" {
		t.Fatalf("results %+v", results)
	}
	r := results[0]
	if r.Decision.Outcome != allow.Merge || !r.Shape.Holds() || len(r.Decision.PerUpdate) != 3 {
		t.Errorf("outcome %s (%v), shape %q, %d updates; want a merge of three", r.Decision.Outcome, r.Decision.Reasons, r.Shape.Value, len(r.Decision.PerUpdate))
	}
}

// A whole policy file is read with no floor under it, and has to set
// every key the built-in file sets.
func TestReadPolicy(t *testing.T) {
	builtInFile, err := os.ReadFile(filepath.Join("..", "config", "policy", "defaults.json"))
	if err != nil {
		t.Fatal(err)
	}
	edit := func(change func(m map[string]any)) []byte {
		var m map[string]any
		if err := json.Unmarshal(builtInFile, &m); err != nil {
			t.Fatal(err)
		}
		change(m)
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	listed := func(m map[string]any) map[string]any { return m["listed"].(map[string]any) }

	if got, err := ReadPolicy(builtInFile); err != nil || !reflect.DeepEqual(got, builtIn(t)) {
		t.Errorf("the built-in file: %+v, %v; want the built-in policy", got, err)
	}
	got, err := ReadPolicy(edit(func(m map[string]any) {
		m["min_age_hours"] = 24
		listed(m)["docker"] = []string{"gcr.io/distroless/"}
		listed(m)["npm"] = []string{}
	}))
	want := noOfficialImages(t)
	want.MinAge, want.Listed[allow.NPM] = 24*time.Hour, nil
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("a file below the built-in values: %+v, %v; want what it says", got, err)
	}

	// Every key, left out one at a time.
	var all map[string]any
	if err := json.Unmarshal(builtInFile, &all); err != nil {
		t.Fatal(err)
	}
	missing := map[string][]byte{}
	for key := range all {
		missing[key] = edit(func(m map[string]any) { delete(m, key) })
	}
	for key := range listed(all) {
		missing["listed."+key] = edit(func(m map[string]any) { delete(listed(m), key) })
	}
	for key, file := range missing {
		if _, err := ReadPolicy(file); err == nil || !strings.Contains(err.Error(), "a key is missing") {
			t.Errorf("without %s: %v, want an error that says a key is missing", key, err)
		}
	}

	for _, tc := range []struct {
		name string
		file []byte
		want string
	}{
		{"an unknown key", edit(func(m map[string]any) { m["allow_everything"] = true }), "unknown field"},
		{"an age of zero", edit(func(m map[string]any) { m["min_age_hours"] = 0 }), allow.ReasonPolicyInvalid.Explain()},
		{"a companion mode that is none", edit(func(m map[string]any) { m["fast_path_companions"] = "sometimes" }), allow.ReasonPolicyInvalid.Explain()},
		{"a second value", append(edit(func(map[string]any) {}), '1'), "more than one JSON value"},
		{"not JSON", []byte("min_age_hours: 24"), "invalid character"},
		{"empty", nil, "EOF"},
	} {
		if _, err := ReadPolicy(tc.file); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error that says %q", tc.name, err, tc.want)
		}
	}
}

func TestRecordsThatCannotBeRead(t *testing.T) {
	const good = `{"ecosystem": "docker", "created": "2026-01-10T12:00:00Z", "files": []}`
	for _, tc := range []struct {
		name, record, want string
	}{
		{"an unknown key", `{"ecosystem": "docker", "created": "2026-01-10T12:00:00Z", "file": []}`, "unknown field"},
		{"no creation time", `{"ecosystem": "docker", "files": []}`, "created time"},
		{"no ecosystem", `{"created": "2026-01-10T12:00:00Z", "files": []}`, "ecosystem"},
		{"a second value", good + good, "more than one JSON value"},
		{"not JSON", `ecosystem: docker`, "invalid character"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "pr.json"), []byte(tc.record), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Run(context.Background(), dir, Options{Policy: builtIn(t), Now: later})
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "pr.json") {
				t.Errorf("error %v, want one about pr.json that says %q", err, tc.want)
			}
		})
	}

	// A record with no file is readable; it is a pull request that changes
	// nothing, which is person. A directory with no record is an error.
	dir := t.TempDir()
	if _, err := Run(context.Background(), dir, Options{Policy: builtIn(t), Now: later}); err == nil {
		t.Error("an empty directory gave no error")
	}
	if err := os.WriteFile(filepath.Join(dir, "pr.json"), []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	results, err := Run(context.Background(), dir, Options{Policy: builtIn(t), Now: later})
	if err != nil || len(results) != 1 || results[0].Decision.Outcome != allow.Person {
		t.Errorf("a record with no file: %+v, %v; want one person", results, err)
	}
}

// A path that does not exist at a commit has no content there, whatever
// the record says: the gatherers tell absent from empty by the mode.
func TestAbsentFileHasNoContent(t *testing.T) {
	rec := Record{
		Ecosystem: allow.Docker,
		Created:   later.AddDate(0, -1, 0),
		Files:     []File{{Path: "Dockerfile", HeadMode: "100644", Base: "FROM a\n", Head: "FROM b\n"}},
	}
	res, err := Decide(context.Background(), rec, Options{Policy: builtIn(t), Now: later})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision.Outcome != allow.Person || !strings.Contains(res.Shape.Value, "not a regular file at both commits") {
		t.Errorf("outcome %s, shape %q; want person for a file added by the pull request", res.Decision.Outcome, res.Shape.Value)
	}
}

// The stand-ins rest on what each gatherer's Changes hands back: the
// facts it reads from the files are answered, and the ones only a
// registry can answer are left unset, so that withStandIns fills in
// those and nothing else.
func TestChangesLeaveRegistryFactsUnset(t *testing.T) {
	dirs := []string{"records"}
	if _, err := exec.LookPath("npm"); err == nil {
		dirs = append(dirs, "npm")
	}
	seen := map[string]int{}
	for _, dir := range dirs {
		entries, err := os.ReadDir(filepath.Join("testdata", dir))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			rec, err := readRecord(filepath.Join("testdata", dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if !allow.HasRule(rec.Ecosystem) {
				continue
			}
			res, err := changes(context.Background(), rec, builtIn(t))
			if err != nil {
				t.Fatal(err)
			}
			for _, u := range res.Updates {
				seen[rec.Ecosystem]++
				for name, f := range map[string]allow.Fact{"Known": u.Known, "Listed": u.Listed, "NewName": u.NewName, "Increase": u.Increase, "Major": u.Major} {
					if !f.Gathered() {
						t.Errorf("%s: %s: %s is not answered from the files", e.Name(), u.Name, name)
					}
				}
				if u.Bound != (allow.Fact{}) || u.Clean != (allow.Fact{}) || u.FirstSeen != (allow.TimeFact{}) || u.NameCreated != (allow.TimeFact{}) {
					t.Errorf("%s: %s: a fact only a registry can answer is set", e.Name(), u.Name)
				}
				if u.Read != "" || u.Veto != nil {
					t.Errorf("%s: %s: Read or Veto is set", e.Name(), u.Name)
				}
			}
		}
	}
	for _, eco := range []string{allow.GoModules, allow.GitHubActions, allow.Docker} {
		if seen[eco] == 0 {
			t.Errorf("the fixture has no %s update", eco)
		}
	}
}

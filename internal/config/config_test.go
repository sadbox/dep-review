package config

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
)

// modelKeys are the settings of spec section 11, amendment 10. The spec
// names them and gives no values; the values are internal/veto's, and a
// test there keeps the two equal.
var modelKeys = []string{"model", "effort", "context_tokens", "max_output_tokens", "chunk_bytes", "max_chunks", "request_timeout_seconds", "attempts"}

// specDefaults is section 5 of the spec, value by value, and the model
// settings as the embedded file has them.
func specDefaults() Config {
	return Config{
		MinAgeHours:        72,
		UnreadAgeDays:      14,
		MajorAgeDays:       14,
		NewNameAgeDays:     365,
		WaitDeadlineDays:   7,
		FastPath:           true,
		FastPathCompanions: "ride-along",

		Model:                 "claude-opus-5-5",
		Effort:                "high",
		ContextTokens:         1_000_000,
		MaxOutputTokens:       16_000,
		ChunkBytes:            400_000,
		MaxChunks:             12,
		RequestTimeoutSeconds: 600,
		Attempts:              3,
		Listed: Lists{
			GoModules: []string{"golang.org/x/", "google.golang.org/", "cloud.google.com/go",
				"github.com/aws/", "github.com/Azure/", "github.com/AzureAD/",
				"github.com/microsoft/", "github.com/microsoftgraph/",
				"go.opentelemetry.io/"},
			GitHubActions: []string{"actions/", "github/", "docker/"},
			Docker:        []string{"docker.io/library/", "gcr.io/distroless/"},
			NPM:           []string{"tailwindcss", "@tailwindcss/"},
		},
	}
}

func mustLoad(t *testing.T) Config {
	t.Helper()
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

func TestDefaults(t *testing.T) {
	if got, want := mustLoad(t), specDefaults(); !reflect.DeepEqual(got, want) {
		t.Errorf("\n got %+v\nwant %+v", got, want)
	}
	// One Load's lists are not another's.
	c := mustLoad(t)
	c.Listed.NPM[0] = "left-pad"
	if again := mustLoad(t); !reflect.DeepEqual(again, specDefaults()) {
		t.Fatal("changing one Config changed the next")
	}
}

// Load is the one way to a Config and takes nothing: no file of a
// repository's, and so none of a pull request's, can reach it (spec
// section 11, amendment 56). A parameter added to it is a way in.
func TestLoadTakesNothing(t *testing.T) {
	if n := reflect.TypeOf(Load).NumIn(); n != 0 {
		t.Errorf("Load takes %d arguments, want none: the embedded file is the only policy", n)
	}
}

// The embedded file is the spec's block: the same keys and the same
// values, entry for entry, in the same order. On top of it the file has
// the model settings of amendment 10, and nothing else.
func TestDefaultsAreTheSpecs(t *testing.T) {
	spec, err := os.ReadFile("../../docs/v0.2-spec.md")
	if err != nil {
		t.Skipf("the spec is not in this checkout: %v", err)
	}
	_, rest, ok := strings.Cut(string(spec), "## 5. Policy and configuration")
	if !ok {
		t.Fatal("the spec has no section 5")
	}
	_, rest, ok = strings.Cut(rest, "```json\n")
	if !ok {
		t.Fatal("section 5 has no json block")
	}
	block, _, ok := strings.Cut(rest, "```")
	if !ok {
		t.Fatal("section 5's json block does not end")
	}
	var want, got map[string]any
	if err := json.Unmarshal([]byte(block), &want); err != nil {
		t.Fatalf("the spec's block: %v", err)
	}
	if err := json.Unmarshal(defaultsJSON, &got); err != nil {
		t.Fatalf("defaults.json: %v", err)
	}
	for _, key := range modelKeys {
		if _, ok := got[key]; !ok {
			t.Errorf("policy/defaults.json has no %q", key)
		}
		if !strings.Contains(string(spec), "`"+key+"`") {
			t.Errorf("the spec's amendment 10 does not name %q", key)
		}
		delete(got, key)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("policy/defaults.json without the model settings is not the spec's section 5:\n got %v\nwant %v", got, want)
	}
}

// The smallest chunk the file may set is the smallest the artifact reader
// prepares.
func TestChunkFloor(t *testing.T) {
	if minChunkBytes != artifact.MinChunkBytes {
		t.Errorf("the floor for chunk_bytes is %d, internal/artifact's is %d", minChunkBytes, artifact.MinChunkBytes)
	}
}

func TestPolicy(t *testing.T) {
	p := mustLoad(t).Policy()
	const day = 24 * time.Hour
	want := allow.Policy{
		MinAge:       72 * time.Hour,
		UnreadAge:    14 * day,
		MajorAge:     14 * day,
		NewNameAge:   365 * day,
		WaitDeadline: 7 * day,
		FastPath:     true,
		Companions:   allow.RideAlong,
		Listed: map[string][]string{
			allow.GoModules:     specDefaults().Listed.GoModules,
			allow.GitHubActions: specDefaults().Listed.GitHubActions,
			allow.Docker:        specDefaults().Listed.Docker,
			allow.NPM:           specDefaults().Listed.NPM,
		},
	}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("\n got %+v\nwant %+v", p, want)
	}

	// The list reaches allow under the names allow looks it up by.
	for eco, name := range map[string]string{
		allow.GoModules:     "cloud.google.com/go/storage",
		allow.GitHubActions: "actions/checkout",
		allow.Docker:        "docker.io/library/golang",
		allow.NPM:           "@tailwindcss/oxide",
	} {
		if !allow.Listed(p, eco, name) {
			t.Errorf("%s: %q is not listed", eco, name)
		}
	}

	// And allow accepts the policy: an old, clean update merges.
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	f := allow.PRFacts{
		Ecosystem:        allow.GoModules,
		Identity:         allow.Yes("y", "s"),
		Shape:            allow.Yes("y", "s"),
		ChecksConfigured: allow.Yes("y", "s"),
		Updates: []allow.UpdateFacts{{
			Name: "golang.org/x/net", From: "v0.62.0", To: "v0.63.0",
			Known: allow.Yes("y", "s"), Listed: allow.Yes("y", "s"), NewName: allow.No("n", "s"),
			Increase: allow.Yes("y", "s"), Major: allow.No("n", "s"), Bound: allow.Yes("y", "s"),
			FirstSeen: allow.At(now.Add(-72*time.Hour), "s"), Clean: allow.Yes("y", "s"),
			NoRegress: allow.Yes("y", "s"), SecurityFix: allow.No("n", "s"), Read: allow.ReadFull,
		}},
	}
	if d := allow.Decide(f, p, now); d.Outcome != allow.Merge {
		t.Fatalf("the default policy: %q %v", d.Outcome, d.Reasons)
	}
	if d := allow.Decide(f, p, now.Add(-time.Second)); d.Outcome != allow.Wait {
		t.Fatalf("a second short of 72 hours: %q", d.Outcome)
	}

	// A policy is the caller's to keep: changing it changes nothing else.
	p.Listed[allow.NPM][0] = "left-pad"
	p.Listed[allow.GoModules] = append(p.Listed[allow.GoModules], "example.com/")
	if again := mustLoad(t).Policy(); !reflect.DeepEqual(again, want) {
		t.Fatal("changing one Policy changed the next")
	}
}

// A list entry is a name or a prefix, byte for byte: what could not mean
// what its author intended is refused, in the embedded file too.
func TestCheckEntry(t *testing.T) {
	for _, ok := range []string{"golang.org/x/", "cloud.google.com/go", "@tailwindcss/", "tailwindcss", "docker.io/library/", "a-b_c.d~e:f"} {
		if err := checkEntry(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, tc := range []struct {
		name, entry, wantErr string
	}{
		{"empty", "", "empty"},
		{"a wildcard", "example-org/*", "no wildcards"},
		{"a glob", "github.com/?", "no wildcards"},
		{"a space", " golang.org/x/", "byte ' ' at 0"},
		{"a newline", "esbuild\n", "byte '\\n'"},
		// A Cyrillic "о" where the Latin one belongs.
		{"not ASCII", "g\u043elang.org/x/", "byte 0xd0 at 1"},
		{"rooted", "/library/", "empty path element"},
		{"only a slash", "/", "empty path element"},
		{"an empty element", "github.com//aws/", "empty path element"},
		{"too long", strings.Repeat("a", maxEntryBytes+1), "longer than 200"},
	} {
		if err := checkEntry(tc.entry); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: %v, want an error that says %q", tc.name, err, tc.wantErr)
		}
	}
}

// The hints that send the owner to the list name the one file that holds
// it, and no hint names a file in the repository the pull request is in:
// there is none (spec section 11, amendment 56).
func TestHintsNameTheBuiltInList(t *testing.T) {
	const builtIn = "internal/config/policy/defaults.json"
	if _, err := os.Stat("policy/defaults.json"); err != nil {
		t.Fatalf("the hints' path is not the embedded file's: %v", err)
	}
	for _, r := range []allow.Reason{allow.ReasonNotKnown, allow.ReasonMajorUnlisted, allow.ReasonNewNameYoung, allow.ReasonNewNameUnread, allow.ReasonNameCreatedUnknown} {
		if !strings.Contains(r.Hint(), builtIn) {
			t.Errorf("%q: the hint does not name %s: %q", r, builtIn, r.Hint())
		}
	}
	for _, r := range allow.Reasons() {
		if text := r.Explain() + " " + r.Hint(); strings.Contains(text, "dep-review.json") || strings.Contains(text, "default branch, or remove") {
			t.Errorf("%q speaks of a repository settings file: %q", r, text)
		}
	}
}

// complete reads the embedded file, which sets every value itself: it
// takes what the file says, and is strict about what the file may say.
func TestComplete(t *testing.T) {
	edit := func(change func(m map[string]any)) []byte {
		var m map[string]any
		if err := json.Unmarshal(defaultsJSON, &m); err != nil {
			t.Fatal(err)
		}
		change(m)
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	got, err := complete(defaultsJSON)
	if err != nil || !reflect.DeepEqual(got, specDefaults()) {
		t.Errorf("the embedded file: %+v, %v; want the defaults", got, err)
	}

	got, err = complete(edit(func(m map[string]any) {
		m["min_age_hours"] = 24
		m["listed"].(map[string]any)["docker"] = []string{"gcr.io/distroless/"}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got.MinAgeHours != 24 || !reflect.DeepEqual(got.Listed.Docker, []string{"gcr.io/distroless/"}) {
		t.Errorf("min_age_hours %d, docker list %q; want what the file says", got.MinAgeHours, got.Listed.Docker)
	}
	if !reflect.DeepEqual(got.Listed.NPM, specDefaults().Listed.NPM) || got.MajorAgeDays != 14 {
		t.Errorf("what the file left as it was changed: %+v", got)
	}

	for _, tc := range []struct {
		name string
		file []byte
		want string
	}{
		{"a missing key", edit(func(m map[string]any) { delete(m, "major_age_days") }), "a key is missing"},
		{"an unknown key", edit(func(m map[string]any) { m["allow_everything"] = true }), "unknown object member name"},
		{"an ecosystem with no rule", edit(func(m map[string]any) { m["listed"].(map[string]any)["uv"] = []string{"requests"} }), "unknown object member name"},
		{"an age of zero", edit(func(m map[string]any) { m["min_age_hours"] = 0 }), "min_age_hours"},
		{"an age too large to mean anything", edit(func(m map[string]any) { m["unread_age_days"] = 3651 }), "want 1 to 3650"},
		{"a wait deadline of zero", edit(func(m map[string]any) { m["wait_deadline_days"] = 0 }), "wait_deadline_days is 0"},
		{"an unknown companion mode", edit(func(m map[string]any) { m["fast_path_companions"] = "ride_along" }), "fast_path_companions"},
		{"a chunk no file header fits", edit(func(m map[string]any) { m["chunk_bytes"] = 255 }), "chunk_bytes is 255, want at least 256"},
		{"no chunk at all", edit(func(m map[string]any) { m["max_chunks"] = 0 }), "max_chunks is 0, want at least 1"},
		{"no model", edit(func(m map[string]any) { m["model"] = "" }), "model or effort is empty"},
		{"a string for a number", edit(func(m map[string]any) { m["min_age_hours"] = "72" }), "unmarshal JSON"},
		{"a fraction", edit(func(m map[string]any) { m["min_age_hours"] = 72.5 }), "unmarshal JSON"},
		{"a bad list entry", edit(func(m map[string]any) { m["listed"].(map[string]any)["npm"] = []string{"/"} }), "listed.npm"},
		{"empty", nil, "EOF"},
		{"not an object", []byte(`[72]`), "unmarshal JSON"},
		{"two documents", append(slices.Clone(defaultsJSON), defaultsJSON...), "after top-level value"},
		// A key is itself only in its exact spelling, and only once: the
		// second of two would otherwise be the one that counts.
		{"a key in another case", bytes.Replace(defaultsJSON, []byte(`"min_age_hours"`), []byte(`"Min_Age_Hours"`), 1), "unknown object member name"},
		{"a key twice", bytes.Replace(defaultsJSON, []byte(`"fast_path": true,`), []byte(`"fast_path": true, "fast_path": true,`), 1), "duplicate object member name"},
	} {
		if _, err := complete(tc.file); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error that says %q", tc.name, err, tc.want)
		}
	}
}

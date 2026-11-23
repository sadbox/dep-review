package config

import (
	"encoding/json"
	"os"
	"reflect"
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

func mustLoad(t *testing.T, repoFile string) Config {
	t.Helper()
	c, err := Load([]byte(repoFile))
	if err != nil {
		t.Fatalf("Load(%s): %v", repoFile, err)
	}
	return c
}

func TestDefaults(t *testing.T) {
	want := specDefaults()
	for name, repoFile := range map[string][]byte{"nil": nil, "empty": {}, "empty object": []byte("{}"), "empty lists": []byte(`{"listed": {}}`)} {
		got, err := Load(repoFile)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %+v\nwant %+v", name, got, want)
		}
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

// A repository may make a read smaller and may not touch anything else
// about the model (spec section 11, amendment 10).
func TestRepoFileAndTheModel(t *testing.T) {
	c := mustLoad(t, `{"chunk_bytes": 100000, "max_chunks": 4}`)
	want := specDefaults()
	want.ChunkBytes, want.MaxChunks = 100_000, 4
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("\n got %+v\nwant %+v", c, want)
	}
	// The built-in values themselves, and the floors.
	for _, ok := range []string{
		`{"chunk_bytes": 400000, "max_chunks": 12}`,
		`{"chunk_bytes": 256}`,
		`{"max_chunks": 1}`,
		`{"chunk_bytes": null, "max_chunks": null, "model": null, "attempts": null}`,
	} {
		mustLoad(t, ok)
	}
	if minChunkBytes != artifact.MinChunkBytes {
		t.Errorf("the floor for chunk_bytes is %d, internal/artifact's is %d", minChunkBytes, artifact.MinChunkBytes)
	}

	for _, tc := range []struct {
		name, repoFile, wantErr string
	}{
		{"a larger chunk", `{"chunk_bytes": 400001}`, "chunk_bytes is 400001, above the built-in 400000"},
		{"more chunks", `{"max_chunks": 13}`, "max_chunks is 13, above the built-in 12"},
		{"a chunk no file header fits", `{"chunk_bytes": 255}`, "chunk_bytes is 255, want at least 256"},
		{"no chunk at all", `{"max_chunks": 0}`, "max_chunks is 0, want at least 1"},
		{"negative", `{"max_chunks": -1}`, "max_chunks is -1"},
		{"another model", `{"model": "claude-haiku-4-5"}`, "model is built in"},
		{"the built-in model, written out", `{"model": "claude-opus-5-5"}`, "model is built in"},
		{"no model", `{"model": ""}`, "model is built in"},
		{"less effort", `{"effort": "low"}`, "effort is built in"},
		{"a larger window", `{"context_tokens": 2000000}`, "context_tokens is built in"},
		{"a shorter answer", `{"max_output_tokens": 100}`, "max_output_tokens is built in"},
		{"a shorter timeout", `{"request_timeout_seconds": 1}`, "request_timeout_seconds is built in"},
		{"one attempt", `{"attempts": 1}`, "attempts is built in"},
		{"a good key does not carry a bad one", `{"max_chunks": 4, "model": "x"}`, "model is built in"},
		{"the endpoint is not a setting", `{"base_url": "https://example.com"}`, "unknown field"},
		{"a string for a number", `{"max_chunks": "4"}`, "cannot unmarshal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Load([]byte(tc.repoFile))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %v, want it to mention %q", err, tc.wantErr)
			}
			if !reflect.DeepEqual(c, Config{}) {
				t.Fatalf("an error came with settings: %+v", c)
			}
		})
	}
}

// The fingerprint is the same for the same settings and differs with any
// one of them.
func TestFingerprint(t *testing.T) {
	base := mustLoad(t, "").Fingerprint()
	if len(base) != 64 || base != mustLoad(t, "{}").Fingerprint() {
		t.Fatalf("fingerprint %q is not a stable SHA-256", base)
	}
	seen := map[string]string{base: "the defaults"}
	for _, repoFile := range []string{
		`{"min_age_hours": 73}`,
		`{"unread_age_days": 15}`,
		`{"major_age_days": 15}`,
		`{"new_name_age_days": 366}`,
		`{"wait_deadline_days": 8}`,
		`{"fast_path": false}`,
		`{"fast_path_companions": "wait"}`,
		`{"chunk_bytes": 399999}`,
		`{"max_chunks": 11}`,
		`{"listed": {"npm": ["esbuild"]}}`,
		`{"listed": {"go_modules": ["esbuild"]}}`,
	} {
		fp := mustLoad(t, repoFile).Fingerprint()
		if other, dup := seen[fp]; dup {
			t.Errorf("%s has the fingerprint of %s", repoFile, other)
		}
		seen[fp] = repoFile
	}
	// Every field is in it: a field added to Config is covered without
	// anyone remembering to.
	c := mustLoad(t, "")
	v := reflect.ValueOf(&c).Elem()
	for i := 0; i < v.NumField(); i++ {
		changed := c
		f := reflect.ValueOf(&changed).Elem().Field(i)
		switch f.Kind() {
		case reflect.Int:
			f.SetInt(f.Int() + 1)
		case reflect.Bool:
			f.SetBool(!f.Bool())
		case reflect.String:
			f.SetString(f.String() + "x")
		case reflect.Struct:
			changed.Listed.Docker = append([]string{"example.com/"}, changed.Listed.Docker...)
		default:
			t.Fatalf("Config.%s has a kind this test does not know", v.Type().Field(i).Name)
		}
		if changed.Fingerprint() == base {
			t.Errorf("Config.%s is not in the fingerprint", v.Type().Field(i).Name)
		}
	}
}

func TestPolicy(t *testing.T) {
	p := mustLoad(t, "").Policy()
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
	if again := mustLoad(t, "").Policy(); !reflect.DeepEqual(again, want) {
		t.Fatal("changing one Policy changed the next")
	}
}

func TestRepoFileRaises(t *testing.T) {
	c := mustLoad(t, `{
		"min_age_hours": 96,
		"unread_age_days": 21,
		"major_age_days": 30,
		"new_name_age_days": 730,
		"wait_deadline_days": 3,
		"fast_path": false,
		"fast_path_companions": "wait"
	}`)
	want := specDefaults()
	want.MinAgeHours, want.UnreadAgeDays, want.MajorAgeDays, want.NewNameAgeDays = 96, 21, 30, 730
	want.WaitDeadlineDays, want.FastPath, want.FastPathCompanions = 3, false, "wait"
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("\n got %+v\nwant %+v", c, want)
	}
	p := c.Policy()
	if p.MinAge != 96*time.Hour || p.UnreadAge != 21*24*time.Hour || p.MajorAge != 30*24*time.Hour ||
		p.NewNameAge != 730*24*time.Hour || p.WaitDeadline != 3*24*time.Hour || p.FastPath || p.Companions != allow.CompanionsWait {
		t.Fatalf("policy %+v", p)
	}

	// The floor itself, a longer wait deadline, and the built-in modes
	// written out are all fine.
	for _, ok := range []string{
		`{"min_age_hours": 72}`,
		`{"unread_age_days": 14, "major_age_days": 14, "new_name_age_days": 365}`,
		`{"wait_deadline_days": 30}`,
		`{"wait_deadline_days": 1}`,
		`{"fast_path": true}`,
		`{"fast_path_companions": "ride-along"}`,
		`{"min_age_hours": 87600}`,
		`{"min_age_hours": null}`,
	} {
		mustLoad(t, ok)
	}
	// A null is an absent key.
	if c := mustLoad(t, `{"min_age_hours": null, "fast_path": null, "listed": null}`); !reflect.DeepEqual(c, specDefaults()) {
		t.Fatalf("nulls changed the defaults: %+v", c)
	}
}

// A repository file can never make the gate more permissive than the
// embedded defaults, and it cannot switch a fact off.
func TestRepoFileCannotLower(t *testing.T) {
	tests := []struct {
		name     string
		repoFile string
		wantErr  string
	}{
		{"min age below the floor", `{"min_age_hours": 71}`, "min_age_hours is 71, below the built-in 72"},
		{"min age zero", `{"min_age_hours": 0}`, "below the built-in"},
		{"min age negative", `{"min_age_hours": -1}`, "below the built-in"},
		{"unread age below the floor", `{"unread_age_days": 13}`, "unread_age_days is 13, below the built-in 14"},
		{"major age below the floor", `{"major_age_days": 7}`, "major_age_days is 7, below the built-in 14"},
		{"major age zero", `{"major_age_days": 0}`, "below the built-in"},
		{"new name age below the floor", `{"new_name_age_days": 364}`, "new_name_age_days is 364, below the built-in 365"},
		{"one good key does not carry a bad one", `{"min_age_hours": 100, "major_age_days": 1}`, "major_age_days"},
		{"an age too large to mean anything", `{"unread_age_days": 3651}`, "more than 3650"},
		{"min age too large", `{"min_age_hours": 87601}`, "more than 87600"},
		{"wait deadline zero", `{"wait_deadline_days": 0}`, "wait_deadline_days is 0"},
		{"wait deadline negative", `{"wait_deadline_days": -7}`, "wait_deadline_days"},
		{"wait deadline too large", `{"wait_deadline_days": 100000}`, "wait_deadline_days"},
		{"unknown companion mode", `{"fast_path_companions": "ride_along"}`, "fast_path_companions"},
		{"empty companion mode", `{"fast_path_companions": ""}`, "fast_path_companions"},

		// There is no key that disables a fact, a check or the model.
		{"disable a fact", `{"require_bound": false}`, "unknown field"},
		{"disable a fact by name", `{"facts": {"clean": false}}`, "unknown field"},
		{"skip the model", `{"veto": "off"}`, "unknown field"},
		{"skip the age", `{"min_age": 0}`, "unknown field"},
		{"an ecosystem with no rule", `{"listed": {"uv": ["requests"]}}`, "unknown field"},
		{"design B's key", `{"soak_days": 1}`, "unknown field"},
		{"remove from the list", `{"unlisted": {"go_modules": ["golang.org/x/"]}}`, "unknown field"},

		{"not JSON", `min_age_hours: 96`, "invalid character"},
		{"not an object", `[72]`, "cannot unmarshal"},
		{"a string for a number", `{"min_age_hours": "96"}`, "cannot unmarshal"},
		{"a fraction", `{"min_age_hours": 72.5}`, "cannot unmarshal"},
		{"a number for a flag", `{"fast_path": 0}`, "cannot unmarshal"},
		{"a string for a list", `{"listed": {"npm": "esbuild"}}`, "cannot unmarshal"},
		{"two documents", `{} {"min_age_hours": 1}`, "more than one JSON value"},
		{"trailing text", `{} x`, "more than one JSON value"},
		{"whitespace only", ` `, "EOF"},
		{"too large", `{"listed": {"npm": ["` + strings.Repeat("a", maxFileBytes) + `"]}}`, "more than 65536"},

		{"empty entry", `{"listed": {"npm": [""]}}`, "empty"},
		{"design B's wildcard", `{"listed": {"github_actions": ["astral-sh/*"]}}`, "no wildcards"},
		{"a glob", `{"listed": {"go_modules": ["github.com/?"]}}`, "no wildcards"},
		{"a space", `{"listed": {"go_modules": [" golang.org/x/"]}}`, "byte ' ' at 0"},
		{"a newline", `{"listed": {"npm": ["esbuild\n"]}}`, "byte '\\n'"},
		// A Cyrillic "о" where the Latin one belongs, written as an escape.
		{"not ASCII", `{"listed": {"go_modules": ["gоlang.org/x/"]}}`, "byte 0xd0 at 1"},
		{"rooted", `{"listed": {"docker": ["/library/"]}}`, "empty path element"},
		{"only a slash", `{"listed": {"docker": ["/"]}}`, "empty path element"},
		{"an empty element", `{"listed": {"go_modules": ["github.com//aws/"]}}`, "empty path element"},
		{"too long", `{"listed": {"npm": ["` + strings.Repeat("a", maxEntryBytes+1) + `"]}}`, "longer than 200"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Load([]byte(tc.repoFile))
			if err == nil {
				t.Fatalf("no error; got %+v", c)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q, want it to mention %q", err, tc.wantErr)
			}
			if !reflect.DeepEqual(c, Config{}) {
				t.Fatalf("an error came with settings: %+v", c)
			}
		})
	}
}

func TestRepoFileExtendsLists(t *testing.T) {
	c := mustLoad(t, `{"listed": {
		"go_modules": ["modernc.org/", "golang.org/x/", "github.com/klauspost/compress"],
		"github_actions": ["astral-sh/", "sadbox/ci"],
		"npm": ["esbuild", "@esbuild/", "esbuild"]
	}}`)
	want := specDefaults()
	want.Listed.GoModules = append(want.Listed.GoModules, "modernc.org/", "github.com/klauspost/compress")
	want.Listed.GitHubActions = append(want.Listed.GitHubActions, "astral-sh/", "sadbox/ci")
	want.Listed.NPM = append(want.Listed.NPM, "esbuild", "@esbuild/")
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("\n got %+v\nwant %+v", c, want)
	}

	p := c.Policy()
	for eco, names := range map[string][]string{
		allow.GoModules:     {"modernc.org/sqlite", "github.com/klauspost/compress", "github.com/klauspost/compress/zstd", "golang.org/x/net"},
		allow.GitHubActions: {"astral-sh/setup-uv", "sadbox/ci", "sadbox/ci/.github/workflows/lint.yml", "actions/checkout"},
		allow.NPM:           {"esbuild", "@esbuild/linux-x64", "tailwindcss"},
		allow.Docker:        {"docker.io/library/node"},
	} {
		for _, name := range names {
			if !allow.Listed(p, eco, name) {
				t.Errorf("%s: %q is not listed", eco, name)
			}
		}
	}
	for eco, names := range map[string][]string{
		allow.GoModules:     {"github.com/klauspost/cpuid", "github.com/klauspost/compress-evil"},
		allow.GitHubActions: {"sadbox/ci-evil", "sadbox/dep-review"},
		allow.NPM:           {"esbuild-evil", "@esbuild-evil/x"},
	} {
		for _, name := range names {
			if allow.Listed(p, eco, name) {
				t.Errorf("%s: %q is listed", eco, name)
			}
		}
	}

	// Every built-in entry survives whatever a repository writes: a list
	// in the file adds to the built-in one, it does not replace it.
	for _, repoFile := range []string{
		`{"listed": {"go_modules": [], "github_actions": [], "docker": [], "npm": []}}`,
		`{"listed": {"go_modules": ["example.com/"]}}`,
		`{"listed": {"go_modules": null}}`,
	} {
		got := mustLoad(t, repoFile).Listed
		def := specDefaults().Listed
		for _, pair := range [][2][]string{
			{got.GoModules, def.GoModules}, {got.GitHubActions, def.GitHubActions}, {got.Docker, def.Docker}, {got.NPM, def.NPM},
		} {
			if len(pair[0]) < len(pair[1]) || !reflect.DeepEqual(pair[0][:len(pair[1])], pair[1]) {
				t.Errorf("%s: built-in entries lost: %v", repoFile, pair[0])
			}
		}
	}

	// One Load's lists are not another's.
	c.Listed.NPM[0] = "left-pad"
	if again := mustLoad(t, ""); !reflect.DeepEqual(again, specDefaults()) {
		t.Fatal("changing one Config changed the next")
	}
}

// The hints that send the owner to the list name this package's file.
func TestHintsNameTheRepoFile(t *testing.T) {
	for _, r := range []allow.Reason{allow.ReasonNotKnown, allow.ReasonMajorUnlisted, allow.ReasonNewNameYoung, allow.ReasonPolicyInvalid} {
		if !strings.Contains(r.Hint(), RepoFile) {
			t.Errorf("%q: the hint does not name %s: %q", r, RepoFile, r.Hint())
		}
	}
}

// Complete takes a whole file in place of the embedded one. It is for
// measuring a policy, so unlike a repository's file it may go below the
// built-in values and leave list entries out; like every file it must be
// strict about what it says.
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

	got, err := Complete(defaultsJSON)
	if err != nil || !reflect.DeepEqual(got, specDefaults()) {
		t.Errorf("the embedded file: %+v, %v; want the defaults", got, err)
	}

	got, err = Complete(edit(func(m map[string]any) {
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
		{"an unknown key", edit(func(m map[string]any) { m["allow_everything"] = true }), "unknown field"},
		{"an age of zero", edit(func(m map[string]any) { m["min_age_hours"] = 0 }), "min_age_hours"},
		{"a bad list entry", edit(func(m map[string]any) { m["listed"].(map[string]any)["npm"] = []string{"/"} }), "listed.npm"},
		{"too large", append(edit(func(map[string]any) {}), make([]byte, maxFileBytes)...), "bytes"},
		{"empty", nil, "EOF"},
	} {
		if _, err := Complete(tc.file); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error that says %q", tc.name, err, tc.want)
		}
	}
}

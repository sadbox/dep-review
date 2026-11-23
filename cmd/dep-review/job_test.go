package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/config"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/veto"
	"github.com/sadbox/dep-review/internal/wire"
)

const (
	testHead = "1111111111111111111111111111111111111111"
	testKey  = "2222222222222222222222222222222222222222222222222222222222222222"
)

// The repository and the app come from the job's environment, and only
// in the shapes the gate puts into URLs and logins.
func TestLandConfig(t *testing.T) {
	c := gh.New("token")
	t.Setenv("GITHUB_REPOSITORY", "o/r")
	t.Setenv("GITHUB_SERVER_URL", "https://github.example")
	t.Setenv("GITHUB_RUN_ID", "42")
	cfg, err := landConfig(c, "dep-review-gate")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GitHub != c || cfg.Repo != "o/r" || cfg.BotLogin != "dep-review-gate[bot]" ||
		cfg.ServerURL != "https://github.example" || cfg.RunURL != "https://github.example/o/r/actions/runs/42" || cfg.Notifier != nil {
		t.Errorf("config %+v", cfg)
	}

	// Values of another shape are left out, not escaped.
	t.Setenv("GITHUB_SERVER_URL", "https://github.example/)[x](https://evil.example")
	t.Setenv("GITHUB_RUN_ID", "42/../../x")
	cfg, err = landConfig(c, "gate")
	if err != nil || cfg.ServerURL != "https://github.com" || cfg.RunURL != "" {
		t.Errorf("config %+v, %v", cfg, err)
	}

	for _, slug := range []string{"", "Gate", "gate[bot]", "a b", "-gate", "gate/../x", strings.Repeat("a", 64)} {
		if _, err := landConfig(c, slug); err == nil {
			t.Errorf("slug %q accepted", slug)
		}
	}
	t.Setenv("GITHUB_REPOSITORY", "o/r/../x")
	if _, err := landConfig(c, "gate"); err == nil {
		t.Error("a repository that is not owner/name accepted")
	}
}

// The review job and the scheduled job build the reviewer from the
// built-in settings, and publish from the repository's. They must agree
// on the fingerprint, or no verdict would ever be joined to a read: what
// a repository may change is not part of it, and a read prepared under a
// repository's lower budget fits the built-in one.
func TestReviewerFingerprint(t *testing.T) {
	builtIn, err := config.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	lowered, err := config.Load([]byte(`{"chunk_bytes": 1000, "max_chunks": 2, "min_age_hours": 200, "listed": {"npm": ["left-pad"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if builtIn.Fingerprint() == lowered.Fingerprint() {
		t.Fatal("the two configurations are the same; the test proves nothing")
	}
	a, b := veto.FromConfig(builtIn), veto.FromConfig(lowered)
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("a repository's file changes the reviewer's fingerprint")
	}
	if b.Limits().ChunkBytes > a.Limits().ChunkBytes || b.Limits().MaxChunks > a.Limits().MaxChunks {
		t.Errorf("a repository raised the read budget: %+v over %+v", b.Limits(), a.Limits())
	}
}

// goodFacts is a facts file about pull request 7 of o/r at testHead with
// one prepared read.
func goodFacts() wire.Facts {
	yes := allow.Yes("ok", "test")
	no := allow.No("no", "test")
	chunk := wire.NewChunkFile(0, 0, "text")
	return wire.Facts{
		Version:     wire.Version,
		PullRequest: wire.PullRequest{Repo: "o/r", Number: 7, Head: testHead},
		Config:      strings.Repeat("3", 64),
		GatheredAt:  time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC),
		Facts: wire.PRFacts{
			Ecosystem: allow.GoModules, Identity: yes, Shape: yes, ChecksConfigured: yes,
			Updates: []wire.Update{{
				Name: "example.com/m", From: "v1.0.0", To: "v1.0.1",
				Known: yes, Listed: no, NewName: no, Increase: yes, Major: no, Bound: yes, Clean: yes, NoRegress: yes, SecurityFix: no, Superseded: no,
				FirstSeen: allow.At(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), "test"),
				Prepared:  wire.Read{Status: wire.Prepared, Key: testKey, State: allow.ReadFull, Chunks: []wire.ChunkFile{chunk}},
			}},
		},
	}
}

func writeFacts(t *testing.T, path string, f wire.Facts) {
	t.Helper()
	b, err := wire.EncodeFacts(f)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(b))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPrepared(t *testing.T) {
	f := goodFacts()
	if !prepared(f) {
		t.Error("a prepared read is nothing to review")
	}
	f.Facts.Updates[0].Prepared = wire.Read{Status: wire.Nothing}
	if prepared(f) {
		t.Error("an update with nothing to read is something to review")
	}
	f.Facts.Updates = nil
	if prepared(f) {
		t.Error("no updates are something to review")
	}
}

// The facts are believed only about the pull request and head classify
// proved, and never to say more for its identity than classify did: the
// job that wrote them reads what a pull request wrote, classify does not.
func TestCheckFacts(t *testing.T) {
	class := model.Classification{Repo: "o/r", PR: 7, HeadSHA: testHead, Kind: model.KindDependabot}
	for _, tt := range []struct {
		name  string
		class func(c *model.Classification)
		facts func(f *wire.Facts)
		want  string // part of the error; "" for none
	}{
		{name: "the same pull request"},
		{name: "another pull request", facts: func(f *wire.Facts) { f.PullRequest.Number = 8 }, want: "classify looked at"},
		{name: "another head", facts: func(f *wire.Facts) { f.PullRequest.Head = strings.Repeat("4", 40) }, want: "classify looked at"},
		{name: "another repository", facts: func(f *wire.Facts) { f.PullRequest.Repo = "o/other" }, want: "classify looked at"},
		{name: "unverified, and the facts say so",
			class: func(c *model.Classification) { c.Kind = model.KindDependabotUnverified },
			facts: func(f *wire.Facts) { f.Facts.Identity = allow.No("pushed by a person", "classify") }},
		{name: "unverified, and the facts say Dependabot's alone",
			class: func(c *model.Classification) { c.Kind = model.KindDependabotUnverified },
			want:  "classify said"},
		{name: "pending, and the facts say it waits",
			class: func(c *model.Classification) { c.Kind = model.KindPending },
			facts: func(f *wire.Facts) { f.Facts.Identity = allow.Unavailable("the log lags", "classify") }},
		{name: "pending, and the facts say Dependabot's alone",
			class: func(c *model.Classification) { c.Kind = model.KindPending },
			want:  "classify said"},
		{name: "a kind the gate does nothing for",
			class: func(c *model.Classification) { c.Kind = model.KindOther },
			want:  "classify said"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, f := class, goodFacts()
			if tt.class != nil {
				tt.class(&c)
			}
			if tt.facts != nil {
				tt.facts(&f)
			}
			err := checkFacts(c, f)
			if tt.want == "" && err != nil || tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

// A verdicts file that is not there is no verdicts; one that is there has
// to decode.
func TestReadVerdicts(t *testing.T) {
	dir := t.TempDir()
	v, err := readVerdicts(filepath.Join(dir, "none.json"))
	if err != nil || v.Version != wire.Version || len(v.Verdicts) != 0 {
		t.Errorf("a missing file: %+v, %v", v, err)
	}
	b, err := wire.EncodeVerdicts(wire.Verdicts{Version: wire.Version, Verdicts: []wire.Verdict{
		{Key: testKey, Fingerprint: strings.Repeat("5", 64), Read: allow.ReadFull},
	}})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "v.json"), string(b))
	if v, err := readVerdicts(filepath.Join(dir, "v.json")); err != nil || len(v.Verdicts) != 1 || v.Verdicts[0].Key != testKey {
		t.Errorf("a verdicts file: %+v, %v", v, err)
	}
	writeFile(t, filepath.Join(dir, "bad.json"), `{"version":1,"verdicts":[{"key":"x"}]}`)
	if _, err := readVerdicts(filepath.Join(dir, "bad.json")); err == nil {
		t.Error("a file that does not decode was read")
	}
	if _, err := readClassification(filepath.Join(dir, "none.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing classification: %v", err)
	}
}

// The example settings file is one the gate accepts, and it shows what a
// repository's file is for: stricter ages and more list entries.
func TestExampleSettings(t *testing.T) {
	b, err := os.ReadFile("../../examples/" + filepath.Base(config.RepoFile))
	if err != nil {
		t.Fatal(err)
	}
	example, err := config.Load(b)
	if err != nil {
		t.Fatalf("the example is not a usable settings file: %v", err)
	}
	builtIn, err := config.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	if example.MinAgeHours <= builtIn.MinAgeHours || len(example.Listed.NPM) <= len(builtIn.Listed.NPM) {
		t.Errorf("the example raises no age or adds no list entry: %+v", example)
	}
}

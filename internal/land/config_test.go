package land

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/config"
	"github.com/sadbox/dep-review/internal/wire"
)

// LoadConfig is how a job that gathers facts gets its settings: the same
// file Decide reads, from the default branch, so that the two agree on
// the fingerprint.
func TestLoadConfig(t *testing.T) {
	const strict = `{"min_age_hours": 200}`
	builtIn, _ := defaults(t)
	raised, err := config.Load([]byte(strict))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		github func(f *fakeGitHub)
		want   config.Config
		usable bool
		err    bool
	}{
		{name: "no file: the built-in settings", want: builtIn, usable: true},
		{name: "the repository's file",
			github: func(f *fakeGitHub) { f.policyCode, f.policy = 200, strict },
			want:   raised, usable: true},
		{name: "a file that cannot be used: the built-in settings, marked",
			github: func(f *fakeGitHub) { f.policyCode, f.policy = 200, `{"min_age_hours": 1}` },
			want:   builtIn},
		{name: "a directory where the file should be",
			github: func(f *fakeGitHub) { f.policyCode, f.policyBody = 200, `[{"type":"file","name":"x"}]` },
			want:   builtIn},
		{name: "the file cannot be fetched",
			github: func(f *fakeGitHub) { f.policyCode = 500 }, err: true},
		{name: "a default branch of another shape is not put in a URL",
			github: func(f *fakeGitHub) { f.branch = "main?ref=evil" }, err: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake(t)
			if tt.github != nil {
				tt.github(f)
			}
			got, usable, err := LoadConfig(context.Background(), f.config(t0, nil))
			if (err != nil) != tt.err {
				t.Fatalf("err = %v, want an error: %v", err, tt.err)
			}
			if err != nil {
				return
			}
			if usable != tt.usable || got.Fingerprint() != tt.want.Fingerprint() {
				t.Errorf("usable %v with fingerprint %s, want %v with %s", usable, got.Fingerprint(), tt.usable, tt.want.Fingerprint())
			}
			if len(f.writes()) != 0 {
				t.Errorf("LoadConfig wrote: %v", f.writes())
			}
		})
	}
	t.Run("without a usable Config", func(t *testing.T) {
		f := newFake(t)
		cfg := f.config(t0, nil)
		cfg.Repo = "o/r/../x"
		if _, _, err := LoadConfig(context.Background(), cfg); err == nil {
			t.Error("a repository that is not owner/name was asked about")
		}
	})
}

// LoadConfig reads the repository's settings and no comment, so the fetch
// job, which is not told who the gate app is, can run it.
func TestLoadConfigWithoutTheGateApp(t *testing.T) {
	f := newFake(t)
	cfg := f.config(t0, nil)
	cfg.BotLogin = ""
	builtIn, _ := defaults(t)
	got, usable, err := LoadConfig(context.Background(), cfg)
	if err != nil || !usable || got.Fingerprint() != builtIn.Fingerprint() {
		t.Errorf("usable %v with fingerprint %s, %v", usable, got.Fingerprint(), err)
	}
	if n := f.count("GET", "/comments"); n != 0 {
		t.Errorf("%d reads of a pull request's comments", n)
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
		{Key: keyA, Fingerprint: strings.Repeat("5", 64), Read: allow.ReadFull},
	}})
	if err != nil {
		t.Fatal(err)
	}
	overwrite(t, dir, "v.json", string(b))
	if v, err := readVerdicts(filepath.Join(dir, "v.json")); err != nil || len(v.Verdicts) != 1 || v.Verdicts[0].Key != keyA {
		t.Errorf("a verdicts file: %+v, %v", v, err)
	}
	overwrite(t, dir, "bad.json", `{"version":1,"verdicts":[{"key":"x"}]}`)
	if _, err := readVerdicts(filepath.Join(dir, "bad.json")); err == nil {
		t.Error("a file that does not decode was read")
	}
}

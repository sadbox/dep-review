package land

import (
	"context"
	"testing"

	"github.com/sadbox/dep-review/internal/config"
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

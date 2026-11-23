// Package config holds the gate's settings (docs/v0.2-spec.md, section 5
// and amendments 10 and 56): the one file embedded in the binary. It does
// no I/O beyond the embed, and nothing a repository or a pull request
// holds changes a setting: there is no repository file, so no job has a
// policy to fetch, and no two jobs of a run can decide under different
// ones.
package config

import (
	_ "embed" // for defaults.json
	json "encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
)

//go:embed policy/defaults.json
var defaultsJSON []byte

const (
	// maxEntryBytes bounds one list entry.
	maxEntryBytes = 200
	// maxDays bounds every age, so no value can overflow a time.Duration
	// (about 292 years) or park a pull request for longer than anyone
	// will remember it.
	maxDays = 3650
	// minChunkBytes is the smallest chunk_bytes the file may set. It is
	// internal/artifact's own minimum (below it a file header may not fit
	// in a chunk); a test keeps the two equal. A smaller value would be a
	// gate whose every read is refused.
	minChunkBytes = 256
)

// Lists is the owner-kept list, per ecosystem. How an entry matches a
// name is allow.Listed's rule.
type Lists struct {
	GoModules     []string `json:"go_modules"`
	GitHubActions []string `json:"github_actions"`
	Docker        []string `json:"docker"`
	NPM           []string `json:"npm"`
}

// Config is the settings: every value present, in the units the file
// uses.
type Config struct {
	MinAgeHours        int    `json:"min_age_hours"`
	UnreadAgeDays      int    `json:"unread_age_days"`
	MajorAgeDays       int    `json:"major_age_days"`
	NewNameAgeDays     int    `json:"new_name_age_days"`
	WaitDeadlineDays   int    `json:"wait_deadline_days"`
	FastPath           bool   `json:"fast_path"`
	FastPathCompanions string `json:"fast_path_companions"`
	Listed             Lists  `json:"listed"`

	// The model settings. internal/veto turns them into its client's
	// settings (veto.FromConfig) and checks them against each other; the
	// fetch job takes its artifact limits from the same values, so a read
	// is always prepared within what the review job will accept.

	// Model is the model ID the veto request names.
	Model string `json:"model"`
	// Effort is how hard the model is asked to think.
	Effort string `json:"effort"`
	// ContextTokens is Model's documented context window.
	ContextTokens int `json:"context_tokens"`
	// MaxOutputTokens is the most the model may write for one chunk.
	MaxOutputTokens int `json:"max_output_tokens"`
	// ChunkBytes is the most escaped text one chunk may hold.
	ChunkBytes int `json:"chunk_bytes"`
	// MaxChunks is the most chunks one update may be split into.
	MaxChunks int `json:"max_chunks"`
	// RequestTimeoutSeconds bounds one attempt at one chunk.
	RequestTimeoutSeconds int `json:"request_timeout_seconds"`
	// Attempts is how many times one chunk's request is sent.
	Attempts int `json:"attempts"`
}

// file is what the embedded file may say. Pointers tell an absent key
// from a zero, so "fast_path": false is a setting and a missing key is
// not.
type file struct {
	MinAgeHours        *int    `json:"min_age_hours"`
	UnreadAgeDays      *int    `json:"unread_age_days"`
	MajorAgeDays       *int    `json:"major_age_days"`
	NewNameAgeDays     *int    `json:"new_name_age_days"`
	WaitDeadlineDays   *int    `json:"wait_deadline_days"`
	FastPath           *bool   `json:"fast_path"`
	FastPathCompanions *string `json:"fast_path_companions"`
	Listed             Lists   `json:"listed"`

	Model                 *string `json:"model"`
	Effort                *string `json:"effort"`
	ContextTokens         *int    `json:"context_tokens"`
	MaxOutputTokens       *int    `json:"max_output_tokens"`
	ChunkBytes            *int    `json:"chunk_bytes"`
	MaxChunks             *int    `json:"max_chunks"`
	RequestTimeoutSeconds *int    `json:"request_timeout_seconds"`
	Attempts              *int    `json:"attempts"`
}

// Load returns the gate's settings: the embedded file's, and nothing
// else. It takes no argument on purpose. Whatever a job is handed (a
// repository's file, a pull request's, an environment variable) has no
// way in.
//
// An error means the embedded file itself is broken. That is a fault of
// the build, which a test finds before a run does; a job that meets it
// fails, and nothing is decided.
func Load() (Config, error) {
	c, err := complete(defaultsJSON)
	if err != nil {
		return Config{}, fmt.Errorf("config: embedded defaults: %w", err)
	}
	return c, nil
}

// Policy converts the settings to what allow.Decide takes. The result
// shares nothing with c.
func (c Config) Policy() allow.Policy {
	const day = 24 * time.Hour
	return allow.Policy{
		MinAge:       time.Duration(c.MinAgeHours) * time.Hour,
		UnreadAge:    time.Duration(c.UnreadAgeDays) * day,
		MajorAge:     time.Duration(c.MajorAgeDays) * day,
		NewNameAge:   time.Duration(c.NewNameAgeDays) * day,
		WaitDeadline: time.Duration(c.WaitDeadlineDays) * day,
		FastPath:     c.FastPath,
		Companions:   allow.Companions(c.FastPathCompanions),
		Listed: map[string][]string{
			allow.GoModules:     append([]string(nil), c.Listed.GoModules...),
			allow.GitHubActions: append([]string(nil), c.Listed.GitHubActions...),
			allow.Docker:        append([]string(nil), c.Listed.Docker...),
			allow.NPM:           append([]string(nil), c.Listed.NPM...),
		},
	}
}

// complete parses the embedded file, which must set everything. Load is
// the package's only way to a Config, and a test in cmd/dep-review keeps
// it so.
func complete(b []byte) (Config, error) {
	f, err := parse(b)
	if err != nil {
		return Config{}, err
	}
	if f.MinAgeHours == nil || f.UnreadAgeDays == nil || f.MajorAgeDays == nil || f.NewNameAgeDays == nil ||
		f.WaitDeadlineDays == nil || f.FastPath == nil || f.FastPathCompanions == nil ||
		f.Model == nil || f.Effort == nil || f.ContextTokens == nil || f.MaxOutputTokens == nil ||
		f.ChunkBytes == nil || f.MaxChunks == nil || f.RequestTimeoutSeconds == nil || f.Attempts == nil {
		return Config{}, errors.New("a key is missing")
	}
	c := Config{
		MinAgeHours:           *f.MinAgeHours,
		UnreadAgeDays:         *f.UnreadAgeDays,
		MajorAgeDays:          *f.MajorAgeDays,
		NewNameAgeDays:        *f.NewNameAgeDays,
		WaitDeadlineDays:      *f.WaitDeadlineDays,
		FastPath:              *f.FastPath,
		FastPathCompanions:    *f.FastPathCompanions,
		Model:                 *f.Model,
		Effort:                *f.Effort,
		ContextTokens:         *f.ContextTokens,
		MaxOutputTokens:       *f.MaxOutputTokens,
		ChunkBytes:            *f.ChunkBytes,
		MaxChunks:             *f.MaxChunks,
		RequestTimeoutSeconds: *f.RequestTimeoutSeconds,
		Attempts:              *f.Attempts,
	}
	// Only that each is there and is not nonsense. Whether they fit each
	// other and the model (chunk size against the context window) is
	// internal/veto's Validate, which knows the request they go into; a
	// test there runs it on these values.
	if c.Model == "" || c.Effort == "" {
		return Config{}, errors.New("model or effort is empty")
	}
	for _, n := range []struct {
		key   string
		value int
		min   int
	}{
		{"context_tokens", c.ContextTokens, 1},
		{"max_output_tokens", c.MaxOutputTokens, 1},
		{"chunk_bytes", c.ChunkBytes, minChunkBytes},
		{"max_chunks", c.MaxChunks, 1},
		{"request_timeout_seconds", c.RequestTimeoutSeconds, 1},
		{"attempts", c.Attempts, 1},
	} {
		if n.value < n.min {
			return Config{}, fmt.Errorf("%s is %d, want at least %d", n.key, n.value, n.min)
		}
	}
	for _, age := range []struct {
		key        string
		value, max int
	}{
		{"min_age_hours", c.MinAgeHours, maxDays * 24},
		{"unread_age_days", c.UnreadAgeDays, maxDays},
		{"major_age_days", c.MajorAgeDays, maxDays},
		{"new_name_age_days", c.NewNameAgeDays, maxDays},
		{"wait_deadline_days", c.WaitDeadlineDays, maxDays},
	} {
		if age.value < 1 || age.value > age.max {
			return Config{}, fmt.Errorf("%s is %d, want 1 to %d", age.key, age.value, age.max)
		}
	}
	if m := allow.Companions(c.FastPathCompanions); m != allow.RideAlong && m != allow.CompanionsWait {
		return Config{}, fmt.Errorf("fast_path_companions is %q", c.FastPathCompanions)
	}
	if err := checkLists(f.Listed); err != nil {
		return Config{}, err
	}
	c.Listed = f.Listed
	return c, nil
}

// parse decodes one file strictly: one JSON object and nothing after it,
// known keys only, each in its exact spelling and at most once.
func parse(b []byte) (file, error) {
	var f file
	err := json.Unmarshal(b, &f, json.RejectUnknownMembers(true))
	return f, err
}

// checkLists holds every entry of the list to checkEntry.
func checkLists(l Lists) error {
	for _, list := range []struct {
		key     string
		entries []string
	}{
		{"go_modules", l.GoModules},
		{"github_actions", l.GitHubActions},
		{"docker", l.Docker},
		{"npm", l.NPM},
	} {
		for _, entry := range list.entries {
			if err := checkEntry(entry); err != nil {
				return fmt.Errorf("listed.%s: %q: %w", list.key, entry, err)
			}
		}
	}
	return nil
}

// checkEntry refuses a list entry that could not mean what its author
// intended. allow.Listed matches byte for byte with no wildcards, so a
// "*" or a stray space would be an entry that silently never matches, and
// an entry that is empty or starts at a "/" has no name in it at all.
func checkEntry(entry string) error {
	if entry == "" {
		return errors.New("empty")
	}
	if len(entry) > maxEntryBytes {
		return fmt.Errorf("longer than %d bytes", maxEntryBytes)
	}
	if at := entryBad.FindStringIndex(entry); at != nil {
		// %q of a byte above 0x7f would print it as a Latin-1 letter that
		// is not in the entry.
		c := entry[at[0]]
		shown := fmt.Sprintf("%q", c)
		if c >= 0x80 {
			shown = fmt.Sprintf("%#02x", c)
		}
		return fmt.Errorf("byte %s at %d: an entry is a name or a prefix ending in \"/\", with letters, digits and -._~@:/ only; there are no wildcards", shown, at[0])
	}
	if strings.HasPrefix(entry, "/") || strings.Contains(entry, "//") {
		return errors.New("an empty path element")
	}
	return nil
}

// entryBad matches the first byte an entry may not have.
var entryBad = regexp.MustCompile(`[^A-Za-z0-9._~@:/-]`)

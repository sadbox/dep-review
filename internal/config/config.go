// Package config resolves the gate's settings (docs/v0.2-spec.md, section
// 5 and amendment 10): the defaults embedded in the binary, and on top of
// them a repository's own file. It does no I/O beyond the embed: the
// caller reads RepoFile from the repository's DEFAULT BRANCH and passes
// the bytes in. A file from the pull request's head must never reach Load,
// because the pull request would then be choosing its own rules.
//
// The embedded values are floors. A repository file can make the gate
// stricter (raise an age, turn the fast path off, make companions wait,
// make a read smaller, which at worst makes it partial) and can add list
// entries. It cannot lower an age, remove a list entry or say which model
// reads the code and how, and it has no key that switches a fact off: an
// unknown key is an error, not something to ignore.
package config

import (
	"crypto/sha256"
	_ "embed" // for defaults.json
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
)

//go:embed policy/defaults.json
var defaultsJSON []byte

// RepoFile is the path of a repository's own settings. Read it from the
// default branch only.
const RepoFile = ".github/dep-review.json"

const (
	// maxFileBytes bounds a repository file. The defaults are under 1 KB;
	// a list of a few hundred entries fits many times over.
	maxFileBytes = 64 << 10
	// maxEntryBytes bounds one list entry.
	maxEntryBytes = 200
	// maxDays bounds every age, so no value can overflow a time.Duration
	// (about 292 years) or park a pull request for longer than anyone
	// will remember it.
	maxDays = 3650
	// minChunkBytes is the smallest chunk_bytes a repository may ask for.
	// It is internal/artifact's own minimum (below it a file header may
	// not fit in a chunk); a test keeps the two equal. A smaller value
	// here would not be a stricter gate, only one whose every read is
	// refused.
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

// Config is the resolved settings: every value present, in the units the
// files use.
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

// file is what either file may say. Pointers tell an absent key from a
// zero, so "fast_path": false is a setting and a missing key is not.
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

// Load returns the embedded defaults with a repository's file applied on
// top. repoFile is the content of RepoFile on the default branch; nil or
// empty means the repository has none, and the result is the defaults.
//
// An error means the file is not usable as written. The caller must not
// fall back to the defaults silently then: the owner asked for something
// stricter or longer and did not get it, so the pull request goes to a
// person.
func Load(repoFile []byte) (Config, error) {
	c, err := complete(defaultsJSON)
	if err != nil {
		return Config{}, fmt.Errorf("config: embedded defaults: %w", err)
	}
	if len(repoFile) == 0 {
		return c, nil
	}
	if len(repoFile) > maxFileBytes {
		return Config{}, fmt.Errorf("config: %s is %d bytes, more than %d", RepoFile, len(repoFile), maxFileBytes)
	}
	f, err := parse(repoFile)
	if err != nil {
		return Config{}, fmt.Errorf("config: %s: %w", RepoFile, err)
	}
	if err := apply(&c, f); err != nil {
		return Config{}, fmt.Errorf("config: %s: %w", RepoFile, err)
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

// Fingerprint is a hash of every resolved setting (lower-case hex
// SHA-256). The fetch job writes it into the facts file, and a later job
// that resolves the configuration itself compares: facts gathered under
// other settings (another list, another chunk size) are not decided on.
func (c Config) Fingerprint() string {
	// Config holds only strings, numbers, a flag and lists of strings, so
	// encoding it cannot fail, and a struct's fields are written in their
	// declared order.
	b, err := json.Marshal(c)
	if err != nil {
		panic("config: " + err.Error())
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// complete parses a file that must set everything, and is held to no
// floor: the embedded one, which is the floor. Load is the package's only
// way in for any other file, and a test in cmd/dep-review keeps it so.
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
	if _, ok := companionStrictness(c.FastPathCompanions); !ok {
		return Config{}, fmt.Errorf("fast_path_companions is %q", c.FastPathCompanions)
	}
	// The embedded list goes through the same checks as a repository's.
	if err := extend(&c.Listed, f.Listed); err != nil {
		return Config{}, err
	}
	return c, nil
}

// parse decodes one file strictly: one JSON object and nothing after it,
// known keys only, each in its exact spelling and at most once.
func parse(b []byte) (file, error) {
	var f file
	err := json.Unmarshal(b, &f, json.RejectUnknownMembers(true))
	return f, err
}

// apply puts a repository's file on top of the defaults in c, refusing
// anything that would make the gate more permissive than the defaults.
func apply(c *Config, f file) error {
	for _, age := range []struct {
		key  string
		have *int
		want *int
		max  int
	}{
		{"min_age_hours", &c.MinAgeHours, f.MinAgeHours, maxDays * 24},
		{"unread_age_days", &c.UnreadAgeDays, f.UnreadAgeDays, maxDays},
		{"major_age_days", &c.MajorAgeDays, f.MajorAgeDays, maxDays},
		{"new_name_age_days", &c.NewNameAgeDays, f.NewNameAgeDays, maxDays},
	} {
		if age.want == nil {
			continue
		}
		if *age.want < *age.have {
			return fmt.Errorf("%s is %d, below the built-in %d: a repository can raise an age, not lower it", age.key, *age.want, *age.have)
		}
		if *age.want > age.max {
			return fmt.Errorf("%s is %d, more than %d", age.key, *age.want, age.max)
		}
		*age.have = *age.want
	}

	// The wait deadline is not an age a merge depends on: it is how long
	// a pull request may sit unmergeable before a person is told. Shorter
	// tells the person sooner, longer keeps retrying; neither can merge
	// anything, so both directions are allowed.
	if f.WaitDeadlineDays != nil {
		if *f.WaitDeadlineDays < 1 || *f.WaitDeadlineDays > maxDays {
			return fmt.Errorf("wait_deadline_days is %d, want 1 to %d", *f.WaitDeadlineDays, maxDays)
		}
		c.WaitDeadlineDays = *f.WaitDeadlineDays
	}

	if f.FastPath != nil {
		if *f.FastPath && !c.FastPath {
			return errors.New("fast_path is true and the built-in is false: a repository can turn the fast path off, not on")
		}
		c.FastPath = *f.FastPath
	}

	if f.FastPathCompanions != nil {
		want, ok := companionStrictness(*f.FastPathCompanions)
		if !ok {
			return fmt.Errorf("fast_path_companions is %q, want %q or %q", *f.FastPathCompanions, allow.RideAlong, allow.CompanionsWait)
		}
		have, _ := companionStrictness(c.FastPathCompanions)
		if want < have {
			return fmt.Errorf("fast_path_companions is %q and the built-in is %q: a repository can make companions wait, not ride along",
				*f.FastPathCompanions, c.FastPathCompanions)
		}
		c.FastPathCompanions = *f.FastPathCompanions
	}

	// The model settings a repository may not touch at all. Writing the
	// built-in value is refused too: the file would then break the day
	// the built-in changes, and until then it says nothing.
	for _, fixed := range []struct {
		key string
		set bool
	}{
		{"model", f.Model != nil},
		{"effort", f.Effort != nil},
		{"context_tokens", f.ContextTokens != nil},
		{"max_output_tokens", f.MaxOutputTokens != nil},
		{"request_timeout_seconds", f.RequestTimeoutSeconds != nil},
		{"attempts", f.Attempts != nil},
	} {
		if fixed.set {
			return fmt.Errorf("%s is built in: a repository can make a read smaller (chunk_bytes, max_chunks), and cannot change the model or how it is asked", fixed.key)
		}
	}
	// The two it may lower. A smaller read is at worst a partial read,
	// which waits longer; a larger one would be refused by the reviewer.
	for _, size := range []struct {
		key  string
		have *int
		want *int
		min  int
	}{
		{"chunk_bytes", &c.ChunkBytes, f.ChunkBytes, minChunkBytes},
		{"max_chunks", &c.MaxChunks, f.MaxChunks, 1},
	} {
		if size.want == nil {
			continue
		}
		if *size.want > *size.have {
			return fmt.Errorf("%s is %d, above the built-in %d: a repository can lower it, not raise it", size.key, *size.want, *size.have)
		}
		if *size.want < size.min {
			return fmt.Errorf("%s is %d, want at least %d", size.key, *size.want, size.min)
		}
		*size.have = *size.want
	}

	return extend(&c.Listed, f.Listed)
}

// companionStrictness orders the two companion modes: the higher one
// merges less.
func companionStrictness(mode string) (int, bool) {
	switch allow.Companions(mode) {
	case allow.RideAlong:
		return 0, true
	case allow.CompanionsWait:
		return 1, true
	}
	return 0, false
}

// extend adds more's entries to have. Entries are only ever added: there
// is no way to write "remove".
func extend(have *Lists, more Lists) error {
	for _, list := range []struct {
		key  string
		have *[]string
		more []string
	}{
		{"go_modules", &have.GoModules, more.GoModules},
		{"github_actions", &have.GitHubActions, more.GitHubActions},
		{"docker", &have.Docker, more.Docker},
		{"npm", &have.NPM, more.NPM},
	} {
		for _, entry := range list.more {
			if err := checkEntry(entry); err != nil {
				return fmt.Errorf("listed.%s: %q: %w", list.key, entry, err)
			}
			if !slices.Contains(*list.have, entry) {
				*list.have = append(*list.have, entry)
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

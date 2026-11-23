package veto

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/config"
)

// The model facts below come from Anthropic's published model table and
// API reference as the claude-api skill carries them (cached 2026-11-03),
// not from memory:
//
//   - claude-opus-5-5 has a context window of 1,000,000 tokens (the
//     max_input_tokens field of GET /v1/models/{id}) and can write at most
//     128,000 tokens in one response.
//   - Thinking is always on for it and counts toward max_tokens, although
//     its text is not returned. Effort (output_config.effort) is the only
//     control over how much it thinks; the API's default is "medium" and
//     the guidance is to set it explicitly.
//   - For a request that is not streamed, max_tokens near 16,000 keeps
//     the response inside the usual ten-minute HTTP timeout.
//   - The only supported way to count tokens is POST
//     /v1/messages/count_tokens with the same model. There is no local
//     tokenizer, so nothing here estimates tokens from text.
const (
	// DefaultModel is the model the gate asks unless told otherwise.
	DefaultModel = "claude-opus-5-5"
	// DefaultBaseURL is the Claude API.
	DefaultBaseURL = "https://api.anthropic.com"

	// defaultContextTokens is DefaultModel's documented context window.
	defaultContextTokens = 1_000_000
	// outputTokensCeiling is the most any current model writes in one
	// response; a larger max_tokens is refused by the API.
	outputTokensCeiling = 128_000

	// requestOverheadBytes is an upper bound on everything in one request
	// that is not chunk text: the system prompt, the answer schema, the
	// header and the list of unread files (at most maxUnreadListed lines
	// of at most maxUnreadPathBytes of path each). TestRequestOverhead
	// builds the largest such request and checks it against this number.
	requestOverheadBytes = 64_000
)

// Config is how the veto client asks: which model, how much it may read
// per request and how long it may take. Every value is a setting; the
// defaults are DefaultConfig.
type Config struct {
	// Model is the model ID, sent as written.
	Model string
	// ContextTokens is the documented context window of Model, in tokens.
	// It is what ChunkBytes is checked against. Whoever changes Model
	// must set this from that model's documentation (max_input_tokens in
	// GET /v1/models/{id}), not from memory.
	ContextTokens int
	// MaxOutputTokens is max_tokens: the most the model may write for one
	// chunk, thinking included. The request is not streamed, so keep it
	// near 16,000. An answer cut off at this limit is no verdict.
	MaxOutputTokens int
	// Effort is output_config.effort: low, medium, high, xhigh or max.
	Effort string
	// ChunkBytes is the most escaped text one chunk may hold. It is the
	// ChunkBytes of the artifact.Limits the read is prepared with, and a
	// request with a larger chunk is refused, not truncated.
	ChunkBytes int
	// MaxChunks is the most chunks one update may be split into, and so
	// the most requests one update costs (before retries).
	MaxChunks int
	// RequestTimeout bounds one attempt at one chunk, from sending the
	// request to reading the whole response.
	RequestTimeout time.Duration
	// Attempts is how many times one chunk's request is sent before the
	// update has no verdict: the first try and the retries after a rate
	// limit, an overload, a server error or a network failure.
	Attempts int
	// BaseURL is the API's origin. It must be https, except for a
	// loopback address in tests.
	BaseURL string
}

// DefaultConfig returns the settings the gate uses for DefaultModel. They
// are the values internal/config embeds (policy/defaults.json), where the
// gate reads them from; a test keeps the two equal, so the derivation
// below is the derivation of the embedded numbers.
//
// How the chunk budget follows from the model's documented window:
//
//	context window                         1,000,000 tokens
//	- max_tokens (answer and thinking)        16,000 tokens
//	- everything but chunk text               64,000 bytes (requestOverheadBytes)
//	= room for chunk text                    920,000 tokens
//
// How many tokens a byte of diff costs is not documented and differs by
// content, so the check assumes the worst a tokenizer can do, one token
// per byte: a chunk of up to 920,000 bytes then always fits. The default
// is 400,000 bytes, well under half of that, for two reasons that are
// judgement, not documentation: the one-token-per-byte bound is itself an
// assumption (see Client.CountTokens for measuring real chunks), and a
// smaller request is likelier to stay inside per-minute input limits and
// the request timeout.
//
// Twelve chunks make 4.8 MB of diff text per update. That covers the
// largest diff the design review measured (setup-go 7.0.0 to 7.1.0,
// dist/setup/index.js, 4.28 MB) even before internal/artifact's bundle
// rule shrinks it. An update that needs more is read in part, which
// allow.Decide treats as partial.
func DefaultConfig() Config {
	return Config{
		Model:           DefaultModel,
		ContextTokens:   defaultContextTokens,
		MaxOutputTokens: 16_000,
		// The API's default for this model is medium. Reading a diff for
		// a hidden payload is the kind of work the guidance asks at least
		// high for, and the calls are few.
		Effort:         "high",
		ChunkBytes:     400_000,
		MaxChunks:      12,
		RequestTimeout: 10 * time.Minute,
		Attempts:       3,
		BaseURL:        DefaultBaseURL,
	}
}

// FromConfig returns the client's settings for the gate's resolved
// configuration: the embedded model settings, with chunk_bytes and
// max_chunks as a repository may have lowered them. The API is always
// DefaultBaseURL; where the gate sends code is not a setting. The result
// still has to pass Validate.
//
// Both jobs go through here: review builds its client from it, and fetch
// takes Limits from it, so a read is prepared within exactly what the
// reviewer accepts.
func FromConfig(c config.Config) Config {
	return Config{
		Model:           c.Model,
		ContextTokens:   c.ContextTokens,
		MaxOutputTokens: c.MaxOutputTokens,
		Effort:          c.Effort,
		ChunkBytes:      c.ChunkBytes,
		MaxChunks:       c.MaxChunks,
		RequestTimeout:  time.Duration(c.RequestTimeoutSeconds) * time.Second,
		Attempts:        c.Attempts,
		BaseURL:         DefaultBaseURL,
	}
}

// Limits returns the budget internal/artifact must prepare a read within
// for this client to accept it.
func (c Config) Limits() artifact.Limits {
	return artifact.Limits{ChunkBytes: c.ChunkBytes, MaxChunks: c.MaxChunks}
}

// Validate reports the first setting the client cannot work with. In
// particular it refuses a chunk budget that could not fit Model's context
// window if every byte of a request cost one token.
func (c Config) Validate() error {
	if !headerSafe(c.Model) {
		return fmt.Errorf("veto: model %q is not a model ID", c.Model)
	}
	switch c.Effort {
	case "low", "medium", "high", "xhigh", "max":
	default:
		return fmt.Errorf("veto: effort %q, want low, medium, high, xhigh or max", c.Effort)
	}
	switch {
	case c.ContextTokens < 1:
		return errors.New("veto: context_tokens is not set: take it from the model's documentation")
	case c.MaxOutputTokens < 1 || c.MaxOutputTokens > outputTokensCeiling:
		return fmt.Errorf("veto: max_output_tokens is %d, want 1 to %d", c.MaxOutputTokens, outputTokensCeiling)
	case c.ChunkBytes < 1:
		return fmt.Errorf("veto: chunk_bytes is %d", c.ChunkBytes)
	case c.MaxChunks < 1:
		return fmt.Errorf("veto: max_chunks is %d", c.MaxChunks)
	case c.RequestTimeout <= 0:
		return fmt.Errorf("veto: request_timeout is %s", c.RequestTimeout)
	case c.Attempts < 1 || c.Attempts > 10:
		return fmt.Errorf("veto: attempts is %d, want 1 to 10", c.Attempts)
	}
	if room := c.ContextTokens - c.MaxOutputTokens - requestOverheadBytes; c.ChunkBytes > room {
		return fmt.Errorf("veto: chunk_bytes is %d, but a context window of %d tokens leaves room for %d bytes of chunk text "+
			"after max_output_tokens (%d) and the rest of the request (%d), at one token per byte",
			c.ChunkBytes, c.ContextTokens, room, c.MaxOutputTokens, requestOverheadBytes)
	}
	if _, err := apiOrigin(c.BaseURL); err != nil {
		return fmt.Errorf("veto: base_url: %w", err)
	}
	return nil
}

// apiOrigin checks that raw is an origin a credential may be sent to and
// returns it without a trailing slash. Plain http is accepted only for a
// loopback address, which is what a test server listens on.
func apiOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("not a URL")
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
		return "", errors.New("want scheme and host only")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
			return "", errors.New("plain http is only for a loopback address")
		}
	default:
		return "", errors.New("want https")
	}
	return u.Scheme + "://" + u.Host, nil
}

// headerSafe reports whether s can stand in a gate-written line as it is:
// 1 to 256 bytes of printable ASCII with no space. Model IDs, ecosystem
// keys, module paths, npm names, owner/repo and versions all are.
func headerSafe(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

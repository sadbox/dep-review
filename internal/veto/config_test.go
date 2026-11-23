package veto

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/config"
)

// The numbers live in two places: internal/config embeds them, and
// DefaultConfig documents how they follow from the model's window. They
// are the same numbers, and the embedded ones are a valid client config.
func TestFromConfig(t *testing.T) {
	embedded, err := config.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	got := FromConfig(embedded)
	if got != DefaultConfig() {
		t.Errorf("the embedded model settings are not DefaultConfig:\n got %+v\nwant %+v", got, DefaultConfig())
	}
	if err := got.Validate(); err != nil {
		t.Errorf("the embedded model settings are not valid: %v", err)
	}

	// What a repository lowered reaches the client, and the artifact
	// limits the fetch job takes from the same value.
	lowered, err := config.Load([]byte(`{"chunk_bytes": 1000, "max_chunks": 2}`))
	if err != nil {
		t.Fatal(err)
	}
	c := FromConfig(lowered)
	if err := c.Validate(); err != nil {
		t.Fatalf("a lowered budget is not valid: %v", err)
	}
	if got, want := c.Limits(), (artifact.Limits{ChunkBytes: 1000, MaxChunks: 2}); got != want {
		t.Errorf("Limits = %+v, want %+v", got, want)
	}
	// The smallest read a repository may ask for is still one the client
	// and the artifact reader accept.
	floor, err := config.Load([]byte(`{"chunk_bytes": 256, "max_chunks": 1}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := FromConfig(floor).Validate(); err != nil || FromConfig(floor).Limits().ChunkBytes != artifact.MinChunkBytes {
		t.Errorf("the floor: %v, %+v", err, FromConfig(floor).Limits())
	}
	// A lowered budget is the same question to the model: a stored
	// verdict is found by the read's key, which the budget shapes.
	if c.Fingerprint() != DefaultConfig().Fingerprint() {
		t.Error("the chunk budget changed the fingerprint")
	}
}

// The fingerprint covers what the model is asked and nothing else (spec
// section 11, amendment 11).
func TestFingerprint(t *testing.T) {
	base := DefaultConfig()
	fp := base.Fingerprint()
	if !isSHA256Hex(fp) || fp != DefaultConfig().Fingerprint() {
		t.Fatalf("fingerprint %q is not a stable SHA-256", fp)
	}
	for name, edit := range map[string]func(*Config){
		"model":  func(c *Config) { c.Model = "claude-haiku-4-5" },
		"effort": func(c *Config) { c.Effort = "medium" },
	} {
		c := base
		edit(&c)
		if c.Fingerprint() == fp {
			t.Errorf("a change of %s leaves the fingerprint as it was", name)
		}
	}
	for name, edit := range map[string]func(*Config){
		"chunk_bytes":       func(c *Config) { c.ChunkBytes = 1000 },
		"max_chunks":        func(c *Config) { c.MaxChunks = 1 },
		"request_timeout":   func(c *Config) { c.RequestTimeout = time.Second },
		"attempts":          func(c *Config) { c.Attempts = 1 },
		"base_url":          func(c *Config) { c.BaseURL = "http://127.0.0.1:1" },
		"context_tokens":    func(c *Config) { c.ContextTokens = 200_000 },
		"max_output_tokens": func(c *Config) { c.MaxOutputTokens = 8000 },
	} {
		c := base
		edit(&c)
		if c.Fingerprint() != fp {
			t.Errorf("a change of %s changes the fingerprint", name)
		}
	}

	// It is the hash of exactly these parts, and each of them counts.
	schema, err := encode(newAnswerSchema())
	if err != nil {
		t.Fatal(err)
	}
	parts := []string{systemPrompt, artifact.TextFormat, requestLayout, string(schema), base.Model, base.Effort}
	if fingerprint(parts...) != fp {
		t.Fatal("Fingerprint is not the hash of the prompt, the diff format, the layout, the schema, the model and the effort")
	}
	for i := range parts {
		changed := append([]string(nil), parts...)
		changed[i] += " "
		if fingerprint(changed...) == fp {
			t.Errorf("part %d is not in the fingerprint", i)
		}
	}
	// Parts are framed: text moved from one to the next is another hash.
	if fingerprint("ab", "c") == fingerprint("a", "bc") || fingerprint("a", "") == fingerprint("a") {
		t.Error("the parts are not length-framed")
	}
}

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig()
	if err := c.Validate(); err != nil {
		t.Fatalf("the default config is not valid: %v", err)
	}
	if c.Model != "claude-opus-5-5" || c.BaseURL != "https://api.anthropic.com" {
		t.Errorf("model %q at %q", c.Model, c.BaseURL)
	}
	if got := c.Limits(); got != (artifact.Limits{ChunkBytes: c.ChunkBytes, MaxChunks: c.MaxChunks}) {
		t.Errorf("Limits = %+v", got)
	}
	// The arithmetic in DefaultConfig's comment.
	if room := c.ContextTokens - c.MaxOutputTokens - requestOverheadBytes; room != 920_000 {
		t.Errorf("room for chunk text is %d, the comment says 920,000", room)
	}
	if c.ChunkBytes*2 > 920_000 {
		t.Errorf("chunk_bytes %d is not under half of the worst-case room", c.ChunkBytes)
	}
	// The red team's example must fit the default budget.
	if total := c.ChunkBytes * c.MaxChunks; total < 4_280_000 {
		t.Errorf("the default budget is %d bytes, less than the 4.28 MB setup-go diff", total)
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		edit    func(*Config)
		wantErr string // "" for valid
	}{
		{"the largest chunk the window allows", func(c *Config) { c.ChunkBytes = 920_000 }, ""},
		{"one byte more", func(c *Config) { c.ChunkBytes = 920_001 }, "leaves room for 920000 bytes"},
		{"a larger answer leaves less room", func(c *Config) { c.MaxOutputTokens, c.ChunkBytes = 64_000, 880_000 }, "leaves room for 872000 bytes"},
		{"a model with a 200K window", func(c *Config) { c.Model, c.ContextTokens = "claude-haiku-4-5", 200_000 }, "leaves room for 120000 bytes"},
		{"a 200K window with a chunk that fits", func(c *Config) { c.ContextTokens, c.ChunkBytes = 200_000, 100_000 }, ""},
		{"context window not set", func(c *Config) { c.ContextTokens = 0 }, "context_tokens"},
		{"no model", func(c *Config) { c.Model = "" }, "model"},
		{"a model with a space", func(c *Config) { c.Model = "claude opus" }, "model"},
		{"effort unset", func(c *Config) { c.Effort = "" }, "effort"},
		{"effort unknown", func(c *Config) { c.Effort = "extreme" }, "effort"},
		{"effort medium", func(c *Config) { c.Effort = "medium" }, ""},
		{"max_tokens over the model's ceiling", func(c *Config) { c.MaxOutputTokens = 128_001 }, "max_output_tokens"},
		{"max_tokens zero", func(c *Config) { c.MaxOutputTokens = 0 }, "max_output_tokens"},
		{"chunk_bytes zero", func(c *Config) { c.ChunkBytes = 0 }, "chunk_bytes"},
		{"max_chunks zero", func(c *Config) { c.MaxChunks = 0 }, "max_chunks"},
		{"no timeout", func(c *Config) { c.RequestTimeout = 0 }, "request_timeout"},
		{"no attempts", func(c *Config) { c.Attempts = 0 }, "attempts"},
		{"one attempt", func(c *Config) { c.Attempts = 1 }, ""},
		{"plain http to a host", func(c *Config) { c.BaseURL = "http://api.anthropic.com" }, "loopback"},
		{"plain http to a name that says localhost", func(c *Config) { c.BaseURL = "http://localhost.example.com" }, "loopback"},
		{"plain http to loopback", func(c *Config) { c.BaseURL = "http://127.0.0.1:8080" }, ""},
		{"a URL with a path", func(c *Config) { c.BaseURL = "https://example.com/v1" }, "scheme and host"},
		{"a URL with credentials", func(c *Config) { c.BaseURL = "https://user:pw@example.com" }, "scheme and host"},
		{"another scheme", func(c *Config) { c.BaseURL = "ftp://example.com" }, "https"},
		{"empty", func(c *Config) { c.BaseURL = "" }, "scheme and host"},
		{"a trailing slash is fine", func(c *Config) { c.BaseURL = "https://api.anthropic.com/" }, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultConfig()
			tc.edit(&c)
			err := c.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("Validate: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Errorf("Validate = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

// requestOverheadBytes must cover the largest request that carries no
// chunk text: the budget check in Validate subtracts it from the model's
// window. What is measured is the text the model reads (the system
// prompt, the schema and the user message), not its JSON encoding.
func TestRequestOverhead(t *testing.T) {
	long := strings.Repeat("x", 256)
	p := artifact.Prepared{
		Pair:   artifact.Pair{Ecosystem: long, Name: long, From: long, To: long},
		Chunks: []artifact.Chunk{{Index: 0, Text: "x\n"}},
		State:  allow.ReadPartial,
		Key:    strings.Repeat("0", 64),
	}
	for i := 0; i < maxUnreadListed*3; i++ {
		// Paths far over the cap, and the widest size there is.
		p.Unread = append(p.Unread, artifact.Unread{Path: strings.Repeat("p", 4000), Size: 1<<62 + int64(i), SHA256: strings.Repeat("f", 64)})
	}
	if err := checkRead(DefaultConfig(), p); err != nil {
		t.Fatalf("checkRead: %v", err)
	}
	user := userMessage(p, 0, strings.Repeat("f", 32))
	schema, err := json.Marshal(newAnswerSchema())
	if err != nil {
		t.Fatal(err)
	}
	overhead := len(systemPrompt) + len(schema) + len(user) - len(p.Chunks[0].Text)
	if overhead > requestOverheadBytes {
		t.Errorf("a request can hold %d bytes that are not chunk text, more than requestOverheadBytes (%d)", overhead, requestOverheadBytes)
	}
	t.Logf("largest request without chunk text: %d bytes of %d reserved (system prompt %d, schema %d)",
		overhead, requestOverheadBytes, len(systemPrompt), len(schema))
}

// The schema sent to the API, byte for byte. A change here changes what
// the model may answer, so it should be a deliberate edit of this test.
func TestAnswerSchema(t *testing.T) {
	const want = `{"type":"object","properties":{` +
		`"verdict":{"type":"string","enum":["no_veto","exfiltration","remote_code","install_time_execution","obfuscation","destructive","unexplained_capability","injection_text","other_malicious"]},` +
		`"quotes":{"type":"array","items":{"type":"string"}},` +
		`"notes":{"type":"string"}},` +
		`"required":["verdict","quotes","notes"],"additionalProperties":false}`
	got, err := json.Marshal(newAnswerSchema())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("schema =\n%s\nwant\n%s", got, want)
	}

	enum := newAnswerSchema().Properties.Verdict.Enum
	cats := Categories()
	if len(enum) != len(cats)+1 || enum[0] != "no_veto" {
		t.Fatalf("enum = %v", enum)
	}
	for i, c := range cats {
		if enum[i+1] != string(c) {
			t.Errorf("enum[%d] = %q, want %q: the enum is no_veto and then Categories in order", i+1, enum[i+1], c)
		}
		if !isCategory(string(c)) {
			t.Errorf("isCategory(%q) is false", c)
		}
	}
	for _, not := range []string{"no_veto", string(Refused), "veto", "", "Exfiltration"} {
		if isCategory(not) {
			t.Errorf("isCategory(%q) is true", not)
		}
	}
}

func TestPrompt(t *testing.T) {
	if systemPrompt != readFile(t, "prompt.md") {
		t.Fatal("the embedded prompt is not prompt.md")
	}
	for _, c := range Categories() {
		if !strings.Contains(systemPrompt, "- `"+string(c)+"`:") {
			t.Errorf("the prompt does not define category %q", c)
		}
	}
	// The owner's threat list (docs/v0.2-spec.md, section 1).
	for _, threat := range []string{
		"a compromised maintainer account", "a new install script", "credential theft",
		"an obvious obfuscated payload", "a re-pointed GitHub Action tag",
		"a malicious new transitive dependency", "cheap prompt injection",
	} {
		if !strings.Contains(systemPrompt, threat) {
			t.Errorf("the prompt does not name the threat %q", threat)
		}
	}
	for _, must := range []string{
		"third-party data", "never instructions", "Such text is itself the reason to stop",
		"`no_veto`", "`verdict`", "`quotes`", "`notes`", "You cannot approve", "You have no tools",
	} {
		if !strings.Contains(systemPrompt, must) {
			t.Errorf("the prompt lacks %q", must)
		}
	}
	// The gate's own category is not offered, and the prompt does not ask
	// the model to write out its reasoning, which the API can decline.
	for _, mustNot := range []string{string(Refused), "reasoning", "step by step", "chain of thought"} {
		if strings.Contains(strings.ToLower(systemPrompt), mustNot) {
			t.Errorf("the prompt contains %q", mustNot)
		}
	}
	// The diff's layout is described once, by the package that produces
	// it, and sent word for word in the header. The prompt points there
	// and keeps no paraphrase that could drift.
	if !strings.Contains(systemPrompt, "`diff format`") {
		t.Error("the prompt does not point at the header's diff format")
	}
	for _, paraphrase := range []string{"starts a hunk", "continues the line above", "<U+XXXX>", "marker character"} {
		if strings.Contains(systemPrompt, paraphrase) {
			t.Errorf("the prompt describes the diff format itself (%q)", paraphrase)
		}
		if !strings.Contains(artifact.TextFormat, paraphrase) {
			t.Errorf("artifact.TextFormat no longer says %q; this test is out of date", paraphrase)
		}
	}
	if u := userMessage(prepared("x\n"), 0, strings.Repeat("a", 32)); !strings.Contains(u, "\ndiff format:\n"+artifact.TextFormat+"\n") {
		t.Error("the header does not carry artifact.TextFormat word for word")
	}
	// The block names the prompt explains are the ones the request uses.
	p := prepared("x\n")
	p.State = allow.ReadPartial
	p.Unread = []artifact.Unread{{Path: "a.bin", Size: 1, SHA256: strings.Repeat("0", 64)}}
	user := userMessage(p, 0, strings.Repeat("a", 32))
	for _, name := range []string{"UNREAD FILES", "DIFF"} {
		if !strings.Contains(systemPrompt, "`"+name+"`") || !strings.Contains(user, "=====BEGIN "+name+" ") || !strings.Contains(user, "=====END "+name+" ") {
			t.Errorf("block %q is not both explained in the prompt and used in the request", name)
		}
	}
}

func TestClip(t *testing.T) {
	tests := []struct {
		in   string
		max  int
		want string
	}{
		{"short", 10, "short"},
		{"exactly ten", 11, "exactly ten"},
		{"abcdefghijkl", 10, "abcdefg..."},
		{"ééééééé", 10, "ééé..."}, // 14 bytes; cut at 7 falls inside a character
		{"日本語のテキスト", 12, "日本語..."},
	}
	for _, tc := range tests {
		if got := clip(tc.in, tc.max); got != tc.want || len(got) > tc.max {
			t.Errorf("clip(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
		}
	}
}

func TestHeaderSafe(t *testing.T) {
	for _, s := range []string{"golang.org/x/mod", "@scope/pkg", "actions/checkout", "v1.2.3-rc.1+build", "go_modules", "claude-opus-5-5"} {
		if !headerSafe(s) {
			t.Errorf("headerSafe(%q) is false", s)
		}
	}
	for _, s := range []string{"", "a b", "a\nb", "a\tb", "café", "x\x00", "x\x7f", strings.Repeat("a", 257)} {
		if headerSafe(s) {
			t.Errorf("headerSafe(%q) is true", s)
		}
	}
}

func TestSleepContext(t *testing.T) {
	if err := sleepContext(t.Context(), time.Millisecond); err != nil {
		t.Errorf("sleepContext: %v", err)
	}
}

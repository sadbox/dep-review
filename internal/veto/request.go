package veto

import (
	"bytes"
	"crypto/sha256"
	_ "embed" // for prompt.md
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
)

// systemPrompt is the whole system prompt, the same for every request.
// Nothing from a pull request is ever added to it: what the publisher
// wrote goes into the user message, inside the data blocks.
//
//go:embed prompt.md
var systemPrompt string

// answerNoVeto is the one value of the answer's "verdict" that is not a
// category.
const answerNoVeto = "no_veto"

// requestLayout names the layout of the user message (userMessage). The
// text around the data is code, which a fingerprint cannot hash, so this
// stands in for it: whoever changes that layout raises the number, and
// every stored verdict stops being reused.
const requestLayout = "1"

// Fingerprint identifies everything about the question that is not the
// read itself: the system prompt, the description of the diff format, the
// layout of the user message, the answer schema, the model and the effort
// (lower-case hex SHA-256). A verdict is stored and reused under the
// read's Key together with this, so a clean verdict does not survive a
// change to any of them (spec section 11, amendment 11). Settings that do
// not change what the model is asked (timeouts, attempts, the chunk
// budget, which already shapes the read's Key) are not part of it.
func (c Config) Fingerprint() string {
	schema, err := encode(newAnswerSchema())
	if err != nil {
		// The schema is a fixed struct of strings and lists of strings.
		panic("veto: " + err.Error())
	}
	return fingerprint(systemPrompt, artifact.TextFormat, requestLayout, string(schema), c.Model, c.Effort)
}

// fingerprint hashes its parts, each behind its length so that no two
// lists of parts hash alike.
func fingerprint(parts ...string) string {
	h := sha256.New()
	fmt.Fprintf(h, "dep-review veto question:%d:", len(parts))
	for _, p := range parts {
		fmt.Fprintf(h, "%d:", len(p))
		io.WriteString(h, p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

const (
	// maxUnreadListed is how many unread files one request names. More
	// than that are counted, not named: the list is context for the model
	// and is repeated in every chunk's request.
	maxUnreadListed = 100
	// maxUnreadPathBytes is how much of an unread file's path is shown.
	maxUnreadPathBytes = 256
)

// messagesRequest is the body of POST /v1/messages. It has no tools, no
// tool_choice and no sampling parameters on purpose: the model can only
// write the answer, and this model family refuses the sampling fields.
type messagesRequest struct {
	Model     string `json:"model"`
	MaxTokens int    `json:"max_tokens"`
	System    string `json:"system"`
	// Thinking is always {"type":"adaptive"}: the only setting the
	// default model accepts, and the one that makes its relatives think.
	Thinking     thinking     `json:"thinking"`
	OutputConfig outputConfig `json:"output_config"`
	Messages     []message    `json:"messages"`
}

type thinking struct {
	Type string `json:"type"`
}

type outputConfig struct {
	Effort string       `json:"effort"`
	Format outputFormat `json:"format"`
}

type outputFormat struct {
	Type   string       `json:"type"`
	Schema answerSchema `json:"schema"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// answerSchema is the JSON schema of the model's answer. It uses only
// what the API's schema-constrained output is documented to support:
// objects with additionalProperties false and every property required,
// strings, a string enum and an array of strings. Lengths cannot be
// expressed, so the caps on quotes and notes are applied after parsing.
type answerSchema struct {
	Type       string `json:"type"`
	Properties struct {
		Verdict struct {
			Type string   `json:"type"`
			Enum []string `json:"enum"`
		} `json:"verdict"`
		Quotes struct {
			Type  string `json:"type"`
			Items struct {
				Type string `json:"type"`
			} `json:"items"`
		} `json:"quotes"`
		Notes struct {
			Type string `json:"type"`
		} `json:"notes"`
	} `json:"properties"`
	Required             []string `json:"required"`
	AdditionalProperties bool     `json:"additionalProperties"`
}

// newAnswerSchema builds the schema from Categories, so the enum offered
// to the model and the list the parser accepts cannot drift apart. The
// answer is one enum, not an answer plus a category: "veto with no
// category" and "no veto, category exfiltration" cannot be written. The
// verdict is the first property so that an answer cut off at max_tokens
// has usually said it already.
func newAnswerSchema() answerSchema {
	var s answerSchema
	s.Type = "object"
	s.Properties.Verdict.Type = "string"
	s.Properties.Verdict.Enum = []string{answerNoVeto}
	for _, c := range Categories() {
		s.Properties.Verdict.Enum = append(s.Properties.Verdict.Enum, string(c))
	}
	s.Properties.Quotes.Type = "array"
	s.Properties.Quotes.Items.Type = "string"
	s.Properties.Notes.Type = "string"
	s.Required = []string{"verdict", "quotes", "notes"}
	s.AdditionalProperties = false
	return s
}

// checkRead refuses a prepared read this client must not send: one that
// is over the configured budget, or one that is not what internal/artifact
// documents. Nothing is repaired or cut to fit, because the verdict is
// stored under the read's key and must be about exactly that read. Review
// returns what this function says as ErrUnusable.
func checkRead(cfg Config, p artifact.Prepared) error {
	if p.State != allow.ReadFull && p.State != allow.ReadPartial {
		return fmt.Errorf("read state is %q, want %q or %q", p.State, allow.ReadFull, allow.ReadPartial)
	}
	if !isSHA256Hex(p.Key) {
		return errors.New("content key is not a lower-case hex SHA-256")
	}
	for _, f := range []struct{ name, value string }{
		{"ecosystem", p.Pair.Ecosystem}, {"name", p.Pair.Name}, {"to", p.Pair.To},
	} {
		if !headerSafe(f.value) {
			return fmt.Errorf("update %s is empty, longer than 256 bytes or not printable ASCII", f.name)
		}
	}
	// From is empty for a new name.
	if p.Pair.From != "" && !headerSafe(p.Pair.From) {
		return errors.New("update from is longer than 256 bytes or not printable ASCII")
	}
	if p.State == allow.ReadFull && len(p.Unread) > 0 {
		return fmt.Errorf("read state is %q with %d unread files", p.State, len(p.Unread))
	}
	if len(p.Chunks) > cfg.MaxChunks {
		return fmt.Errorf("%d chunks, more than max_chunks (%d)", len(p.Chunks), cfg.MaxChunks)
	}
	for i, c := range p.Chunks {
		switch {
		case c.Index != i:
			return fmt.Errorf("chunk at position %d has index %d", i, c.Index)
		case c.Text == "":
			return fmt.Errorf("chunk %d is empty", i)
		case len(c.Text) > cfg.ChunkBytes:
			return fmt.Errorf("chunk %d is %d bytes, more than chunk_bytes (%d)", i, len(c.Text), cfg.ChunkBytes)
		case !utf8.ValidString(c.Text):
			return fmt.Errorf("chunk %d is not valid UTF-8", i)
		}
	}
	for i, u := range p.Unread {
		switch {
		case u.Path == "" || !utf8.ValidString(u.Path) || strings.ContainsFunc(u.Path, isControl):
			return fmt.Errorf("unread file %d: path is empty or not escaped", i)
		case u.Size < 0:
			return fmt.Errorf("unread file %d: size is %d", i, u.Size)
		case !isSHA256Hex(u.SHA256):
			return fmt.Errorf("unread file %d: sha256 is not lower-case hex", i)
		}
	}
	return nil
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}

// newMarker returns the one-time marker for a request: 128 random bits
// as hex, drawn again in the (never seen) case that the publisher's text
// already contains it. The publisher cannot know it when writing the
// package, so text inside a data block cannot close the block.
func newMarker(random io.Reader, p artifact.Prepared, chunk int) (string, error) {
	for range 4 {
		var b [16]byte
		if _, err := io.ReadFull(random, b[:]); err != nil {
			return "", fmt.Errorf("random marker: %w", err)
		}
		marker := hex.EncodeToString(b[:])
		if !containsMarker(p, chunk, marker) {
			return marker, nil
		}
	}
	return "", errors.New("random marker: every draw occurs in the data")
}

func containsMarker(p artifact.Prepared, chunk int, marker string) bool {
	if strings.Contains(p.Chunks[chunk].Text, marker) {
		return true
	}
	for _, u := range p.Unread {
		if strings.Contains(u.Path, marker) {
			return true
		}
	}
	return false
}

// userMessage is the one user turn: a header in the gate's own words,
// then the publisher's text inside blocks that begin and end with the
// marker. The header's values passed checkRead, so no line of it can be
// something the publisher shaped beyond a name or a version.
//
// A change to what this function writes around the data changes what the
// model is asked: raise requestLayout with it.
func userMessage(p artifact.Prepared, chunk int, marker string) string {
	var b strings.Builder
	from := p.Pair.From
	if from == "" {
		from = "(none: a new dependency)"
	}
	fmt.Fprintf(&b, "This header was written by the gate.\n\n")
	fmt.Fprintf(&b, "ecosystem: %s\n", p.Pair.Ecosystem)
	fmt.Fprintf(&b, "package: %s\n", p.Pair.Name)
	fmt.Fprintf(&b, "from: %s\n", from)
	fmt.Fprintf(&b, "to: %s\n", p.Pair.To)
	fmt.Fprintf(&b, "part: %d of %d\n", chunk+1, len(p.Chunks))
	fmt.Fprintf(&b, "changed files not shown: %d\n", len(p.Unread))
	fmt.Fprintf(&b, "marker: %s\n", marker)
	// internal/artifact's own description of the text it produced, word
	// for word, so the two cannot drift apart.
	fmt.Fprintf(&b, "\ndiff format:\n%s\n", artifact.TextFormat)

	if len(p.Unread) > 0 {
		fmt.Fprintf(&b, "\n=====BEGIN UNREAD FILES %s=====\n", marker)
		for i, u := range p.Unread {
			if i == maxUnreadListed {
				break
			}
			fmt.Fprintf(&b, "%d bytes, sha256 %s, %s\n", u.Size, u.SHA256, clip(u.Path, maxUnreadPathBytes))
		}
		fmt.Fprintf(&b, "=====END UNREAD FILES %s=====\n", marker)
		if more := len(p.Unread) - maxUnreadListed; more > 0 {
			fmt.Fprintf(&b, "(%d more files are not listed.)\n", more)
		}
	}

	text := p.Chunks[chunk].Text
	fmt.Fprintf(&b, "\n=====BEGIN DIFF %s=====\n", marker)
	b.WriteString(text)
	if !strings.HasSuffix(text, "\n") {
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "=====END DIFF %s=====\n", marker)
	return b.String()
}

// clip cuts s to at most max bytes without splitting a character, and
// says so when it did.
func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	const mark = "..."
	cut := max - len(mark)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + mark
}

// requestBody encodes the Messages request for one chunk.
func requestBody(cfg Config, user string) ([]byte, error) {
	return encode(messagesRequest{
		Model:     cfg.Model,
		MaxTokens: cfg.MaxOutputTokens,
		System:    systemPrompt,
		Thinking:  thinking{Type: "adaptive"},
		OutputConfig: outputConfig{
			Effort: cfg.Effort,
			Format: outputFormat{Type: "json_schema", Schema: newAnswerSchema()},
		},
		Messages: []message{{Role: "user", Content: user}},
	})
}

// countRequest is the body of POST /v1/messages/count_tokens: the parts
// of a request whose tokens are the input.
type countRequest struct {
	Model    string    `json:"model"`
	System   string    `json:"system"`
	Messages []message `json:"messages"`
}

// encode is json.Marshal without the HTML escaping, which would triple
// the size of every "<" and ">" in a diff on the wire for nothing.
func encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

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

	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/config"
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

// Fingerprint identifies everything about the question that is not the
// read itself (lower-case hex SHA-256): the system prompt, the answer
// schema, the model, the effort, and the user message as userMessage
// writes it for one made-up read, which carries the header's wording, the
// layout of the blocks and artifact.TextFormat. A verdict is stored and
// reused under the read's Key together with this, so a clean verdict does
// not survive a change to any of them (spec section 11, amendment 11).
// Settings that do not change what the model is asked (timeouts,
// attempts, the chunk budget, which already shapes the read's Key) are
// not part of it.
func (c Config) Fingerprint() string {
	schema, err := encode(newAnswerSchema())
	if err != nil {
		// The schema is a fixed struct of strings and lists of strings.
		panic("veto: " + err.Error())
	}
	return fingerprint(systemPrompt, string(schema), c.conf.Model, c.conf.Effort, userMessage(sampleRead(), 0, sampleMarker))
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

const sampleMarker = "MARKER"

// sampleRead is the made-up read whose user message Fingerprint hashes.
// It makes userMessage write every line it can: a new name, more unread
// files than are listed, a path that is cut, a chunk without a final
// newline. The request's wording is code, and this is how a change to it
// reaches the fingerprint without a number someone has to remember to
// raise. A branch added to userMessage must be reachable from this read;
// TestFingerprint lists the lines it expects.
func sampleRead() artifact.Prepared {
	p := artifact.Prepared{
		Pair:   artifact.Pair{Ecosystem: "ecosystem", Name: "name", To: "to"},
		Chunks: []artifact.Chunk{{Text: "chunk"}},
	}
	for range maxUnreadListed + 1 {
		p.Unread = append(p.Unread, artifact.Unread{Path: strings.Repeat("p", maxUnreadPathBytes+1), SHA256: "sha256"})
	}
	return p
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
// has no text or is over the configured budget, or one whose name,
// versions or text cannot stand in the request. Nothing is repaired or cut to fit, because
// the verdict is stored under the read's key and must be about exactly
// that read. Review returns what this function says as ErrUnusable.
//
// The read's state, key, chunk order and the unread files' sizes and
// hashes are not looked at again: internal/wire refused a facts file
// that had them wrong, and the review job builds every read from one.
func checkRead(conf config.Config, p artifact.Prepared) error {
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
	if len(p.Chunks) == 0 {
		// Review would ask nothing and answer "no veto" for it.
		return errors.New("no chunk: there is nothing to ask the model about")
	}
	if len(p.Chunks) > conf.MaxChunks {
		return fmt.Errorf("%d chunks, more than max_chunks (%d)", len(p.Chunks), conf.MaxChunks)
	}
	for i, c := range p.Chunks {
		switch {
		case len(c.Text) > conf.ChunkBytes:
			return fmt.Errorf("chunk %d is %d bytes, more than chunk_bytes (%d)", i, len(c.Text), conf.ChunkBytes)
		case !utf8.ValidString(c.Text):
			return fmt.Errorf("chunk %d is not valid UTF-8", i)
		}
	}
	for i, u := range p.Unread {
		// The facts file's check does not look inside a path.
		if u.Path == "" || !utf8.ValidString(u.Path) || strings.ContainsFunc(u.Path, isControl) {
			return fmt.Errorf("unread file %d: path is empty or not escaped", i)
		}
	}
	return nil
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// userMessage is the one user turn: a header in the gate's own words,
// then the publisher's text inside blocks that begin and end with marker,
// which is random for each request: the publisher cannot know it when
// writing the package, so text inside a block cannot close the block. The
// header's values passed checkRead, so no line of it can be something the
// publisher shaped beyond a name or a version.
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
func requestBody(conf config.Config, user string) ([]byte, error) {
	return encode(messagesRequest{
		Model:     conf.Model,
		MaxTokens: conf.MaxOutputTokens,
		System:    systemPrompt,
		Thinking:  thinking{Type: "adaptive"},
		OutputConfig: outputConfig{
			Effort: conf.Effort,
			Format: outputFormat{Type: "json_schema", Schema: newAnswerSchema()},
		},
		Messages: []message{{Role: "user", Content: user}},
	})
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

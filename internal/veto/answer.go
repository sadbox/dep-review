package veto

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// ErrNoVerdict is wrapped by every error that means "the model answered,
// and the answer is not one this package accepts": text that is not the
// closed structure, an answer cut off at max_tokens, a response with
// blocks that should not be there. The update then has no verdict; the
// caller records allow.ReadNone.
var ErrNoVerdict = errors.New("no verdict")

func noVerdict(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrNoVerdict, fmt.Sprintf(format, args...))
}

// What is kept of the text the model wrote. Its quotes and notes go into
// a pull request comment, so their size is bounded here whatever the
// model was talked into writing; the answer schema cannot express a
// length. Over the cap is cut, never refused: see parseAnswer.
const (
	maxQuotes     = 10
	maxQuoteBytes = 300
	maxNotesBytes = 1000
)

// messagesResponse is what this package reads of a Messages response.
// The API adds fields over time; unknown ones are ignored here. The
// strict reading is for the model's own text (parseAnswer).
type messagesResponse struct {
	Type        string         `json:"type"`
	Content     []contentBlock `json:"content"`
	StopReason  string         `json:"stop_reason"`
	StopDetails *stopDetails   `json:"stop_details"`
	Usage       struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// stopDetails says why a request was refused. It is informational and
// can be absent on a refusal: the decision is made on stop_reason alone.
type stopDetails struct {
	Category    string `json:"category"`
	Explanation string `json:"explanation"`
}

// chunkAnswer is the answer for one chunk.
type chunkAnswer struct {
	// category is empty for no_veto, Refused for a refusal, and one of
	// Categories for a veto.
	category Category
	quotes   []string
	notes    string
}

// interpret turns one Messages response into the answer for its chunk.
//
// The two answers are not read with the same care, on purpose. A veto is
// taken from anything that carries one: it can only send the update to a
// person, and losing it to a formality would give the update a second
// try at a clean answer. A no_veto is accepted only from a response that
// ended normally and is exactly the closed structure.
func interpret(resp messagesResponse) (chunkAnswer, error) {
	if resp.Type != "message" {
		return chunkAnswer{}, noVerdict("response type is %q, want \"message\"", clip(resp.Type, 40))
	}
	// A refusal is decided on stop_reason before content is looked at:
	// content is then empty or a partial answer that must not be used.
	if resp.StopReason == "refusal" {
		return chunkAnswer{category: Refused, quotes: []string{}, notes: refusalNotes(resp.StopDetails)}, nil
	}

	var texts []string
	other := ""
	for _, b := range resp.Content {
		switch b.Type {
		case "text":
			texts = append(texts, b.Text)
		case "thinking", "redacted_thinking":
			// Thinking is always on; a response starts with these, and
			// their text is empty unless a display was asked for.
		default:
			other = b.Type
		}
	}
	for _, t := range texts {
		if a, ok := vetoIn(t); ok {
			return a, nil
		}
	}

	switch {
	case resp.StopReason != "end_turn":
		return chunkAnswer{}, noVerdict("stop_reason is %q, want \"end_turn\"", clip(resp.StopReason, 40))
	case other != "":
		// No tools were offered, so nothing but text and thinking belongs
		// in the response.
		return chunkAnswer{}, noVerdict("response has a %q block", clip(other, 40))
	case len(texts) != 1:
		return chunkAnswer{}, noVerdict("response has %d text blocks, want 1", len(texts))
	}
	return parseNoVeto(texts[0])
}

// member is one "key": value pair of the answer object, in the order
// written. encoding/json's own struct decoding is not used for the
// answer: it matches keys without regard to case and lets the last of
// two equal keys win, and either would let an answer mean two things.
type member struct {
	key   string
	value json.RawMessage
}

// readObject reads text as one JSON object. whole is false when the text
// is not exactly one complete object: members then holds what was read
// before the fault.
func readObject(text string) (members []member, whole bool) {
	dec := json.NewDecoder(strings.NewReader(text))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return members, false
		}
		key, ok := tok.(string)
		if !ok {
			return members, false
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return members, false
		}
		members = append(members, member{key, value})
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return members, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return members, false // something after the object
	}
	return members, true
}

// vetoIn reports the veto in text, if there is one: a JSON object, even
// one that is cut off or has extra members, with a "verdict" member
// whose value is one of Categories. The quotes and notes are taken as
// far as they are usable and cut to the caps.
func vetoIn(text string) (chunkAnswer, bool) {
	members, _ := readObject(text)
	category := Category("")
	for _, m := range members {
		if s, ok := jsonString(m.value); ok && m.key == "verdict" && isCategory(s) {
			category = Category(s)
			break
		}
	}
	if category == "" {
		return chunkAnswer{}, false
	}
	a := chunkAnswer{category: category, quotes: []string{}}
	for _, m := range members {
		switch m.key {
		case "quotes":
			var items []json.RawMessage
			if len(a.quotes) > 0 || json.Unmarshal(m.value, &items) != nil {
				continue
			}
			for _, item := range items {
				if s, ok := jsonString(item); ok && len(a.quotes) < maxQuotes {
					a.quotes = append(a.quotes, clip(strings.ToValidUTF8(s, "�"), maxQuoteBytes))
				}
			}
		case "notes":
			if s, ok := jsonString(m.value); ok && a.notes == "" {
				a.notes = clip(strings.ToValidUTF8(s, "�"), maxNotesBytes)
			}
		}
	}
	return a, true
}

// parseNoVeto accepts text only when it is exactly
//
//	{"verdict": "no_veto", "quotes": [strings], "notes": "string"}
//
// with those three keys once each, spelled exactly, and nothing else
// before, inside or after. Anything else is no verdict, including a
// verdict outside the enum such as "approve" or "model_refused".
func parseNoVeto(text string) (chunkAnswer, error) {
	if !utf8.ValidString(text) {
		return chunkAnswer{}, noVerdict("answer is not valid UTF-8")
	}
	members, whole := readObject(text)
	if !whole {
		return chunkAnswer{}, noVerdict("answer is not exactly one JSON object")
	}
	seen := map[string]json.RawMessage{}
	for _, m := range members {
		if m.key != "verdict" && m.key != "quotes" && m.key != "notes" {
			return chunkAnswer{}, noVerdict("answer has an unknown member")
		}
		if _, dup := seen[m.key]; dup {
			return chunkAnswer{}, noVerdict("answer has %q twice", m.key)
		}
		seen[m.key] = m.value
	}

	// A member that is missing is nil here, and nil is neither a string
	// nor an array.
	verdict, ok := jsonString(seen["verdict"])
	if !ok || verdict != answerNoVeto {
		// A category would have been found by vetoIn already.
		return chunkAnswer{}, noVerdict("verdict is not one of the answers")
	}
	var quotes []json.RawMessage
	if !startsWith(seen["quotes"], '[') || json.Unmarshal(seen["quotes"], &quotes) != nil {
		return chunkAnswer{}, noVerdict("quotes is not an array")
	}
	for _, q := range quotes {
		if _, ok := jsonString(q); !ok {
			return chunkAnswer{}, noVerdict("quotes holds something that is not a string")
		}
	}
	notes, ok := jsonString(seen["notes"])
	if !ok {
		return chunkAnswer{}, noVerdict("notes is not a string")
	}
	// Quotes on a no_veto are dropped: there is no veto to explain.
	return chunkAnswer{quotes: []string{}, notes: clip(notes, maxNotesBytes)}, nil
}

// jsonString decodes raw when it is a JSON string, and only then (null
// would otherwise decode into "" without an error).
func jsonString(raw json.RawMessage) (string, bool) {
	if !startsWith(raw, '"') {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

func startsWith(raw json.RawMessage, c byte) bool {
	return len(raw) > 0 && raw[0] == c
}

func isCategory(s string) bool {
	for _, c := range Categories() {
		if s == string(c) {
			return true
		}
	}
	return false
}

// refusalNotes is what a person is shown about a refusal: the API's own
// category and explanation when it gave them.
func refusalNotes(d *stopDetails) string {
	if d == nil || (d.Category == "" && d.Explanation == "") {
		return "The model refused to answer (stop_reason refusal); the API gave no details."
	}
	category := d.Category
	if category == "" {
		category = "none given"
	}
	notes := "The model refused to answer (stop_reason refusal). Category: " + clip(category, 64) + "."
	if d.Explanation != "" {
		notes += " Explanation: " + clip(strings.ToValidUTF8(d.Explanation, "�"), 300)
	}
	return notes
}

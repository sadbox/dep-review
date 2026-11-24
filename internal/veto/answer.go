package veto

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
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

// The caps on what is kept of the model's text. This is the one place a
// veto's quotes and notes are cut: they go into a pull request comment,
// and the answer schema cannot express a length. Over the cap is cut,
// never refused, because refusing would lose the veto.
const (
	maxQuotes     = 10
	maxQuoteBytes = 300
	maxNotesBytes = 1000
)

// messagesResponse is what this package reads of a Messages response.
// The API adds fields over time; unknown ones are ignored here. The
// strict reading is for the model's own text (readAnswer).
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
// taken from any text block, under any stop reason: it can only send the
// update to a person, and losing it to a formality would give the update
// a second try at a clean answer. A no_veto is accepted only from a
// response that ended normally and is exactly the closed structure.
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
	var first chunkAnswer
	var firstErr error
	for i, t := range texts {
		a, err := readAnswer(t)
		if err == nil && a.category != "" {
			return a, nil
		}
		if i == 0 {
			first, firstErr = a, err
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
	return first, firstErr
}

// answer is the model's text as the answer schema describes it. The
// pointers tell a member that is missing or null from an empty one.
type answer struct {
	Verdict *string    `json:"verdict"`
	Quotes  *[]*string `json:"quotes"`
	Notes   *string    `json:"notes"`
}

// readAnswer reads one text block. It is a no_veto only when it is exactly
//
//	{"verdict": "no_veto", "quotes": [strings], "notes": "string"}
//
// with nothing before, inside or after. encoding/json/v2 matches names in
// exact case and refuses a name given twice, text after the object and
// invalid UTF-8; the option refuses a member the schema does not have.
// Anything else is a veto when it names a category and no verdict when it
// does not, including a verdict outside the enum such as "approve" or
// "model_refused".
func readAnswer(text string) (chunkAnswer, error) {
	var a answer
	if err := json.Unmarshal([]byte(text), &a, json.RejectUnknownMembers(true)); err != nil {
		if category, ok := looseVeto(text); ok {
			return chunkAnswer{category: category, quotes: []string{}, notes: looseNotes}, nil
		}
		return chunkAnswer{}, noVerdict("answer is not the closed structure")
	}
	switch {
	case a.Verdict != nil && isCategory(*a.Verdict):
		v := chunkAnswer{category: Category(*a.Verdict), quotes: []string{}}
		if a.Quotes != nil {
			for _, q := range *a.Quotes {
				if q != nil && len(v.quotes) < maxQuotes {
					v.quotes = append(v.quotes, clip(*q, maxQuoteBytes))
				}
			}
		}
		if a.Notes != nil {
			v.notes = clip(*a.Notes, maxNotesBytes)
		}
		return v, nil
	case a.Verdict == nil || *a.Verdict != answerNoVeto:
		return chunkAnswer{}, noVerdict("verdict is not one of the answers")
	case a.Quotes == nil || slices.Contains(*a.Quotes, nil) || a.Notes == nil:
		return chunkAnswer{}, noVerdict("quotes is not a list of strings or notes is not a string")
	}
	// Quotes on a no_veto are dropped: there is no veto to explain.
	return chunkAnswer{quotes: []string{}, notes: clip(*a.Notes, maxNotesBytes)}, nil
}

// looseNotes stands in for the quotes and notes of a veto that was not
// written as the closed structure: only its category is taken.
const looseNotes = "The model's answer was cut off or was not in the agreed form; only its verdict was kept."

// looseVeto finds the category in text that is not the closed structure:
// an object, even one that is cut off, has a member too many, gives the
// verdict twice or is followed by words, in which a "verdict" member
// names a category. The members are read in order, as far as they are
// JSON, and the first such member is the answer.
func looseVeto(text string) (Category, bool) {
	dec := jsontext.NewDecoder(strings.NewReader(text), jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true))
	if tok, err := dec.ReadToken(); err != nil || tok.Kind() != '{' {
		return "", false
	}
	for dec.PeekKind() == '"' {
		name, err := dec.ReadToken()
		if err != nil {
			return "", false
		}
		isVerdict := name.String() == "verdict"
		value, err := dec.ReadValue()
		if err != nil {
			return "", false
		}
		var verdict string
		if isVerdict && value.Kind() == '"' && json.Unmarshal(value, &verdict) == nil && isCategory(verdict) {
			return Category(verdict), true
		}
	}
	return "", false
}

func isCategory(s string) bool {
	return slices.Contains(Categories(), Category(s))
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

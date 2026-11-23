package veto

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
)

// interpret on responses built in Go, for the cases a JSON response body
// cannot carry (invalid UTF-8 survives no JSON decoder) and for the exact
// boundary between "a veto was found" and "no verdict".
func TestInterpret(t *testing.T) {
	message := func(stop string, texts ...string) messagesResponse {
		r := messagesResponse{Type: "message", StopReason: stop}
		r.Content = append(r.Content, contentBlock{Type: "thinking"})
		for _, s := range texts {
			r.Content = append(r.Content, contentBlock{Type: "text", Text: s})
		}
		return r
	}
	tests := []struct {
		name     string
		resp     messagesResponse
		want     Category // "" for no_veto
		wantNone bool     // ErrNoVerdict
	}{
		{"no_veto", message("end_turn", `{"verdict":"no_veto","quotes":[],"notes":""}`), "", false},
		{"no_veto with other key order and spacing", message("end_turn", " {\n \"notes\": \"n\", \"quotes\": [ ], \"verdict\": \"no_veto\" }\n"), "", false},
		{"no_veto that quotes lines is still no_veto", message("end_turn", `{"verdict":"no_veto","quotes":["+x"],"notes":""}`), "", false},
		{"every category is a veto", message("end_turn", `{"verdict":"other_malicious","quotes":[],"notes":""}`), OtherMalicious, false},
		{"no_veto with invalid UTF-8", message("end_turn", "{\"verdict\":\"no_veto\",\"quotes\":[],\"notes\":\"\xff\"}"), "", true},
		{"a veto with invalid UTF-8 in a quote", message("end_turn", "{\"verdict\":\"destructive\",\"quotes\":[\"+rm \xff\"],\"notes\":\"\"}"), Destructive, false},
		{"cut off inside the second key", message("max_tokens", `{"verdict":"injection_text","quo`), InjectionText, false},
		{"cut off inside the verdict", message("max_tokens", `{"verdict":"injection_te`), "", true},
		{"cut off before the verdict", message("max_tokens", `{"notes":"looks fi`), "", true},
		{"a category under another key", message("end_turn", `{"category":"exfiltration","verdict":"no_veto","quotes":[],"notes":""}`), "", true},
		{"a category nested in the verdict", message("end_turn", `{"verdict":{"verdict":"exfiltration"},"quotes":[],"notes":""}`), "", true},
		{"a category in an array", message("end_turn", `[{"verdict":"exfiltration"}]`), "", true},
		{"a category with other capitals", message("end_turn", `{"verdict":"Exfiltration","quotes":[],"notes":""}`), "", true},
		{"the verdict key with other capitals", message("end_turn", `{"VERDICT":"exfiltration","quotes":[],"notes":""}`), "", true},
		{"a veto in the second of two objects is not looked for", message("end_turn", `{"verdict":"no_veto","quotes":[],"notes":""}{"verdict":"exfiltration"}`), "", true},
		{"refusal", messagesResponse{Type: "message", StopReason: "refusal"}, Refused, false},
		{"refusal beats a veto in the partial text", message("refusal", `{"verdict":"exfiltration","quotes":[],"notes":""}`), Refused, false},
		{"a response that is not a message", messagesResponse{Type: "error", StopReason: "end_turn"}, "", true},
		{"pause_turn", message("pause_turn", `{"verdict":"no_veto","quotes":[],"notes":""}`), "", true},
		{"stop_sequence", message("stop_sequence", `{"verdict":"no_veto","quotes":[],"notes":""}`), "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, err := interpret(tc.resp)
			if tc.wantNone {
				if !errors.Is(err, ErrNoVerdict) {
					t.Fatalf("interpret = %+v, %v; want ErrNoVerdict", a, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("interpret: %v", err)
			}
			if a.category != tc.want {
				t.Errorf("category = %q, want %q", a.category, tc.want)
			}
			if a.quotes == nil {
				t.Error("quotes is nil; it is always a list")
			}
			for _, q := range a.quotes {
				if strings.Contains(q, "\xff") {
					t.Errorf("a quote kept invalid UTF-8: %q", q)
				}
			}
			if a.category == "" && len(a.quotes) != 0 {
				t.Errorf("a no_veto kept quotes: %v", a.quotes)
			}
		})
	}
}

// Every category the schema offers comes back as that category, and the
// caller can turn it into an allow.Veto as api.go describes.
func TestEveryCategoryRoundTrips(t *testing.T) {
	for _, cat := range Categories() {
		t.Run(string(cat), func(t *testing.T) {
			f := newFakeAPI(t)
			f.reply = func(int, recorded) reply { return ok(answerJSON(string(cat), []string{"+line"}, "note")) }
			c, _ := testClient(t, f, APIKey(f.apiKey))
			v, err := c.Review(context.Background(), Request{Read: prepared("a\n")})
			if err != nil {
				t.Fatalf("Review: %v", err)
			}
			if v.Answer != Vetoed || v.Category != cat || v.Read != allow.ReadFull {
				t.Errorf("verdict = %+v", v)
			}
			veto := &allow.Veto{Category: string(v.Category), Quotes: v.Quotes, Notes: v.Notes}
			if veto.Category == allow.VetoModelRefused || veto.Category == "" {
				t.Errorf("category %q", veto.Category)
			}
		})
	}
}

func TestResponseTooLarge(t *testing.T) {
	f := newFakeAPI(t)
	huge := `{"type":"message","stop_reason":"end_turn","content":[{"type":"text","text":"` + strings.Repeat("a", maxResponseBytes) + `"}]}`
	f.reply = func(int, recorded) reply { return reply{body: huge} }
	c, _ := testClient(t, f, APIKey(f.apiKey))
	_, err := c.Review(context.Background(), Request{Read: prepared("a\n")})
	if !errors.Is(err, ErrNoVerdict) {
		t.Fatalf("Review error = %v, want ErrNoVerdict", err)
	}
	if n := len(f.recordedRequests()); n != 1 {
		t.Errorf("%d requests, want 1: an oversized response is not retried", n)
	}
}

// The marker must be absent from every piece of the publisher's text in
// the request, the unread paths included.
func TestMarkerNotInUnreadPath(t *testing.T) {
	first := bytes.Repeat([]byte{0x12}, 16)
	second := bytes.Repeat([]byte{0x34}, 16)
	f := newFakeAPI(t)
	c, _ := testClient(t, f, APIKey(f.apiKey))
	c.random = bytes.NewReader(append(append([]byte{}, first...), second...))
	p := prepared("a\n")
	p.State = allow.ReadPartial
	p.Unread = []artifact.Unread{{Path: "dist/" + hex.EncodeToString(first) + ".bin", Size: 1, SHA256: strings.Repeat("0", 64)}}
	if _, err := c.Review(context.Background(), Request{Read: p}); err != nil {
		t.Fatalf("Review: %v", err)
	}
	if u := f.recordedRequests()[0].user; !strings.Contains(u, "marker: "+hex.EncodeToString(second)+"\n") {
		t.Error("the marker that occurs in an unread path was used")
	}
}

// A count_tokens failure is reported, and retried like any request.
func TestCountTokensErrors(t *testing.T) {
	f := newFakeAPI(t)
	c, _ := testClient(t, f, APIKey("sk-ant-wrong"))
	_, err := c.CountTokens(context.Background(), Request{Read: prepared("a\n")})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized || apiErr.Type != "authentication_error" || apiErr.RequestID != "req_fake_error" {
		t.Fatalf("CountTokens error = %v", err)
	}
	if !strings.Contains(err.Error(), "HTTP 401 authentication_error: invalid credential (request-id req_fake_error)") {
		t.Errorf("error text: %v", err)
	}
}

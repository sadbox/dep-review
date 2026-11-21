package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/publish"
)

// MaxStdout caps what the reviewer may print. A `claude -p --output-format
// json` result with a 3000-character summary is a few kilobytes; one that
// assesses model.MaxFlagged items is a few hundred (and the CLI may echo
// the structured output in "result" too).
const MaxStdout = 1 << 20

// ReadVerdict is the sandbox's only output channel: it reads the
// container's stdout (all of it, so the writer never blocks, keeping at
// most MaxStdout bytes), requires exactly one JSON object, the CLI's
// result message (claude -p --output-format json, Claude Code 2.1.329):
//
//	{"type":"result","subtype":"success","is_error":false,
//	 "structured_output":{...}, "result":"...", "usage":{...}, ...}
//
// and returns its structured_output once it passes publish.ParseVerdict,
// the Go form of schema/verdict.json (TestSchemaInSync keeps the two
// equal). The result is re-encoded, so verdict.json never holds bytes the
// model chose beyond the four validated fields. Over the cap, trailing
// bytes, invalid JSON, an error result, a missing structured_output or a
// schema failure are all errors: no verdict.
//
// The caller must also require that the container exited 0 in time.
func ReadVerdict(stdout io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(stdout, MaxStdout+1))
	io.Copy(io.Discard, stdout)
	if err != nil {
		return nil, fmt.Errorf("reading the reviewer's output: %w", err)
	}
	if len(b) > MaxStdout {
		return nil, fmt.Errorf("the reviewer printed more than %d bytes", MaxStdout)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	var res struct {
		Type             string          `json:"type"`
		Subtype          string          `json:"subtype"`
		IsError          *bool           `json:"is_error"`
		StructuredOutput json.RawMessage `json:"structured_output"`
	}
	if err := dec.Decode(&res); err != nil {
		return nil, fmt.Errorf("the reviewer's output is not a JSON result: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("the reviewer printed more than one JSON value")
	}
	switch {
	case res.Type != "result":
		return nil, fmt.Errorf("the reviewer's output is a %q message, not a result", short(res.Type))
	case res.IsError == nil || *res.IsError || res.Subtype != "success":
		return nil, fmt.Errorf("the review ended with an error (subtype %q)", short(res.Subtype))
	case len(res.StructuredOutput) == 0 || string(res.StructuredOutput) == "null":
		return nil, errors.New("the review returned no structured output")
	}
	v, err := publish.ParseVerdict(res.StructuredOutput)
	if err != nil {
		return nil, fmt.Errorf("structured output: %w", err)
	}
	if v.Flags == nil {
		v.Flags = []string{}
	}
	if v.Items == nil {
		v.Items = []model.ItemAssessment{}
	}
	return json.Marshal(v)
}

func short(s string) string {
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

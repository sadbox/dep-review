package publish

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/sadbox/dep-review/internal/model"
)

// Flags is schema/verdict.json's flags enum; a test keeps them in sync.
var Flags = []string{
	"network-access-added",
	"process-execution-added",
	"filesystem-access-added",
	"credential-or-env-access",
	"obfuscated-or-encoded-code",
	"build-or-install-hook-changed",
	"new-dependency",
	"maintainer-or-publisher-change",
	"behavior-change-affects-repo",
	"api-incompatibility",
	"default-changed",
	"security-fix-incomplete",
	"evidence-incomplete",
	"instructions-in-data",
}

const (
	maxFlags       = 12
	maxVerdictSize = 64 << 10
)

// ParseVerdict decodes and validates the review job's structured output
// against the rules of schema/verdict.json: exactly the three fields, the
// verdict and flag enums, unique flags, the length limits. Anything else
// is an error and the PR goes to a human.
func ParseVerdict(raw []byte) (model.Verdict, error) {
	var v model.Verdict
	if len(raw) > maxVerdictSize {
		return v, errors.New("verdict is too large")
	}
	if !utf8.Valid(raw) {
		return v, errors.New("verdict is not UTF-8")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return v, fmt.Errorf("verdict is not a JSON object: %w", err)
	}
	for _, k := range []string{"verdict", "flags", "summary"} {
		if _, ok := fields[k]; !ok {
			return v, fmt.Errorf("verdict lacks %q", k)
		}
	}
	if len(fields) != 3 {
		return v, errors.New("verdict has unexpected fields")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return v, fmt.Errorf("decoding verdict: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return v, errors.New("trailing data after verdict")
	}
	if fields["flags"][0] != '[' || fields["verdict"][0] != '"' || fields["summary"][0] != '"' {
		return v, errors.New("verdict fields have the wrong types")
	}
	switch v.Verdict {
	case model.Pass, model.Fail, model.Unsure:
	default:
		return v, errors.New("verdict is not pass, fail or unsure")
	}
	if len(v.Flags) > maxFlags {
		return v, errors.New("too many flags")
	}
	seen := map[string]bool{}
	for _, f := range v.Flags {
		if !knownFlag(f) {
			return v, errors.New("unknown flag")
		}
		if seen[f] {
			return v, errors.New("duplicate flag")
		}
		seen[f] = true
	}
	if utf8.RuneCountInString(v.Summary) > summaryMax {
		return v, errors.New("summary is too long")
	}
	return v, nil
}

func knownFlag(f string) bool {
	for _, k := range Flags {
		if f == k {
			return true
		}
	}
	return false
}

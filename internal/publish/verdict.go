package publish

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"unicode/utf8"

	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/strictjson"
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
	maxFlags = 12
	// itemFieldMax bounds an item's update, code and item strings (the
	// gate's own, so a longer one cannot match anything); itemNoteMax its
	// note. maxVerdictSize leaves room for model.MaxFlagged full items.
	itemFieldMax   = model.MaxItemField
	itemNoteMax    = 400
	maxVerdictSize = 640 << 10
)

// ParseVerdict decodes and validates the review job's structured output
// against the rules of schema/verdict.json: exactly the four fields (and
// exactly the five in each item), the verdict, flag and assessment enums,
// unique flags and items, the length and count limits. Anything else is
// an error and the PR goes to a human. Keys that are duplicated or differ
// from a field only in case are refused (strictjson), so what publish
// reads is what the schema validated.
func ParseVerdict(raw []byte) (model.Verdict, error) {
	var v model.Verdict
	if len(raw) > maxVerdictSize {
		return v, errors.New("verdict is too large")
	}
	if !utf8.Valid(raw) {
		return v, errors.New("verdict is not UTF-8")
	}
	if err := strictjson.Check(raw, reflect.TypeFor[model.Verdict]()); err != nil {
		return v, fmt.Errorf("verdict: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return v, fmt.Errorf("verdict is not a JSON object: %w", err)
	}
	for _, k := range []string{"verdict", "flags", "summary", "items"} {
		if _, ok := fields[k]; !ok {
			return v, fmt.Errorf("verdict lacks %q", k)
		}
	}
	if len(fields) != 4 {
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
	if fields["flags"][0] != '[' || fields["verdict"][0] != '"' || fields["summary"][0] != '"' || fields["items"][0] != '[' {
		return v, errors.New("verdict fields have the wrong types")
	}
	if err := checkItems(fields["items"], v.Items); err != nil {
		return v, err
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

// itemKeys are the string fields of one item, every one required; commits,
// also required, is an array of full commit hashes.
var itemKeys = []string{"update", "code", "item", "assessment", "note"}

// maxItemCommits bounds one item's cited commits (schema maxItems).
const maxItemCommits = 20

// checkItems validates the items array: raw is its JSON, items what it
// decoded to.
func checkItems(raw json.RawMessage, items []model.ItemAssessment) error {
	if len(items) > model.MaxFlagged {
		return errors.New("too many items")
	}
	var objs []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &objs); err != nil || len(objs) != len(items) {
		return errors.New("items is not an array of objects")
	}
	seen := map[model.FlaggedItem]bool{}
	for i, o := range objs {
		if len(o) != len(itemKeys)+1 {
			return errors.New("an item has missing or unexpected fields")
		}
		if f, ok := o["commits"]; !ok || len(f) == 0 || f[0] != '[' {
			return errors.New(`an item lacks "commits" or it is not an array`)
		}
		for _, k := range itemKeys {
			if f, ok := o[k]; !ok || len(f) == 0 || f[0] != '"' {
				return fmt.Errorf("an item lacks %q or it is not a string", k)
			}
		}
		it := items[i]
		switch it.Assessment {
		case model.Benign, model.Suspicious, model.Unclear:
		default:
			return errors.New("an item's assessment is not benign, suspicious or unclear")
		}
		for _, s := range []string{it.Update, it.Code, it.Item} {
			if utf8.RuneCountInString(s) > itemFieldMax {
				return errors.New("an item's update, code or item is too long")
			}
		}
		if utf8.RuneCountInString(it.Note) > itemNoteMax {
			return errors.New("an item's note is too long")
		}
		if len(it.Commits) > maxItemCommits {
			return errors.New("an item cites too many commits")
		}
		for j, c := range it.Commits {
			if !isCommitHash(c) || slices.Contains(it.Commits[:j], c) {
				return errors.New("an item's commits are not distinct full commit hashes")
			}
		}
		k := model.FlaggedItem{Update: it.Update, Code: it.Code, Item: it.Item}
		if seen[k] {
			return errors.New("duplicate item")
		}
		seen[k] = true
	}
	return nil
}

func knownFlag(f string) bool {
	for _, k := range Flags {
		if f == k {
			return true
		}
	}
	return false
}

// isCommitHash: 40 lowercase hex digits (a SHA-1 commit hash).
func isCommitHash(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

package publish

import (
	"fmt"
	"strings"

	"github.com/sadbox/dep-review/internal/model"
)

// accounting compares the reviewer's per-item assessments with the items
// the gate flagged. The evidence's list is the reference: the model can
// neither drop an item (missing), nor answer for something the gate did
// not show it (extra), nor pass one it could not clear (suspicious or
// unclear). ok is true only when every flagged item, and nothing else,
// was assessed benign. reason is in the gate's own words.
func accounting(flagged []model.FlaggedItem, items []model.ItemAssessment) (ok bool, reason string) {
	if len(flagged) > model.MaxFlagged {
		return false, fmt.Sprintf("the gate flagged too many items for a review (%d, limit %d)", len(flagged), model.MaxFlagged)
	}
	want := make(map[model.FlaggedItem]bool, len(flagged))
	for _, f := range flagged {
		if want[f] {
			// fetch never writes one twice; an evidence file that does is
			// not what the gate produced.
			return false, "the evidence's flagged list repeats an item"
		}
		want[f] = true
	}
	got := map[model.FlaggedItem]model.Assessment{}
	extra := 0
	for _, it := range items {
		k := model.FlaggedItem{Update: it.Update, Code: it.Code, Item: it.Item}
		if !want[k] {
			extra++
			continue
		}
		got[k] = it.Assessment
	}
	missing, suspicious, unclear := 0, 0, 0
	for f := range want {
		switch a, ok := got[f]; {
		case !ok:
			missing++
		case a == model.Suspicious:
			suspicious++
		case a != model.Benign:
			unclear++
		}
	}
	var why []string
	if missing > 0 {
		why = append(why, fmt.Sprintf("did not assess %d of %d flagged items", missing, len(want)))
	}
	if suspicious > 0 || unclear > 0 {
		why = append(why, fmt.Sprintf("marked %d suspicious and %d unclear", suspicious, unclear))
	}
	if extra > 0 {
		why = append(why, fmt.Sprintf("listed %d %s the gate did not flag", extra, plural(extra, "item", "items")))
	}
	if len(why) == 0 {
		return true, ""
	}
	return false, "the reviewer answered pass but " + strings.Join(why, "; ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

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
//
// upstream adds a citation rule: where an update's upstream history was
// verified and lists commits for an item, a benign assessment counts only
// if it cites at least one of them and nothing else. An item with no
// listed commits must cite none (there is nothing the gate could check a
// citation against).
func accounting(flagged []model.FlaggedItem, items []model.ItemAssessment, upstream []model.Upstream) (ok bool, reason string) {
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
	listed := listedCommits(upstream)
	got := map[model.FlaggedItem]model.Assessment{}
	extra, uncited := 0, 0
	for _, it := range items {
		k := model.FlaggedItem{Update: it.Update, Code: it.Code, Item: it.Item}
		if !want[k] {
			extra++
			continue
		}
		a := it.Assessment
		if a == model.Benign && !citesListed(it.Commits, listed[k]) {
			a, uncited = model.Unclear, uncited+1
		}
		got[k] = a
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
	if suspicious > 0 || unclear-uncited > 0 {
		why = append(why, fmt.Sprintf("marked %d suspicious and %d unclear", suspicious, unclear-uncited))
	}
	if uncited > 0 {
		why = append(why, fmt.Sprintf("cleared %d %s without citing only the upstream commits listed for %s", uncited, plural(uncited, "item", "items"), plural(uncited, "it", "them")))
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

// listedCommits maps each flagged item of a verified update to the
// commits the evidence lists for it.
func listedCommits(upstream []model.Upstream) map[model.FlaggedItem]map[string]bool {
	out := map[model.FlaggedItem]map[string]bool{}
	for _, u := range upstream {
		if u.Status != model.UpstreamVerified {
			continue
		}
		for _, it := range u.Items {
			k := model.FlaggedItem{Update: u.Update, Code: it.Code, Item: it.Item}
			if out[k] == nil {
				out[k] = map[string]bool{}
			}
			for _, c := range it.Commits {
				out[k][c] = true
			}
		}
	}
	return out
}

// citesListed: every cited commit is listed, and at least one is when
// any is listed.
func citesListed(cited []string, listed map[string]bool) bool {
	for _, c := range cited {
		if !listed[c] {
			return false
		}
	}
	return len(listed) == 0 || len(cited) > 0
}

// examinedAll checks the verdict's examined list against the evidence's
// diffs: every required one is listed, and nothing the evidence does not
// have. Optional diffs may be listed or not.
func examinedAll(diffs []model.DiffFile, examined []string) (ok bool, reason string) {
	required := 0
	known := map[string]bool{}
	for _, d := range diffs {
		known[d.ID] = true
		if d.Required {
			required++
		}
	}
	if required > model.MaxRequiredDiffs {
		return false, fmt.Sprintf("the evidence has too many required diffs for a review (%d, limit %d)", required, model.MaxRequiredDiffs)
	}
	listed := map[string]bool{}
	unknown := 0
	for _, id := range examined {
		if !known[id] {
			unknown++
		}
		listed[id] = true
	}
	missing := 0
	for _, d := range diffs {
		if d.Required && !listed[d.ID] {
			missing++
		}
	}
	var why []string
	if missing > 0 {
		why = append(why, fmt.Sprintf("did not list %d of %d required diffs as examined", missing, required))
	}
	if unknown > 0 {
		why = append(why, fmt.Sprintf("listed %d %s the evidence does not have", unknown, plural(unknown, "diff", "diffs")))
	}
	if len(why) == 0 {
		return true, ""
	}
	return false, "the reviewer answered pass but " + strings.Join(why, "; ")
}

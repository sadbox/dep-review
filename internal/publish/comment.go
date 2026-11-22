package publish

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
)

// markerPrefix starts the first line of the gate's one comment per PR. The
// comment is found by this prefix AND the gate app's bot login; the rest
// of the marker records which heads were already notified, so a re-run or
// sweep never notifies twice for the same head.
const markerPrefix = "<!-- dep-review:v1"

const (
	maxRows        = 50
	maxMarkerShas  = 20
	commentHardMax = 60000 // GitHub's limit is 65536
)

type marker struct {
	Notified []string // heads a decision/merge-failure notification was sent for
	Stuck    []string // heads a "stuck without a decision" notification was sent for
	// Approved is the head publish last approved for merging, or "". Sweep
	// merges only when it equals the current head AND the gate app's own
	// `success` status is on that head: write collaborators can edit this
	// comment, so the marker alone never authorises anything.
	Approved string
}

var markerRe = regexp.MustCompile(`^<!-- dep-review:v1((?: [a-z]+=[^ <>]*)*) -->`)

func parseMarker(body string) (marker, bool) {
	m := markerRe.FindStringSubmatch(body)
	if m == nil {
		return marker{}, false
	}
	var mk marker
	for _, kv := range strings.Fields(m[1]) {
		k, v, _ := strings.Cut(kv, "=")
		var shas []string
		for _, s := range strings.Split(v, ",") {
			if gh.ValidSHA(s) {
				shas = append(shas, s)
			}
		}
		switch k {
		case "notified":
			mk.Notified = shas
		case "stuck":
			mk.Stuck = shas
		case "approved":
			if len(shas) == 1 {
				mk.Approved = shas[0]
			}
		}
	}
	return mk, true
}

func (m marker) String() string {
	approved := ""
	if gh.ValidSHA(m.Approved) {
		approved = " approved=" + m.Approved
	}
	return fmt.Sprintf("%s notified=%s stuck=%s%s -->", markerPrefix, strings.Join(m.Notified, ","), strings.Join(m.Stuck, ","), approved)
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func add(list []string, s string) []string {
	if has(list, s) {
		return list
	}
	list = append(list, s)
	if len(list) > maxMarkerShas {
		list = list[len(list)-maxMarkerShas:]
	}
	return list
}

// replaceMarker swaps the marker line of one of our own comments.
func replaceMarker(body string, m marker) string {
	if loc := markerRe.FindStringIndex(body); loc != nil {
		return m.String() + body[loc[1]:]
	}
	return m.String() + "\n" + body
}

type commentData struct {
	Class     model.Classification
	Evidence  *model.Evidence
	Outcome   Outcome
	MergeNote string // the gate's own words
	RunURL    string // built from validated workflow env, or ""
	Marker    marker
	Rebuild   []model.RebuildResult
}

var headline = map[model.Decision]string{
	model.DecisionMerge:   "approved",
	model.DecisionHuman:   "needs a person",
	model.DecisionPending: "no decision (the gate failed; it will retry on the next push or re-run)",
}

func renderComment(d commentData) string {
	var b strings.Builder
	o := d.Outcome
	b.WriteString(d.Marker.String())
	fmt.Fprintf(&b, "\n### dep-review: %s\n\n", headline[o.Decision])
	b.WriteString("| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Decision | `%s` |\n", o.Decision)
	if o.Route != "" {
		fmt.Fprintf(&b, "| Route | `%s` |\n", o.Route)
	}
	fmt.Fprintf(&b, "| Head | %s |\n", code(d.Class.HeadSHA))
	fmt.Fprintf(&b, "| Reason | %s |\n", Inline(o.Reason))
	if d.Class.Kind == model.KindDependabotUnverified && d.Class.Reason != "" {
		fmt.Fprintf(&b, "| Classification | %s |\n", Inline(d.Class.Reason))
	}
	if d.RunURL != "" {
		fmt.Fprintf(&b, "| Run | [workflow run](%s) |\n", d.RunURL)
	}
	if d.MergeNote != "" {
		fmt.Fprintf(&b, "\n**Merge:** %s\n", Inline(d.MergeNote))
	}

	updates, title := d.Class.Declared, "Updates declared by Dependabot"
	if d.Evidence != nil {
		updates, title = d.Evidence.Updates, "Updates found by the gate"
	}
	if len(updates) > 0 {
		fmt.Fprintf(&b, "\n#### %s (%d)\n\n", title, len(updates))
		b.WriteString("| Dependency | Ecosystem | Directory | From | To | Type | Notes |\n|---|---|---|---|---|---|---|\n")
		for i, u := range updates {
			if i == maxRows {
				fmt.Fprintf(&b, "| … %d more | | | | | | |\n", len(updates)-maxRows)
				break
			}
			var notes []string
			if u.Security {
				notes = append(notes, "security")
			}
			if u.NoOp {
				notes = append(notes, "no-op")
			}
			if !u.Direct {
				notes = append(notes, "indirect")
			}
			for _, a := range u.Advisory {
				notes = append(notes, a)
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n",
				code(u.Name), code(string(u.Ecosystem)), code(u.Directory),
				code(u.From), code(u.To), code(string(u.Type)), Inline(strings.Join(notes, ", ")))
		}
	}

	if d.Evidence != nil && len(d.Evidence.Findings) > 0 {
		fs := d.Evidence.Findings
		fmt.Fprintf(&b, "\n#### Findings (%d)\n\n", len(fs))
		b.WriteString("| Code | Route | Update | Detail |\n|---|---|---|---|\n")
		for i, f := range fs {
			if i == maxRows {
				fmt.Fprintf(&b, "| … %d more | | | |\n", len(fs)-maxRows)
				break
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", code(f.Code), code(string(f.Route)), code(f.Update), code(f.Detail))
		}
	}
	if d.Evidence != nil && d.Evidence.Truncated {
		b.WriteString("\nThe evidence was truncated by a size cap.\n")
	}
	if d.Evidence != nil && len(d.Evidence.Rebuilds) > 0 {
		renderRebuilds(&b, d.Evidence.Rebuilds, d.Rebuild)
	}

	if v := o.Verdict; v != nil {
		if o.Triage {
			b.WriteString("\n#### Triage for the person deciding\n\nThe model reviewed this pull request as triage only: a person decides, whatever it answered.\n\n| | |\n|---|---|\n")
		} else {
			b.WriteString("\n#### Review\n\n| | |\n|---|---|\n")
		}
		if o.Triage {
			fmt.Fprintf(&b, "| Triage verdict (does not decide) | `%s` |\n", v.Verdict)
		} else {
			fmt.Fprintf(&b, "| Verdict | `%s` |\n", v.Verdict)
		}
		flags := make([]string, len(v.Flags))
		for i, f := range v.Flags {
			flags[i] = code(f)
		}
		if len(flags) == 0 {
			flags = []string{"none"}
		}
		fmt.Fprintf(&b, "| Flags | %s |\n", strings.Join(flags, ", "))
		if s := SanitizeSummary(v.Summary); s != "" {
			b.WriteString("\nReviewer's summary (model output, sanitized):\n\n```text\n")
			b.WriteString(s)
			b.WriteString("\n```\n")
		}
		if d.Evidence != nil && len(d.Evidence.Flagged) > 0 {
			renderUpstream(&b, d.Evidence.Upstream)
			renderItems(&b, d.Evidence.Flagged, v.Items, d.Evidence.Upstream)
		}
	}

	b.WriteString("\n<sub>dep-review applies this decision to the head commit above only. A new push starts a new review.</sub>\n")
	s := b.String()
	if len(s) > commentHardMax {
		s = s[:commentHardMax] + "\n\n(comment truncated)\n"
	}
	return s
}

// renderStuck is sweep's comment for a head that has had no decision for
// too long.
func renderStuck(head string, m marker) string {
	return m.String() + "\n### dep-review: no decision\n\n" +
		"The gate has not decided on head " + code(head) + " within two hours. " +
		"Check the dep-review workflow runs for this pull request, or re-run the trigger.\n"
}

// renderItems lists the reviewer's assessment of each flagged item, the
// ones that stopped a merge first. Update, code and item come from the
// evidence (the gate's strings); only the assessment and the note
// (sanitized) come from the model, and an item the reviewer listed but
// the gate did not flag is only counted.
func renderItems(b *strings.Builder, flagged []model.FlaggedItem, items []model.ItemAssessment, upstream []model.Upstream) {
	listed := listedCommits(upstream)
	got := map[model.FlaggedItem]model.ItemAssessment{}
	for _, it := range items {
		got[model.FlaggedItem{Update: it.Update, Code: it.Code, Item: it.Item}] = it
	}
	type row struct {
		f    model.FlaggedItem
		a    string
		note string
		rank int // not assessed, suspicious, unclear, benign
	}
	var rows []row
	counts := map[string]int{}
	for _, f := range flagged {
		r := row{f: f, a: "not assessed"}
		if it, ok := got[f]; ok {
			r.a, r.note = string(it.Assessment), it.Note
			if it.Assessment == model.Benign && !citesListed(it.Commits, listed[f]) {
				// Counted as accounting counts it.
				it.Assessment, r.a = model.Unclear, "unclear (benign without a listed commit)"
			} else if it.Assessment == model.Benign && len(it.Commits) > 0 {
				var short []string
				for _, c := range it.Commits {
					short = append(short, c[:7])
				}
				r.a += ", cites " + strings.Join(short, " ")
			}
			switch it.Assessment {
			case model.Suspicious:
				r.rank = 1
			case model.Unclear:
				r.rank = 2
			default:
				r.rank = 3
			}
			delete(got, f)
		}
		switch r.rank {
		case 1:
			counts["suspicious"]++
		case 2:
			counts["unclear"]++
		case 3:
			counts["benign"]++
		default:
			counts["not assessed"]++
		}
		rows = append(rows, r)
	}
	slices.SortStableFunc(rows, func(x, y row) int { return x.rank - y.rank })
	fmt.Fprintf(b, "\n#### Flagged items (%d): %d benign, %d suspicious, %d unclear, %d not assessed",
		len(flagged), counts["benign"], counts["suspicious"], counts["unclear"], counts["not assessed"])
	if len(got) > 0 {
		fmt.Fprintf(b, "; %d listed by the reviewer that the gate did not flag", len(got))
	}
	b.WriteString("\n\n| Update | Code | Item | Assessment | Reviewer's note (model output, sanitized) |\n|---|---|---|---|---|\n")
	for i, r := range rows {
		if i == maxRows {
			fmt.Fprintf(b, "| … %d more | | | | |\n", len(rows)-maxRows)
			break
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s |\n", code(r.f.Update), code(r.f.Code), code(r.f.Item), code(r.a), code(r.note))
	}
}

// renderUpstream says, per update, what the gate found upstream: the
// gate's own words.
func renderUpstream(b *strings.Builder, upstream []model.Upstream) {
	if len(upstream) == 0 {
		return
	}
	b.WriteString("\n#### Upstream history\n\n| Update | Status | Detail |\n|---|---|---|\n")
	for _, u := range upstream {
		fmt.Fprintf(b, "| %s | %s | %s |\n", code(u.Update), code(string(u.Status)), code(u.Detail))
	}
}

// rebuildOutcome is the result shown for a plan: the first result bound
// to it (same update, repository and commit) with a known outcome, or
// "not run".
func rebuildOutcome(p model.RebuildPlan, results []model.RebuildResult) (outcome, script, detail string) {
	for _, r := range results {
		if r.Update != p.Update || r.Repo != p.Repo || r.Commit != p.Commit {
			continue
		}
		switch r.Outcome {
		case model.RebuildVerified, model.RebuildDiffers, model.RebuildFailed:
			return r.Outcome, r.Script, r.Detail
		}
	}
	return "not run", "", "the rebuild job produced no result for it"
}

// renderRebuilds shows the rebuild job's results. They are information:
// no route depends on them (see package rebuild for what a match shows).
func renderRebuilds(b *strings.Builder, plans []model.RebuildPlan, results []model.RebuildResult) {
	fmt.Fprintf(b, "\n#### Bundle rebuilds (%d; information only, no route depends on them)\n\n", len(plans))
	b.WriteString("| Update | Commit | Result | Detail |\n|---|---|---|---|\n")
	for i, p := range plans {
		if i == maxRows {
			fmt.Fprintf(b, "| … %d more | | | |\n", len(plans)-maxRows)
			break
		}
		outcome, _, detail := rebuildOutcome(p, results)
		fmt.Fprintf(b, "| %s | %s | %s | %s |\n", code(p.Update), code(p.Commit), code(outcome), code(detail))
	}
}

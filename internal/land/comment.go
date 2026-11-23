package land

import (
	"context"
	"encoding/base64"
	json "encoding/json/v2"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/wire"
)

const (
	// commentPrefix starts the first line of the gate's one comment per
	// pull request, in every version of the gate, so a comment v0.1 left
	// is updated in place and not joined by a second one.
	commentPrefix = "<!-- dep-review:"
	// maxCommentBytes keeps a comment under GitHub's limit of 65536
	// characters.
	maxCommentBytes = 60000
	// maxMarkerBytes bounds the marker inside it.
	maxMarkerBytes = 16000
	// maxUpdatesShown bounds the fact tables. The rest are counted.
	maxUpdatesShown = 20
	// maxNotified is how many heads the marker remembers a notification
	// for.
	maxNotified = 20
	// maxCached is how many verdicts the marker remembers. One that does
	// not fit is a read the scheduled job has no answer for: it waits for
	// an event's run to ask the model, and is a person's at the deadline.
	maxCached = 100
	// A cached veto keeps this much of what the model wrote: enough for
	// the person reading the next comment, small enough for the marker.
	maxCachedQuotes = 3
	maxCachedText   = 300
	// maxQuotesShown is how many of a veto's quotes the comment shows.
	maxQuotesShown = 5
)

// marker is what the gate's comment remembers between runs, in a hidden
// first line. None of it is an approval: Outcome tells the scheduled job
// which pull requests to evaluate again, Notified keeps a re-run from
// notifying twice, Cache is the model's answers for the scheduled job,
// which asks no model, and FirstSeen is the gate's own clock for a pin no
// registry dates.
//
// It is believed only in a comment whose author is the gate app
// (findComment). A person who can write to the repository can edit that
// comment all the same; such a person can also merge by hand.
type marker struct {
	// Outcome is what the run that wrote the comment did, or ActionFailed
	// for a run that ended without doing anything. Never ActionStale: a
	// stale run writes nothing.
	Outcome Action `json:"outcome"`
	// Head is the commit it was done for.
	Head string `json:"head"`
	// NotBefore and Deadline are the decision's, for ActionWait.
	NotBefore time.Time `json:"not_before"`
	Deadline  time.Time `json:"deadline"`
	// Notified lists the heads a notification about a decision was sent
	// for. NotifiedFailed and NotifiedUnread do the same for the two about
	// the gate's own run: one that failed (Failed), and a reviewer that
	// did not answer (Act). They are lists of their own, so that having
	// told the owner one thing never keeps the next from being told.
	Notified       []string `json:"notified"`
	NotifiedFailed []string `json:"notified_failed"`
	NotifiedUnread []string `json:"notified_unread"`
	// Fingerprint is the reviewer's fingerprint every Cache entry was
	// written under.
	Fingerprint string `json:"fingerprint"`
	// Cache is the verdicts worth keeping, by content key.
	Cache []cached `json:"cache"`
	// FirstSeen is when publish first evaluated each pin of the pull
	// request that no registry had a time for (dateUnseen). A marker
	// written before the gate remembered these has none.
	FirstSeen []seen `json:"first_seen"`
}

// cached is one remembered verdict: wire.Verdict without the fingerprint,
// which the marker carries once.
type cached struct {
	Key  string          `json:"key"`
	Read allow.ReadState `json:"read"`
	Veto *allow.Veto     `json:"veto"`
}

// markerRE is the marker line. The payload is base64 of JSON, because a
// cached veto carries text the model quoted from a dependency, and no such
// text may be able to end the HTML comment it sits in.
var markerRE = regexp.MustCompile(`^<!-- dep-review:v2 ([A-Za-z0-9_-]+) -->`)

// String is the marker line. Cache entries are dropped from the end until
// it fits.
func (m marker) String() string {
	for {
		b, err := json.Marshal(m)
		if s := base64.RawURLEncoding.EncodeToString(b); err == nil && (len(s) <= maxMarkerBytes || len(m.Cache) == 0) {
			return "<!-- dep-review:v2 " + s + " -->"
		}
		if len(m.Cache) == 0 {
			// What is left is commit IDs, times and the gate's own words.
			panic("land: marker: " + err.Error())
		}
		m.Cache = m.Cache[:len(m.Cache)-1]
	}
}

// parseMarker reads the marker of a comment body. Anything that is not
// exactly what String writes is no marker at all.
func parseMarker(body string) (marker, bool) {
	found := markerRE.FindStringSubmatch(body)
	if found == nil || len(found[1]) > maxMarkerBytes {
		return marker{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(found[1])
	if err != nil {
		return marker{}, false
	}
	var m marker
	if err := json.Unmarshal(raw, &m, json.RejectUnknownMembers(true)); err != nil {
		return marker{}, false
	}
	switch m.Outcome {
	case ActionMerged, ActionWait, ActionPerson, ActionRefused, ActionFailed:
	default:
		return marker{}, false
	}
	if !gh.ValidSHA(m.Head) || len(m.Cache) > maxCached || len(m.FirstSeen) > maxFirstSeen {
		return marker{}, false
	}
	pins := map[string]bool{}
	for _, s := range m.FirstSeen {
		// Two times for one pin: which one counts must not be a matter of
		// order.
		if !pinRE.MatchString(s.Pin) || s.At.IsZero() || pins[s.Pin] {
			return marker{}, false
		}
		pins[s.Pin] = true
	}
	for _, list := range [][]string{m.Notified, m.NotifiedFailed, m.NotifiedUnread} {
		if len(list) > maxNotified || slices.ContainsFunc(list, func(head string) bool { return !gh.ValidSHA(head) }) {
			return marker{}, false
		}
	}
	// The cache has to be what a verdicts file may say, and internal/wire
	// is where that is written down.
	if _, err := wire.EncodeVerdicts(m.verdicts()); err != nil {
		return marker{}, false
	}
	return m, true
}

// verdicts is the cache as a verdicts file.
func (m marker) verdicts() wire.Verdicts {
	v := wire.Verdicts{Version: wire.Version, Verdicts: []wire.Verdict{}}
	for _, c := range m.Cache {
		v.Verdicts = append(v.Verdicts, wire.Verdict{Key: c.Key, Fingerprint: m.Fingerprint, Read: c.Read, Veto: c.Veto})
	}
	return v
}

// cacheEntries picks the verdicts to remember: the ones wire.Join used for
// this pull request's prepared reads under the current fingerprint, and of
// those only a model's complete answer. Read full or partial with no veto
// is a clean entry, and the review job writes that only after every chunk
// answered no_veto; a read with no answer (none) or one the reviewer would
// not send (refused) is not remembered, so it is asked again.
func cacheEntries(f wire.Facts, v wire.Verdicts, fingerprint string) []cached {
	answers := map[string]wire.Verdict{}
	for _, verdict := range v.Verdicts {
		if verdict.Fingerprint == fingerprint {
			answers[verdict.Key] = verdict
		}
	}
	var out []cached
	for _, u := range f.Facts.Updates {
		verdict, ok := answers[u.Prepared.Key]
		if !ok || u.Prepared.Status != wire.Prepared || len(out) == maxCached {
			continue
		}
		if verdict.Read != allow.ReadFull && verdict.Read != allow.ReadPartial {
			continue
		}
		delete(answers, u.Prepared.Key) // two updates with one key are one entry
		c := cached{Key: verdict.Key, Read: verdict.Read}
		if verdict.Veto != nil {
			veto := allow.Veto{Category: verdict.Veto.Category, Quotes: []string{}, Notes: cut(verdict.Veto.Notes)}
			for _, q := range verdict.Veto.Quotes[:min(len(verdict.Veto.Quotes), maxCachedQuotes)] {
				veto.Quotes = append(veto.Quotes, cut(q))
			}
			c.Veto = &veto
		}
		out = append(out, c)
	}
	return out
}

// cut keeps the first maxCachedText bytes of s, as valid UTF-8.
func cut(s string) string {
	if len(s) > maxCachedText {
		s = s[:maxCachedText]
	}
	return strings.ToValidUTF8(s, "")
}

// comment is the part of GitHub's issue comment object this package reads.
type comment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
	User *struct {
		Login string `json:"login"`
	} `json:"user"`
}

// findComment returns the gate's comment on a pull request, or nil. It is
// the gate's only when the gate app wrote it: a comment by anyone else
// that starts like one is not looked at, whatever its marker says.
func findComment(ctx context.Context, cfg Config, number int) (*comment, error) {
	comments, err := gh.List[comment](ctx, cfg.GitHub, fmt.Sprintf("repos/%s/issues/%d/comments", cfg.Repo, number))
	if err != nil {
		return nil, err
	}
	for i := range comments {
		c := &comments[i]
		if c.User != nil && c.User.Login == cfg.BotLogin && strings.HasPrefix(c.Body, commentPrefix) {
			return c, nil
		}
	}
	return nil, nil
}

// upsertComment writes body to the gate's comment, creating it when prev
// is nil.
func upsertComment(ctx context.Context, cfg Config, number int, prev *comment, body string) error {
	if prev != nil {
		return cfg.GitHub.Patch(ctx, fmt.Sprintf("repos/%s/issues/comments/%d", cfg.Repo, prev.ID), map[string]string{"body": body}, nil)
	}
	return cfg.GitHub.Post(ctx, fmt.Sprintf("repos/%s/issues/%d/comments", cfg.Repo, number), map[string]string{"body": body}, nil)
}

// view is everything a comment is rendered from.
type view struct {
	res    Result
	ev     Evaluation
	marker marker
	runURL string
}

var headlines = map[Action]string{
	ActionMerged:  "merged",
	ActionWait:    "waiting",
	ActionPerson:  "needs a person",
	ActionRefused: "GitHub refused the merge",
}

// render writes the comment: the marker, the outcome first, then every
// fact with its value and source.
//
// Two kinds of text meet here. The gate's own (headings, a reason's
// explanation and hint, times it formatted) is written as it is. All the
// rest came out of a file an earlier job wrote from what a registry, a
// publisher or the model said: names, versions, every fact's value and
// source, quotes, notes, and GitHub's refusal. That text only ever passes
// through code, which makes it one capped line inside a code span.
func render(v view) string {
	d := v.res.Decision
	var b strings.Builder
	b.WriteString(v.marker.String())
	fmt.Fprintf(&b, "\n### dep-review: %s\n\n", headlines[v.res.Action])
	b.WriteString(lead(v))
	if len(d.Reasons) > 1 {
		b.WriteString("\nAlso:\n\n")
		for _, r := range d.Reasons[1:] {
			fmt.Fprintf(&b, "- %s: %s\n", code(string(r)), r.Explain())
		}
	}
	b.WriteString("\n#### The pull request\n\n")
	writeTable(&b, pullRows(v.ev.Facts))

	foot := fmt.Sprintf("\nDecided for head %s on facts gathered %s. A new push starts a new evaluation.",
		code(v.ev.PullRequest.Head), stamp(v.ev.file.GatheredAt))
	if v.runURL != "" {
		foot += " [Workflow run](" + v.runURL + ")."
	}

	// The updates that hold the pull request back come first, and whole
	// sections are left out when the comment would be too long: a cut in
	// the middle of one could open a code span and never close it.
	order := make([]int, len(v.ev.Facts.Updates))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(x, y int) int { return rank(d, x) - rank(d, y) })
	shown := 0
	for _, i := range order {
		section := updateSection(v, i)
		if shown == maxUpdatesShown || b.Len()+len(section)+len(foot)+200 > maxCommentBytes {
			break
		}
		b.WriteString(section)
		shown++
	}
	if rest := len(order) - shown; rest > 0 {
		fmt.Fprintf(&b, "\n%d more updates are not shown: the comment would be too long.\n", rest)
	}
	b.WriteString(foot + "\n")
	return b.String()
}

// rank orders updates for the comment: person, then wait, then the rest.
func rank(d allow.Decision, i int) int {
	if i < len(d.PerUpdate) {
		switch d.PerUpdate[i].Outcome {
		case allow.Person:
			return 0
		case allow.Wait:
			return 1
		}
	}
	return 2
}

// lead is the comment's first paragraph: the outcome, and for anything
// but a merge the one reason that leads, the fact it is about and the
// cheapest way out.
func lead(v view) string {
	d := v.res.Decision
	head := code(v.ev.PullRequest.Head)
	switch v.res.Action {
	case ActionMerged:
		return "**Merged** at head " + head + ". Every fact below holds, " + modelSaid(v) + ", and GitHub's required checks allowed the merge.\n" + ownSaid(v)
	case ActionRefused:
		return "**GitHub refused the merge.** Every fact below holds and " + modelSaid(v) + ", so the gate asked GitHub to merge head " + head +
			". GitHub answered: " + code(v.res.Note) + "\n" + ownSaid(v) + "\n**Way out:** look at the pull request's merge box, then merge by hand or have Dependabot recreate the pull request. The gate does not try this head again.\n"
	}
	if len(d.Reasons) == 0 {
		return "**No reason was recorded.** Look at the update and merge or close the pull request by hand.\n"
	}
	r := d.Reasons[0]
	var b strings.Builder
	switch {
	case v.res.Action == ActionPerson:
		fmt.Fprintf(&b, "**Needs a person.** %s\n", r.Explain())
	case r == allow.ReasonAge:
		fmt.Fprintf(&b, "**Waiting until %s.** %s\n", stamp(d.NotBefore), r.Explain())
	case d.Deadline.IsZero():
		// allow.Decide sets no deadline while nothing says when the wait
		// began.
		fmt.Fprintf(&b, "**Waiting.** %s No deadline is set yet: neither when the pull request was opened nor when its versions were published is known.\n", r.Explain())
	default:
		// A retry: it ends when the retry succeeds, and at the deadline a
		// person is asked.
		fmt.Fprintf(&b, "**Waiting, at most until %s.** %s", stamp(d.Deadline), r.Explain())
		if v.ev.now.Before(d.NotBefore) {
			fmt.Fprintf(&b, " It cannot merge before %s either.", stamp(d.NotBefore))
		}
		b.WriteString("\n")
	}
	if fact, where, ok := failed(v, r); ok {
		fmt.Fprintf(&b, "\nThe fact: `%s` of %s is %s: %s", fact.fact, where, fact.answer, fact.value)
		if fact.source != "" {
			fmt.Fprintf(&b, " (source: %s)", fact.source)
		}
		b.WriteString(".\n")
	}
	if v.res.Note != "" {
		// The base branch moved while GitHub merged. The decision is the
		// one for required checks (see Act); this is what GitHub said.
		fmt.Fprintf(&b, "\nGitHub's answer to the merge call this time: %s.\n", code(v.res.Note))
	}
	fmt.Fprintf(&b, "\n**Way out:** %s\n", r.Hint())
	return b.String()
}

// modelSaid is the clause about the model in the lead of a decision to
// merge. The model raised no veto only where it was asked. Nothing of an
// image is read, and two artifacts that hold the same files have nothing
// to read: neither is put before a model, and the clause holds for both.
// An own workflow is not put before one either, and there the gate did
// have something to show: ownSaid says so in a paragraph of its own.
func modelSaid(v view) string {
	own := false
	for i, u := range v.ev.file.Facts.Updates {
		if u.Prepared.Status == wire.Prepared {
			return "the model raised no veto"
		}
		own = own || ownWorkflow(v, i)
	}
	if own {
		return "no model was asked"
	}
	return "no model was asked (the gate had nothing to show one)"
}

// ownWorkflow reports whether update i is one the gate accepts as the
// gate owner's own workflow, unread: allow.Decide's test (spec section
// 11, amendment 60).
func ownWorkflow(v view, i int) bool {
	return v.ev.Facts.Ecosystem == allow.GitHubActions && i < len(v.ev.Facts.Updates) && v.ev.Facts.Updates[i].Own.Holds()
}

// ownAccepted is what the comment says of an update that was accepted as
// the gate owner's own workflow. Such an update merges with nothing read
// and no age, and the comment must not leave that to be worked out from
// the fact table.
const ownAccepted = "accepted as the gate owner's own workflow, unread: nothing of it was read, no model was asked about it and no age was asked of it. " +
	"The gate checked where its commit comes from (the repository by its IDs, the tag, the default branch, the old pin) and not what it does"

// ownSaid is the paragraph the lead of a decision to merge owes every
// update that was accepted as the gate owner's own workflow, or "". The
// decision is to merge, so every update whose Own holds was accepted.
func ownSaid(v view) string {
	var names []string
	for i, u := range v.ev.Facts.Updates {
		if ownWorkflow(v, i) {
			names = append(names, updateName(u))
		}
	}
	if len(names) == 0 {
		return ""
	}
	return "\n**Own workflow, not read.** " + strings.Join(names, " and ") + ": " + ownAccepted + ".\n"
}

// A fact's four states, as the tables show them.
const (
	answerYes         = "yes"
	answerNo          = "no"
	answerNotGathered = "not gathered"
	answerUnavailable = "unavailable"
)

// reasonFact names, for each reason, the row of the fact tables the
// comment's lead quotes: a fact's name, answerNotGathered or
// answerUnavailable for "the first fact in that state", or "" where no
// single row says more than the reason's own explanation does. A test
// keeps it in step with allow.Reasons.
var reasonFact = map[allow.Reason]string{
	allow.ReasonPolicyInvalid:       "",
	allow.ReasonNoRule:              "",
	allow.ReasonNoUpdates:           "",
	allow.ReasonIdentity:            "Identity",
	allow.ReasonShape:               "Shape",
	allow.ReasonChecksNotConfigured: "ChecksConfigured",
	allow.ReasonFactMissing:         answerNotGathered,
	allow.ReasonListMismatch:        "Listed",
	allow.ReasonInconsistent:        "Known",
	allow.ReasonNotKnown:            "Known",
	allow.ReasonNewNameUnread:       "Read",
	allow.ReasonNewNameYoung:        "NameCreated",
	allow.ReasonNameCreatedUnknown:  "NameCreated",
	allow.ReasonNotIncrease:         "Increase",
	allow.ReasonNotBound:            "Bound",
	allow.ReasonNotClean:            "Clean",
	allow.ReasonRegress:             "NoRegress",
	allow.ReasonVeto:                "Veto",
	allow.ReasonModelRefused:        "Veto",
	allow.ReasonReadUnknown:         "Read",
	allow.ReasonReadRefused:         "Read",
	allow.ReasonMajorUnlisted:       "Major",
	allow.ReasonMajorOwn:            "Major",
	allow.ReasonFirstSeenUnknown:    "FirstSeen",
	allow.ReasonReadDeadline:        "",
	allow.ReasonSourceDeadline:      "",
	allow.ReasonSupersededDeadline:  "",
	allow.ReasonChecksDeadline:      "",
	allow.ReasonAge:                 "FirstSeen",
	allow.ReasonReadPending:         "Read",
	allow.ReasonSourceUnavailable:   answerUnavailable,
	allow.ReasonSuperseded:          "Superseded",
	allow.ReasonChecksPending:       "",
}

// failed finds the row a reason is about, and says whose fact it is: the
// pull request's, or the first update's that has the reason.
func failed(v view, reason allow.Reason) (r row, where string, ok bool) {
	want := reasonFact[reason]
	if want == "" {
		return row{}, "", false
	}
	match := func(rows []row) (row, bool) {
		for _, r := range rows {
			// A fact is never called by a state's name, and an answer is
			// always one of the gate's own words, so one test does both.
			if r.fact == want || r.answer == code(want) {
				return r, true
			}
		}
		return row{}, false
	}
	if r, ok := match(pullRows(v.ev.Facts)); ok {
		return r, "the pull request", true
	}
	for i, ud := range v.res.Decision.PerUpdate {
		if i >= len(v.ev.Facts.Updates) || !slices.Contains(ud.Reasons, reason) {
			continue
		}
		if r, ok := match(updateRows(v, i)); ok {
			return r, updateName(v.ev.Facts.Updates[i]), true
		}
	}
	return row{}, "", false
}

// row is one line of a fact table. fact is the gate's name for it and
// answer one of the gate's own words; all three cells after the name are
// already rendered, each through code.
type row struct{ fact, answer, value, source string }

func writeTable(b *strings.Builder, rows []row) {
	b.WriteString("| Fact | Answer | Value | Source |\n|---|---|---|---|\n")
	for _, r := range rows {
		fmt.Fprintf(b, "| %s | %s | %s | %s |\n", r.fact, r.answer, r.value, r.source)
	}
}

// factRow shows a fact in the four states allow gives it.
func factRow(name string, f allow.Fact) row {
	answer := answerNo
	switch {
	case f.Source == "":
		answer = answerNotGathered
	case f.Unavailable:
		answer = answerUnavailable
	case f.OK:
		answer = answerYes
	}
	return row{name, code(answer), code(f.Value), code(f.Source)}
}

// timeRow is factRow for a time. The value is the gatherer's, which for a
// known time is the time itself.
func timeRow(name string, t allow.TimeFact) row {
	return factRow(name, allow.Fact{OK: t.Known(), Unavailable: t.Unavailable, Value: t.Value, Source: t.Source})
}

func pullRows(f allow.PRFacts) []row {
	return []row{factRow("Identity", f.Identity), factRow("Shape", f.Shape), factRow("ChecksConfigured", f.ChecksConfigured)}
}

func updateRows(v view, i int) []row {
	u := v.ev.Facts.Updates[i]
	rows := []row{
		factRow("Known", u.Known), factRow("Listed", u.Listed), factRow("NewName", u.NewName),
		factRow("Increase", u.Increase), factRow("Major", u.Major),
	}
	// The four facts only some updates have are shown where they are in
	// play: whether the repository declares the dependency itself for a Go
	// module or an npm package, whether a workflow is the gate owner's
	// own, a name's age for a new name, a superseded pin for an image.
	if u.Indirect != (allow.Fact{}) {
		rows = append(rows, factRow("Indirect", u.Indirect))
	}
	if u.Own != (allow.Fact{}) {
		rows = append(rows, factRow("Own", u.Own))
	}
	rows = append(rows, factRow("Bound", u.Bound), timeRow("FirstSeen", u.FirstSeen))
	if u.NewName.Holds() || u.NameCreated != (allow.TimeFact{}) {
		rows = append(rows, timeRow("NameCreated", u.NameCreated))
	}
	rows = append(rows, factRow("Clean", u.Clean), factRow("NoRegress", u.NoRegress), factRow("SecurityFix", u.SecurityFix))
	if u.Superseded != (allow.Fact{}) {
		rows = append(rows, factRow("Superseded", u.Superseded))
	}

	// Read: the state allow.Decide was given, and what fetch prepared. The
	// state is the verdicts file's only for a prepared read, which is the
	// one read a model is asked about; every other is the facts file's
	// alone, and its detail says what happened.
	read, prepared, source := string(u.Read), "nothing was prepared", "the facts file"
	if read == "" {
		read = "not recorded"
	}
	asked := false // a model was asked about this read
	if i < len(v.ev.file.Facts.Updates) {
		p := v.ev.file.Facts.Updates[i].Prepared
		prepared = string(p.Status)
		switch {
		case p.Status == wire.Prepared:
			prepared = fmt.Sprintf("chunks prepared: %d; changed files not shown: %d", len(p.Chunks), len(p.Unread))
			source, asked = "the verdicts file", true
		case p.Detail != "":
			prepared += ": " + p.Detail
		}
	}
	rows = append(rows, row{"Read", code(read), code(prepared), code(source)})

	// Veto: the category, then each quoted line in a span of its own. With
	// no veto there is a row only when the model answered: "none" beside a
	// read that never happened, or one no model was asked about (two
	// artifacts that hold the same files), would say more than is known.
	switch {
	case u.Veto == nil && asked && (u.Read == allow.ReadFull || u.Read == allow.ReadPartial):
		rows = append(rows, row{"Veto", code("none"), "", code("the model")})
	case u.Veto != nil:
		cells := []string{code(u.Veto.Category)}
		for _, q := range u.Veto.Quotes[:min(len(u.Veto.Quotes), maxQuotesShown)] {
			cells = append(cells, code(q))
		}
		if more := len(u.Veto.Quotes) - maxQuotesShown; more > 0 {
			cells = append(cells, fmt.Sprintf("(%d more)", more))
		}
		rows = append(rows, row{"Veto", code("raised"), strings.Join(cells, " "), code("the model")})
		if u.Veto.Notes != "" {
			rows = append(rows, row{"Model's note", "", code(u.Veto.Notes), code("the model")})
		}
	}
	return rows
}

// updateName is an update as a heading or a sentence names it.
func updateName(u allow.UpdateFacts) string {
	from := code(u.From)
	if u.From == "" {
		from = "nothing (a new dependency)"
	}
	return fmt.Sprintf("%s %s to %s", code(u.Name), from, code(u.To))
}

// updateSection is one update: what allow.Decide said of it alone, and
// its fact table.
func updateSection(v view, i int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n#### %s\n\n", updateName(v.ev.Facts.Updates[i]))
	if i < len(v.res.Decision.PerUpdate) {
		ud := v.res.Decision.PerUpdate[i]
		switch {
		case ud.Outcome == allow.Merge && ownWorkflow(v, i):
			// Whatever becomes of the pull request, this update is not
			// one that was read.
			b.WriteString("Does not hold the pull request back: " + ownAccepted + ".")
		case ud.Outcome == allow.Merge:
			b.WriteString("Does not hold the pull request back.")
		default:
			codes := make([]string, len(ud.Reasons))
			for j, r := range ud.Reasons {
				codes[j] = code(string(r))
			}
			fmt.Fprintf(&b, "On its own: %s (%s).", ud.Outcome, strings.Join(codes, ", "))
		}
		// No age is asked of an own workflow, so no time says when it is
		// old enough.
		if !ud.NotBefore.IsZero() && !ownWorkflow(v, i) {
			fmt.Fprintf(&b, " Old enough from %s.", stamp(ud.NotBefore))
		}
		b.WriteString("\n\n")
	}
	writeTable(&b, updateRows(v, i))
	return b.String()
}

// stamp is a time as the comment and the status show it.
func stamp(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

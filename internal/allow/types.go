// Package allow decides what happens to a Dependabot pull request: merge,
// wait, or hand it to a person (docs/v0.2-spec.md, sections 2 to 4).
//
// The default is person. A merge is granted only by facts that the gate's
// deterministic code gathered from authoritative sources; the model's
// reading of the code can take a merge away and can never add one. Decide
// is a pure function of (facts, policy, now): no I/O, no clock, no
// environment, so the same record always yields the same decision and the
// decision can be replayed from a stored record.
//
// This package imports only the standard library. Everything else in v0.2
// builds against its types.
package allow

import "time"

// Outcome is what the gate does with a pull request.
type Outcome string

// The three outcomes, most permissive first.
const (
	// Merge: every fact holds, nothing was vetoed. Publish calls the merge
	// API with the head commit; GitHub's rules decide whether the required
	// checks allow it (see ChecksRefused).
	Merge Outcome = "merge"
	// Wait: only time, CI or a retry is missing (the model call, or a
	// source that did not answer). The pull request is evaluated again
	// without a person.
	Wait Outcome = "wait"
	// Person: a fact is false or was never gathered, or a veto was raised.
	Person Outcome = "person"
)

// The ecosystems that have a rule. The strings are the keys of the policy
// list ("listed" in policy/defaults.json), not Dependabot's branch names:
// Dependabot calls npm "npm_and_yarn", and whoever reads the branch name
// maps it. Every other ecosystem (uv, OpenTofu, submodules, anything new)
// has no rule and is always Person.
const (
	GoModules     = "go_modules"
	NPM           = "npm"
	GitHubActions = "github_actions"
	Docker        = "docker"
)

// HasRule reports whether ecosystem is one of the four that can merge
// without a person.
func HasRule(ecosystem string) bool {
	switch ecosystem {
	case GoModules, NPM, GitHubActions, Docker:
		return true
	}
	return false
}

// ReadState is how much of an update's changed code the model was shown
// and answered for.
type ReadState string

// The read states. The zero value ("") is none of them: an update whose
// read was never recorded is unknown, which is Person.
const (
	// ReadFull: every changed text file was sent, every chunk was
	// answered, and no file was left unread.
	ReadFull ReadState = "full"
	// ReadPartial: every chunk that was sent was answered, but the budget
	// was exceeded or some changed files were not text.
	ReadPartial ReadState = "partial"
	// ReadNone: the code has not been read yet. The artifact could not be
	// downloaded, or the model call failed, was not available or gave no
	// complete answer. It is retried at each evaluation; see
	// Policy.WaitDeadline.
	ReadNone ReadState = "none"
	// ReadNotApplicable: there is nothing a model could read. Valid for
	// Docker only; in any other ecosystem it is treated as unknown.
	ReadNotApplicable ReadState = "not-applicable"
	// ReadRefused: the gate would not read the code, and asking again
	// gives the same answer. The artifact did not match the hash the pull
	// request is bound to, its archive was unsafe to extract, its
	// reference was not one the gate fetches, or the reviewer called the
	// prepared read unusable. Person at once.
	ReadRefused ReadState = "refused"
)

// Fact is one thing the gate established about a pull request or about
// one update in it, with what was observed and where, so the pull request
// comment can show why.
//
// A fact is in one of four states, and only the first can contribute to a
// merge:
//
//   - it holds (Yes);
//   - it does not hold: the source answered, and the answer is no (No);
//   - it is unavailable: the source was asked and did not answer, because
//     of a network error, a server error or a rate limit (Unavailable).
//     Decide waits for it and asks again, up to the wait deadline;
//   - it was never gathered: Source is empty, whatever the other fields
//     say. Decide answers Person. Value may still say why nothing could be
//     established (an answer that arrived and could not be read is not an
//     outage).
type Fact struct {
	// OK: the fact holds. For Identity, Shape, ChecksConfigured, Known,
	// Increase, Bound, Clean and NoRegress, true is the good answer. For
	// Listed, NewName, Major, SecurityFix and Superseded it is the plain
	// answer to a yes/no question, and "no" is a normal thing to have
	// gathered.
	OK bool `json:"ok"`
	// Unavailable: the source was asked and did not answer. OK then means
	// nothing.
	Unavailable bool `json:"unavailable"`
	// Value is what was observed, in the gate's own words. It can quote
	// what a publisher or a registry wrote (a script, a deprecation
	// notice, a path), so it is third-party text all the same: nothing
	// decides on it, and publish shows it only through the comment
	// sanitiser, inside a code span, with a length cap.
	Value string `json:"value"`
	// Source is where it was read (an API path, a tool, a file). Empty
	// means nothing gathered this fact.
	Source string `json:"source"`
}

// Yes is a gathered fact that holds.
func Yes(value, source string) Fact { return Fact{OK: true, Value: value, Source: source} }

// No is a gathered fact that does not hold.
func No(value, source string) Fact { return Fact{OK: false, Value: value, Source: source} }

// Unavailable is a fact whose source was asked and did not answer. Use it
// only for a request that got no usable response at all: a network error,
// a 5xx or a rate limit. An answer that arrived and says no, or that
// could not be understood, is not unavailable.
func Unavailable(value, source string) Fact {
	return Fact{Unavailable: true, Value: value, Source: source}
}

// Gathered reports whether a source answered for the fact, yes or no.
func (f Fact) Gathered() bool { return f.Source != "" && !f.Unavailable }

// Holds reports whether the fact was gathered and is true.
func (f Fact) Holds() bool { return f.OK && f.Gathered() }

// And is the fact that holds only when both f and g hold. Otherwise it is
// whichever of the two settles more, f when they are level: a gathered
// "no" comes before a fact that was never gathered, and that before an
// unavailable one. So an outage never hides a "no", and the result is
// unavailable only when waiting could still make it hold.
func (f Fact) And(g Fact) Fact {
	if f.Holds() && g.Holds() {
		return Yes(f.Value+"; "+g.Value, f.Source+"; "+g.Source)
	}
	if stateOf(g) < stateOf(f) {
		return g
	}
	return f
}

// factState orders the four states of a fact from the one that settles
// most (a person, now) to the only one that grants.
type factState int

const (
	factNo factState = iota
	factMissing
	factUnavailable
	factYes
)

func stateOf(f Fact) factState {
	switch {
	case f.Source == "":
		return factMissing
	case f.Unavailable:
		return factUnavailable
	case f.OK:
		return factYes
	}
	return factNo
}

// TimeFact is a fact whose answer is a point in time (FirstSeen,
// NameCreated). It is known only when OK is set, Source is not empty and
// Time is not the zero time. Like a Fact it can be unavailable instead:
// the clock was asked and did not answer. Build one with At or
// UnavailableTime; any other value is a time that was not established.
type TimeFact struct {
	OK bool `json:"ok"`
	// Unavailable: the source was asked and did not answer.
	Unavailable bool      `json:"unavailable"`
	Time        time.Time `json:"time"`
	Value       string    `json:"value"`
	Source      string    `json:"source"`
}

// At is a gathered time.
func At(t time.Time, source string) TimeFact {
	return TimeFact{OK: true, Time: t, Value: t.UTC().Format(time.RFC3339), Source: source}
}

// UnavailableTime is a time whose source was asked and did not answer;
// see Unavailable.
func UnavailableTime(value, source string) TimeFact {
	return TimeFact{Unavailable: true, Value: value, Source: source}
}

// Known reports whether the time was established.
func (t TimeFact) Known() bool {
	return t.OK && !t.Unavailable && t.Source != "" && !t.Time.IsZero()
}

// unavailable reports whether the clock was asked and did not answer.
func (t TimeFact) unavailable() bool { return t.Unavailable && t.Source != "" }

// VetoModelRefused is the Veto category the gate itself sets when the
// model refused to answer. A refusal on a dependency diff is odd, and odd
// goes to a person. The model cannot choose this category.
const VetoModelRefused = "model_refused"

// Veto is the model's objection to one update. Any Veto is Person,
// whatever its category says: the category and quotes are shown, never
// interpreted.
type Veto struct {
	// Category is one of internal/veto's fixed categories, or
	// VetoModelRefused.
	Category string `json:"category"`
	// Quotes are the lines the model pointed at. Untrusted text, shown
	// like a Fact's Value: sanitised, in a code span, cut to a length.
	Quotes []string `json:"quotes"`
	// Notes is the model's optional remark. Untrusted text.
	Notes string `json:"notes"`
}

// UpdateFacts is everything known about one package the pull request
// moves. The change set comes from the base and head manifests, never
// from the pull request's title, body, labels or Dependabot's metadata.
type UpdateFacts struct {
	// Name is the module path, the npm package name, the action's
	// owner/repo, or the image name with its registry
	// (docker.io/library/golang). It is what the policy list is matched
	// against, byte for byte.
	Name string `json:"name"`
	// From is the version at the base commit; empty for a new name.
	From string `json:"from"`
	// To is the version at the head commit.
	To string `json:"to"`

	// Known: the name is a dependency at the base commit, or matches the
	// policy list. For Docker it means listed only: nothing in an image is
	// read, so being in a Dockerfile already is not enough. It must hold
	// whenever Listed does, and must not hold for a new name that is not
	// listed; Decide answers person for a record that says otherwise.
	Known Fact `json:"known"`
	// Listed: the name matches the policy list (the gatherer calls
	// Listed). Decide checks it against its own policy.
	Listed Fact `json:"listed"`
	// NewName: the name is absent at the base commit.
	NewName Fact `json:"new_name"`
	// Increase: both versions are plain releases and To is greater than
	// From. For a new name there is no From: To is a plain release.
	Increase Fact `json:"increase"`
	// Major: the leading version component changed.
	Major Fact `json:"major"`
	// Bound: the pinned hash, commit or digest equals what the registry
	// reports now.
	Bound Fact `json:"bound"`
	// FirstSeen: when To became public, by a clock the publisher cannot
	// set. Where the registry has no such clock, or it did not answer,
	// the fetch command puts the pull request's creation time here, with
	// the source "pull request opened" (spec section 11, amendment 4).
	FirstSeen TimeFact `json:"first_seen"`
	// NameCreated: when the package name first appeared. Needed only for
	// a new name that is not listed.
	NameCreated TimeFact `json:"name_created"`
	// Clean: still published; not retracted, yanked or deprecated; no
	// malware advisory; no advisory on To that From did not have. For
	// Docker: the registry serves the pinned digest under the tag now and
	// does not mark it deprecated.
	Clean Fact `json:"clean"`
	// NoRegress: no new or changed install script; provenance identity
	// not lost; for Actions, the new commit descends from the old one on
	// the default or a release branch and the tag resolves to it. For
	// Docker there is nothing to compare, and it holds.
	NoRegress Fact `json:"no_regress"`
	// SecurityFix: GitHub's Advisory Database has a reviewed,
	// non-withdrawn advisory that affects From, does not affect To, and
	// names To as the first patched version. For Docker a gathered no.
	SecurityFix Fact `json:"security_fix"`
	// Superseded: the registry serves another digest under the pinned tag
	// now, so the pin is no longer the current one (Docker only; Decide
	// ignores it elsewhere). Dependabot refreshes the digest itself, so
	// the update waits for that instead of going to a person: Bound,
	// Clean and FirstSeen then describe a pin that is about to be
	// replaced and are not looked at. It never merges while this holds.
	// The zero Fact and a gathered "no" both mean not superseded, so only
	// the Docker gatherer ever sets it.
	Superseded Fact `json:"superseded"`
	// Read: how much of the change the model read.
	Read ReadState `json:"read"`
	// Veto: nil, or the model's objection. Nil means "no veto" only
	// together with Read; a model that never answered is ReadNone.
	Veto *Veto `json:"veto"`
}

// PRFacts is everything known about one pull request at one head commit.
type PRFacts struct {
	// Ecosystem is the one ecosystem the pull request belongs to, as one
	// of this package's constants, or anything else for an ecosystem with
	// no rule.
	Ecosystem string `json:"ecosystem"`
	// Identity: the pull request is Dependabot's alone, its base is the
	// default branch and the head is current.
	Identity Fact `json:"identity"`
	// Shape: only that ecosystem's manifest and lock files changed, and
	// only version or hash tokens in them.
	Shape Fact `json:"shape"`
	// ChecksConfigured: the default branch has a required-status-checks
	// rule.
	ChecksConfigured Fact `json:"checks_configured"`
	// Opened is when GitHub created the pull request (the pull request's
	// created_at). It is not one of the spec's facts and it grants
	// nothing: it only keeps the wait deadline from starting before the
	// pull request existed (see Decision.Deadline). The zero time means
	// unknown, and the deadline then runs from the latest required time
	// alone, which is the earlier and stricter reading.
	Opened time.Time `json:"opened"`
	// Updates is every package the pull request moves. An empty list is
	// Person: Dependabot never opens such a pull request.
	Updates []UpdateFacts `json:"updates"`
}

// Companions is what happens to the other updates of a pull request that
// contains a security fix on the fast path.
type Companions string

// The two companion modes.
const (
	// RideAlong: an update that is known, not a new name, not a major and
	// fully read needs no age when the pull request carries a security
	// fix that was fully read.
	RideAlong Companions = "ride-along"
	// CompanionsWait: every update needs its own age.
	CompanionsWait Companions = "wait"
)

// Policy is the owner's settings, as internal/config resolves them from
// the embedded defaults and the repository's file on the default branch.
// Decide answers Person for a Policy whose ages are not all positive or
// whose Companions is not one of the two modes, so the zero Policy can
// never merge anything.
type Policy struct {
	// MinAge is how long a fully read update must have been public.
	MinAge time.Duration
	// UnreadAge is how long an update that was only partly read must
	// have been public. Decide never lets it be shorter than MinAge.
	UnreadAge time.Duration
	// MajorAge is how long a major update of a listed name must have
	// been public. Decide never lets a major need less than the same
	// update would need as a minor.
	MajorAge time.Duration
	// NewNameAge is how old a package name must be before a new, unlisted
	// dependency under that name can merge without a person.
	NewNameAge time.Duration
	// WaitDeadline is how long a pull request may stay unmergeable past
	// its latest required time before it becomes Person; see
	// Decision.Deadline.
	WaitDeadline time.Duration
	// FastPath lets a security fix merge sooner. Off, SecurityFix changes
	// nothing.
	FastPath bool
	// Companions is the mode for the other updates in a fast-path pull
	// request.
	Companions Companions
	// Listed is the owner-kept list, by ecosystem constant. See Listed
	// for how an entry matches.
	Listed map[string][]string
}

// UpdateDecision is Decide's answer for one update, before the pull
// request's own facts and the other updates are taken into account.
type UpdateDecision struct {
	Name string `json:"name"`
	From string `json:"from"`
	To   string `json:"to"`
	// Outcome for this update alone. Merge here means "this update does
	// not hold the pull request back".
	Outcome Outcome `json:"outcome"`
	// Reasons explain a Wait or Person outcome; empty for Merge.
	Reasons []Reason `json:"reasons"`
	// RequiredAge is how long To must have been public. For ReadNone it
	// is the age a full read would need, the earliest possible; for an
	// update that waits on a source it is computed from the answers that
	// did arrive, and again when the source answers. Zero for Person.
	RequiredAge time.Duration `json:"required_age_ns"`
	// NotBefore is FirstSeen plus RequiredAge. Zero for Person, and while
	// FirstSeen is not known.
	NotBefore time.Time `json:"not_before"`
}

// Decision is Decide's answer for the pull request.
type Decision struct {
	Outcome Outcome `json:"outcome"`
	// Reasons explain a Wait or Person outcome, most general first; empty
	// for Merge. Every element is one of Reasons().
	Reasons []Reason `json:"reasons"`
	// NotBefore is the latest required time: the latest NotBefore of any
	// update, the earliest moment the pull request can merge. It can be
	// in the past while the outcome is Wait (the model read is pending, a
	// source did not answer, or a pin was superseded). Zero for Person.
	NotBefore time.Time `json:"not_before"`
	// Deadline is when a pull request that still cannot merge becomes
	// Person: Policy.WaitDeadline after the later of the latest required
	// time and PRFacts.Opened. It ends a retry (a model read, a source
	// that did not answer, a superseded pin) and a refusal by GitHub
	// (ChecksRefused); waiting for an age has no deadline. While a retry
	// is pending, the latest required time is taken as if every update
	// had been read in full, so a partial read never moves the deadline
	// later. Zero for Person.
	Deadline time.Time `json:"deadline"`
	// PerUpdate has one entry per PRFacts.Updates element, in order.
	PerUpdate []UpdateDecision `json:"per_update"`
}

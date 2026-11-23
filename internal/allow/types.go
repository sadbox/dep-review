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
	// Wait: only time, CI or a retry of the model call is missing. The
	// pull request is evaluated again without a person.
	Wait Outcome = "wait"
	// Person: a fact is false or unknown, or a veto was raised.
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
	// ReadNone: no complete model answer (the call failed or was not
	// available). It is retried at each evaluation; see Policy.WaitDeadline.
	ReadNone ReadState = "none"
	// ReadNotApplicable: there is nothing a model could read. Valid for
	// Docker only; in any other ecosystem it is treated as unknown.
	ReadNotApplicable ReadState = "not-applicable"
)

// Fact is one thing the gate established about a pull request or about
// one update in it, with what was observed and where, so the pull request
// comment can show why.
//
// A Fact with an empty Source was never gathered. It is unknown whatever
// OK says, and Decide answers Person for it. Build facts with Yes and No.
type Fact struct {
	// OK: the fact holds. For Identity, Shape, ChecksConfigured, Known,
	// Increase, Bound, Clean and NoRegress, true is the good answer. For
	// Listed, NewName, Major and SecurityFix it is the plain answer to a
	// yes/no question, and "no" is a normal thing to have gathered.
	OK bool `json:"ok"`
	// Value is what was observed, in the gate's own words.
	Value string `json:"value"`
	// Source is where it was read (an API path, a tool, a file). Empty
	// means nothing gathered this fact.
	Source string `json:"source"`
}

// Yes is a gathered fact that holds.
func Yes(value, source string) Fact { return Fact{OK: true, Value: value, Source: source} }

// No is a gathered fact that does not hold.
func No(value, source string) Fact { return Fact{OK: false, Value: value, Source: source} }

// Gathered reports whether anything established the fact, true or false.
func (f Fact) Gathered() bool { return f.Source != "" }

// Holds reports whether the fact was gathered and is true.
func (f Fact) Holds() bool { return f.OK && f.Source != "" }

// TimeFact is a fact whose answer is a point in time (FirstSeen,
// NameCreated). It is unknown unless OK is set, Source is not empty and
// Time is not the zero time. Build one with At.
type TimeFact struct {
	OK     bool      `json:"ok"`
	Time   time.Time `json:"time"`
	Value  string    `json:"value"`
	Source string    `json:"source"`
}

// At is a gathered time.
func At(t time.Time, source string) TimeFact {
	return TimeFact{OK: true, Time: t, Value: t.UTC().Format(time.RFC3339), Source: source}
}

// Known reports whether the time was established.
func (t TimeFact) Known() bool { return t.OK && t.Source != "" && !t.Time.IsZero() }

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
	// Quotes are the lines the model pointed at. Untrusted text: sanitise
	// before showing.
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
	// policy list. It must hold whenever Listed does, and must not hold
	// for a new name that is not listed; Decide answers person for a
	// record that says otherwise.
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
	// set.
	FirstSeen TimeFact `json:"first_seen"`
	// NameCreated: when the package name first appeared. Needed only for
	// a new name that is not listed.
	NameCreated TimeFact `json:"name_created"`
	// Clean: still published; not retracted, yanked or deprecated; no
	// malware advisory; no advisory on To that From did not have.
	Clean Fact `json:"clean"`
	// NoRegress: no new or changed install script; provenance identity
	// not lost; for Actions, the new commit descends from the old one on
	// the default or a release branch and the tag resolves to it.
	NoRegress Fact `json:"no_regress"`
	// SecurityFix: GitHub's Advisory Database has a reviewed,
	// non-withdrawn advisory that affects From, does not affect To, and
	// names To as the first patched version.
	SecurityFix Fact `json:"security_fix"`
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
	// its latest required time before it becomes Person.
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
	// is the age a full read would need, the earliest possible. Zero for
	// Person.
	RequiredAge time.Duration `json:"required_age_ns"`
	// NotBefore is FirstSeen plus RequiredAge. Zero for Person.
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
	// in the past while the outcome is Wait (the model read is pending).
	// Zero for Person.
	NotBefore time.Time `json:"not_before"`
	// Deadline is when a pull request that still cannot merge becomes
	// Person: Policy.WaitDeadline after the later of NotBefore and
	// PRFacts.Opened. Zero for Person.
	Deadline time.Time `json:"deadline"`
	// PerUpdate has one entry per PRFacts.Updates element, in order.
	PerUpdate []UpdateDecision `json:"per_update"`
}

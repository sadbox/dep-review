// Package allow decides what happens to a Dependabot pull request: merge,
// wait, or hand it to a person (docs/v0.2-spec.md, sections 2 to 4).
//
// The default is person. Only facts the gate's deterministic code gathered
// grant a merge; the model's reading can take one away and never add one.
// Decide is a pure function of (facts, policy, now), so a stored record
// always replays to the same decision. The package imports only the
// standard library.
package allow

import "time"

// Outcome is what the gate does with a pull request.
type Outcome string

// The three outcomes, most permissive first.
const (
	// Merge: every fact holds and nothing was vetoed. Whether the required
	// checks allow it is GitHub's answer to the merge call (ChecksRefused).
	Merge Outcome = "merge"
	// Wait: only time, CI or a retry is missing. Evaluated again later.
	Wait Outcome = "wait"
	// Person: a fact is false or was never gathered, or a veto was raised.
	Person Outcome = "person"
)

// The ecosystems that have a rule, by their keys in the policy list. These
// are not Dependabot's branch names (it calls npm "npm_and_yarn"); whoever
// reads the branch name maps it. Every other ecosystem is always Person.
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

// The read states. The zero value is none of them: a read that was never
// recorded is unknown, which is Person.
const (
	// ReadFull: every changed text file was sent and every chunk answered.
	ReadFull ReadState = "full"
	// ReadPartial: every chunk sent was answered, but the budget was
	// exceeded or some changed files were not text.
	ReadPartial ReadState = "partial"
	// ReadNone: not read yet. The artifact could not be downloaded, or the
	// model gave no complete answer. Retried until the wait deadline.
	ReadNone ReadState = "none"
	// ReadNotApplicable: nothing is put before a model. That is an image,
	// of which nothing can be read, and a reusable workflow of one of the
	// gate owner's own repositories, which is accepted unread (spec section
	// 11, amendment 60). Nowhere else.
	ReadNotApplicable ReadState = "not-applicable"
	// ReadRefused: the gate would not read the code, and asking again gives
	// the same answer (a hash mismatch, an unsafe archive, a reference the
	// gate does not fetch, an unusable read). Person at once.
	ReadRefused ReadState = "refused"
)

// Fact is one thing the gate established about a pull request or an
// update, with what was observed and where, so the comment can show why.
// It is in one of four states, and only the first contributes to a merge:
// it holds (Yes); it does not, because the source answered no (No); it is
// unavailable, because the source was asked and did not answer, and Decide
// waits and asks again up to the wait deadline (Unavailable); or it was
// never gathered, which is an empty Source whatever the other fields say,
// and Person. Value may still say why: an answer that arrived and could
// not be read is not an outage.
type Fact struct {
	// OK: the fact holds. For Listed, NewName, Major, SecurityFix and
	// Superseded "no" is a normal thing to have gathered.
	OK bool `json:"ok"`
	// Unavailable: OK then means nothing.
	Unavailable bool `json:"unavailable"`
	// Value is what was observed. It can quote a publisher or a registry,
	// so it is third-party text: nothing decides on it, and publish shows
	// it only sanitised, in a code span, cut to a length.
	Value string `json:"value"`
	// Source is where it was read. Empty means nothing gathered the fact.
	Source string `json:"source"`
}

// Yes is a gathered fact that holds.
func Yes(value, source string) Fact { return Fact{OK: true, Value: value, Source: source} }

// No is a gathered fact that does not hold.
func No(value, source string) Fact { return Fact{OK: false, Value: value, Source: source} }

// Unavailable is a fact whose source was asked and gave no usable response
// at all: a network error, a 5xx or a rate limit. An answer that says no,
// or that could not be understood, is not unavailable.
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
// NameCreated). Build one with At or UnavailableTime; any other value is a
// time that was not established.
type TimeFact struct {
	OK          bool      `json:"ok"`
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

// Veto is the model's objection to one update. Any Veto is Person: the
// category and quotes are shown, never interpreted.
type Veto struct {
	// Category is one of internal/veto's fixed categories, or
	// VetoModelRefused.
	Category string `json:"category"`
	// Quotes are the lines the model pointed at, and Notes its optional
	// remark. Untrusted text, shown like a Fact's Value.
	Quotes []string `json:"quotes"`
	Notes  string   `json:"notes"`
}

// UpdateFacts is everything known about one package the pull request
// moves, read from the base and head manifests and never from the pull
// request's title, body, labels or Dependabot's metadata. What each fact
// means is spec section 3; a comment here says what that table does not.
type UpdateFacts struct {
	// Name is the module path, the npm package name, the action's
	// owner/repo, or the image name with its registry. The policy list is
	// matched against it byte for byte.
	Name string `json:"name"`
	// From is the version at the base commit, empty for a new name. To is
	// the version at the head commit.
	From string `json:"from"`
	To   string `json:"to"`

	// Known must hold whenever Listed does, and must not hold for a new
	// name that is not listed. For Docker it means listed only: nothing in
	// an image is read. Decide answers person for any other record.
	Known Fact `json:"known"`
	// Listed is the gatherer's answer from Listed. Decide checks it
	// against its own policy.
	Listed  Fact `json:"listed"`
	NewName Fact `json:"new_name"`
	// Increase: for a new name there is no From, and To is a plain
	// release.
	Increase Fact `json:"increase"`
	Major    Fact `json:"major"`
	// Indirect lets a major update of an unlisted name be decided like a
	// listed one's: the version was the parent's choice. Only a fact that
	// holds counts, and Decide never waits for it. It is looked at for Go
	// modules and npm only: an action or an image is always the
	// repository's own choice.
	Indirect Fact `json:"indirect"`
	Bound    Fact `json:"bound"`
	// FirstSeen: where the registry has no clock the publisher cannot
	// set, the publish job puts here when it first evaluated this pin on
	// the pull request (spec section 11, amendment 38).
	FirstSeen TimeFact `json:"first_seen"`
	// NameCreated is needed only for a new name that is not listed.
	NameCreated TimeFact `json:"name_created"`
	Clean       Fact     `json:"clean"`
	NoRegress   Fact     `json:"no_regress"`
	SecurityFix Fact     `json:"security_fix"`
	// Superseded: the registry serves another digest under the pinned tag
	// now (Docker only; Decide ignores it elsewhere). Dependabot refreshes
	// the digest itself, so the update waits for that: Bound, Clean and
	// FirstSeen describe a pin that is about to be replaced and are not
	// looked at. It never merges while this holds. The zero Fact and a
	// gathered "no" both mean not superseded.
	Superseded Fact `json:"superseded"`
	// Own: the update moves the commit pin of a reusable workflow in a
	// repository on the policy's own list (Actions only; spec section 11,
	// amendment 60). Such an update is granted on where its commit comes
	// from: nothing of it is read and no age is asked of it. Only a fact
	// that holds counts, Decide never waits for it, and Decide checks the
	// name against its own list.
	Own  Fact      `json:"own"`
	Read ReadState `json:"read"`
	// Veto: nil means "no veto" only together with Read; a model that
	// never answered is ReadNone.
	Veto *Veto `json:"veto"`
}

// PRFacts is everything known about one pull request at one head commit.
type PRFacts struct {
	// Ecosystem is one of this package's constants, or anything else for
	// an ecosystem with no rule.
	Ecosystem        string `json:"ecosystem"`
	Identity         Fact   `json:"identity"`
	Shape            Fact   `json:"shape"`
	ChecksConfigured Fact   `json:"checks_configured"`
	// Opened is the pull request's created_at. It is not one of the
	// spec's facts and grants nothing: it only keeps the wait deadline
	// from starting before the pull request existed (see
	// Decision.Deadline). The zero time means unknown.
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

// Policy is the owner's settings, as internal/config resolves them. Decide
// answers Person for a Policy whose ages are not all positive or whose
// Companions is not one of the two modes, so the zero Policy can never
// merge anything.
type Policy struct {
	// MinAge is how long a fully read update must have been public.
	MinAge time.Duration
	// UnreadAge is the same for an update that was only partly read.
	// Decide never lets it be shorter than MinAge.
	UnreadAge time.Duration
	// MajorAge is the same for a major update of a listed name or of an
	// indirect dependency. Decide never lets a major need less than the
	// same update would need as a minor.
	MajorAge time.Duration
	// NewNameAge is how old a package name must be before a new, unlisted
	// dependency under it can merge without a person.
	NewNameAge time.Duration
	// WaitDeadline: see Decision.Deadline.
	WaitDeadline time.Duration
	// FastPath lets a security fix merge sooner. Off, SecurityFix changes
	// nothing.
	FastPath   bool
	Companions Companions
	// Listed is the owner-kept list, by ecosystem constant. See Listed
	// for how an entry matches.
	Listed map[string][]string
	// Own is the gate owner's own repositories whose reusable workflows
	// callers pin. See OwnRepository.
	Own []OwnRepo
}

// OwnRepo is one repository of the gate's owner, named exactly and with
// the numeric IDs GitHub gave it, so that neither a look-alike name nor a
// name someone else registered again is taken for it.
type OwnRepo struct {
	Repository   string `json:"repository"`
	RepositoryID int64  `json:"repository_id"`
	OwnerID      int64  `json:"owner_id"`
}

// OwnRepository returns the policy's own entry for name. The match is the
// whole name, byte for byte: no prefix, no owner alone, no other case.
func OwnRepository(p Policy, name string) (OwnRepo, bool) {
	for _, o := range p.Own {
		if name != "" && o.Repository == name {
			return o, true
		}
	}
	return OwnRepo{}, false
}

// UpdateDecision is Decide's answer for one update, before the pull
// request's own facts and the other updates are taken into account.
type UpdateDecision struct {
	Name string `json:"name"`
	From string `json:"from"`
	To   string `json:"to"`
	// Outcome for this update alone. Merge here means "this update does
	// not hold the pull request back".
	Outcome Outcome  `json:"outcome"`
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
	// that did not answer, a superseded pin) and a merge that GitHub
	// refused or publish did not ask for yet (ChecksRefused); waiting for
	// an age has no deadline. While a retry
	// is pending, the latest required time is taken as if every update
	// had been read in full, so a partial read never moves the deadline
	// later. Zero for Person, and for a Wait that has nothing to count
	// from: neither PRFacts.Opened nor any update's first-seen time is
	// known. Such a pull request waits until one of them is.
	Deadline time.Time `json:"deadline"`
	// PerUpdate has one entry per PRFacts.Updates element, in order.
	PerUpdate []UpdateDecision `json:"per_update"`
}

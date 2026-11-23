package allow

// Reason is one way for a pull request to be Wait or Person. The set is
// closed: Decide and ChecksRefused return nothing else, and nothing a
// dependency, a pull request or the model wrote ever becomes a Reason.
type Reason string

// Reasons that concern the pull request as a whole. All are Person.
const (
	// ReasonPolicyInvalid: the policy handed to Decide is not usable.
	ReasonPolicyInvalid Reason = "policy_invalid"
	// ReasonNoRule: the ecosystem has no rule (uv, OpenTofu, submodules).
	ReasonNoRule Reason = "no_rule"
	// ReasonNoUpdates: the base and head manifests show no update.
	ReasonNoUpdates Reason = "no_updates"
	// ReasonIdentity: the Identity fact is false or unknown.
	ReasonIdentity Reason = "identity"
	// ReasonShape: the Shape fact is false or unknown.
	ReasonShape Reason = "shape"
	// ReasonChecksNotConfigured: the ChecksConfigured fact is false or
	// unknown.
	ReasonChecksNotConfigured Reason = "checks_not_configured"
)

// Reasons that concern one update. All are Person.
const (
	// ReasonFactMissing: the update has no name or target version, or one
	// of Known, Listed, NewName, Major or SecurityFix was never gathered.
	ReasonFactMissing Reason = "fact_missing"
	// ReasonListMismatch: the Listed fact disagrees with the policy
	// Decide was given.
	ReasonListMismatch Reason = "list_mismatch"
	// ReasonInconsistent: Known contradicts its own definition. It holds
	// for a name that is new and not listed, or does not hold for a name
	// that is listed.
	ReasonInconsistent Reason = "facts_inconsistent"
	// ReasonNotKnown: Known does not hold for a name that is present at
	// the base commit and not listed.
	ReasonNotKnown Reason = "not_known"
	// ReasonNewNameUnread: a new, unlisted name that was not fully read.
	ReasonNewNameUnread Reason = "new_name_unread"
	// ReasonNewNameYoung: a new, unlisted name created less than
	// Policy.NewNameAge ago.
	ReasonNewNameYoung Reason = "new_name_young"
	// ReasonNameCreatedUnknown: a new, unlisted name whose creation time
	// is unknown.
	ReasonNameCreatedUnknown Reason = "name_created_unknown"
	// ReasonNotIncrease: the Increase fact is false or unknown.
	ReasonNotIncrease Reason = "not_increase"
	// ReasonNotBound: the Bound fact is false or unknown.
	ReasonNotBound Reason = "not_bound"
	// ReasonNotClean: the Clean fact is false or unknown.
	ReasonNotClean Reason = "not_clean"
	// ReasonRegress: the NoRegress fact is false or unknown.
	ReasonRegress Reason = "regress"
	// ReasonVeto: the model raised a veto.
	ReasonVeto Reason = "veto"
	// ReasonModelRefused: the model refused to answer.
	ReasonModelRefused Reason = "model_refused"
	// ReasonReadUnknown: Read is empty, not a known state, or
	// not-applicable outside Docker.
	ReasonReadUnknown Reason = "read_unknown"
	// ReasonMajorUnlisted: a major update of a name that is not listed.
	ReasonMajorUnlisted Reason = "major_unlisted"
	// ReasonFirstSeenUnknown: the FirstSeen fact is unknown.
	ReasonFirstSeenUnknown Reason = "first_seen_unknown"
)

// Reasons that come from waiting too long. Both are Person.
const (
	// ReasonReadDeadline: the model read was still missing at the wait
	// deadline.
	ReasonReadDeadline Reason = "read_deadline"
	// ReasonChecksDeadline: GitHub was still refusing the merge at the
	// wait deadline.
	ReasonChecksDeadline Reason = "checks_deadline"
)

// Reasons to wait. All are Wait.
const (
	// ReasonAge: the new version has not been public long enough.
	ReasonAge Reason = "age"
	// ReasonReadPending: the model read is missing and will be retried.
	ReasonReadPending Reason = "read_pending"
	// ReasonChecksPending: GitHub refused the merge because required
	// checks are pending or failing.
	ReasonChecksPending Reason = "checks_pending"
)

// The three ways out that several reasons share.
const (
	// byHand is the way out when nothing cheaper exists.
	byHand = "Look at the update and merge or close the pull request by hand."
	// listIt names the owner-kept list. The path is internal/config's
	// RepoFile; a test there keeps the two in step.
	listIt = "Merge by hand, or add the name or its publisher's prefix to \"listed\" in .github/dep-review.json on the default branch."
	// settings is where repository settings are changed. Where rulesets
	// and required checks are kept as code, a fix made by hand in the
	// web UI or with gh is undone by the next apply.
	settings = "Where repository settings are kept as code, change them there: a change made by hand in the web UI or with gh is undone by the next apply."
	// rerun is the way out when the gate could not read something.
	rerun = "Re-run the gate. If it says the same again, look at the update and merge or close the pull request by hand."
)

// reasonText is one row of the closed set.
type reasonText struct {
	reason  Reason
	outcome Outcome
	explain string
	hint    string
}

// reasonTable is the closed set, in the order Reasons returns it. A test
// checks that every Reason constant in this file has exactly one row.
var reasonTable = []reasonText{
	{ReasonPolicyInvalid, Person,
		"The gate's policy is not usable: an age is zero or negative, or the companion mode is unknown.",
		"Fix .github/dep-review.json on the default branch, or remove it to get the defaults."},
	{ReasonNoRule, Person,
		"This ecosystem has no rule, so nothing was read and nothing can be granted.",
		byHand},
	{ReasonNoUpdates, Person,
		"The base and head manifests show no dependency that changed.",
		byHand},
	{ReasonIdentity, Person,
		"The pull request could not be shown to be Dependabot's alone, on the default branch, at its current head.",
		"Look at who pushed to the branch, then merge or close by hand. If the ruleset that keeps dependabot/ branches to Dependabot is missing or does not match, fix it there: " + settings},
	{ReasonShape, Person,
		"The pull request changes something other than version or hash tokens in this ecosystem's manifest and lock files.",
		byHand},
	{ReasonChecksNotConfigured, Person,
		"The default branch has no required-status-checks rule, so nothing would stop a broken update from merging.",
		"Add a required-status-checks rule to the default branch's ruleset. " + settings},
	{ReasonFactMissing, Person,
		"A fact about this update was never gathered.",
		rerun},
	{ReasonListMismatch, Person,
		"The update was checked against a different list than the one the gate decides with (the list changed between the two steps).",
		rerun},
	{ReasonInconsistent, Person,
		"The facts about this update contradict each other.",
		rerun},
	{ReasonNotKnown, Person,
		"The name is not an established dependency of this repository and is not on the list.",
		listIt},
	{ReasonNewNameUnread, Person,
		"The update adds a dependency that is not on the list, and its code could not be read in full.",
		listIt},
	{ReasonNewNameYoung, Person,
		"The update adds a dependency that is not on the list, under a package name younger than the policy's new-name age.",
		listIt},
	{ReasonNameCreatedUnknown, Person,
		"The update adds a dependency that is not on the list, and the age of its package name could not be established.",
		listIt},
	{ReasonNotIncrease, Person,
		"The update is not a plain release moving to a higher plain release (a downgrade, a pre-release, a pseudo-version or an unreadable version).",
		byHand},
	{ReasonNotBound, Person,
		"The hash, commit or digest the pull request pins is not what the registry reports for that version now.",
		"Do not merge. Find out why the pin and the registry disagree; when the registry is right, ask Dependabot to recreate the pull request."},
	{ReasonNotClean, Person,
		"The new version is unpublished, retracted, yanked or deprecated, or has an advisory the old version did not have.",
		"Close the pull request, or wait for the next release; Dependabot opens a new pull request for it."},
	{ReasonRegress, Person,
		"The new version has a new or changed install script, lost its provenance, or (Actions) does not descend from the old commit.",
		byHand},
	{ReasonVeto, Person,
		"The model objected to code in this update. The quoted lines are in this comment.",
		"Read the quoted lines. Merge by hand if they are harmless, close the pull request if they are not."},
	{ReasonModelRefused, Person,
		"The model refused to read this update.",
		byHand},
	{ReasonReadUnknown, Person,
		"Whether the update's code was read is not recorded.",
		rerun},
	{ReasonMajorUnlisted, Person,
		"A major update of a name that is not on the list.",
		listIt},
	{ReasonFirstSeenUnknown, Person,
		"When the new version became public could not be established by a clock its publisher cannot set.",
		rerun},
	{ReasonReadDeadline, Person,
		"The model read was still missing when the wait deadline passed.",
		rerun},
	{ReasonChecksDeadline, Person,
		"The required checks were still pending or failing when the wait deadline passed.",
		"Fix the failing checks or close the pull request."},
	{ReasonAge, Wait,
		"The new version has not been public for long enough yet.",
		"Nothing to do: the gate looks again after the time shown. Merge by hand to have it sooner."},
	{ReasonReadPending, Wait,
		"The model read did not complete; it is retried at the next evaluation.",
		"Nothing to do: the gate retries until the deadline shown. Merge by hand to have it sooner."},
	{ReasonChecksPending, Wait,
		"GitHub refused the merge because required checks are pending or failing.",
		"Nothing to do while checks run. If a check failed, fix it or close the pull request."},
}

// Reasons returns the closed set, in a fixed order.
func Reasons() []Reason {
	out := make([]Reason, len(reasonTable))
	for i, row := range reasonTable {
		out[i] = row.reason
	}
	return out
}

// lookup finds r's row.
func (r Reason) lookup() (reasonText, bool) {
	for _, row := range reasonTable {
		if row.reason == r {
			return row, true
		}
	}
	return reasonText{}, false
}

// Outcome is the outcome this reason leads to: Wait or Person. A value
// outside the closed set is Person, like everything else unknown.
func (r Reason) Outcome() Outcome {
	if row, ok := r.lookup(); ok {
		return row.outcome
	}
	return Person
}

// Explain is one line for the pull request comment saying what is wrong.
// Empty for a value outside the closed set.
func (r Reason) Explain() string {
	row, _ := r.lookup()
	return row.explain
}

// Hint is the cheapest way out, for the pull request comment. Empty for a
// value outside the closed set.
func (r Reason) Hint() string {
	row, _ := r.lookup()
	return row.hint
}

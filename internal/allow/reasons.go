package allow

// Reason is one way for a pull request to be Wait or Person. The set is
// closed: Decide and ChecksRefused return nothing else, and nothing a
// dependency, a pull request or the model wrote ever becomes a Reason.
// What each one means is its row of reasonTable; a comment here says only
// what that row does not.
type Reason string

// Reasons that concern the pull request as a whole. All are Person.
const (
	ReasonPolicyInvalid       Reason = "policy_invalid"
	ReasonNoRule              Reason = "no_rule"
	ReasonNoUpdates           Reason = "no_updates"
	ReasonIdentity            Reason = "identity"
	ReasonShape               Reason = "shape"
	ReasonChecksNotConfigured Reason = "checks_not_configured"
)

// Reasons that concern one update. All are Person. Each fact that must
// hold has a reason for a gathered "no" (not_increase, not_bound,
// not_clean, regress).
const (
	// ReasonFactMissing: a fact the decision needs has no source, one of
	// the pull request's own three included, or the update has no name or
	// target version. This is the gate not knowing, not the gate having
	// found something: a source that did not answer is
	// ReasonSourceUnavailable.
	ReasonFactMissing Reason = "fact_missing"
	// ReasonListMismatch: the Listed fact disagrees with the policy Decide
	// was given.
	ReasonListMismatch Reason = "list_mismatch"
	// ReasonInconsistent: Known contradicts its own definition. It holds
	// for a name that is new and not listed, or does not hold for a name
	// that is listed.
	ReasonInconsistent Reason = "facts_inconsistent"
	// ReasonNotKnown: a name that is present at the base commit, is not
	// listed, and is not known or is an image.
	ReasonNotKnown           Reason = "not_known"
	ReasonNewNameUnread      Reason = "new_name_unread"
	ReasonNewNameYoung       Reason = "new_name_young"
	ReasonNameCreatedUnknown Reason = "name_created_unknown"
	ReasonNotIncrease        Reason = "not_increase"
	ReasonNotBound           Reason = "not_bound"
	ReasonNotClean           Reason = "not_clean"
	ReasonRegress            Reason = "regress"
	ReasonVeto               Reason = "veto"
	ReasonModelRefused       Reason = "model_refused"
	// ReasonReadUnknown: Read is empty, not a known state, not-applicable
	// for anything but an image or an own workflow, or anything else for
	// an own workflow.
	ReasonReadUnknown   Reason = "read_unknown"
	ReasonReadRefused   Reason = "read_refused"
	ReasonMajorUnlisted Reason = "major_unlisted"
	// ReasonMajorOwn: a major update of an own workflow, whatever the
	// list says of its name.
	ReasonMajorOwn         Reason = "major_own"
	ReasonFirstSeenUnknown Reason = "first_seen_unknown"
)

// A reason that concerns the gate's own memory of the pull request. It is
// Person (VetoesForgotten).
const (
	ReasonVetoesForgotten Reason = "vetoes_forgotten"
)

// Reasons that come from waiting too long. All are Person.
const (
	ReasonReadDeadline        Reason = "read_deadline"
	ReasonSourceDeadline      Reason = "source_deadline"
	ReasonSupersededDeadline  Reason = "superseded_deadline"
	ReasonChecksDeadline      Reason = "checks_deadline"
	ReasonScriptsOffDeadline  Reason = "scripts_off_deadline"
	ReasonBaseChangedDeadline Reason = "base_changed_deadline"
)

// Reasons to wait. All are Wait.
const (
	ReasonAge               Reason = "age"
	ReasonReadPending       Reason = "read_pending"
	ReasonSourceUnavailable Reason = "source_unavailable"
	ReasonSuperseded        Reason = "superseded"
	ReasonChecksPending     Reason = "checks_pending"
	// ReasonScriptsOffChanged: publish did not ask GitHub to merge,
	// because the default branch's root .npmrc is no longer the file the
	// facts rest on (ScriptsOffChanged).
	ReasonScriptsOffChanged Reason = "scripts_off_changed"
	// ReasonBaseChanged: publish did not ask GitHub to merge, because the
	// default branch has changed a file the pull request changes since the
	// commit it branches from (BaseChanged).
	ReasonBaseChanged Reason = "base_changed"
)

// The ways out that several reasons share.
const (
	// byHand is the way out when nothing cheaper exists.
	byHand = "Look at the update and merge or close the pull request by hand."
	// listIt names the owner-kept list. It is the gate's own: the path is
	// internal/config's embedded file, and a test there keeps the two in
	// step. An entry works in a repository once that repository's pin of
	// the gate has moved to a release that has it, so by hand comes first.
	listIt = "Merge by hand. If this publisher should always pass, add the name or its prefix to \"listed\" in internal/config/policy/defaults.json in the gate's repository, and move this repository's pin to the release that has it."
	// settings is where repository settings are changed. Where rulesets
	// and required checks are kept as code, a fix made by hand in the
	// web UI or with gh is undone by the next apply.
	settings = "Where repository settings are kept as code, change them there: a change made by hand in the web UI or with gh is undone by the next apply."
	// rerun is the way out when the gate does not know something. It says
	// nothing against the update, on purpose: these reasons are the gate
	// failing to find out, not the gate finding a fault. All jobs: one
	// that is run again by itself gets the facts of the first attempt.
	rerun = "Re-run all jobs of the gate's workflow run. If it says the same again, look at the update and merge or close the pull request by hand."
	// sooner ends the hint of a wait that needs nobody.
	sooner = " Merge by hand to have it sooner."
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
//
// The words matter as much as the outcome. A reason for something the
// gate found (not_bound, not_clean, regress, veto) may tell the owner not
// to merge. A reason for something the gate could not find out
// (fact_missing, source_unavailable, source_deadline, read_pending) must
// not: an unreachable registry is not a bad pin, and a test keeps the two
// kinds of wording apart.
var reasonTable = []reasonText{
	{ReasonPolicyInvalid, Person,
		"The gate's policy is not usable: an age is zero or negative, or the companion mode is unknown.",
		"The policy is built into the gate, so this is a fault in the gate and not in the pull request. Look at the update and merge or close the pull request by hand."},
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
		"The pull request changes something other than version or hash tokens in this ecosystem's manifest and lock files, or changes a line the gate never grants (a reusable workflow of a repository that is not one of the gate owner's own).",
		byHand},
	{ReasonChecksNotConfigured, Person,
		"The default branch has no required-status-checks rule, so nothing would stop a broken update from merging.",
		"Add a required-status-checks rule to the default branch's ruleset. " + settings},
	{ReasonFactMissing, Person,
		"A fact the decision needs was never established: nothing gathered it, or the answer that came back could not be read. Nothing was found wrong with the update.",
		rerun},
	{ReasonListMismatch, Person,
		"The update was checked against a different list than the one the gate decides with.",
		rerun},
	{ReasonInconsistent, Person,
		"The facts about this update contradict each other.",
		rerun},
	{ReasonNotKnown, Person,
		"The name is not an established dependency of this repository and is not on the list. (An image must be on the list: being in a Dockerfile already is not enough.)",
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
		"The update does not move to a higher plain release: it is a downgrade, moves to a pre-release or to a version that cannot be read, or moves to a pseudo-version (which only a listed Go module may, and only upwards).",
		byHand},
	{ReasonNotBound, Person,
		"The registry answered, and the hash, commit or digest the pull request pins is not what it reports for that version now.",
		"Do not merge. Find out why the two disagree; when the registry is right, ask Dependabot to recreate the pull request."},
	{ReasonNotClean, Person,
		"The registry or the advisory database says something against the new version: it is unpublished, retracted, yanked or deprecated, or has an advisory the old version did not have.",
		"Do not merge this version. Close the pull request, or wait for the next release; Dependabot opens a new pull request for it. For a deprecated package or image, move to its successor."},
	{ReasonRegress, Person,
		"The new version has a new or changed install script, lost its provenance, or (Actions) does not descend from the old commit.",
		byHand},
	{ReasonVeto, Person,
		"The model objected to code in this update.",
		"Read the lines it quoted, in the update's table. Merge by hand if they are harmless, close the pull request if they are not. The gate does not take a veto back: it stands for this same code when the gate runs again or the pull request is rebased, whatever the model answers then."},
	{ReasonModelRefused, Person,
		"The model refused to read this update.",
		byHand},
	{ReasonReadUnknown, Person,
		"Whether the update's code was read is not recorded.",
		rerun},
	{ReasonReadRefused, Person,
		"The gate would not read this update's code: what it downloaded did not match the hash the pull request pins, the archive was unsafe to unpack, the action runs a container image or is not shown to run its repository's own files, a file that changed has a name the gate does not show a model, nothing that changed is text a model can be shown, or the prepared text was not usable.",
		"Do not merge without knowing why. Re-running gives the same answer while the registry serves the same bytes; look at the update by hand."},
	{ReasonMajorUnlisted, Person,
		"A major update of a name that is not on the list, and that the repository's own manifest does not show to be a dependency of a dependency.",
		listIt},
	{ReasonMajorOwn, Person,
		"A major update of one of the gate owner's own workflows. Nothing of it was read and the pull request does not run the new version: a major is how its owner says that the callers may have to change with it.",
		byHand},
	{ReasonFirstSeenUnknown, Person,
		"When the new version became public could not be established by a clock its publisher cannot set.",
		rerun},
	{ReasonVetoesForgotten, Person,
		"The gate recorded more vetoes on this pull request than its comment can remember, and gave some of them up. A veto it does not remember would be asked about again, so this pull request needs a person from now on, whatever later runs find.",
		"Look at the vetoes in this and earlier comments, then merge or close the pull request by hand."},
	{ReasonReadDeadline, Person,
		"The update's code had still not been read when the wait deadline passed.",
		rerun},
	{ReasonSourceDeadline, Person,
		"A source the gate depends on (a registry, an index or an API) had still not answered when the wait deadline passed. Nothing was found wrong with the update.",
		rerun},
	{ReasonSupersededDeadline, Person,
		"The registry serves a newer image under the pinned tag, and the pull request had not been refreshed when the wait deadline passed.",
		"Ask Dependabot to recreate the pull request, or close it."},
	{ReasonChecksDeadline, Person,
		"The required checks were still pending or failing when the wait deadline passed.",
		"Fix the failing checks or close the pull request."},
	{ReasonScriptsOffDeadline, Person,
		"The default branch's root .npmrc was still not the file that turns install scripts off, which this pull request's facts rest on, when the wait deadline passed. The update's install scripts and build files were not compared.",
		"Ask Dependabot to rebase the pull request, so that the new head is evaluated on its own, or compare the update's install scripts by hand and merge or close the pull request."},
	{ReasonBaseChangedDeadline, Person,
		"The default branch had changed a file this pull request changes, since the commit the pull request branches from, and the pull request had not been rebuilt when the wait deadline passed. Every other fact held, and the gate did not ask GitHub to merge: the facts are about the head on the base it had.",
		"Ask Dependabot to rebase the pull request, so that the new head is evaluated on its own, or look at what the merge would give and merge by hand."},
	{ReasonAge, Wait,
		"The new version has not been public for long enough yet.",
		"Nothing to do: the gate looks again after the time shown." + sooner},
	{ReasonReadPending, Wait,
		"The update's code has not been read yet: fetching it or the model call did not complete.",
		"Nothing to do: the gate retries until the deadline shown." + sooner},
	{ReasonSourceUnavailable, Wait,
		"A source the gate depends on (a registry, an index or an API) was asked and did not answer, so a fact is not known yet. Nothing was found wrong with the update.",
		"Nothing to do: the gate asks again at its next evaluation, until the deadline shown." + sooner},
	{ReasonSuperseded, Wait,
		"The registry serves a newer image under the pinned tag, so the pinned digest is no longer the current one.",
		"Nothing to do: Dependabot refreshes the digest on its next run, and the gate then looks at the new one."},
	{ReasonChecksPending, Wait,
		"GitHub refused the merge because required checks are pending or failing.",
		"Nothing to do while checks run. If a check failed, fix it or close the pull request."},
	{ReasonScriptsOffChanged, Wait,
		"The default branch's root .npmrc is no longer the file that turns install scripts off. This pull request's facts rest on that file as it was at the commit the pull request records, so the update's install scripts and build files were not compared, and the gate did not ask GitHub to merge.",
		"Once Dependabot rebuilds the pull request (ask it to rebase if it does not), the new head is evaluated on its own, with its install inputs compared. If the file is put back, this head merges at the next run."},
	{ReasonBaseChanged, Wait,
		"The default branch has changed a file this pull request changes, since the commit the pull request branches from, so the gate did not ask GitHub to merge: the facts are about the head on the base it had, and a merge now would put it on another.",
		"Dependabot rebuilds most such pull requests by itself, and the new head is evaluated on its own. If it has not, ask Dependabot to rebase the pull request, or merge by hand."},
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

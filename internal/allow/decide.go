package allow

import (
	"strings"
	"time"
)

// Listed reports whether name matches the policy's list for ecosystem.
//
// An entry that ends in "/" is a namespace: it matches every name that
// starts with it ("golang.org/x/" matches "golang.org/x/net",
// "@tailwindcss/" matches "@tailwindcss/oxide", "actions/" matches
// "actions/checkout"). Any other entry is a name: it matches that exact
// name and everything below it at a "/" boundary ("cloud.google.com/go"
// matches itself and "cloud.google.com/go/storage", never
// "cloud.google.com/gopher"; "tailwindcss" never matches
// "tailwindcss-extra"). Matching is byte for byte and case-sensitive, with
// no wildcards: a name that differs only in case is not listed.
func Listed(p Policy, ecosystem, name string) bool {
	if name == "" {
		return false
	}
	for _, entry := range p.Listed[ecosystem] {
		if entryMatches(entry, name) {
			return true
		}
	}
	return false
}

// entryMatches is the rule for one list entry (see Listed).
func entryMatches(entry, name string) bool {
	// An empty entry or one that starts at a boundary would be a prefix
	// of names it was never meant for. internal/config rejects both; this
	// is the same answer for a Policy built by hand.
	if entry == "" || strings.HasPrefix(entry, "/") {
		return false
	}
	if strings.HasSuffix(entry, "/") {
		return len(name) > len(entry) && strings.HasPrefix(name, entry)
	}
	return name == entry || strings.HasPrefix(name, entry+"/")
}

// Decide answers what to do with a pull request (docs/v0.2-spec.md,
// section 4). It is a pure function: it reads nothing but its arguments
// and changes none of them.
//
// Every reason for Person is collected before anything can be Wait, so a
// missing model read or a young version never hides a failed fact.
func Decide(f PRFacts, p Policy, now time.Time) Decision {
	var person []Reason
	if !policyUsable(p) {
		person = append(person, ReasonPolicyInvalid)
	}
	if !HasRule(f.Ecosystem) {
		person = append(person, ReasonNoRule)
	}
	if !f.Identity.Holds() {
		person = append(person, ReasonIdentity)
	}
	if !f.Shape.Holds() {
		person = append(person, ReasonShape)
	}
	if !f.ChecksConfigured.Holds() {
		person = append(person, ReasonChecksNotConfigured)
	}
	if len(f.Updates) == 0 {
		person = append(person, ReasonNoUpdates)
	}

	rideAlong := carriesFastPathUpdate(f.Updates, p)

	d := Decision{PerUpdate: make([]UpdateDecision, 0, len(f.Updates))}
	var waiting []Reason
	var latest time.Time
	for _, u := range f.Updates {
		ud := decideUpdate(u, f.Ecosystem, p, now, rideAlong)
		d.PerUpdate = append(d.PerUpdate, ud)
		switch ud.Outcome {
		case Person:
			person = appendNew(person, ud.Reasons...)
		case Wait:
			waiting = appendNew(waiting, ud.Reasons...)
		}
		if ud.NotBefore.After(latest) {
			latest = ud.NotBefore
		}
	}

	if len(person) > 0 {
		d.Outcome = Person
		d.Reasons = person
		return d
	}

	// The deadline runs from the latest required time. A pull request
	// opened long after its versions were published would otherwise be
	// past its deadline before the gate first saw it, so it never starts
	// before the pull request existed. An unknown Opened is the zero
	// time, which leaves the latest required time alone.
	start := latest
	if f.Opened.After(start) {
		start = f.Opened
	}
	d.NotBefore = latest
	d.Deadline = start.Add(p.WaitDeadline)

	if len(waiting) > 0 {
		// The deadline is after every update's NotBefore, so nothing is
		// still waiting for its age here: what is left is a model read
		// that never completed.
		if !now.Before(d.Deadline) {
			d.Outcome = Person
			d.Reasons = []Reason{ReasonReadDeadline}
			d.NotBefore = time.Time{}
			d.Deadline = time.Time{}
			return d
		}
		d.Outcome = Wait
		d.Reasons = waiting
		return d
	}

	d.Outcome = Merge
	return d
}

// ChecksRefused is the decision after GitHub refused to merge a pull
// request that Decide allowed, because required checks are pending or
// failing. The gate does not judge CI itself: publish calls the merge API
// with the head commit, and when GitHub says no, this turns the Merge
// into Wait, or into Person once the deadline has passed. A decision that
// is not Merge is returned unchanged. Pure, like Decide.
func ChecksRefused(d Decision, now time.Time) Decision {
	if d.Outcome != Merge {
		return d
	}
	out := d
	out.PerUpdate = append([]UpdateDecision(nil), d.PerUpdate...)
	if !now.Before(d.Deadline) {
		out.Outcome = Person
		out.Reasons = []Reason{ReasonChecksDeadline}
		out.NotBefore = time.Time{}
		out.Deadline = time.Time{}
		return out
	}
	out.Outcome = Wait
	out.Reasons = []Reason{ReasonChecksPending}
	return out
}

// decideUpdate answers for one update. rideAlong says the pull request
// carries a fast-path security fix and the policy lets companions ride
// along.
func decideUpdate(u UpdateFacts, ecosystem string, p Policy, now time.Time, rideAlong bool) UpdateDecision {
	ud := UpdateDecision{Name: u.Name, From: u.From, To: u.To}
	var person []Reason

	// The yes/no facts have no safe default (an ungathered Major read as
	// "not a major" would grant something), so each must have been
	// gathered. Below they are read only as gathered answers.
	if u.Name == "" || u.To == "" || !u.Known.Gathered() || !u.Listed.Gathered() ||
		!u.NewName.Gathered() || !u.Major.Gathered() || !u.SecurityFix.Gathered() {
		person = append(person, ReasonFactMissing)
	}
	listed := u.Listed.Holds()
	newName := u.NewName.Holds()
	major := u.Major.Holds()

	// The list is the owner's, and the policy handed to Decide is the
	// authority for it. A gatherer that ran with another list (the file
	// changed between the jobs) does not get to grant with it.
	if u.Listed.Gathered() && listed != Listed(p, ecosystem, u.Name) {
		person = append(person, ReasonListMismatch)
	}

	switch {
	case !u.Known.Gathered():
		// Counted as missing above.
	case u.Known.Holds():
		if newName && !listed {
			person = append(person, ReasonInconsistent)
		}
	case newName && !listed:
		// The new-name rule: an unlisted new name is allowed only when it
		// was fully read, did not regress (checked below, for every
		// update) and its name is old enough. A read that is still
		// missing is not a refusal: it is retried like any other.
		if !u.NameCreated.Known() {
			person = append(person, ReasonNameCreatedUnknown)
		} else if now.Sub(u.NameCreated.Time) < p.NewNameAge {
			person = append(person, ReasonNewNameYoung)
		}
		if u.Read == ReadPartial || u.Read == ReadNotApplicable {
			person = append(person, ReasonNewNameUnread)
		}
	case listed:
		// A listed name is known by definition. Telling the owner to list
		// it would send them to an entry that is already there.
		person = append(person, ReasonInconsistent)
	default:
		// Present at the base commit, and the gatherer still says it is
		// not known: its ecosystem asks for more than presence.
		person = append(person, ReasonNotKnown)
	}

	if !u.Increase.Holds() {
		person = append(person, ReasonNotIncrease)
	}
	if !u.Bound.Holds() {
		person = append(person, ReasonNotBound)
	}
	if !u.Clean.Holds() {
		person = append(person, ReasonNotClean)
	}
	if !u.NoRegress.Holds() {
		person = append(person, ReasonRegress)
	}
	if u.Veto != nil {
		if u.Veto.Category == VetoModelRefused {
			person = append(person, ReasonModelRefused)
		} else {
			person = append(person, ReasonVeto)
		}
	}
	if !readValid(u.Read, ecosystem) {
		person = append(person, ReasonReadUnknown)
	}
	if major && !listed {
		person = append(person, ReasonMajorUnlisted)
	}
	if !u.FirstSeen.Known() {
		person = append(person, ReasonFirstSeenUnknown)
	}

	if len(person) > 0 {
		ud.Outcome = Person
		ud.Reasons = person
		return ud
	}

	// The age table. A new name has no old version an advisory could
	// affect, so it never takes the fast path.
	securityFix := p.FastPath && u.SecurityFix.Holds() && !newName
	var age time.Duration
	switch u.Read {
	case ReadFull, ReadNone:
		// For a missing read this is the age a full read would need: the
		// earliest the update could merge once the retry succeeds.
		age = p.MinAge
		if securityFix {
			age = 0
		}
		if rideAlong && u.Read == ReadFull && companion(u) {
			age = 0
		}
	case ReadPartial:
		// A partial read must never need less than a full one, also when
		// a repository raised MinAge above UnreadAge.
		age = longer(p.UnreadAge, p.MinAge)
		if securityFix {
			age = p.MinAge
		}
	case ReadNotApplicable:
		age = p.MinAge
	}
	if major {
		age = longer(age, p.MajorAge)
	}

	ud.RequiredAge = age
	ud.NotBefore = u.FirstSeen.Time.Add(age)
	if u.Read == ReadNone {
		ud.Outcome = Wait
		ud.Reasons = append(ud.Reasons, ReasonReadPending)
	}
	if now.Before(ud.NotBefore) {
		ud.Outcome = Wait
		ud.Reasons = append(ud.Reasons, ReasonAge)
	}
	if ud.Outcome == "" {
		ud.Outcome = Merge
	}
	return ud
}

// carriesFastPathUpdate reports whether companions may ride along: the
// policy says so and the pull request contains a security fix that was
// fully read.
func carriesFastPathUpdate(us []UpdateFacts, p Policy) bool {
	if !p.FastPath || p.Companions != RideAlong {
		return false
	}
	for _, u := range us {
		if u.SecurityFix.Holds() && !u.NewName.Holds() && u.Read == ReadFull {
			return true
		}
	}
	return false
}

// companion reports whether an update may ride along with a security fix
// in the same pull request: known, not a new name, not a major. The
// caller checks that it was fully read.
func companion(u UpdateFacts) bool {
	return u.Known.Holds() && !u.NewName.Holds() && !u.Major.Holds()
}

// readValid reports whether r is a read state Decide can reason about in
// this ecosystem. "Nothing to read" is true of Docker only; anywhere else
// it would be a way to skip the read.
func readValid(r ReadState, ecosystem string) bool {
	switch r {
	case ReadFull, ReadPartial, ReadNone:
		return true
	case ReadNotApplicable:
		return ecosystem == Docker
	}
	return false
}

// policyUsable reports whether Decide can use p. A zero or negative age
// would turn "wait" into "merge now", so it is refused, not clamped.
func policyUsable(p Policy) bool {
	if p.MinAge <= 0 || p.UnreadAge <= 0 || p.MajorAge <= 0 || p.NewNameAge <= 0 || p.WaitDeadline <= 0 {
		return false
	}
	return p.Companions == RideAlong || p.Companions == CompanionsWait
}

// longer returns the longer of two durations.
func longer(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// appendNew appends each reason that is not in the list yet.
func appendNew(list []Reason, more ...Reason) []Reason {
	for _, r := range more {
		seen := false
		for _, have := range list {
			if have == r {
				seen = true
				break
			}
		}
		if !seen {
			list = append(list, r)
		}
	}
	return list
}

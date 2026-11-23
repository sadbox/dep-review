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
// section 4 and the amendments of section 11). It is a pure function: it
// reads nothing but its arguments and changes none of them.
//
// Every reason for Person is collected before anything can be Wait, so a
// missing model read, a young version or a source that did not answer
// never hides a failed fact. Only a fact that holds contributes to Merge:
// one that is false or was never gathered is Person, and one that is
// unavailable is Wait until the deadline and Person after it.
func Decide(f PRFacts, p Policy, now time.Time) Decision {
	var person []Reason
	if !policyUsable(p) {
		person = append(person, ReasonPolicyInvalid)
	}
	if !HasRule(f.Ecosystem) {
		person = append(person, ReasonNoRule)
	}
	asking := false // a source did not answer
	for _, need := range []struct {
		fact Fact
		no   Reason
	}{
		{f.Identity, ReasonIdentity},
		{f.Shape, ReasonShape},
		{f.ChecksConfigured, ReasonChecksNotConfigured},
	} {
		switch stateOf(need.fact) {
		case factNo:
			person = append(person, need.no)
		case factMissing:
			person = appendNew(person, ReasonFactMissing)
		case factUnavailable:
			asking = true
		}
	}
	if len(f.Updates) == 0 {
		person = append(person, ReasonNoUpdates)
	}

	rideAlong := carriesFastPathUpdate(f.Updates, p, false)
	rideAlongIfRead := carriesFastPathUpdate(f.Updates, p, true)

	d := Decision{PerUpdate: make([]UpdateDecision, 0, len(f.Updates))}
	var waiting []Reason
	if asking {
		waiting = append(waiting, ReasonSourceUnavailable)
	}
	// latest is the latest required time. earliest is what it would be
	// had every update been read in full.
	var latest, earliest time.Time
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
		if u.FirstSeen.Known() {
			if t := u.FirstSeen.Time.Add(requiredAge(u, ReadFull, p, rideAlongIfRead)); t.After(earliest) {
				earliest = t
			}
		}
	}

	if len(person) > 0 {
		d.Outcome = Person
		d.Reasons = person
		return d
	}

	// What is being retried, as the reasons it has when it never comes:
	// a model read, a source's answer, Dependabot's refresh of a
	// superseded pin. Waiting for an age is not a retry and has no
	// deadline: when the age is reached the pull request merges.
	var gaveUp []Reason
	for _, w := range waiting {
		switch w {
		case ReasonReadPending:
			gaveUp = append(gaveUp, ReasonReadDeadline)
		case ReasonSourceUnavailable:
			gaveUp = append(gaveUp, ReasonSourceDeadline)
		case ReasonSuperseded:
			gaveUp = append(gaveUp, ReasonSupersededDeadline)
		}
	}

	// The deadline runs from the latest required time. While something is
	// being retried that is the time a full read would give: a partial
	// read needs a longer age, and what the model returned must not buy a
	// failing retry more time (invariant 1). A pull request opened long
	// after its versions were published would otherwise be past its
	// deadline before the gate first saw it, so the deadline never starts
	// before the pull request existed. An unknown Opened is the zero
	// time, which leaves the latest required time alone.
	start := latest
	if len(gaveUp) > 0 {
		start = earliest
	}
	if f.Opened.After(start) {
		start = f.Opened
	}
	d.NotBefore = latest
	d.Deadline = start.Add(p.WaitDeadline)

	switch {
	case len(gaveUp) > 0 && !now.Before(d.Deadline):
		d.Outcome = Person
		d.Reasons = gaveUp
		d.NotBefore = time.Time{}
		d.Deadline = time.Time{}
	case len(waiting) > 0:
		d.Outcome = Wait
		d.Reasons = waiting
	default:
		d.Outcome = Merge
	}
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
	asking := false // a source did not answer

	if u.Name == "" || u.To == "" {
		person = append(person, ReasonFactMissing)
	}

	// The yes/no facts have no safe default (an ungathered Major read as
	// "not a major" would grant something), so each must have an answer.
	known, listed, newName, major := stateOf(u.Known), stateOf(u.Listed), stateOf(u.NewName), stateOf(u.Major)
	for _, s := range []factState{known, listed, newName, major, stateOf(u.SecurityFix)} {
		switch s {
		case factMissing:
			person = appendNew(person, ReasonFactMissing)
		case factUnavailable:
			asking = true
		}
	}
	// A rule that reads several answers is applied only when all of them
	// arrived. With one unavailable the update waits, and the rule is
	// applied at the evaluation that has the answer.
	answered := func(states ...factState) bool {
		for _, s := range states {
			if s != factYes && s != factNo {
				return false
			}
		}
		return true
	}

	// The list is the owner's, and the policy handed to Decide is the
	// authority for it. A gatherer that ran with another list (the file
	// changed between the jobs) does not get to grant with it.
	if answered(listed) && (listed == factYes) != Listed(p, ecosystem, u.Name) {
		person = append(person, ReasonListMismatch)
	}

	if answered(known, listed, newName) {
		switch {
		case known == factYes:
			if newName == factYes && listed == factNo {
				person = append(person, ReasonInconsistent)
			}
		case newName == factYes && listed == factNo:
			// The new-name rule: an unlisted new name is allowed only when it
			// was fully read, did not regress (checked below, for every
			// update) and its name is old enough. A read that is still
			// missing is not a refusal: it is retried like any other.
			switch {
			case u.NameCreated.Known():
				if now.Sub(u.NameCreated.Time) < p.NewNameAge {
					person = append(person, ReasonNewNameYoung)
				}
			case u.NameCreated.unavailable():
				asking = true
			default:
				person = append(person, ReasonNameCreatedUnknown)
			}
			if u.Read == ReadPartial || u.Read == ReadNotApplicable {
				person = append(person, ReasonNewNameUnread)
			}
		case listed == factYes:
			// A listed name is known by definition. Telling the owner to list
			// it would send them to an entry that is already there.
			person = append(person, ReasonInconsistent)
		default:
			// Present at the base commit, and the gatherer still says it is
			// not known: its ecosystem asks for more than presence (Docker).
			person = append(person, ReasonNotKnown)
		}
	}

	// The facts that must hold. Each can fail in three ways, and they are
	// kept apart: a gathered "no" is the fact's own reason, a fact nobody
	// gathered is the gate not knowing, and an unavailable one is a wait.
	hold := func(f Fact, no Reason) {
		switch stateOf(f) {
		case factNo:
			person = append(person, no)
		case factMissing:
			person = appendNew(person, ReasonFactMissing)
		case factUnavailable:
			asking = true
		}
	}
	// A superseded pin is about to be replaced by Dependabot. What the
	// registry says about it now (not the tag's digest, so not bound, not
	// served, no date) is true and beside the point, so those three facts
	// are not looked at and the update waits. Everything else about the
	// update is still checked: a refresh would not change it.
	superseded := ecosystem == Docker && u.Superseded.Holds()
	if stateOf(u.Superseded) == factUnavailable {
		asking = true
	}
	hold(u.Increase, ReasonNotIncrease)
	if !superseded {
		hold(u.Bound, ReasonNotBound)
		hold(u.Clean, ReasonNotClean)
	}
	hold(u.NoRegress, ReasonRegress)
	if u.Veto != nil {
		if u.Veto.Category == VetoModelRefused {
			person = append(person, ReasonModelRefused)
		} else {
			person = append(person, ReasonVeto)
		}
	}
	switch {
	case u.Read == ReadRefused:
		person = append(person, ReasonReadRefused)
	case !readValid(u.Read, ecosystem):
		person = append(person, ReasonReadUnknown)
	}
	if major == factYes && listed == factNo {
		person = append(person, ReasonMajorUnlisted)
	}
	if !superseded && !u.FirstSeen.Known() {
		if u.FirstSeen.unavailable() {
			asking = true
		} else {
			person = append(person, ReasonFirstSeenUnknown)
		}
	}

	if len(person) > 0 {
		ud.Outcome = Person
		ud.Reasons = person
		return ud
	}

	ud.RequiredAge = requiredAge(u, u.Read, p, rideAlong)
	if u.FirstSeen.Known() {
		ud.NotBefore = u.FirstSeen.Time.Add(ud.RequiredAge)
	}
	if superseded {
		ud.Reasons = append(ud.Reasons, ReasonSuperseded)
	}
	if asking {
		ud.Reasons = append(ud.Reasons, ReasonSourceUnavailable)
	}
	if u.Read == ReadNone {
		ud.Reasons = append(ud.Reasons, ReasonReadPending)
	}
	if u.FirstSeen.Known() && now.Before(ud.NotBefore) {
		ud.Reasons = append(ud.Reasons, ReasonAge)
	}
	ud.Outcome = Wait
	if len(ud.Reasons) == 0 {
		ud.Outcome = Merge
	}
	return ud
}

// requiredAge is the age table of spec section 4 for one update whose
// read state is read: how long its new version must have been public.
//
// A new name has no old version an advisory could affect, so it never
// takes the fast path. An answer that has not arrived reads as "no"
// here, which is safe: such an update waits whatever its age, and the age
// is worked out again once the source has answered.
func requiredAge(u UpdateFacts, read ReadState, p Policy, rideAlong bool) time.Duration {
	securityFix := p.FastPath && u.SecurityFix.Holds() && !u.NewName.Holds()
	var age time.Duration
	switch read {
	case ReadFull, ReadNone:
		// For a missing read this is the age a full read would need: the
		// earliest the update could merge once the retry succeeds.
		age = p.MinAge
		if securityFix {
			age = 0
		}
		if rideAlong && read == ReadFull && companion(u) {
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
	if u.Major.Holds() {
		age = longer(age, p.MajorAge)
	}
	return age
}

// carriesFastPathUpdate reports whether companions may ride along: the
// policy says so and the pull request contains a security fix that was
// fully read. With ifRead it answers as if every update had been read in
// full.
func carriesFastPathUpdate(us []UpdateFacts, p Policy, ifRead bool) bool {
	if !p.FastPath || p.Companions != RideAlong {
		return false
	}
	for _, u := range us {
		if u.SecurityFix.Holds() && !u.NewName.Holds() && (ifRead || u.Read == ReadFull) {
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

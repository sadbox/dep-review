package allow

import (
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand/v2"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// t0 is "now" in these tests.
var t0 = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

const (
	hour = time.Hour
	day  = 24 * time.Hour
)

// Names the test policy does and does not list.
const (
	unlistedName = "github.com/kr/text"
	listedName   = "golang.org/x/net"
)

// testPolicy is the spec's section 5 defaults, written out here so this
// package's tests depend on nothing but this package.
func testPolicy() Policy {
	return Policy{
		MinAge:       72 * hour,
		UnreadAge:    14 * day,
		MajorAge:     14 * day,
		NewNameAge:   365 * day,
		WaitDeadline: 7 * day,
		FastPath:     true,
		Companions:   RideAlong,
		Listed: map[string][]string{
			GoModules: {"golang.org/x/", "google.golang.org/", "cloud.google.com/go",
				"github.com/aws/", "github.com/Azure/", "github.com/AzureAD/",
				"github.com/microsoft/", "github.com/microsoftgraph/",
				"go.opentelemetry.io/"},
			GitHubActions: {"actions/", "github/", "docker/", "astral-sh/"},
			Docker:        {"docker.io/library/", "gcr.io/distroless/"},
			NPM:           {"tailwindcss", "@tailwindcss/"},
		},
	}
}

// update is an established, unlisted, fully read minor update whose new
// version has been public for age.
func update(age time.Duration, mods ...func(*UpdateFacts)) UpdateFacts {
	u := UpdateFacts{
		Name:        unlistedName,
		From:        "v1.2.3",
		To:          "v1.3.0",
		Known:       Yes("in go.mod at the base commit", "base go.mod"),
		Listed:      No("matches no list entry", "policy"),
		NewName:     No("in go.mod at the base commit", "base go.mod"),
		Increase:    Yes("v1.2.3 to v1.3.0", "x/mod/semver"),
		Major:       No("v1 to v1", "x/mod/semver"),
		Bound:       Yes("h1:abc", "go mod download"),
		FirstSeen:   At(t0.Add(-age), "index.golang.org"),
		Clean:       Yes("published, nothing new against it", "advisories"),
		NoRegress:   Yes("nothing to lose", "gate"),
		SecurityFix: No("no advisory names v1.3.0", "advisories"),
		Read:        ReadFull,
	}
	for _, mod := range mods {
		mod(&u)
	}
	return u
}

func listed(u *UpdateFacts) {
	u.Name = listedName
	u.Listed = Yes("golang.org/x/", "policy")
}

func major(u *UpdateFacts) {
	u.From, u.To = "v1.9.0", "v2.0.0"
	u.Major = Yes("v1 to v2", "x/mod/semver")
}

// indirect makes the update one the repository does not declare itself.
func indirect(u *UpdateFacts) {
	u.Indirect = Yes("the require line is marked // indirect", "go.mod at base and head")
}

func securityFix(u *UpdateFacts) {
	u.SecurityFix = Yes("GHSA-xxxx-xxxx-xxxx: first patched v1.3.0", "advisories")
}

func read(s ReadState) func(*UpdateFacts) {
	return func(u *UpdateFacts) { u.Read = s }
}

// image makes the update an image on the list: no other image is known
// (spec section 11, amendment 3).
func image(u *UpdateFacts) {
	u.Name = "docker.io/library/golang"
	u.Listed = Yes("docker.io/library/", "policy")
}

// updateIn is update for an ecosystem: for Docker, of a listed image.
func updateIn(ecosystem string, age time.Duration, mods ...func(*UpdateFacts)) UpdateFacts {
	if ecosystem == Docker {
		mods = append([]func(*UpdateFacts){image}, mods...)
	}
	return update(age, mods...)
}

// newListed makes the update a new dependency under a listed name.
func newListed(u *UpdateFacts) {
	listed(u)
	u.From = ""
	u.NewName = Yes("absent at the base commit", "base go.mod")
	u.Known = Yes("golang.org/x/", "policy")
}

// newUnlisted makes the update a new dependency under an unlisted name
// that was created nameAge ago.
func newUnlisted(nameAge time.Duration) func(*UpdateFacts) {
	return func(u *UpdateFacts) {
		u.From = ""
		u.NewName = Yes("absent at the base commit", "base go.mod")
		u.Known = No("absent at the base commit and not listed", "base go.mod")
		u.NameCreated = At(t0.Add(-nameAge), "registry")
	}
}

// pr is a pull request whose own facts all hold.
func pr(ecosystem string, updates ...UpdateFacts) PRFacts {
	return PRFacts{
		Ecosystem:        ecosystem,
		Identity:         Yes("dependabot[bot] alone", "classify"),
		Shape:            Yes("go.mod and go.sum, versions only", "x/mod/modfile"),
		ChecksConfigured: Yes("1 required check", "rules/branches"),
		Opened:           t0.Add(-hour),
		Updates:          updates,
	}
}

func clonePR(f PRFacts) PRFacts {
	out := f
	out.Updates = nil
	for _, u := range f.Updates {
		if u.Veto != nil {
			v := *u.Veto
			v.Quotes = append([]string(nil), v.Quotes...)
			u.Veto = &v
		}
		out.Updates = append(out.Updates, u)
	}
	return out
}

// cloneDecision copies d and everything it points at, keeping nil slices
// nil so the copy is DeepEqual to the original.
func cloneDecision(d Decision) Decision {
	out := d
	if d.Reasons != nil {
		out.Reasons = append([]Reason{}, d.Reasons...)
	}
	if d.PerUpdate != nil {
		out.PerUpdate = make([]UpdateDecision, len(d.PerUpdate))
		for i, ud := range d.PerUpdate {
			if ud.Reasons != nil {
				ud.Reasons = append([]Reason{}, ud.Reasons...)
			}
			out.PerUpdate[i] = ud
		}
	}
	return out
}

func clonePolicy(p Policy) Policy {
	out := p
	if p.Listed != nil {
		out.Listed = map[string][]string{}
		for k, v := range p.Listed {
			out.Listed[k] = append([]string(nil), v...)
		}
	}
	return out
}

func rank(o Outcome) int {
	switch o {
	case Merge:
		return 2
	case Wait:
		return 1
	}
	return 0
}

func wantOutcome(t *testing.T, d Decision, want Outcome, reasons ...Reason) {
	t.Helper()
	if d.Outcome != want {
		t.Fatalf("outcome %q (reasons %v), want %q", d.Outcome, d.Reasons, want)
	}
	if len(reasons) == 0 && len(d.Reasons) == 0 {
		return
	}
	if !reflect.DeepEqual(d.Reasons, reasons) {
		t.Fatalf("reasons %v, want %v", d.Reasons, reasons)
	}
}

// ---- the four invariants of spec section 2 ----

// Invariant 1: no model output makes a decision more permissive than "no
// veto". For any facts, any combination of vetoes and read states yields
// an outcome no better, and a merge time no earlier, than the same facts
// with every update fully read and nothing vetoed.
func TestVetoMonotone(t *testing.T) {
	r := rand.New(rand.NewPCG(20261122, 4))
	baselines := map[Outcome]int{}
	lowered := 0
	for i := 0; i < 30000; i++ {
		f := randomPR(r)
		p := randomPolicy(r)
		now := t0.Add(time.Duration(r.Int64N(int64(30*day))) - 10*day)

		base := clonePR(f)
		for k := range base.Updates {
			base.Updates[k].Read = ReadFull
			base.Updates[k].Veto = nil
		}
		d0 := Decide(base, p, now)
		baselines[d0.Outcome]++

		for j := 0; j < 6; j++ {
			v := clonePR(f)
			if j > 0 { // j == 0 is the record as generated
				for k := range v.Updates {
					v.Updates[k].Read = randomRead(r)
					v.Updates[k].Veto = randomVeto(r)
				}
			}
			d := Decide(v, p, now)
			if rank(d.Outcome) > rank(d0.Outcome) {
				t.Fatalf("case %d: model output made the decision more permissive: %q (%v) with full reads and no veto, %q with\n%+v",
					i, d0.Outcome, d0.Reasons, d.Outcome, v.Updates)
			}
			if rank(d.Outcome) < rank(d0.Outcome) {
				lowered++
			}
			if d.Outcome != Person && d0.Outcome != Person && d.NotBefore.Before(d0.NotBefore) {
				t.Fatalf("case %d: model output moved the merge earlier: %v, was %v with full reads\n%+v",
					i, d.NotBefore, d0.NotBefore, v.Updates)
			}
		}
	}
	// The property is empty unless the generator produces records that
	// could merge and model output that takes the merge away.
	if baselines[Merge] < 2000 || baselines[Wait] < 2000 || baselines[Person] < 2000 || lowered < 2000 {
		t.Fatalf("generator is too one-sided: baselines %v, lowered %d", baselines, lowered)
	}
}

// A veto of any category, on any update, is person.
func TestAnyVetoIsPerson(t *testing.T) {
	p := testPolicy()
	for _, category := range []string{"exfiltration", "injection_text", "other_malicious", "", "no_veto", "merge"} {
		f := pr(GoModules, update(100*hour, securityFix), update(100*hour))
		f.Updates[1].Veto = &Veto{Category: category, Quotes: []string{"x"}}
		wantOutcome(t, Decide(f, p, t0), Person, ReasonVeto)
	}
	f := pr(GoModules, update(100*hour))
	f.Updates[0].Veto = &Veto{Category: VetoModelRefused}
	wantOutcome(t, Decide(f, p, t0), Person, ReasonModelRefused)
}

// Invariant 2, as amended (spec section 11): a fact that is missing or
// false is person, never merge or wait. Every field of the two fact
// records is blanked in turn, on every kind of record that merges.
// TestUnavailableFact has the third state, and TestMergeNeedsEveryFact
// the other half: nothing but a holding fact contributes to a merge.
func TestUnknownFactIsPerson(t *testing.T) {
	p := testPolicy()

	if d := Decide(PRFacts{}, p, t0); d.Outcome != Person {
		t.Fatalf("zero PRFacts: %q", d.Outcome)
	}
	if d := Decide(pr(GoModules, UpdateFacts{}), p, t0); d.Outcome != Person {
		t.Fatalf("zero UpdateFacts: %q", d.Outcome)
	}
	if d := Decide(pr(GoModules, update(100*hour), UpdateFacts{}), p, t0); d.Outcome != Person {
		t.Fatalf("zero UpdateFacts beside a good one: %q", d.Outcome)
	}
	// All of the pull request's own facts hold, and it moves nothing.
	wantOutcome(t, Decide(pr(GoModules), p, t0), Person, ReasonNoUpdates)

	for name, base := range mergingBaselines() {
		if d := Decide(base, p, t0); d.Outcome != Merge {
			t.Fatalf("%s: the baseline must merge for this test to mean anything: %q %v", name, d.Outcome, d.Reasons)
		}
		last := len(base.Updates) - 1

		prType := reflect.TypeOf(PRFacts{})
		for i := 0; i < prType.NumField(); i++ {
			field := prType.Field(i).Name
			if exemptPR[field] != "" {
				continue
			}
			f := clonePR(base)
			reflect.ValueOf(&f).Elem().Field(i).SetZero()
			if d := Decide(f, p, t0); d.Outcome != Person {
				t.Errorf("%s: PRFacts.%s blank: %q, want person", name, field, d.Outcome)
			}
		}

		updateType := reflect.TypeOf(UpdateFacts{})
		for i := 0; i < updateType.NumField(); i++ {
			field := updateType.Field(i).Name
			if exemptUpdate[field] != "" && !(field == "NameCreated" && name == "seasoned new name") {
				continue
			}
			f := clonePR(base)
			fv := reflect.ValueOf(&f.Updates[last]).Elem().Field(i)
			fv.SetZero()
			if d := Decide(f, p, t0); d.Outcome != Person {
				t.Errorf("%s: UpdateFacts.%s blank: %q, want person", name, field, d.Outcome)
			}

			// "Yes" from nowhere is as unknown as nothing at all, and so is
			// "unavailable" from nowhere.
			switch fv.Interface().(type) {
			case Fact:
				for what, fact := range map[string]Fact{
					"true without a source":        {OK: true, Value: "yes"},
					"unavailable without a source": {Unavailable: true, Value: "no answer"},
				} {
					f := clonePR(base)
					reflect.ValueOf(&f.Updates[last]).Elem().Field(i).Set(reflect.ValueOf(fact))
					if d := Decide(f, p, t0); d.Outcome != Person || !reflect.DeepEqual(d.Reasons, []Reason{ReasonFactMissing}) {
						t.Errorf("%s: UpdateFacts.%s %s: %q %v, want person [fact_missing]", name, field, what, d.Outcome, d.Reasons)
					}
				}
			case TimeFact:
				for what, tf := range map[string]TimeFact{
					"without a source":             {OK: true, Time: t0.Add(-1000 * day)},
					"without a time":               {OK: true, Source: "registry"},
					"not ok":                       {OK: false, Time: t0.Add(-1000 * day), Source: "registry"},
					"unavailable without a source": {Unavailable: true, Time: t0.Add(-1000 * day)},
				} {
					f := clonePR(base)
					reflect.ValueOf(&f.Updates[last]).Elem().Field(i).Set(reflect.ValueOf(tf))
					if d := Decide(f, p, t0); d.Outcome != Person {
						t.Errorf("%s: UpdateFacts.%s %s: %q, want person", name, field, what, d.Outcome)
					}
				}
			}
		}

		// A fact that was gathered and is false has its own reason. One
		// that nobody gathered does not borrow it: "not bound" tells the
		// owner not to merge, and that is not what a gap in the gate's own
		// knowledge means.
		for field, reason := range map[string]Reason{
			"Increase": ReasonNotIncrease, "Bound": ReasonNotBound,
			"Clean": ReasonNotClean, "NoRegress": ReasonRegress,
		} {
			f := clonePR(base)
			fv := reflect.ValueOf(&f.Updates[last]).Elem().FieldByName(field)
			fv.Set(reflect.ValueOf(No("no", "test")))
			wantOutcome(t, Decide(f, p, t0), Person, reason)
			fv.Set(reflect.ValueOf(Fact{Value: "the answer could not be read"}))
			wantOutcome(t, Decide(f, p, t0), Person, ReasonFactMissing)
		}
		for field, reason := range map[string]Reason{
			"Identity": ReasonIdentity, "Shape": ReasonShape, "ChecksConfigured": ReasonChecksNotConfigured,
		} {
			f := clonePR(base)
			reflect.ValueOf(&f).Elem().FieldByName(field).Set(reflect.ValueOf(No("no", "test")))
			wantOutcome(t, Decide(f, p, t0), Person, reason)
			reflect.ValueOf(&f).Elem().FieldByName(field).Set(reflect.ValueOf(Fact{OK: true}))
			wantOutcome(t, Decide(f, p, t0), Person, ReasonFactMissing)
		}
	}
}

// mergingBaselines is one pull request of every kind that merges at t0
// under testPolicy.
func mergingBaselines() map[string]PRFacts {
	return map[string]PRFacts{
		"established":       pr(GoModules, update(100*hour)),
		"listed":            pr(GoModules, update(100*hour, listed)),
		"listed new name":   pr(GoModules, update(100*hour, newListed)),
		"listed major":      pr(GoModules, update(15*day, listed, major)),
		"indirect major":    pr(GoModules, update(15*day, major, indirect)),
		"security fix":      pr(GoModules, update(0, securityFix)),
		"partial read":      pr(NPM, update(15*day, read(ReadPartial))),
		"docker":            pr(Docker, update(100*hour, image, read(ReadNotApplicable))),
		"seasoned new name": pr(NPM, update(100*hour, newUnlisted(400*day))),
		"ride-along":        pr(GoModules, update(0, securityFix), update(hour)),
	}
}

// Fields of the two fact records whose zero value is not a missing fact.
var (
	exemptPR = map[string]string{
		"Opened": "not a fact of the spec; it cannot grant (TestOpenedOnlyMovesTheDeadline)",
	}
	exemptUpdate = map[string]string{
		"From":        "empty for a new name; decides nothing",
		"Veto":        "nil is the absence of an objection; a model that never answered is Read none",
		"NameCreated": "needed for an unlisted new name only, and tried on that baseline",
		"Superseded":  "unset is not superseded; set, it can only turn a merge into a wait (TestSuperseded)",
		"Indirect":    "unset is a dependency the repository declares itself; only holding does it change anything (TestIndirect)",
		"Own":         "unset is not an own workflow; only holding does it change anything (TestOwn, TestOwnNotHolding)",
	}
)

// The third state (spec section 11, amendment 1): a fact whose source was
// asked and did not answer is wait, never merge and never person before
// the deadline, and person at the deadline. Every fact field is made
// unavailable in turn, on every kind of record that merges.
func TestUnavailableFact(t *testing.T) {
	p := testPolicy()
	for name, base := range mergingBaselines() {
		last := len(base.Updates) - 1
		check := func(field string, f PRFacts) {
			t.Helper()
			d := Decide(f, p, t0)
			// The answer that has not arrived may also have been the one
			// that excused the age (a security fix, a ride along), so "too
			// young" can come with it. Nothing else can.
			want := []Reason{ReasonSourceUnavailable}
			if len(d.Reasons) == 2 {
				want = append(want, ReasonAge)
			}
			if d.Outcome != Wait || !reflect.DeepEqual(d.Reasons, want) {
				t.Errorf("%s: %s unavailable: %q %v, want wait [source_unavailable]", name, field, d.Outcome, d.Reasons)
				return
			}
			if !d.Deadline.After(t0) {
				t.Errorf("%s: %s unavailable: deadline %v is not in the future", name, field, d.Deadline)
			}
			if got := Decide(f, p, d.Deadline.Add(-1)); got.Outcome != Wait || got.Reasons[0] != ReasonSourceUnavailable {
				t.Errorf("%s: %s unavailable, a moment before the deadline: %q %v", name, field, got.Outcome, got.Reasons)
			}
			for _, later := range []time.Duration{0, day, 1000 * day} {
				got := Decide(f, p, d.Deadline.Add(later))
				if got.Outcome != Person || !reflect.DeepEqual(got.Reasons, []Reason{ReasonSourceDeadline}) {
					t.Errorf("%s: %s unavailable, %v after the deadline: %q %v, want person [source_deadline]", name, field, later, got.Outcome, got.Reasons)
				}
			}
		}

		// OK set as well must not turn "no answer" into "yes".
		facts := []Fact{Unavailable("HTTP 503, 3 tries", "registry"), {OK: true, Unavailable: true, Value: "HTTP 503", Source: "registry"}}

		prType := reflect.TypeOf(PRFacts{})
		for i := 0; i < prType.NumField(); i++ {
			if prType.Field(i).Type != reflect.TypeOf(Fact{}) {
				continue
			}
			for _, fact := range facts {
				f := clonePR(base)
				reflect.ValueOf(&f).Elem().Field(i).Set(reflect.ValueOf(fact))
				check("PRFacts."+prType.Field(i).Name, f)
			}
		}
		updateType := reflect.TypeOf(UpdateFacts{})
		for i := 0; i < updateType.NumField(); i++ {
			field := updateType.Field(i).Name
			if field == "Indirect" || field == "Own" {
				// Never waited for: unavailable is direct (TestIndirect),
				// and not own (TestOwnNotHolding).
				continue
			}
			switch updateType.Field(i).Type {
			case reflect.TypeOf(Fact{}):
				for _, fact := range facts {
					f := clonePR(base)
					reflect.ValueOf(&f.Updates[last]).Elem().Field(i).Set(reflect.ValueOf(fact))
					check("UpdateFacts."+field, f)
				}
			case reflect.TypeOf(TimeFact{}):
				if field == "NameCreated" && name != "seasoned new name" {
					continue // not looked at
				}
				for _, tf := range []TimeFact{
					UnavailableTime("HTTP 503", "registry"),
					{OK: true, Unavailable: true, Time: t0.Add(-1000 * day), Value: "HTTP 503", Source: "registry"},
				} {
					f := clonePR(base)
					reflect.ValueOf(&f.Updates[last]).Elem().Field(i).Set(reflect.ValueOf(tf))
					check("UpdateFacts."+field, f)
				}
			}
		}
	}

	// A fact that failed is not waited out because another is unavailable.
	down := func(u *UpdateFacts) {
		u.Clean = Unavailable("the advisory database did not answer", "advisories")
		u.SecurityFix = Unavailable("the advisory database did not answer", "advisories")
	}
	for reason, breakIt := range map[Reason]func(*UpdateFacts){
		ReasonNotBound:      func(u *UpdateFacts) { u.Bound = No("hash differs", "go mod download") },
		ReasonFactMissing:   func(u *UpdateFacts) { u.NoRegress = Fact{} },
		ReasonMajorUnlisted: major,
		ReasonVeto:          func(u *UpdateFacts) { u.Veto = &Veto{Category: "obfuscation"} },
		ReasonReadRefused:   read(ReadRefused),
	} {
		wantOutcome(t, Decide(pr(GoModules, update(100*hour, down, breakIt)), p, t0), Person, reason)
	}
	// It waits together with whatever else is only waiting, and when the
	// source answers the rest still has to be true.
	u := update(hour, down, read(ReadNone))
	d := Decide(pr(GoModules, u), p, t0)
	wantOutcome(t, d, Wait, ReasonSourceUnavailable, ReasonReadPending, ReasonAge)
	wantOutcome(t, Decide(pr(GoModules, u), p, d.Deadline), Person, ReasonSourceDeadline, ReasonReadDeadline)
	// An unavailable pull request fact, with an update that only waits.
	f := pr(GoModules, update(hour))
	f.ChecksConfigured = Unavailable("HTTP 502", "rules/branches")
	wantOutcome(t, Decide(f, p, t0), Wait, ReasonSourceUnavailable, ReasonAge)

	// An answer that has not arrived is never read as the answer that
	// grants more: a major whose listing is not known does not get the
	// listed major's age, and a fix that is not confirmed is not a fix.
	notListedYet := update(15*day, listed, major, func(u *UpdateFacts) { u.Listed = Unavailable("no answer", "policy") })
	wantOutcome(t, Decide(pr(GoModules, notListedYet), p, t0), Wait, ReasonSourceUnavailable)
	unconfirmedFix := update(hour, func(u *UpdateFacts) { u.SecurityFix = Unavailable("no answer", "advisories") })
	d = Decide(pr(GoModules, unconfirmedFix), p, t0)
	wantOutcome(t, d, Wait, ReasonSourceUnavailable, ReasonAge)
	if d.PerUpdate[0].RequiredAge != 72*hour {
		t.Fatalf("an unconfirmed fix needs %v", d.PerUpdate[0].RequiredAge)
	}
	// And it gives no companion a ride.
	d = Decide(pr(GoModules, unconfirmedFix, update(hour)), p, t0)
	if d.PerUpdate[1].RequiredAge != 72*hour {
		t.Fatalf("a companion of an unconfirmed fix needs %v", d.PerUpdate[1].RequiredAge)
	}
}

// The other half of invariant 2: nothing but a holding fact contributes
// to a merge. Whatever the record, a merge means every fact the decision
// rests on was gathered and holds.
func TestMergeNeedsEveryFact(t *testing.T) {
	r := rand.New(rand.NewPCG(2, 11))
	merges := 0
	// 70000 records, so that the floor of 3000 merges below still stands
	// now that an unlisted image never merges.
	for i := 0; i < 70000; i++ {
		f, p := randomPR(r), randomPolicy(r)
		now := t0.Add(time.Duration(r.Int64N(int64(30*day))) - 10*day)
		if Decide(f, p, now).Outcome != Merge {
			continue
		}
		merges++
		if !f.Identity.Holds() || !f.Shape.Holds() || !f.ChecksConfigured.Holds() || len(f.Updates) == 0 {
			t.Fatalf("merged without a pull request fact: %+v", f)
		}
		for _, u := range f.Updates {
			switch {
			case !u.Increase.Holds(), !u.Bound.Holds(), !u.Clean.Holds(), !u.NoRegress.Holds():
				t.Fatalf("merged without a fact that must hold: %+v", u)
			case !u.Known.Gathered(), !u.Listed.Gathered(), !u.NewName.Gathered(), !u.Major.Gathered(), !u.SecurityFix.Gathered():
				t.Fatalf("merged without an answer: %+v", u)
			case !u.FirstSeen.Known(), now.Before(u.FirstSeen.Time):
				t.Fatalf("merged without a first-seen time in the past: %+v", u)
			case u.Veto != nil:
				t.Fatalf("merged over a veto: %+v", u)
			case u.Read != ReadFull && u.Read != ReadPartial && !(u.Read == ReadNotApplicable && f.Ecosystem == Docker):
				t.Fatalf("merged unread: %+v", u)
			case f.Ecosystem == Docker && u.Superseded.Holds():
				t.Fatalf("merged a superseded pin: %+v", u)
			case u.Major.Holds() && !u.Listed.Holds() && !(u.Indirect.Holds() && (f.Ecosystem == GoModules || f.Ecosystem == NPM)):
				t.Fatalf("merged an unlisted major of a dependency the repository declares: %+v", u)
			case u.NewName.Holds() && !u.Listed.Holds() && (!u.NameCreated.Known() || u.Read != ReadFull):
				t.Fatalf("merged an unlisted new name without its conditions: %+v", u)
			case !u.Known.Holds() && !(u.NewName.Holds() && !u.Listed.Holds()):
				t.Fatalf("merged a name that is not known: %+v", u)
			case f.Ecosystem == Docker && !u.Listed.Holds():
				t.Fatalf("merged an image that is not listed: %+v", u)
			}
		}
	}
	if merges < 3000 {
		t.Fatalf("only %d of the random records merged", merges)
	}
}

// A failed fact is person even when something else would only be wait:
// every person reason is found before the read or the age is looked at.
func TestPersonBeforeWait(t *testing.T) {
	p := testPolicy()
	breakers := map[Reason]func(*UpdateFacts){
		ReasonNotIncrease:      func(u *UpdateFacts) { u.Increase = No("downgrade", "x/mod/semver") },
		ReasonNotBound:         func(u *UpdateFacts) { u.Bound = No("hash differs", "go mod download") },
		ReasonReadRefused:      read(ReadRefused),
		ReasonNotClean:         func(u *UpdateFacts) { u.Clean = No("retracted", "go list") },
		ReasonRegress:          func(u *UpdateFacts) { u.NoRegress = No("new install script", "registry") },
		ReasonFirstSeenUnknown: func(u *UpdateFacts) { u.FirstSeen = TimeFact{} },
		ReasonMajorUnlisted:    major,
		ReasonNotKnown:         func(u *UpdateFacts) { u.Known = No("unlisted image", "policy") },
		ReasonFactMissing:      func(u *UpdateFacts) { u.Major = Fact{} },
		ReasonVeto:             func(u *UpdateFacts) { u.Veto = &Veto{Category: "obfuscation"} },
	}
	for reason, breakIt := range breakers {
		// Too young, unread and waiting on a source, each of which alone
		// is wait. (breakIt comes last: one of the breakers is a read
		// state.)
		for _, u := range []UpdateFacts{
			update(hour, breakIt),
			update(100*hour, read(ReadNone), breakIt),
			update(hour, read(ReadNone), breakIt),
			update(hour, func(u *UpdateFacts) { u.Clean = Unavailable("HTTP 503", "registry") }, breakIt),
		} {
			wantOutcome(t, Decide(pr(GoModules, u), p, t0), Person, reason)
			// And beside an update that is only waiting.
			d := Decide(pr(GoModules, update(hour), u), p, t0)
			wantOutcome(t, d, Person, reason)
			if d.PerUpdate[0].Outcome != Wait || d.PerUpdate[1].Outcome != Person {
				t.Fatalf("%s: per-update outcomes %q, %q", reason, d.PerUpdate[0].Outcome, d.PerUpdate[1].Outcome)
			}
		}
	}
}

// Invariant 3: Decide is a pure function of (facts, policy, now).
func TestPure(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 3))
	for i := 0; i < 2000; i++ {
		f, p := randomPR(r), randomPolicy(r)
		now := t0.Add(time.Duration(r.Int64N(int64(30*day))) - 10*day)
		fCopy, pCopy := clonePR(f), clonePolicy(p)

		d1 := Decide(f, p, now)
		d2 := Decide(f, p, now)
		if !reflect.DeepEqual(d1, d2) {
			t.Fatalf("two calls with the same arguments differ:\n%+v\n%+v", d1, d2)
		}
		if !reflect.DeepEqual(f, fCopy) || !reflect.DeepEqual(p, pCopy) {
			t.Fatal("Decide changed its arguments")
		}
		before := cloneDecision(d1)
		r1 := ChecksRefused(d1, now)
		if !reflect.DeepEqual(d1, before) {
			t.Fatal("ChecksRefused changed its argument")
		}
		if !reflect.DeepEqual(r1, ChecksRefused(d1, now)) {
			t.Fatal("two ChecksRefused calls with the same arguments differ")
		}
	}

	// No I/O and no clock: the package's own files import nothing that
	// could do either, and never ask what time it is.
	pure := map[string]bool{"strings": true, "time": true}
	clock := map[string]bool{"Now": true, "Since": true, "Until": true, "After": true, "Tick": true, "Sleep": true, "NewTimer": true, "NewTicker": true, "AfterFunc": true}
	for _, file := range packageFiles(t) {
		for _, imp := range file.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if !pure[path] {
				t.Errorf("package allow imports %q", path)
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "time" && clock[sel.Sel.Name] {
				t.Errorf("package allow uses time.%s", sel.Sel.Name)
			}
			return true
		})
	}
}

// packageFiles parses this package's non-test files.
func packageFiles(t *testing.T) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), e.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	if len(files) < 3 {
		t.Fatalf("found %d source files", len(files))
	}
	return files
}

// Invariant 4: reasons come from a closed set of constants, and no free
// text decides.
func TestReasonsClosed(t *testing.T) {
	set := map[Reason]bool{}
	for _, r := range Reasons() {
		if set[r] {
			t.Errorf("%q is in the set twice", r)
		}
		set[r] = true
		if o := r.Outcome(); o != Wait && o != Person {
			t.Errorf("%q leads to %q", r, o)
		}
		if r.Explain() == "" || r.Hint() == "" {
			t.Errorf("%q has no explanation or no way out", r)
		}
		if strings.Contains(r.Explain(), "\n") || strings.Contains(r.Hint(), "\n") {
			t.Errorf("%q: explanation and hint are one line each", r)
		}
	}

	// Every Reason constant in the source has a row, and there is no row
	// without a constant.
	declared := 0
	for _, file := range packageFiles(t) {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs := spec.(*ast.ValueSpec)
				if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "Reason" {
					continue
				}
				for _, v := range vs.Values {
					lit, ok := v.(*ast.BasicLit)
					if !ok {
						t.Fatalf("Reason constant %s is not a string literal", vs.Names[0].Name)
					}
					s, _ := strconv.Unquote(lit.Value)
					declared++
					if !set[Reason(s)] {
						t.Errorf("constant %s (%q) has no row in the table", vs.Names[0].Name, s)
					}
				}
			}
		}
	}
	if declared != len(set) {
		t.Errorf("%d Reason constants, %d rows", declared, len(set))
	}

	// A value from outside the set is person and says nothing.
	if r := Reason("merge"); r.Outcome() != Person || r.Explain() != "" || r.Hint() != "" {
		t.Errorf("unknown reason: %q %q %q", r.Outcome(), r.Explain(), r.Hint())
	}

	// A reason for something the gate could not find out never reads like
	// a finding: an unreachable registry is not a bad pin.
	for _, r := range []Reason{ReasonFactMissing, ReasonSourceUnavailable, ReasonSourceDeadline, ReasonReadPending, ReasonReadDeadline,
		ReasonFirstSeenUnknown, ReasonReadUnknown, ReasonListMismatch, ReasonInconsistent} {
		text := strings.ToLower(r.Explain() + " " + r.Hint())
		for _, accusing := range []string{"do not merge", "disagree", "close the pull request, or", "is not what"} {
			if strings.Contains(text, accusing) {
				t.Errorf("%q is the gate not knowing, and its text says %q: %s", r, accusing, text)
			}
		}
	}
	for _, r := range []Reason{ReasonSourceUnavailable, ReasonSourceDeadline, ReasonFactMissing} {
		if !strings.Contains(r.Explain(), "Nothing was found wrong with the update") {
			t.Errorf("%q does not say that nothing was found wrong: %q", r, r.Explain())
		}
	}
	// And the reason for a pin the registry contradicts does say so.
	if !strings.Contains(ReasonNotBound.Hint(), "Do not merge") || !strings.Contains(ReasonNotBound.Explain(), "The registry answered") {
		t.Errorf("not_bound lost its warning: %q %q", ReasonNotBound.Explain(), ReasonNotBound.Hint())
	}

	// The reasons fixed in repository settings say where those live.
	for _, r := range []Reason{ReasonChecksNotConfigured, ReasonIdentity} {
		if !strings.Contains(r.Hint(), "kept as code, change them there") {
			t.Errorf("%q does not point at the repository settings' source: %q", r, r.Hint())
		}
	}

	check := func(what string, o Outcome, reasons []Reason) {
		t.Helper()
		if (o == Merge) != (len(reasons) == 0) {
			t.Fatalf("%s: outcome %q with reasons %v", what, o, reasons)
		}
		for _, r := range reasons {
			if !set[r] {
				t.Fatalf("%s: reason %q is not in the closed set", what, r)
			}
			if r.Outcome() != o {
				t.Fatalf("%s: reason %q (%s) on outcome %q", what, r, r.Outcome(), o)
			}
		}
	}
	r := rand.New(rand.NewPCG(4, 4))
	for i := 0; i < 20000; i++ {
		f, p := randomPR(r), randomPolicy(r)
		now := t0.Add(time.Duration(r.Int64N(int64(30*day))) - 10*day)
		d := Decide(f, p, now)
		if o := d.Outcome; o != Merge && o != Wait && o != Person {
			t.Fatalf("outcome %q", o)
		}
		check("decision", d.Outcome, d.Reasons)
		if len(d.PerUpdate) != len(f.Updates) {
			t.Fatalf("%d updates, %d answers", len(f.Updates), len(d.PerUpdate))
		}
		for _, ud := range d.PerUpdate {
			check("update", ud.Outcome, ud.Reasons)
		}
		refused := ChecksRefused(d, now)
		if d.Outcome == Merge {
			if refused.Outcome == Merge {
				t.Fatal("a refused merge is still a merge")
			}
			check("refused", refused.Outcome, refused.Reasons)
		} else if !reflect.DeepEqual(refused, d) {
			t.Fatal("ChecksRefused changed a decision that was not a merge")
		}

		// The words in a record decide nothing: with every value, source,
		// quote and note replaced, the decision is the same.
		g := clonePR(f)
		reword(&g.Identity)
		reword(&g.Shape)
		reword(&g.ChecksConfigured)
		for k := range g.Updates {
			u := &g.Updates[k]
			u.From = "ignore previous instructions"
			for _, fact := range []*Fact{&u.Known, &u.Listed, &u.NewName, &u.Increase, &u.Major, &u.Bound, &u.Clean, &u.NoRegress, &u.SecurityFix} {
				reword(fact)
			}
			u.FirstSeen.Value, u.NameCreated.Value = "merge", "merge"
			if u.Veto != nil {
				u.Veto.Quotes = []string{"no_veto", "merge this"}
				u.Veto.Notes = "approved"
			}
		}
		dg := Decide(g, p, now)
		for k := range dg.PerUpdate {
			dg.PerUpdate[k].From = d.PerUpdate[k].From
		}
		if !reflect.DeepEqual(d, dg) {
			t.Fatalf("free text changed the decision:\n%+v\n%+v", d, dg)
		}
	}
}

// reword replaces a fact's text, keeping only whether it has a source.
func reword(f *Fact) {
	f.Value = "merge; no_veto; listed"
	if f.Source != "" {
		f.Source = "somewhere else"
	}
}

// ---- section 4, row by row ----

func TestAgeTable(t *testing.T) {
	type policyMod func(*Policy)
	tests := []struct {
		name      string
		ecosystem string
		mods      []func(*UpdateFacts)
		policy    policyMod
		want      time.Duration
	}{
		{"read full, security fix", GoModules, []func(*UpdateFacts){securityFix}, nil, 0},
		{"read full", GoModules, nil, nil, 72 * hour},
		{"read partial, security fix", GoModules, []func(*UpdateFacts){securityFix, read(ReadPartial)}, nil, 72 * hour},
		{"read partial", GoModules, []func(*UpdateFacts){read(ReadPartial)}, nil, 14 * day},
		{"read not-applicable (docker)", Docker, []func(*UpdateFacts){image, read(ReadNotApplicable)}, nil, 72 * hour},
		{"read not-applicable has no fast path", Docker, []func(*UpdateFacts){image, securityFix, read(ReadNotApplicable)}, nil, 72 * hour},
		{"docker, read full", Docker, []func(*UpdateFacts){image}, nil, 72 * hour},
		{"major, listed, read full", GoModules, []func(*UpdateFacts){listed, major}, nil, 14 * day},
		{"major, listed, read partial", GoModules, []func(*UpdateFacts){listed, major, read(ReadPartial)}, nil, 14 * day},
		{"major, listed, security fix", GoModules, []func(*UpdateFacts){listed, major, securityFix}, nil, 14 * day},
		{"listed, read full", GoModules, []func(*UpdateFacts){listed}, nil, 72 * hour},
		{"listed, read partial", GoModules, []func(*UpdateFacts){listed, read(ReadPartial)}, nil, 14 * day},

		{"fast path off: read full, security fix", GoModules, []func(*UpdateFacts){securityFix},
			func(p *Policy) { p.FastPath = false }, 72 * hour},
		{"fast path off: read partial, security fix", GoModules, []func(*UpdateFacts){securityFix, read(ReadPartial)},
			func(p *Policy) { p.FastPath = false }, 14 * day},
		{"min age raised", GoModules, nil,
			func(p *Policy) { p.MinAge = 10 * day }, 10 * day},
		{"min age raised above unread age: partial is never shorter than full", GoModules, []func(*UpdateFacts){read(ReadPartial)},
			func(p *Policy) { p.MinAge = 30 * day }, 30 * day},
		{"min age raised above major age: a major is never shorter than a minor", GoModules, []func(*UpdateFacts){listed, major},
			func(p *Policy) { p.MinAge = 30 * day }, 30 * day},
		{"major age raised", GoModules, []func(*UpdateFacts){listed, major},
			func(p *Policy) { p.MajorAge = 30 * day }, 30 * day},
		{"unread age raised: partial major takes the longer", GoModules, []func(*UpdateFacts){listed, major, read(ReadPartial)},
			func(p *Policy) { p.UnreadAge = 21 * day }, 21 * day},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := testPolicy()
			if tc.policy != nil {
				tc.policy(&p)
			}

			// Exactly old enough.
			d := Decide(pr(tc.ecosystem, update(tc.want, tc.mods...)), p, t0)
			wantOutcome(t, d, Merge)
			if got := d.PerUpdate[0].RequiredAge; got != tc.want {
				t.Fatalf("required age %v, want %v", got, tc.want)
			}

			// One nanosecond too young.
			u := update(tc.want-1, tc.mods...)
			d = Decide(pr(tc.ecosystem, u), p, t0)
			wantOutcome(t, d, Wait, ReasonAge)
			if want := u.FirstSeen.Time.Add(tc.want); !d.NotBefore.Equal(want) {
				t.Fatalf("not before %v, want %v", d.NotBefore, want)
			}
			// And it merges at exactly that time, with nothing else changed.
			wantOutcome(t, Decide(pr(tc.ecosystem, u), p, d.NotBefore), Merge)
		})
	}

	person := []struct {
		name string
		u    UpdateFacts
		want Reason
	}{
		{"major, not listed", update(400*day, major), ReasonMajorUnlisted},
		{"major, not listed, security fix", update(400*day, major, securityFix), ReasonMajorUnlisted},
		{"first seen unknown", update(400*day, func(u *UpdateFacts) { u.FirstSeen = TimeFact{} }), ReasonFirstSeenUnknown},
		{"first seen unknown, security fix", update(400*day, securityFix, func(u *UpdateFacts) { u.FirstSeen = TimeFact{} }), ReasonFirstSeenUnknown},
		{"first seen unknown, listed", update(400*day, listed, func(u *UpdateFacts) { u.FirstSeen = TimeFact{} }), ReasonFirstSeenUnknown},
		{"first seen with a reason but no time", update(400*day, func(u *UpdateFacts) {
			u.FirstSeen = TimeFact{Value: "index scan exhausted", Source: "index.golang.org"}
		}), ReasonFirstSeenUnknown},
	}
	for _, tc := range person {
		t.Run(tc.name, func(t *testing.T) {
			wantOutcome(t, Decide(pr(GoModules, tc.u), testPolicy(), t0), Person, tc.want)
		})
	}
}

func TestReadStates(t *testing.T) {
	p := testPolicy()
	// Nothing-to-read is Docker's, and an own workflow's (TestOwn);
	// elsewhere it would skip the read.
	for _, eco := range []string{GoModules, NPM, GitHubActions} {
		wantOutcome(t, Decide(pr(eco, update(400*day, read(ReadNotApplicable))), p, t0), Person, ReasonReadUnknown)
	}
	for _, s := range []ReadState{"", "Full", "complete", "n/a"} {
		for _, eco := range []string{GoModules, Docker} {
			wantOutcome(t, Decide(pr(eco, updateIn(eco, 400*day, read(s))), p, t0), Person, ReasonReadUnknown)
		}
	}

	// Read none waits however old the version is, and says when a full
	// read could merge.
	d := Decide(pr(GoModules, update(100*hour, read(ReadNone))), p, t0)
	wantOutcome(t, d, Wait, ReasonReadPending)
	if d.PerUpdate[0].RequiredAge != 72*hour || !d.NotBefore.Equal(t0.Add(-28*hour)) {
		t.Fatalf("required age %v, not before %v", d.PerUpdate[0].RequiredAge, d.NotBefore)
	}
	// Unread and too young: both, and it does not merge when the age is reached.
	d = Decide(pr(GoModules, update(hour, read(ReadNone))), p, t0)
	wantOutcome(t, d, Wait, ReasonReadPending, ReasonAge)
	wantOutcome(t, Decide(pr(GoModules, update(hour, read(ReadNone))), p, d.NotBefore), Wait, ReasonReadPending)
	// A listed major must have been read at least in part.
	wantOutcome(t, Decide(pr(GoModules, update(400*day, listed, major, read(ReadNone))), p, t0), Wait, ReasonReadPending)
	// A security fix does not merge unread either.
	wantOutcome(t, Decide(pr(GoModules, update(hour, securityFix, read(ReadNone))), p, t0), Wait, ReasonReadPending)

	// A read the gate refused (a hash mismatch, an unsafe archive, an
	// unusable read) is person at once, in every ecosystem, however old
	// and however listed the update is: asking again gives the same.
	for _, eco := range []string{GoModules, NPM, GitHubActions, Docker} {
		wantOutcome(t, Decide(pr(eco, updateIn(eco, 400*day, read(ReadRefused))), p, t0), Person, ReasonReadRefused)
	}
	wantOutcome(t, Decide(pr(GoModules, update(400*day, listed, securityFix, read(ReadRefused))), p, t0), Person, ReasonReadRefused)
}

// A Docker pin whose tag has moved on waits for Dependabot's refresh
// (spec section 11, amendment 2). It never merges while superseded, and
// only what a refresh would change is excused.
func TestSuperseded(t *testing.T) {
	p := testPolicy()
	// What the Docker gatherer reports for such a pin.
	moved := func(u *UpdateFacts) {
		u.Read = ReadNotApplicable
		u.Superseded = Yes("tag 1.27 resolves to sha256:bbb now, not to the pinned sha256:aaa", "HEAD registry")
		u.Bound = No("tag 1.27 resolves to sha256:bbb now, not to the pinned sha256:aaa", "HEAD registry")
		u.Clean = No("the registry no longer serves the pinned digest under tag 1.27", "HEAD registry")
		u.FirstSeen = TimeFact{Value: "not asked: the tag has moved on", Source: "HEAD registry"}
	}
	f := pr(Docker, update(0, image, moved))
	d := Decide(f, p, t0)
	wantOutcome(t, d, Wait, ReasonSuperseded)
	if want := f.Opened.Add(7 * day); !d.Deadline.Equal(want) || !d.NotBefore.IsZero() {
		t.Fatalf("deadline %v (want %v), not before %v", d.Deadline, want, d.NotBefore)
	}
	wantOutcome(t, Decide(f, p, d.Deadline.Add(-1)), Wait, ReasonSuperseded)
	wantOutcome(t, Decide(f, p, d.Deadline), Person, ReasonSupersededDeadline)
	wantOutcome(t, Decide(f, p, d.Deadline.Add(1000*day)), Person, ReasonSupersededDeadline)

	// Superseded never merges, even with every other fact holding and the
	// version old enough: it can only take a merge away.
	old := pr(Docker, update(400*day, image, read(ReadNotApplicable)))
	wantOutcome(t, Decide(old, p, t0), Merge)
	old.Updates[0].Superseded = Yes("the tag has moved on", "HEAD registry")
	wantOutcome(t, Decide(old, p, t0), Wait, ReasonSuperseded)
	old.Updates[0].Superseded = No("the tag still resolves to the pin", "HEAD registry")
	wantOutcome(t, Decide(old, p, t0), Merge)

	// What a refresh would not change is still person, at once. An image
	// that is not listed is not known, and its major is nobody's choice.
	unlisted := func(u *UpdateFacts) {
		u.Name = unlistedName
		u.Listed, u.Known = No("matches no list entry", "policy"), No("image is not listed", "policy")
	}
	for _, tc := range []struct {
		breakIt func(*UpdateFacts)
		reasons []Reason
	}{
		{unlisted, []Reason{ReasonNotKnown}},
		{func(u *UpdateFacts) { u.Increase = No("a lower tag", "tags") }, []Reason{ReasonNotIncrease}},
		{func(u *UpdateFacts) { u.NoRegress = No("no", "test") }, []Reason{ReasonRegress}},
		{func(u *UpdateFacts) { unlisted(u); major(u) }, []Reason{ReasonNotKnown, ReasonMajorUnlisted}},
		{func(u *UpdateFacts) { u.Major = Fact{} }, []Reason{ReasonFactMissing}},
		{read(ReadFull + "?"), []Reason{ReasonReadUnknown}},
	} {
		wantOutcome(t, Decide(pr(Docker, update(0, image, moved, tc.breakIt)), p, t0), Person, tc.reasons...)
	}

	// It is a Docker state. Elsewhere a version is immutable and nothing
	// refreshes a pin, so the flag is not honoured and the facts decide.
	for _, eco := range []string{GoModules, NPM, GitHubActions} {
		d := Decide(pr(eco, update(400*day, moved, read(ReadFull))), p, t0)
		wantOutcome(t, d, Person, ReasonNotBound, ReasonNotClean, ReasonFirstSeenUnknown)
		ok := pr(eco, update(400*day, func(u *UpdateFacts) { u.Superseded = Yes("moved on", "registry") }))
		wantOutcome(t, Decide(ok, p, t0), Merge)
	}
}

func TestNewNames(t *testing.T) {
	p := testPolicy()
	tests := []struct {
		name      string
		ecosystem string
		u         UpdateFacts
		want      Outcome
		reasons   []Reason
	}{
		{"listed: treated as known", GoModules, update(72*hour, newListed), Merge, nil},
		{"listed: still needs its age", GoModules, update(71*hour, newListed), Wait, []Reason{ReasonAge}},
		{"listed: partial read is the unread age", GoModules, update(13*day, newListed, read(ReadPartial)), Wait, []Reason{ReasonAge}},

		{"unlisted, read full, name a year old", NPM, update(72*hour, newUnlisted(365*day)), Merge, nil},
		{"unlisted, read full, name a year old, too young a version", NPM, update(71*hour, newUnlisted(365*day)), Wait, []Reason{ReasonAge}},
		{"unlisted, name one nanosecond short of a year", NPM, update(400*day, newUnlisted(365*day-1)), Person, []Reason{ReasonNewNameYoung}},
		{"unlisted, name created yesterday", NPM, update(400*day, newUnlisted(day)), Person, []Reason{ReasonNewNameYoung}},
		{"unlisted, name age unknown", NPM, update(400*day, newUnlisted(400*day), func(u *UpdateFacts) { u.NameCreated = TimeFact{} }),
			Person, []Reason{ReasonNameCreatedUnknown}},
		{"unlisted, read partial", NPM, update(400*day, newUnlisted(400*day), read(ReadPartial)), Person, []Reason{ReasonNewNameUnread}},
		{"unlisted, nothing to read (docker)", Docker, update(400*day, newUnlisted(400*day), read(ReadNotApplicable)),
			Person, []Reason{ReasonNewNameUnread}},
		{"unlisted, read missing: retried, not refused", NPM, update(400*day, newUnlisted(400*day), read(ReadNone)),
			Wait, []Reason{ReasonReadPending}},
		{"unlisted, young name, read missing: person first", NPM, update(400*day, newUnlisted(day), read(ReadNone)),
			Person, []Reason{ReasonNewNameYoung}},
		{"unlisted, regressed", NPM, update(400*day, newUnlisted(400*day), func(u *UpdateFacts) { u.NoRegress = No("install script", "registry") }),
			Person, []Reason{ReasonRegress}},
		{"unlisted, no-regress never gathered", NPM, update(400*day, newUnlisted(400*day), func(u *UpdateFacts) { u.NoRegress = Fact{} }),
			Person, []Reason{ReasonFactMissing}},
		{"unlisted, no-regress unavailable", NPM, update(400*day, newUnlisted(400*day), func(u *UpdateFacts) { u.NoRegress = Unavailable("HTTP 503", "registry") }),
			Wait, []Reason{ReasonSourceUnavailable}},
		{"unlisted, name age unavailable", NPM, update(400*day, newUnlisted(400*day), func(u *UpdateFacts) { u.NameCreated = UnavailableTime("HTTP 503", "registry") }),
			Wait, []Reason{ReasonSourceUnavailable}},
		{"unlisted, name age unavailable, read partial: person first", NPM,
			update(400*day, newUnlisted(400*day), read(ReadPartial), func(u *UpdateFacts) { u.NameCreated = UnavailableTime("HTTP 503", "registry") }),
			Person, []Reason{ReasonNewNameUnread}},
		{"unlisted: a security fix is no shortcut", NPM, update(71*hour, newUnlisted(400*day), securityFix), Wait, []Reason{ReasonAge}},
		{"unlisted, major", NPM, update(400*day, newUnlisted(400*day), major), Person, []Reason{ReasonMajorUnlisted}},

		{"unlisted new name claimed as known", NPM,
			update(400*day, newUnlisted(400*day), func(u *UpdateFacts) { u.Known = Yes("known", "gatherer") }),
			Person, []Reason{ReasonInconsistent}},
		{"present at base, yet not known", Docker, update(400*day, read(ReadNotApplicable), func(u *UpdateFacts) { u.Known = No("image is not listed", "policy") }),
			Person, []Reason{ReasonNotKnown}},
		{"listed, yet not known", GoModules, update(400*day, listed, func(u *UpdateFacts) { u.Known = No("no", "gatherer") }),
			Person, []Reason{ReasonInconsistent}},
		{"new and listed, yet not known", GoModules, update(400*day, newListed, func(u *UpdateFacts) { u.Known = No("no", "gatherer") }),
			Person, []Reason{ReasonInconsistent}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wantOutcome(t, Decide(pr(tc.ecosystem, tc.u), p, t0), tc.want, tc.reasons...)
		})
	}

	// The new-name age is the policy's.
	p.NewNameAge = 30 * day
	wantOutcome(t, Decide(pr(NPM, update(72*hour, newUnlisted(30*day))), p, t0), Merge)
	wantOutcome(t, Decide(pr(NPM, update(72*hour, newUnlisted(29*day))), p, t0), Person, ReasonNewNameYoung)
}

// The Listed fact is checked against the policy Decide was given.
func TestListMismatch(t *testing.T) {
	p := testPolicy()
	// Claimed listed, the policy does not list it: a major would ride on it.
	lie := update(400*day, major, func(u *UpdateFacts) { u.Listed = Yes("github.com/kr/", "a different list") })
	wantOutcome(t, Decide(pr(GoModules, lie), p, t0), Person, ReasonListMismatch)
	// Claimed unlisted, the policy lists it.
	stale := update(400*day, func(u *UpdateFacts) { u.Name = listedName })
	wantOutcome(t, Decide(pr(GoModules, stale), p, t0), Person, ReasonListMismatch)
	// Listed for another ecosystem is not listed here.
	wantOutcome(t, Decide(pr(NPM, update(400*day, listed)), p, t0), Person, ReasonListMismatch)
	// The same record under a policy that does list it.
	p.Listed[GoModules] = append(p.Listed[GoModules], "github.com/kr/")
	wantOutcome(t, Decide(pr(GoModules, lie), p, t0), Merge)
}

func TestMajors(t *testing.T) {
	p := testPolicy()
	tests := []struct {
		name    string
		u       UpdateFacts
		want    Outcome
		reasons []Reason
	}{
		{"listed, 14 days", update(14*day, listed, major), Merge, nil},
		{"listed, 13 days", update(13*day, listed, major), Wait, []Reason{ReasonAge}},
		{"listed, partial read, 14 days", update(14*day, listed, major, read(ReadPartial)), Merge, nil},
		{"listed, read missing", update(400*day, listed, major, read(ReadNone)), Wait, []Reason{ReasonReadPending}},
		{"listed, security fix, 13 days", update(13*day, listed, major, securityFix), Wait, []Reason{ReasonAge}},
		{"not listed", update(400*day, major), Person, []Reason{ReasonMajorUnlisted}},
		{"not listed, read missing", update(400*day, major, read(ReadNone)), Person, []Reason{ReasonMajorUnlisted}},
		{"major unknown", update(400*day, listed, func(u *UpdateFacts) { u.Major = Fact{} }), Person, []Reason{ReasonFactMissing}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := pr(GoModules, tc.u)
			f.Opened = t0.Add(-hour)
			wantOutcome(t, Decide(f, p, t0), tc.want, tc.reasons...)
		})
	}
}

// Indirect (spec section 11, amendment 23): a major update of an unlisted
// name that the repository does not declare itself is decided like a
// listed major. Only a fact that holds does that, only for Go modules and
// npm, and it changes nothing else.
func TestIndirect(t *testing.T) {
	p := testPolicy()
	is := func(f Fact) func(*UpdateFacts) { return func(u *UpdateFacts) { u.Indirect = f } }
	tests := []struct {
		name    string
		eco     string
		u       UpdateFacts
		want    Outcome
		reasons []Reason
	}{
		{"major, indirect, 14 days", GoModules, update(14*day, major, indirect), Merge, nil},
		{"major, indirect, 13 days", GoModules, update(13*day, major, indirect), Wait, []Reason{ReasonAge}},
		{"major, indirect, npm", NPM, update(14*day, major, indirect), Merge, nil},
		{"major, indirect, partial read, 14 days", GoModules, update(14*day, major, indirect, read(ReadPartial)), Merge, nil},
		{"major, indirect, read missing", GoModules, update(400*day, major, indirect, read(ReadNone)), Wait, []Reason{ReasonReadPending}},
		{"major, indirect, security fix, 13 days", GoModules, update(13*day, major, indirect, securityFix), Wait, []Reason{ReasonAge}},

		// Everything that is not a holding fact is a dependency the
		// repository declares, at once: it is never waited for.
		{"major, declared", GoModules, update(400*day, major, is(No("required directly", "go.mod"))), Person, []Reason{ReasonMajorUnlisted}},
		{"major, never gathered", GoModules, update(400*day, major), Person, []Reason{ReasonMajorUnlisted}},
		{"major, unavailable", GoModules, update(400*day, major, is(Unavailable("no answer", "go.mod"))), Person, []Reason{ReasonMajorUnlisted}},
		{"major, yes from nowhere", GoModules, update(400*day, major, is(Fact{OK: true, Value: "yes"})), Person, []Reason{ReasonMajorUnlisted}},
		{"major, yes and unavailable", GoModules, update(400*day, major, is(Fact{OK: true, Unavailable: true, Value: "yes", Source: "go.mod"})), Person, []Reason{ReasonMajorUnlisted}},
		// An action is always the repository's own choice.
		{"major, indirect, an action", GitHubActions, update(400*day, major, indirect), Person, []Reason{ReasonMajorUnlisted}},

		// Nothing else moves.
		{"minor, indirect, 72 hours", GoModules, update(72*hour, indirect), Merge, nil},
		{"minor, indirect, 71 hours", GoModules, update(71*hour, indirect), Wait, []Reason{ReasonAge}},
		{"listed major, indirect, 13 days", GoModules, update(13*day, listed, major, indirect), Wait, []Reason{ReasonAge}},
		{"new name, indirect, young name", NPM, update(400*day, newUnlisted(300*day), indirect), Person, []Reason{ReasonNewNameYoung}},
		{"new name, indirect, name age unknown", NPM, update(400*day, newUnlisted(400*day), indirect, func(u *UpdateFacts) { u.NameCreated = TimeFact{} }), Person, []Reason{ReasonNameCreatedUnknown}},
		{"new name, indirect, partial read", NPM, update(400*day, newUnlisted(400*day), indirect, read(ReadPartial)), Person, []Reason{ReasonNewNameUnread}},
		{"major, indirect, not bound", GoModules, update(400*day, major, indirect, func(u *UpdateFacts) { u.Bound = No("hash differs", "go mod download") }), Person, []Reason{ReasonNotBound}},
		{"major, indirect, veto", GoModules, update(400*day, major, indirect, func(u *UpdateFacts) { u.Veto = &Veto{Category: "obfuscation"} }), Person, []Reason{ReasonVeto}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wantOutcome(t, Decide(pr(tc.eco, tc.u), p, t0), tc.want, tc.reasons...)
		})
	}
	// It does not make a companion: the fast path's ride is for an update
	// that is not a major.
	d := Decide(pr(GoModules, update(0, securityFix), update(hour, major, indirect)), p, t0)
	wantOutcome(t, d, Wait, ReasonAge)
	if d.PerUpdate[1].RequiredAge != 14*day {
		t.Fatalf("an indirect major beside a security fix needs %v", d.PerUpdate[1].RequiredAge)
	}
}

// Indirect holding never gives a worse outcome than not holding, it
// changes nothing but the decision about an unlisted major, and every
// way of not holding is the same as a dependency the repository declares.
func TestIndirectMonotone(t *testing.T) {
	r := rand.New(rand.NewPCG(23, 5))
	set := func(f PRFacts, fact Fact) PRFacts {
		out := clonePR(f)
		for k := range out.Updates {
			out.Updates[k].Indirect = fact
		}
		return out
	}
	spared := 0
	for i := 0; i < 30000; i++ {
		f, p := randomPR(r), randomPolicy(r)
		now := t0.Add(time.Duration(r.Int64N(int64(30*day))) - 10*day)

		declared := Decide(set(f, No("declared", "manifest")), p, now)
		holding := Decide(set(f, Yes("indirect", "manifest")), p, now)
		switch {
		case rank(holding.Outcome) < rank(declared.Outcome):
			t.Fatalf("case %d: Indirect made the decision worse: %q, %q without\n%+v", i, holding.Outcome, declared.Outcome, f)
		case reflect.DeepEqual(holding, declared):
		case !slices.Contains(declared.Reasons, ReasonMajorUnlisted):
			t.Fatalf("case %d: Indirect changed a decision that was not about an unlisted major: %v, %v without\n%+v", i, holding.Reasons, declared.Reasons, f)
		}
		if rank(holding.Outcome) > rank(declared.Outcome) {
			spared++
		}
		for what, fact := range map[string]Fact{
			"unset":                        {},
			"unavailable":                  Unavailable("no answer", "manifest"),
			"true without a source":        {OK: true, Value: "yes"},
			"true and unavailable":         {OK: true, Unavailable: true, Value: "yes", Source: "manifest"},
			"unavailable without a source": {Unavailable: true, Value: "no answer"},
		} {
			if d := Decide(set(f, fact), p, now); !reflect.DeepEqual(d, declared) {
				t.Fatalf("case %d: Indirect %s is not decided as declared: %q %v, want %q %v", i, what, d.Outcome, d.Reasons, declared.Outcome, declared.Reasons)
			}
		}
	}
	// The property is empty unless Indirect sometimes decides.
	if spared < 100 {
		t.Fatalf("Indirect changed the outcome of only %d random records", spared)
	}
}

func TestCompanions(t *testing.T) {
	fix := update(0, securityFix) // published this instant
	tests := []struct {
		name      string
		mode      Companions
		fastPath  bool
		updates   []UpdateFacts
		want      Outcome
		reasons   []Reason
		notBefore time.Duration // relative to t0, for Wait
	}{
		{"ride-along: a known, fully read companion needs no age", RideAlong, true,
			[]UpdateFacts{fix, update(hour)}, Merge, nil, 0},
		{"ride-along: several companions", RideAlong, true,
			[]UpdateFacts{update(hour, listed), fix, update(2 * hour)}, Merge, nil, 0},
		{"ride-along: a partly read companion keeps the unread age", RideAlong, true,
			[]UpdateFacts{fix, update(hour, read(ReadPartial))}, Wait, []Reason{ReasonAge}, 14*day - hour},
		{"ride-along: an unread companion is retried", RideAlong, true,
			[]UpdateFacts{fix, update(hour, read(ReadNone))}, Wait, []Reason{ReasonReadPending, ReasonAge}, 72*hour - hour},
		{"ride-along: a new listed name keeps its age", RideAlong, true,
			[]UpdateFacts{fix, update(hour, newListed)}, Wait, []Reason{ReasonAge}, 72*hour - hour},
		{"ride-along: a new unlisted name keeps its age", RideAlong, true,
			[]UpdateFacts{fix, update(hour, newUnlisted(400*day))}, Wait, []Reason{ReasonAge}, 72*hour - hour},
		{"ride-along: a listed major keeps the major age", RideAlong, true,
			[]UpdateFacts{fix, update(hour, listed, major)}, Wait, []Reason{ReasonAge}, 14*day - hour},
		{"ride-along: an unlisted major is still person", RideAlong, true,
			[]UpdateFacts{fix, update(hour, major)}, Person, []Reason{ReasonMajorUnlisted}, 0},
		{"ride-along: the fix was only partly read, so nobody rides", RideAlong, true,
			[]UpdateFacts{update(72*hour, securityFix, read(ReadPartial)), update(hour)}, Wait, []Reason{ReasonAge}, 72*hour - hour},
		{"ride-along: the fix was not read, so nobody rides", RideAlong, true,
			[]UpdateFacts{update(hour, securityFix, read(ReadNone)), update(hour)}, Wait, []Reason{ReasonReadPending, ReasonAge}, 72*hour - hour},
		{"ride-along: no security fix, no ride", RideAlong, true,
			[]UpdateFacts{update(100 * hour), update(hour)}, Wait, []Reason{ReasonAge}, 72*hour - hour},
		{"ride-along: a vetoed companion is person", RideAlong, true,
			[]UpdateFacts{fix, update(hour, func(u *UpdateFacts) { u.Veto = &Veto{Category: "exfiltration"} })}, Person, []Reason{ReasonVeto}, 0},

		{"wait: every update needs its own age", CompanionsWait, true,
			[]UpdateFacts{fix, update(hour)}, Wait, []Reason{ReasonAge}, 72*hour - hour},
		{"wait: the fix alone still merges at once", CompanionsWait, true,
			[]UpdateFacts{fix}, Merge, nil, 0},
		{"wait: old enough companions merge", CompanionsWait, true,
			[]UpdateFacts{fix, update(72 * hour)}, Merge, nil, 0},

		{"fast path off: no ride and no shortcut", RideAlong, false,
			[]UpdateFacts{update(72*hour, securityFix), update(hour)}, Wait, []Reason{ReasonAge}, 72*hour - hour},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := testPolicy()
			p.Companions, p.FastPath = tc.mode, tc.fastPath
			d := Decide(pr(GoModules, tc.updates...), p, t0)
			wantOutcome(t, d, tc.want, tc.reasons...)
			if tc.want == Wait && !d.NotBefore.Equal(t0.Add(tc.notBefore)) {
				t.Fatalf("not before %v, want %v", d.NotBefore, t0.Add(tc.notBefore))
			}
		})
	}
}

// The pull request's outcome: person if any update is person, else wait
// until the latest required time, else merge.
func TestPullRequestOutcome(t *testing.T) {
	p := testPolicy()
	old, young, younger := update(100*hour), update(70*hour), update(10*hour)
	bad := update(100*hour, func(u *UpdateFacts) { u.Bound = No("hash differs", "go mod download") })

	wantOutcome(t, Decide(pr(GoModules, old, old), p, t0), Merge)

	d := Decide(pr(GoModules, old, young, younger), p, t0)
	wantOutcome(t, d, Wait, ReasonAge)
	if want := t0.Add(62 * hour); !d.NotBefore.Equal(want) {
		t.Fatalf("not before %v, want the latest required time %v", d.NotBefore, want)
	}
	if got := []Outcome{d.PerUpdate[0].Outcome, d.PerUpdate[1].Outcome, d.PerUpdate[2].Outcome}; !reflect.DeepEqual(got, []Outcome{Merge, Wait, Wait}) {
		t.Fatalf("per update %v", got)
	}
	wantOutcome(t, Decide(pr(GoModules, old, young, younger), p, t0.Add(62*hour)), Merge)

	d = Decide(pr(GoModules, old, young, bad), p, t0)
	wantOutcome(t, d, Person, ReasonNotBound)
	if !d.NotBefore.IsZero() || !d.Deadline.IsZero() {
		t.Fatalf("a person decision carries times: %v %v", d.NotBefore, d.Deadline)
	}

	// Reasons are listed once, the pull request's own first.
	f := pr(GoModules, bad, bad)
	f.Shape = No("a workflow file changed too", "git diff-tree")
	wantOutcome(t, Decide(f, p, t0), Person, ReasonShape, ReasonNotBound)
}

func TestNoRule(t *testing.T) {
	p := testPolicy()
	// npm_and_yarn is Dependabot's name for npm; unmapped, it has no rule.
	for _, eco := range []string{"", "uv", "pip", "terraform", "opentofu", "submodules", "gitsubmodule", "npm_and_yarn", "GO_MODULES", "multi-ecosystem"} {
		wantOutcome(t, Decide(pr(eco, update(400*day)), p, t0), Person, ReasonNoRule)
		if HasRule(eco) {
			t.Errorf("HasRule(%q)", eco)
		}
	}
	for _, eco := range []string{GoModules, NPM, GitHubActions, Docker} {
		wantOutcome(t, Decide(pr(eco, updateIn(eco, 400*day)), p, t0), Merge)
	}
}

// For Docker, Known means listed and nothing else (spec section 11,
// amendment 3), and Decide holds every record to that: the gatherer's word
// that an image is known does not grant.
func TestImageMustBeListed(t *testing.T) {
	p := testPolicy()
	// An image the Dockerfile already had, which its record calls known.
	atBase := update(400*day, read(ReadNotApplicable))
	wantOutcome(t, Decide(pr(Docker, atBase), p, t0), Person, ReasonNotKnown)
	wantOutcome(t, Decide(pr(Docker, update(400*day)), p, t0), Person, ReasonNotKnown)
	wantOutcome(t, Decide(pr(Docker, atBase, update(400*day, image, read(ReadNotApplicable))), p, t0), Person, ReasonNotKnown)
	// The same record elsewhere is an established dependency, and the
	// image merges once the list names it.
	wantOutcome(t, Decide(pr(GoModules, update(400*day)), p, t0), Merge)
	wantOutcome(t, Decide(pr(Docker, update(400*day, image, read(ReadNotApplicable))), p, t0), Merge)
	p.Listed[Docker] = append(p.Listed[Docker], unlistedName)
	atBase.Listed = Yes(unlistedName, "policy")
	wantOutcome(t, Decide(pr(Docker, atBase), p, t0), Merge)

	// A new image that is not listed has no way in: the new-name rule
	// asks for a full read, and an image is never read, whatever its
	// record says. The same record is a seasoned new name elsewhere.
	p = testPolicy()
	for _, s := range []ReadState{ReadFull, ReadPartial, ReadNotApplicable} {
		wantOutcome(t, Decide(pr(Docker, update(400*day, newUnlisted(400*day), read(s))), p, t0), Person, ReasonNewNameUnread)
	}
	wantOutcome(t, Decide(pr(NPM, update(400*day, newUnlisted(400*day))), p, t0), Merge)
}

func TestPolicyUnusable(t *testing.T) {
	good := pr(GoModules, update(400*day, securityFix))
	wantOutcome(t, Decide(good, testPolicy(), t0), Merge)
	wantOutcome(t, Decide(good, Policy{}, t0), Person, ReasonPolicyInvalid)

	for name, breakIt := range map[string]func(*Policy){
		"min age zero":           func(p *Policy) { p.MinAge = 0 },
		"min age negative":       func(p *Policy) { p.MinAge = -hour },
		"unread age zero":        func(p *Policy) { p.UnreadAge = 0 },
		"major age zero":         func(p *Policy) { p.MajorAge = 0 },
		"new name age zero":      func(p *Policy) { p.NewNameAge = 0 },
		"wait deadline zero":     func(p *Policy) { p.WaitDeadline = 0 },
		"wait deadline negative": func(p *Policy) { p.WaitDeadline = -day },
		"companions empty":       func(p *Policy) { p.Companions = "" },
		"companions unknown":     func(p *Policy) { p.Companions = "ride_along" },
	} {
		p := testPolicy()
		breakIt(&p)
		d := Decide(good, p, t0)
		if d.Outcome != Person || d.Reasons[0] != ReasonPolicyInvalid {
			t.Errorf("%s: %q %v", name, d.Outcome, d.Reasons)
		}
	}

	// The zero policy merges nothing, whatever the facts.
	r := rand.New(rand.NewPCG(5, 5))
	for i := 0; i < 5000; i++ {
		if d := Decide(randomPR(r), Policy{}, t0); d.Outcome != Person {
			t.Fatalf("zero policy: %q", d.Outcome)
		}
	}
	// A nil list is a usable policy that lists nothing.
	p := testPolicy()
	p.Listed = nil
	wantOutcome(t, Decide(pr(GoModules, update(400*day)), p, t0), Merge)
	wantOutcome(t, Decide(pr(GoModules, update(400*day, listed)), p, t0), Person, ReasonListMismatch)
}

func TestWaitDeadline(t *testing.T) {
	p := testPolicy()

	// The model read is missing on a version published 40 days ago, in a
	// pull request opened a day ago. The latest required time is 37 days
	// back; the deadline still runs from the day the pull request opened.
	unread := pr(GoModules, update(40*day, read(ReadNone)))
	unread.Opened = t0.Add(-day)
	d := Decide(unread, p, t0)
	wantOutcome(t, d, Wait, ReasonReadPending)
	if want := unread.Opened.Add(7 * day); !d.Deadline.Equal(want) {
		t.Fatalf("deadline %v, want %v", d.Deadline, want)
	}
	wantOutcome(t, Decide(unread, p, d.Deadline.Add(-1)), Wait, ReasonReadPending)
	atDeadline := Decide(unread, p, d.Deadline)
	wantOutcome(t, atDeadline, Person, ReasonReadDeadline)
	if atDeadline.PerUpdate[0].Outcome != Wait {
		t.Fatalf("the update itself is still only waiting: %q", atDeadline.PerUpdate[0].Outcome)
	}
	wantOutcome(t, Decide(unread, p, d.Deadline.Add(30*day)), Person, ReasonReadDeadline)

	// A pull request opened before the latest required time: the deadline
	// runs from the required time.
	young := pr(GoModules, update(hour, read(ReadNone)))
	young.Opened = t0.Add(-30 * day)
	d = Decide(young, p, t0)
	wantOutcome(t, d, Wait, ReasonReadPending, ReasonAge)
	if want := t0.Add(71*hour + 7*day); !d.Deadline.Equal(want) {
		t.Fatalf("deadline %v, want %v", d.Deadline, want)
	}
	wantOutcome(t, Decide(young, p, d.Deadline.Add(-1)), Wait, ReasonReadPending)
	wantOutcome(t, Decide(young, p, d.Deadline), Person, ReasonReadDeadline)

	// The deadline is the policy's.
	p.WaitDeadline = 2 * day
	wantOutcome(t, Decide(unread, p, unread.Opened.Add(2*day-1)), Wait, ReasonReadPending)
	wantOutcome(t, Decide(unread, p, unread.Opened.Add(2*day)), Person, ReasonReadDeadline)
	p = testPolicy()

	// Waiting for age alone never reaches the deadline: when the age is
	// reached the pull request merges, however long ago it was opened.
	aging := pr(GoModules, update(hour, read(ReadPartial)))
	aging.Opened = t0.Add(-300 * day)
	d = Decide(aging, p, t0)
	wantOutcome(t, d, Wait, ReasonAge)
	wantOutcome(t, Decide(aging, p, d.NotBefore.Add(-1)), Wait, ReasonAge)
	wantOutcome(t, Decide(aging, p, d.NotBefore), Merge)
	wantOutcome(t, Decide(aging, p, d.NotBefore.Add(300*day)), Merge)

	// A read that completes after the deadline merges: the deadline is
	// about what is still missing, not about how old the pull request is.
	done := clonePR(unread)
	done.Updates[0].Read = ReadFull
	wantOutcome(t, Decide(done, p, t0.Add(300*day)), Merge)

	// What the model returned does not buy a failing retry more time. A
	// partial read needs 14 days, and a source that is not answering is
	// still given up on 7 days after the 72 hours a full read would need.
	// (This is what keeps invariant 1 true at the deadline.)
	down := func(u *UpdateFacts) { u.Clean = Unavailable("HTTP 503", "registry") }
	for _, r := range []ReadState{ReadFull, ReadPartial, ReadNone} {
		f := pr(GoModules, update(hour, down, read(r)))
		d := Decide(f, p, t0)
		if d.Outcome != Wait || !d.Deadline.Equal(t0.Add(71*hour+7*day)) {
			t.Fatalf("read %s: %q, deadline %v", r, d.Outcome, d.Deadline)
		}
		if got := Decide(f, p, d.Deadline); got.Outcome != Person || got.Reasons[0] != ReasonSourceDeadline {
			t.Fatalf("read %s at the deadline: %q %v", r, got.Outcome, got.Reasons)
		}
	}
	// Without a retry pending the deadline is for GitHub's refusal, and
	// runs from the time the pull request can really merge.
	partial := pr(GoModules, update(hour, read(ReadPartial)))
	d = Decide(partial, p, t0)
	wantOutcome(t, d, Wait, ReasonAge)
	if want := t0.Add(-hour + 14*day + 7*day); !d.Deadline.Equal(want) {
		t.Fatalf("deadline %v, want %v", d.Deadline, want)
	}
	merged := Decide(partial, p, d.NotBefore)
	wantOutcome(t, merged, Merge)
	wantOutcome(t, ChecksRefused(merged, d.NotBefore), Wait, ReasonChecksPending)
}

// With no first-seen time and no opened time nothing says when the wait
// began (spec section 11, amendment 22). There is then no deadline, and
// the pull request is not given up on the moment the gate first looks.
func TestNoDeadlineWithoutAStart(t *testing.T) {
	p := testPolicy()
	noClock := func(u *UpdateFacts) { u.FirstSeen = UnavailableTime("HTTP 503", "index.golang.org") }
	superseded := func(u *UpdateFacts) {
		u.Name, u.Listed, u.Read = "docker.io/library/golang", Yes("docker.io/library/", "policy"), ReadNotApplicable
		u.Superseded = Yes("the tag resolves to another digest now", "registry")
		u.FirstSeen = TimeFact{Value: "not asked", Source: "registry"}
	}
	tests := []struct {
		name   string
		f      PRFacts
		reason Reason
		// gaveUp is the reason once a start is known and its deadline has
		// passed.
		gaveUp Reason
	}{
		{"no clock answered", pr(GoModules, update(hour, noClock)), ReasonSourceUnavailable, ReasonSourceDeadline},
		{"no clock answered, read missing", pr(GoModules, update(hour, noClock, read(ReadNone))), ReasonSourceUnavailable, ReasonSourceDeadline},
		{"two updates, neither has a time", pr(GoModules, update(hour, noClock), update(hour, noClock)), ReasonSourceUnavailable, ReasonSourceDeadline},
		{"a superseded pin, whose time is not looked at", pr(Docker, update(hour, image, superseded)), ReasonSuperseded, ReasonSupersededDeadline},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.f
			f.Opened = time.Time{}
			for _, now := range []time.Time{t0.Add(-1000 * day), t0, t0.Add(1000 * day)} {
				d := Decide(f, p, now)
				if d.Outcome != Wait || d.Reasons[0] != tc.reason {
					t.Fatalf("at %v: %q %v, want wait with %q first", now, d.Outcome, d.Reasons, tc.reason)
				}
				if !d.Deadline.IsZero() {
					t.Fatalf("at %v: deadline %v, want none", now, d.Deadline)
				}
			}
			// Either start brings the deadline back.
			f.Opened = t0.Add(-day)
			d := Decide(f, p, t0)
			if want := f.Opened.Add(7 * day); d.Outcome != Wait || !d.Deadline.Equal(want) {
				t.Fatalf("with an opened time: %q, deadline %v, want wait until %v", d.Outcome, d.Deadline, want)
			}
			if got := Decide(f, p, d.Deadline); got.Outcome != Person || got.Reasons[0] != tc.gaveUp {
				t.Fatalf("at the deadline: %q %v, want person with %q", got.Outcome, got.Reasons, tc.gaveUp)
			}
		})
	}
	// One update with a time is a start, also without Opened.
	f := pr(GoModules, update(40*day, read(ReadNone)), update(hour, noClock))
	f.Opened = time.Time{}
	wantOutcome(t, Decide(f, p, t0), Person, ReasonReadDeadline, ReasonSourceDeadline)
}

// Opened is not a fact: it can move the deadline later and do nothing
// else. Unknown, the deadline is the spec's literal one.
func TestOpenedOnlyMovesTheDeadline(t *testing.T) {
	p := testPolicy()

	unread := pr(GoModules, update(40*day, read(ReadNone)))
	unread.Opened = time.Time{}
	d := Decide(unread, p, t0)
	// 40 days old, required at 72 hours: the literal deadline passed
	// 30 days ago.
	wantOutcome(t, d, Person, ReasonReadDeadline)
	wantOutcome(t, Decide(unread, p, t0.Add(-37*day+7*day-1)), Wait, ReasonReadPending)

	r := rand.New(rand.NewPCG(6, 6))
	for i := 0; i < 20000; i++ {
		f, pol := randomPR(r), randomPolicy(r)
		now := t0.Add(time.Duration(r.Int64N(int64(30*day))) - 10*day)
		without := clonePR(f)
		without.Opened = time.Time{}
		d0, d := Decide(without, pol, now), Decide(f, pol, now)
		switch {
		case d0.Outcome == Merge || d.Outcome == Merge:
			// Opened never decides a merge either way.
			if d0.Outcome != d.Outcome {
				t.Fatalf("Opened changed a merge: %q without, %q with", d0.Outcome, d.Outcome)
			}
		case d0.Outcome == Wait && !d0.Deadline.IsZero() && d.Outcome != Wait:
			// A wait that had no deadline for want of a start is the one
			// that Opened may end: it is the start.
			t.Fatalf("Opened ended a wait: %q", d.Outcome)
		}
		if d0.Outcome != Person && d.Outcome != Person {
			if !d.NotBefore.Equal(d0.NotBefore) {
				t.Fatalf("Opened moved the merge time: %v, %v", d0.NotBefore, d.NotBefore)
			}
			if d.Deadline.Before(d0.Deadline) {
				t.Fatalf("Opened moved the deadline earlier: %v, %v", d0.Deadline, d.Deadline)
			}
		}
	}
}

func TestChecksRefused(t *testing.T) {
	p := testPolicy()
	f := pr(GoModules, update(40*day))
	f.Opened = t0.Add(-day)
	d := Decide(f, p, t0)
	wantOutcome(t, d, Merge)
	deadline := f.Opened.Add(7 * day)
	if !d.Deadline.Equal(deadline) || !d.NotBefore.Equal(t0.Add(-37*day)) {
		t.Fatalf("deadline %v, not before %v", d.Deadline, d.NotBefore)
	}

	w := ChecksRefused(d, t0)
	wantOutcome(t, w, Wait, ReasonChecksPending)
	if !w.Deadline.Equal(deadline) || len(w.PerUpdate) != 1 {
		t.Fatalf("refused decision lost its deadline or updates: %+v", w)
	}
	wantOutcome(t, ChecksRefused(d, deadline.Add(-1)), Wait, ReasonChecksPending)
	wantOutcome(t, ChecksRefused(d, deadline), Person, ReasonChecksDeadline)
	wantOutcome(t, ChecksRefused(d, deadline.Add(day)), Person, ReasonChecksDeadline)

	// Only a merge can be refused.
	for _, other := range []Decision{
		Decide(pr(GoModules, update(hour)), p, t0),
		Decide(pr(GoModules, update(hour, major)), p, t0),
	} {
		if got := ChecksRefused(other, t0.Add(400*day)); !reflect.DeepEqual(got, other) {
			t.Fatalf("ChecksRefused changed a %q decision", other.Outcome)
		}
	}
	// A merge decision that carries no deadline did not come from Decide.
	wantOutcome(t, ChecksRefused(Decision{Outcome: Merge}, t0), Person, ReasonChecksDeadline)
}

func TestListed(t *testing.T) {
	p := testPolicy()
	tests := []struct {
		ecosystem string
		name      string
		want      bool
	}{
		// A namespace entry ("golang.org/x/").
		{GoModules, "golang.org/x/net", true},
		{GoModules, "golang.org/x/crypto/x509roots/fallback", true},
		{GoModules, "golang.org/x/", false},
		{GoModules, "golang.org/x", false},
		{GoModules, "golang.org/xnet", false},
		{GoModules, "golang.org/y/net", false},
		{GoModules, "evil.example/golang.org/x/net", false},
		{GoModules, "Golang.org/x/net", false},
		{GoModules, "github.com/aws/aws-sdk-go-v2", true},
		{GoModules, "github.com/aws-evil/aws-sdk-go-v2", false},
		{GoModules, "github.com/awsx/y", false},
		{GoModules, "github.com/Azure/azure-sdk-for-go/sdk/azcore", true},
		{GoModules, "github.com/azure/azure-sdk-for-go", false},
		{GoModules, "go.opentelemetry.io/otel", true},
		{GoModules, "go.opentelemetry.io.evil.example/otel", false},
		// A name entry without a trailing slash ("cloud.google.com/go").
		{GoModules, "cloud.google.com/go", true},
		{GoModules, "cloud.google.com/go/storage", true},
		{GoModules, "cloud.google.com/gopherx", false},
		{GoModules, "cloud.google.com/go-evil", false},
		{GoModules, "cloud.google.com/g", false},
		{GoModules, "cloud.google.com", false},
		{GoModules, unlistedName, false},
		{GoModules, "", false},

		{GitHubActions, "actions/checkout", true},
		{GitHubActions, "actions/cache/restore", true},
		{GitHubActions, "actions-evil/x", false},
		{GitHubActions, "actions", false},
		{GitHubActions, "actions/", false},
		{GitHubActions, "Actions/checkout", false},
		{GitHubActions, "github/codeql-action/init", true},
		{GitHubActions, "docker/login-action", true},
		{GitHubActions, "astral-sh/setup-uv", true},
		{GitHubActions, "astral-sh-fork/setup-uv", false},
		{GitHubActions, "example-org/setup-tool", false},
		{GitHubActions, "x/actions/checkout", false},

		{Docker, "docker.io/library/golang", true},
		{Docker, "docker.io/libraryx/y", false},
		{Docker, "docker.io/library", false},
		{Docker, "docker.io/evil/golang", false},
		{Docker, "gcr.io/distroless/static-debian12", true},
		{Docker, "gcr.io/distroless-evil/static", false},
		{Docker, "golang", false}, // the gatherer writes the registry out

		{NPM, "tailwindcss", true},
		{NPM, "tailwindcss-evil", false},
		{NPM, "tailwindcs", false},
		{NPM, "@tailwindcss/oxide", true},
		{NPM, "@tailwindcss/oxide-wasm32-wasi", true},
		{NPM, "@tailwindcss-evil/oxide", false},
		{NPM, "@tailwindcss", false},
		{NPM, "@tailwindcss/", false},
		{NPM, "esbuild", false},

		// Each ecosystem has its own list, and an unknown one has none.
		{NPM, "golang.org/x/net", false},
		{GoModules, "tailwindcss", false},
		{"uv", "tailwindcss", false},
		{"", "golang.org/x/net", false},
	}
	for _, tc := range tests {
		if got := Listed(p, tc.ecosystem, tc.name); got != tc.want {
			t.Errorf("Listed(%s, %q) = %v, want %v", tc.ecosystem, tc.name, got, tc.want)
		}
	}

	// Empty and rooted entries match nothing, and "*" is a character, not
	// a wildcard.
	bad := Policy{Listed: map[string][]string{GoModules: {"", "/", "/x", "*", "golang.org/*", "golang.org/x/*"}}}
	for _, name := range []string{"golang.org/x/net", "/x/y", "/x", "x", "/", "golang.org/y", "anything"} {
		if Listed(bad, GoModules, name) {
			t.Errorf("a degenerate entry lists %q", name)
		}
	}
	if Listed(Policy{}, GoModules, "golang.org/x/net") {
		t.Error("the zero policy lists something")
	}
}

func TestFactHelpers(t *testing.T) {
	if f := Yes("v", "s"); !f.Holds() || !f.Gathered() {
		t.Error("Yes")
	}
	if f := No("v", "s"); f.Holds() || !f.Gathered() {
		t.Error("No")
	}
	if f := (Fact{OK: true, Value: "v"}); f.Holds() || f.Gathered() {
		t.Error("a fact without a source")
	}
	if (Fact{}).Holds() || (Fact{}).Gathered() || (TimeFact{}).Known() {
		t.Error("zero facts")
	}
	if f := Unavailable("v", "s"); f.Holds() || f.Gathered() || !f.Unavailable || f.OK {
		t.Error("Unavailable")
	}
	if f := (Fact{OK: true, Unavailable: true, Value: "v", Source: "s"}); f.Holds() || f.Gathered() {
		t.Error("an unavailable fact that also says yes")
	}
	if tf := UnavailableTime("v", "s"); tf.Known() || !tf.unavailable() {
		t.Error("UnavailableTime")
	}
	if tf := (TimeFact{OK: true, Unavailable: true, Time: t0, Source: "s"}); tf.Known() {
		t.Error("an unavailable time that also has a time")
	}
	if (TimeFact{Unavailable: true}).unavailable() {
		t.Error("unavailable from nowhere")
	}

	// And: both must hold; otherwise the one that settles more, and the
	// first of two that are level.
	yes, yes2 := Yes("a", "s1"), Yes("b", "s2")
	no, no2 := No("no", "s3"), No("no too", "s4")
	missing := Fact{Value: "unreadable answer"}
	down := Unavailable("HTTP 503", "s5")
	if got := yes.And(yes2); got != Yes("a; b", "s1; s2") {
		t.Errorf("yes and yes: %+v", got)
	}
	for _, tc := range []struct {
		name string
		a, b Fact
		want Fact
	}{
		{"yes, no", yes, no, no},
		{"no, yes", no, yes, no},
		{"no, no", no, no2, no},
		{"yes, missing", yes, missing, missing},
		{"missing, yes", missing, yes, missing},
		{"yes, unavailable", yes, down, down},
		{"unavailable, yes", down, yes, down},
		{"unavailable, no: the no is not hidden", down, no, no},
		{"no, unavailable", no, down, no},
		{"missing, no", missing, no, no},
		{"unavailable, missing: waiting cannot help", down, missing, missing},
		{"missing, unavailable", missing, down, missing},
		{"yes, the zero fact", yes, Fact{}, Fact{}},
	} {
		if got := tc.a.And(tc.b); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
		if tc.a.And(tc.b).Holds() {
			t.Errorf("%s holds", tc.name)
		}
	}
	at := At(t0, "registry")
	if !at.Known() || at.Value != "2026-11-22T12:00:00Z" {
		t.Errorf("At: %+v", at)
	}
	if At(time.Time{}, "registry").Known() {
		t.Error("the zero time is known")
	}
}

// ---- random records ----

// usually returns true with probability p.
func usually(r *rand.Rand, p float64) bool { return r.Float64() < p }

// randomFact is a good fact most of the time, and otherwise one of the
// ways a fact can be false, unavailable or never gathered.
func randomFact(r *rand.Rand, good float64) Fact {
	if usually(r, good) {
		return Yes("yes", "source")
	}
	switch r.IntN(6) {
	case 0:
		return No("no", "source")
	case 1:
		return Fact{OK: true, Value: "yes, says nobody"}
	case 2:
		return Unavailable("no answer", "source")
	case 3:
		return Fact{OK: true, Unavailable: true, Value: "no answer, and yes", Source: "source"}
	case 4:
		return Fact{Unavailable: true, Value: "no answer, says nobody"}
	}
	return Fact{}
}

// randomAnswer is a gathered yes or no, and now and then nothing or no
// answer.
func randomAnswer(r *rand.Rand, yes float64) Fact {
	if usually(r, 0.02) {
		return Fact{}
	}
	if usually(r, 0.01) {
		return Unavailable("no answer", "source")
	}
	if usually(r, yes) {
		return Yes("yes", "source")
	}
	return No("no", "source")
}

func randomTime(r *rand.Rand, known float64, within time.Duration) TimeFact {
	if !usually(r, known) {
		switch r.IntN(5) {
		case 0:
			return TimeFact{OK: true, Time: t0.Add(-within)}
		case 1:
			return TimeFact{OK: true, Source: "registry"}
		case 2:
			return UnavailableTime("no answer", "registry")
		case 3:
			return TimeFact{OK: true, Unavailable: true, Time: t0.Add(-within), Source: "registry"}
		}
		return TimeFact{}
	}
	return At(t0.Add(-time.Duration(r.Int64N(int64(within)))), "registry")
}

func randomRead(r *rand.Rand) ReadState {
	states := []ReadState{ReadFull, ReadFull, ReadFull, ReadPartial, ReadPartial, ReadNone, ReadNone, ReadNotApplicable, ReadRefused, "", "FULL"}
	return states[r.IntN(len(states))]
}

func randomVeto(r *rand.Rand) *Veto {
	if usually(r, 0.8) {
		return nil
	}
	categories := []string{"exfiltration", "injection_text", VetoModelRefused, "", "no_veto"}
	return &Veto{Category: categories[r.IntN(len(categories))], Quotes: []string{"a line"}, Notes: "a note"}
}

var randomNames = map[string][]string{
	GoModules:     {"golang.org/x/net", "cloud.google.com/go/storage", "github.com/kr/text", "modernc.org/sqlite"},
	NPM:           {"tailwindcss", "@tailwindcss/oxide", "esbuild", "chart.js"},
	GitHubActions: {"actions/checkout", "docker/login-action", "example-org/setup-tool"},
	Docker:        {"docker.io/library/golang", "gcr.io/distroless/static-debian12", "ghcr.io/example/app"},
	"uv":          {"requests"},
}

func randomPR(r *rand.Rand) PRFacts {
	ecosystems := []string{GoModules, GoModules, GoModules, NPM, NPM, GitHubActions, Docker, Docker, "uv"}
	eco := ecosystems[r.IntN(len(ecosystems))]
	f := PRFacts{
		Ecosystem:        eco,
		Identity:         randomFact(r, 0.985),
		Shape:            randomFact(r, 0.985),
		ChecksConfigured: randomFact(r, 0.985),
	}
	if usually(r, 0.9) {
		f.Opened = t0.Add(-time.Duration(r.Int64N(int64(20 * day))))
	}
	policy := testPolicy()
	for n := r.IntN(4); n >= 0; n-- {
		if n == 0 && usually(r, 0.02) {
			break // now and then, no update at all
		}
		names := randomNames[eco]
		u := UpdateFacts{
			Name:        names[r.IntN(len(names))],
			From:        "1.0.0",
			To:          "1.1.0",
			Increase:    randomFact(r, 0.985),
			Bound:       randomFact(r, 0.985),
			Clean:       randomFact(r, 0.985),
			NoRegress:   randomFact(r, 0.985),
			NewName:     randomAnswer(r, 0.15),
			Major:       randomAnswer(r, 0.15),
			Indirect:    randomFact(r, 0.4),
			SecurityFix: randomAnswer(r, 0.3),
			FirstSeen:   randomTime(r, 0.985, 30*day),
			NameCreated: randomTime(r, 0.9, 800*day),
			Read:        randomRead(r),
			Veto:        randomVeto(r),
		}
		// Listed and Known are truthful most of the time.
		isListed := Listed(policy, eco, u.Name)
		if usually(r, 0.03) {
			isListed = !isListed
		}
		u.Listed = No("no", "policy")
		if isListed {
			u.Listed = Yes("yes", "policy")
		}
		isKnown := !u.NewName.OK || isListed
		if usually(r, 0.03) {
			isKnown = !isKnown
		}
		u.Known = No("no", "base")
		if isKnown {
			u.Known = Yes("yes", "base")
		}
		if usually(r, 0.01) {
			u.Listed = Fact{}
		}
		if usually(r, 0.01) {
			u.Known = Fact{}
		}
		if usually(r, 0.01) {
			u.Name = ""
		}
		f.Updates = append(f.Updates, u)
	}
	return f
}

func randomPolicy(r *rand.Rand) Policy {
	p := testPolicy()
	if usually(r, 0.6) {
		return p
	}
	if usually(r, 0.05) {
		return Policy{}
	}
	age := func() time.Duration { return time.Duration(1 + r.Int64N(int64(40*day))) }
	if usually(r, 0.5) {
		p.MinAge, p.UnreadAge, p.MajorAge = age(), age(), age()
	}
	if usually(r, 0.3) {
		p.NewNameAge = age() * 10
	}
	if usually(r, 0.3) {
		p.WaitDeadline = age()
	}
	p.FastPath = usually(r, 0.7)
	if usually(r, 0.4) {
		p.Companions = CompanionsWait
	}
	if usually(r, 0.1) {
		p.Listed = nil
	}
	return p
}

// ---- amendment 60: the gate owner's own workflows ----

// ownName is the one repository ownPolicy calls the gate owner's own.
const ownName = "acme-infra/ci"

// ownPolicy is testPolicy with an own list of one made-up repository.
func ownPolicy() Policy {
	p := testPolicy()
	p.Own = []OwnRepo{{Repository: ownName, RepositoryID: 4242, OwnerID: 77}}
	return p
}

// ownUpdate is the commit pin of an own workflow as the Actions gatherer
// and wire.Join hand it to Decide: every fact about where the commit
// comes from holds, nothing was read, and nothing dates it.
func ownUpdate(mods ...func(*UpdateFacts)) UpdateFacts {
	u := UpdateFacts{
		Name: ownName, From: "v1.2.3", To: "v1.3.0",
		Known:       Yes("replaced in place", "the workflow"),
		Listed:      No("matches no list entry", "policy"),
		NewName:     No("replaced in place", "the workflow"),
		Increase:    Yes("v1.2.3 -> v1.3.0", "the workflow"),
		Major:       No("both v1", "the workflow"),
		Bound:       Yes("tag v1.3.0 is the pinned commit; repository 4242 of owner 77", "GitHub"),
		Clean:       Yes("no advisory", "advisories"),
		NoRegress:   Yes("ahead of the old pin; on branch main", "GitHub"),
		SecurityFix: No("no advisory names v1.3.0", "advisories"),
		Own:         Yes(ownName+" is on the own list", "policy"),
		Read:        ReadNotApplicable,
	}
	for _, mod := range mods {
		mod(&u)
	}
	return u
}

// Own (spec section 11, amendment 60): the commit pin of a reusable
// workflow in a repository on the policy's own list merges on where its
// commit comes from, with nothing read and no age. Every other fact must
// hold as for any update, a major is a person's, and a name the policy
// Decide was given does not have is not own whatever the fact says.
func TestOwn(t *testing.T) {
	p := ownPolicy()
	// A repository's name on the owner-kept list as well, as a prefix.
	listedToo := ownPolicy()
	listedToo.Listed = map[string][]string{GitHubActions: {"acme-infra/"}}
	isListed := func(u *UpdateFacts) { u.Listed = Yes("acme-infra/", "policy") }
	named := func(name string) func(*UpdateFacts) { return func(u *UpdateFacts) { u.Name = name } }

	for _, tc := range []struct {
		name    string
		policy  Policy
		eco     string
		u       UpdateFacts
		want    Outcome
		reasons []Reason
	}{
		{"merges at once, unread and undated", p, GitHubActions, ownUpdate(), Merge, nil},
		{"published this instant", p, GitHubActions, ownUpdate(func(u *UpdateFacts) { u.FirstSeen = At(t0, "the gate's own clock") }), Merge, nil},
		{"also listed, a minor", listedToo, GitHubActions, ownUpdate(isListed), Merge, nil},

		// The name is Decide's own policy's to say, whole and byte for byte.
		{"a policy with no own list", testPolicy(), GitHubActions, ownUpdate(), Person, []Reason{ReasonListMismatch}},
		{"a look-alike owner", p, GitHubActions, ownUpdate(named("acme-1nfra/ci")), Person, []Reason{ReasonListMismatch}},
		{"a look-alike repository", p, GitHubActions, ownUpdate(named("acme-infra/c1")), Person, []Reason{ReasonListMismatch}},
		{"a name the entry is a prefix of", p, GitHubActions, ownUpdate(named("acme-infra/ci-tools")), Person, []Reason{ReasonListMismatch}},
		{"the owner alone", p, GitHubActions, ownUpdate(named("acme-infra")), Person, []Reason{ReasonListMismatch}},
		{"another repository of the owner", p, GitHubActions, ownUpdate(named("acme-infra/gate")), Person, []Reason{ReasonListMismatch}},
		{"the name in another case", p, GitHubActions, ownUpdate(named("Acme-infra/ci")), Person, []Reason{ReasonListMismatch}},
		{"the name with its workflow file", p, GitHubActions, ownUpdate(named(ownName + "/.github/workflows/lint.yml")), Person, []Reason{ReasonListMismatch}},

		// Every other fact, as for any update.
		{"not bound: the tag is another commit, or the IDs are not the list's", p, GitHubActions, ownUpdate(func(u *UpdateFacts) { u.Bound = No("tag v1.3.0 is another commit", "GitHub") }), Person, []Reason{ReasonNotBound}},
		{"not on the default branch, or not a descendant of the old pin", p, GitHubActions, ownUpdate(func(u *UpdateFacts) { u.NoRegress = No("not reachable from main", "GitHub") }), Person, []Reason{ReasonRegress}},
		{"not an increase", p, GitHubActions, ownUpdate(func(u *UpdateFacts) { u.Increase = No("v1.3.0 -> v1.3.0", "the workflow") }), Person, []Reason{ReasonNotIncrease}},
		{"an advisory names it", p, GitHubActions, ownUpdate(func(u *UpdateFacts) { u.Clean = No("malware advisory", "advisories") }), Person, []Reason{ReasonNotClean}},
		{"a veto, from wherever", p, GitHubActions, ownUpdate(func(u *UpdateFacts) { u.Veto = &Veto{Category: "obfuscation"} }), Person, []Reason{ReasonVeto}},
		{"Bound did not answer: it waits", p, GitHubActions, ownUpdate(func(u *UpdateFacts) { u.Bound = Unavailable("HTTP 503", "GitHub") }), Wait, []Reason{ReasonSourceUnavailable}},

		// A major is always the owner's, listed or not.
		{"a major", p, GitHubActions, ownUpdate(major), Person, []Reason{ReasonMajorOwn}},
		{"a major of a name that is also listed", listedToo, GitHubActions, ownUpdate(major, isListed), Person, []Reason{ReasonMajorOwn}},
		{"a major that is not known to be one", p, GitHubActions, ownUpdate(func(u *UpdateFacts) { u.Major = Fact{} }), Person, []Reason{ReasonFactMissing}},

		// Not-applicable is the one read state it has.
		{"a record that says it was read", p, GitHubActions, ownUpdate(read(ReadFull)), Person, []Reason{ReasonReadUnknown}},
		{"a record that says it was read in part", p, GitHubActions, ownUpdate(read(ReadPartial)), Person, []Reason{ReasonReadUnknown}},
		{"a record that says the read is still to come", p, GitHubActions, ownUpdate(read(ReadNone)), Person, []Reason{ReasonReadUnknown}},
		{"a record with no read", p, GitHubActions, ownUpdate(read("")), Person, []Reason{ReasonReadUnknown}},
		{"a read the gate refused", p, GitHubActions, ownUpdate(read(ReadRefused)), Person, []Reason{ReasonReadRefused}},

		// The fact means nothing in another ecosystem: unread and undated
		// is what it is there.
		{"a Go module", p, GoModules, ownUpdate(), Person, []Reason{ReasonReadUnknown, ReasonFirstSeenUnknown}},
		{"an npm package", p, NPM, ownUpdate(), Person, []Reason{ReasonReadUnknown, ReasonFirstSeenUnknown}},
		{"an image", p, Docker, ownUpdate(), Person, []Reason{ReasonNotKnown, ReasonFirstSeenUnknown}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantOutcome(t, Decide(pr(tc.eco, tc.u), tc.policy, t0), tc.want, tc.reasons...)
		})
	}

	// No age: the required age is zero whatever else the update is, and a
	// time the publish job gave it does not hold it back.
	d := Decide(pr(GitHubActions, ownUpdate(func(u *UpdateFacts) { u.FirstSeen = At(t0, "the gate's own clock") })), p, t0)
	if d.PerUpdate[0].RequiredAge != 0 || !d.NotBefore.Equal(t0) {
		t.Errorf("required age %v, not before %v; want none, and t0", d.PerUpdate[0].RequiredAge, d.NotBefore)
	}

	// Decided per update: beside an action that was read and is too young,
	// the pull request waits for the action alone.
	young := update(hour, func(u *UpdateFacts) { u.Name = "octo-tools/setup" })
	d = Decide(pr(GitHubActions, ownUpdate(), young), p, t0)
	wantOutcome(t, d, Wait, ReasonAge)
	if d.PerUpdate[0].Outcome != Merge || d.PerUpdate[1].Outcome != Wait || !d.NotBefore.Equal(t0.Add(71*hour)) {
		t.Errorf("per update %+v, not before %v", d.PerUpdate, d.NotBefore)
	}
	// And an action beside it is not excused its read or its age.
	wantOutcome(t, Decide(pr(GitHubActions, ownUpdate(), update(400*day, read(ReadNotApplicable))), p, t0), Person, ReasonReadUnknown)
	wantOutcome(t, Decide(pr(GitHubActions, ownUpdate(), update(400*day, func(u *UpdateFacts) { u.FirstSeen = TimeFact{} })), p, t0), Person, ReasonFirstSeenUnknown)
}

// An own workflow that merges still has every fact but the two the rule
// waives: blanking any other field of the record is a person's.
func TestOwnNeedsEveryOtherFact(t *testing.T) {
	p := ownPolicy()
	base := pr(GitHubActions, ownUpdate())
	wantOutcome(t, Decide(base, p, t0), Merge)

	waived := map[string]string{
		"FirstSeen": "no age is asked of an own workflow",
		"Veto":      "nil already",
	}
	updateType := reflect.TypeOf(UpdateFacts{})
	for i := 0; i < updateType.NumField(); i++ {
		field := updateType.Field(i).Name
		f := clonePR(base)
		fv := reflect.ValueOf(&f.Updates[0]).Elem().Field(i)
		if fv.IsZero() || waived[field] != "" {
			// Unset in the record that merges (From aside, nothing in it
			// is): NameCreated, Indirect, Superseded.
			continue
		}
		fv.SetZero()
		d := Decide(f, p, t0)
		if field == "From" {
			// Decides nothing, as for every update.
			wantOutcome(t, d, Merge)
			continue
		}
		if d.Outcome != Person {
			t.Errorf("UpdateFacts.%s blank: %q %v, want person", field, d.Outcome, d.Reasons)
		}
	}
	prType := reflect.TypeOf(PRFacts{})
	for i := 0; i < prType.NumField(); i++ {
		field := prType.Field(i).Name
		if exemptPR[field] != "" {
			continue
		}
		f := clonePR(base)
		reflect.ValueOf(&f).Elem().Field(i).SetZero()
		if d := Decide(f, p, t0); d.Outcome != Person {
			t.Errorf("PRFacts.%s blank: %q %v, want person", field, d.Outcome, d.Reasons)
		}
	}

	// The same over random records: whatever else is in one, an own
	// workflow that merges has every fact that must hold, an answer for
	// every yes/no fact, no veto, no major, the one read state, and a name
	// on the policy's own list.
	r := rand.New(rand.NewPCG(60, 2))
	merges := 0
	for i := 0; i < 40000; i++ {
		f, policy := randomPR(r), randomPolicy(r)
		policy.Own = p.Own
		f.Ecosystem = GitHubActions
		for k := range f.Updates {
			u := &f.Updates[k]
			u.Own = Yes("own", "policy")
			if usually(r, 0.9) {
				u.Name = ownName
				u.Listed = No("no", "policy")
			}
			if usually(r, 0.8) {
				u.Read, u.Veto = ReadNotApplicable, nil
			}
			if usually(r, 0.9) {
				u.Known, u.NewName = Yes("yes", "base"), No("no", "base")
			}
		}
		now := t0.Add(time.Duration(r.Int64N(int64(30*day))) - 10*day)
		if Decide(f, policy, now).Outcome != Merge {
			continue
		}
		merges++
		if !f.Identity.Holds() || !f.Shape.Holds() || !f.ChecksConfigured.Holds() || len(f.Updates) == 0 {
			t.Fatalf("merged without a pull request fact: %+v", f)
		}
		for _, u := range f.Updates {
			switch {
			case u.Name != ownName:
				t.Fatalf("merged a name that is not on the own list: %+v", u)
			case !u.Increase.Holds(), !u.Bound.Holds(), !u.Clean.Holds(), !u.NoRegress.Holds(), !u.Known.Holds():
				t.Fatalf("merged without a fact that must hold: %+v", u)
			case !u.Listed.Gathered(), !u.NewName.Gathered(), !u.Major.Gathered(), !u.SecurityFix.Gathered():
				t.Fatalf("merged without an answer: %+v", u)
			case u.Major.Holds():
				t.Fatalf("merged a major: %+v", u)
			case u.Veto != nil:
				t.Fatalf("merged over a veto: %+v", u)
			case u.Read != ReadNotApplicable:
				t.Fatalf("merged with a read state an own workflow does not have: %+v", u)
			}
		}
	}
	if merges < 1000 {
		t.Fatalf("only %d of the random records merged", merges)
	}
}

// Own counts only when it holds, and only for an action: every other
// state of the fact, and the fact in any other ecosystem, is decided as
// "not own". Nothing waits for it.
func TestOwnNotHolding(t *testing.T) {
	set := func(f PRFacts, fact Fact) PRFacts {
		out := clonePR(f)
		for k := range out.Updates {
			out.Updates[k].Own = fact
		}
		return out
	}
	r := rand.New(rand.NewPCG(60, 3))
	changed := 0
	for i := 0; i < 30000; i++ {
		f, p := randomPR(r), randomPolicy(r)
		p.Own = ownPolicy().Own
		for k := range f.Updates {
			if usually(r, 0.5) {
				f.Updates[k].Name = ownName
			}
		}
		now := t0.Add(time.Duration(r.Int64N(int64(30*day))) - 10*day)

		notOwn := Decide(set(f, No("not own", "policy")), p, now)
		for what, fact := range map[string]Fact{
			"unset":                        {},
			"unavailable":                  Unavailable("no answer", "policy"),
			"true without a source":        {OK: true, Value: "yes"},
			"true and unavailable":         {OK: true, Unavailable: true, Value: "yes", Source: "policy"},
			"unavailable without a source": {Unavailable: true, Value: "no answer"},
		} {
			if d := Decide(set(f, fact), p, now); !reflect.DeepEqual(d, notOwn) {
				t.Fatalf("case %d: Own %s is not decided as not own: %q %v, want %q %v", i, what, d.Outcome, d.Reasons, notOwn.Outcome, notOwn.Reasons)
			}
		}
		holding := Decide(set(f, Yes("own", "policy")), p, now)
		if f.Ecosystem != GitHubActions {
			if !reflect.DeepEqual(holding, notOwn) {
				t.Fatalf("case %d: Own changed a decision in %s: %q %v, want %q %v", i, f.Ecosystem, holding.Outcome, holding.Reasons, notOwn.Outcome, notOwn.Reasons)
			}
			continue
		}
		if !reflect.DeepEqual(holding, notOwn) {
			changed++
		}
	}
	// The property is empty unless Own sometimes decides.
	if changed < 500 {
		t.Fatalf("Own changed the decision of only %d random records", changed)
	}
}

// The own list matches a whole name, byte for byte.
func TestOwnRepository(t *testing.T) {
	p := ownPolicy()
	if o, ok := OwnRepository(p, ownName); !ok || o.RepositoryID != 4242 || o.OwnerID != 77 {
		t.Errorf("OwnRepository(%q) = %+v, %v", ownName, o, ok)
	}
	for _, name := range []string{"", "acme-infra", "acme-infra/", "acme-infra/ci/", "acme-infra/ci-tools", "acme-infra/c", "Acme-Infra/ci", "acme-infra/CI",
		"acme-1nfra/ci", "acme-infra/c1", " acme-infra/ci", "acme-infra/ci ", "acme-infra/ci/.github/workflows/lint.yml", "other/acme-infra/ci"} {
		if o, ok := OwnRepository(p, name); ok {
			t.Errorf("OwnRepository(%q) = %+v: only the whole name is on the list", name, o)
		}
	}
	// An entry with no name matches nothing, and neither does a policy
	// with no list.
	if _, ok := OwnRepository(Policy{Own: []OwnRepo{{RepositoryID: 1, OwnerID: 1}}}, ""); ok {
		t.Error("an entry with no name matched the empty name")
	}
	if _, ok := OwnRepository(testPolicy(), ownName); ok {
		t.Error("a policy with no own list has an own repository")
	}
}

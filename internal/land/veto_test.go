package land

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/wire"
)

// headC is a third head, for a pull request that is rebased twice.
var headC = strings.Repeat("c", 40)

// moveTo puts the pull request of the fake at head, as a rebase does: the
// facts, and so the content keys, stay what they were.
func moveTo(f *fakeGitHub, facts *wire.Facts, head string) {
	facts.PullRequest.Head = head
	f.pulls = []string{pullJSON(testPR, "open", head, "main", "clean", false)}
}

// remembersVeto fails the test unless the gate's comment still remembers
// a veto for key.
func remembersVeto(t *testing.T, f *fakeGitHub, what, key string) {
	t.Helper()
	m, ok := parseMarker(f.gateComment(testPR))
	if !ok || !slices.ContainsFunc(m.Cache, func(c cached) bool { return c.Key == key && c.Veto != nil }) {
		t.Errorf("%s: the comment no longer remembers the veto: %+v", what, m.Cache)
	}
}

// TestAnswers is the table of answers: which verdict counts for a content
// key, by what the gate's comment remembers and what this run's verdicts
// file says (spec section 11, amendment 63). Any veto wins, in both
// directions.
func TestAnswers(t *testing.T) {
	_, reviewer := defaults(t)
	other := strings.Repeat("0", 64)
	old := &allow.Veto{Category: "exfiltration", Quotes: []string{"remembered"}}
	now := &allow.Veto{Category: "obfuscation", Quotes: []string{"this run's"}}
	this := func(read allow.ReadState, veto *allow.Veto) *wire.Verdict {
		return &wire.Verdict{Key: keyA, Fingerprint: reviewer, Read: read, Veto: veto}
	}
	remembered := func(fingerprint string, veto *allow.Veto) marker {
		return marker{Fingerprint: fingerprint, Cache: []cached{{Key: keyA, Read: allow.ReadPartial, Veto: veto}}}
	}
	stands := &wire.Verdict{Key: keyA, Fingerprint: reviewer, Read: allow.ReadPartial, Veto: old}
	recalled := &wire.Verdict{Key: keyA, Fingerprint: reviewer, Read: allow.ReadPartial}
	for _, tc := range []struct {
		name string
		old  marker
		file *wire.Verdict // nil: the file has no entry for the key
		// want is the entry that counts on an event's run, and scheduled
		// the one on a scheduled run; nil: no entry.
		want, scheduled *wire.Verdict
		stood           bool
	}{
		{"a remembered veto, and this run says nothing", remembered(reviewer, old), nil, stands, stands, true},
		{"a remembered veto, and this run got no answer", remembered(reviewer, old), this(allow.ReadNone, nil), stands, stands, true},
		{"a remembered veto, and the reviewer will not take the read now", remembered(reviewer, old), this(allow.ReadRefused, nil), stands, stands, true},
		{"a remembered veto, and this run says no veto", remembered(reviewer, old), this(allow.ReadFull, nil), stands, stands, true},
		{"a remembered veto, and this run objects again", remembered(reviewer, old), this(allow.ReadFull, now), this(allow.ReadFull, now), this(allow.ReadFull, now), false},

		{"a remembered clean read, and this run objects", remembered(reviewer, nil), this(allow.ReadFull, now), this(allow.ReadFull, now), this(allow.ReadFull, now), false},
		{"a remembered clean read, and this run says no veto", remembered(reviewer, nil), this(allow.ReadFull, nil), this(allow.ReadFull, nil), this(allow.ReadFull, nil), false},
		{"a remembered clean read, and the reviewer will not take the read now", remembered(reviewer, nil), this(allow.ReadRefused, nil), this(allow.ReadRefused, nil), this(allow.ReadRefused, nil), false},
		// An event's run asks the model, and a clean answer of an earlier
		// run does not stand in for the one it did not get. The scheduled
		// run does not ask about a read that has an answer, and takes the
		// remembered one.
		{"a remembered clean read, and this run got no answer", remembered(reviewer, nil), this(allow.ReadNone, nil), this(allow.ReadNone, nil), recalled, false},
		{"a remembered clean read, and this run says nothing", remembered(reviewer, nil), nil, nil, recalled, false},

		{"nothing remembered, and this run objects", marker{}, this(allow.ReadFull, now), this(allow.ReadFull, now), this(allow.ReadFull, now), false},
		{"nothing remembered, and this run says no veto", marker{}, this(allow.ReadFull, nil), this(allow.ReadFull, nil), this(allow.ReadFull, nil), false},
		{"nothing remembered, and this run got no answer", marker{}, this(allow.ReadNone, nil), this(allow.ReadNone, nil), this(allow.ReadNone, nil), false},
		{"nothing remembered, and this run says nothing", marker{}, nil, nil, nil, false},

		// Another prompt or model is another question: what gets past a
		// veto besides a person and other content, and what a clean
		// verdict does not outlive either.
		{"a veto remembered under another fingerprint", remembered(other, old), this(allow.ReadFull, nil), this(allow.ReadFull, nil), this(allow.ReadFull, nil), false},
		{"a veto remembered under another fingerprint, and this run says nothing", remembered(other, old), nil, nil, nil, false},
		{"a clean read remembered under another fingerprint", remembered(other, nil), nil, nil, nil, false},
	} {
		for _, scheduled := range []bool{false, true} {
			name, want := tc.name+", on an event", tc.want
			if scheduled {
				name, want = tc.name+", on the schedule", tc.scheduled
			}
			t.Run(name, func(t *testing.T) {
				file := wire.Verdicts{Version: wire.Version}
				if tc.file != nil {
					file.Verdicts = append(file.Verdicts, *tc.file)
				}
				// A verdict under another fingerprint is nobody's answer here.
				file.Verdicts = append(file.Verdicts, wire.Verdict{Key: keyB, Fingerprint: other, Read: allow.ReadFull})
				got, stood := answers(file, tc.old, reviewer, scheduled)
				var wanted []wire.Verdict
				if want != nil {
					wanted = append(wanted, *want)
				}
				if !reflect.DeepEqual(append([]wire.Verdict(nil), got.Verdicts...), wanted) {
					t.Errorf("verdicts %+v, want %+v", got.Verdicts, wanted)
				}
				if stood[keyA] != tc.stood || len(stood) > 1 {
					t.Errorf("stood %v, want the key in it: %t", stood, tc.stood)
				}
				if _, err := wire.EncodeVerdicts(got); err != nil {
					t.Errorf("the result is not a verdicts file: %v", err)
				}
			})
		}
	}
}

// TestVetoStands: a veto the gate recorded is not taken back by a later
// run (spec section 11, amendment 63). Dependabot rebases, the content and
// so its key stay, and the model, asked again, may answer anything: the
// pull request stays a person's and nothing is merged.
func TestVetoStands(t *testing.T) {
	_, reviewer := defaults(t)
	for _, tc := range []struct {
		name string
		// verdicts is what the review job hands publish at the new head.
		verdicts func(*testing.T) *wire.Verdicts
		stood    bool // the comment names the veto as a remembered one
	}{
		{"the model answers no veto", clean, true},
		{"the review job wrote no file", noVerdicts, true},
		{"the model did not answer", func(t *testing.T) *wire.Verdicts {
			v := clean(t)
			v.Verdicts[0].Read = allow.ReadNone
			return v
		}, true},
		{"the reviewer will not take the read", func(t *testing.T) *wire.Verdicts {
			v := clean(t)
			v.Verdicts[0].Read = allow.ReadRefused
			return v
		}, true},
		{"the model objects again", vetoed("obfuscation", allow.ReadFull), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			rec := &recorder{}
			facts := goodFacts(t)
			res, err := publish(t, f.config(t0, rec), files(t, facts, vetoed("exfiltration", allow.ReadFull)(t)))
			if err != nil || res.Action != ActionPerson {
				t.Fatalf("the veto: %+v, %v", res, err)
			}
			remembersVeto(t, f, "after the veto", keyA)

			moveTo(f, &facts, headB)
			cfg := f.config(t0, rec)
			cfg.ModelAsked = true
			res, err = publish(t, cfg, files(t, facts, tc.verdicts(t)))
			if err != nil {
				t.Fatal(err)
			}
			if res.Action != ActionPerson || !slices.Contains(res.Decision.Reasons, allow.ReasonVeto) || f.count("PUT", "/merge") != 0 {
				t.Fatalf("after the rebase: %s %v with %d merge calls; want a person for the veto and none",
					res.Action, res.Decision.Reasons, f.count("PUT", "/merge"))
			}
			remembersVeto(t, f, "after the rebase", keyA)
			body := f.gateComment(testPR)
			if got := strings.Contains(body, stoodSource); got != tc.stood {
				t.Errorf("the comment names the veto as a remembered one: %t, want %t:\n%s", got, tc.stood, body)
			}
			if !strings.Contains(body, "The gate does not take a veto back") {
				t.Errorf("the comment does not say that the veto stands:\n%s", body)
			}

			// And again: no number of clean answers wears it down.
			moveTo(f, &facts, headC)
			if res, err = publish(t, f.config(t0, rec), files(t, facts, clean(t))); err != nil || res.Action != ActionPerson || f.count("PUT", "/merge") != 0 {
				t.Fatalf("after a second rebase: %+v, %v", res, err)
			}
			remembersVeto(t, f, "after a second rebase", keyA)
		})
	}

	// On the schedule too: whatever the second review job's file holds,
	// and with no file at all, the veto in the comment stands.
	for name, verdicts := range map[string]func(*testing.T) *wire.Verdicts{"that says no veto": clean, "that is not there": noVerdicts} {
		t.Run("on the schedule, with a verdicts file "+name, func(t *testing.T) {
			f := newFake(t)
			facts := goodFacts(t)
			if res, err := publish(t, f.config(t0, nil), files(t, facts, vetoed("exfiltration", allow.ReadFull)(t))); err != nil || res.Action != ActionPerson {
				t.Fatalf("the veto: %+v, %v", res, err)
			}
			moveTo(f, &facts, headB)
			cfg := f.config(t0, nil)
			cfg.Scheduled = true
			res, err := publish(t, cfg, files(t, facts, verdicts(t)))
			if err != nil || res.Action != ActionPerson || f.count("PUT", "/merge") != 0 {
				t.Fatalf("%+v, %v with %d merge calls", res, err, f.count("PUT", "/merge"))
			}
			remembersVeto(t, f, "after the scheduled run", keyA)
		})
	}

	// A run that failed in between keeps the veto too.
	t.Run("across a run that could not decide", func(t *testing.T) {
		f := newFake(t)
		facts := goodFacts(t)
		if res, err := publish(t, f.config(t0, nil), files(t, facts, vetoed("exfiltration", allow.ReadFull)(t))); err != nil || res.Action != ActionPerson {
			t.Fatalf("the veto: %+v, %v", res, err)
		}
		moveTo(f, &facts, headB)
		if err := Failed(context.Background(), f.config(t0, nil), testPR, headB, "In this run the fetch job ended failure.", Vetoes{}); err != nil {
			t.Fatal(err)
		}
		remembersVeto(t, f, "after the failed run", keyA)
		moveTo(f, &facts, headC)
		if res, err := publish(t, f.config(t0, nil), files(t, facts, clean(t))); err != nil || res.Action != ActionPerson || f.count("PUT", "/merge") != 0 {
			t.Fatalf("after the failed run: %+v, %v", res, err)
		}
	})

	// What does get past a veto: other content, and another reviewer.
	t.Run("other content merges, and the veto is still there for the old", func(t *testing.T) {
		f := newFake(t)
		facts := goodFacts(t)
		if res, err := publish(t, f.config(t0, nil), files(t, facts, vetoed("exfiltration", allow.ReadFull)(t))); err != nil || res.Action != ActionPerson {
			t.Fatalf("the veto: %+v, %v", res, err)
		}
		// Dependabot rewrites the pull request to a version with other
		// code, which the model has nothing against...
		moveTo(f, &facts, headB)
		facts.Facts.Updates[0].Prepared = preparedRead(0, keyB)
		other := &wire.Verdicts{Version: wire.Version, Verdicts: []wire.Verdict{{Key: keyB, Fingerprint: reviewer, Read: allow.ReadFull}}}
		// ...but its age is not reached yet, so it waits.
		facts.Facts.Updates[0].FirstSeen = allow.At(t0.Add(-1), "index.golang.org")
		if res, err := publish(t, f.config(t0, nil), files(t, facts, other)); err != nil || res.Action != ActionWait {
			t.Fatalf("other content: %+v, %v", res, err)
		}
		remembersVeto(t, f, "with other content", keyA)
		// Back to the code that was vetoed.
		moveTo(f, &facts, headC)
		facts.Facts.Updates[0].Prepared = preparedRead(0, keyA)
		if res, err := publish(t, f.config(t0, nil), files(t, facts, clean(t))); err != nil || res.Action != ActionPerson || f.count("PUT", "/merge") != 0 {
			t.Fatalf("back at the vetoed content: %+v, %v", res, err)
		}
	})
	t.Run("a veto under another reviewer fingerprint does not stand", func(t *testing.T) {
		f := newFake(t)
		m := marker{Outcome: ActionPerson, Head: headA, Fingerprint: strings.Repeat("0", 64),
			Cache: []cached{{Key: keyA, Read: allow.ReadFull, Veto: &allow.Veto{Category: "exfiltration", Quotes: []string{}}}}}
		f.comments[testPR] = []*fakeComment{{1, testBot, m.String() + "\n### dep-review: needs a person\n"}}
		res, err := publish(t, f.config(t0, nil), files(t, goodFacts(t), clean(t)))
		if err != nil || res.Action != ActionMerged {
			t.Fatalf("%+v, %v; want a merge: the prompt or the model changed, and the new one has no objection", res, err)
		}
	})
	t.Run("a veto in somebody else's comment is nobody's", func(t *testing.T) {
		f := newFake(t)
		m := marker{Outcome: ActionPerson, Head: headA, Fingerprint: reviewer,
			Cache: []cached{{Key: keyA, Read: allow.ReadFull, Veto: &allow.Veto{Category: "exfiltration", Quotes: []string{}}}}}
		f.comments[testPR] = []*fakeComment{{1, "mallory", m.String() + "\n### dep-review: needs a person\n"}}
		if res, err := publish(t, f.config(t0, nil), files(t, goodFacts(t), clean(t))); err != nil || res.Action != ActionMerged {
			t.Fatalf("%+v, %v; want a merge", res, err)
		}
	})
}

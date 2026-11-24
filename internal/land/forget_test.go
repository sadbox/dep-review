package land

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/wire"
)

// A veto is never forgotten because the marker is full (spec section 11,
// amendment 71). What the marker gives up, in order: clean entries from
// the end; then the quotes and notes of vetoes, from the last veto back;
// only then whole vetoes, and the marker then says so for good.

// fullVeto is a veto with as much text as the marker keeps, made of c.
func fullVeto(c string) *allow.Veto {
	text := strings.Repeat(c, maxCachedText/len(c))
	return &allow.Veto{Category: "exfiltration", Quotes: []string{text, text, text}, Notes: text}
}

func cacheKey(i int) string { return fmt.Sprintf("%064x", i) }

// withText reports whether a cached veto still has what the model wrote.
func withText(c cached) bool { return c.Veto != nil && (len(c.Veto.Quotes) > 0 || c.Veto.Notes != "") }

func TestMarkerKeepsVetoes(t *testing.T) {
	_, reviewer := defaults(t)
	base := marker{Outcome: ActionPerson, Head: headA, Fingerprint: reviewer}

	t.Run("clean entries go first", func(t *testing.T) {
		m := base
		for i := range 3 {
			m.Cache = append(m.Cache, cached{Key: cacheKey(i), Read: allow.ReadFull, Veto: fullVeto("q")})
		}
		for i := range 100 {
			m.Cache = append(m.Cache, cached{Key: cacheKey(100 + i), Read: allow.ReadFull})
		}
		got := m.fit()
		if len(got.String()) > maxMarkerBytes+40 || got.Forgot {
			t.Fatalf("marker of %d bytes, forgot %t", len(got.String()), got.Forgot)
		}
		for i := range 3 {
			if c := got.Cache[i]; c.Key != cacheKey(i) || !withText(c) || len(c.Veto.Quotes) != 3 {
				t.Errorf("veto %d: %+v, want it whole", i, c)
			}
		}
		if len(got.Cache) == 3 || len(got.Cache) == 103 {
			t.Errorf("%d entries kept, want the vetoes and some clean ones", len(got.Cache))
		}
		if !slices.Equal(keys(got.Cache), keys(m.Cache[:len(got.Cache)])) {
			t.Error("the clean entries kept are not the first ones")
		}
	})

	t.Run("then the text of vetoes, from the last back", func(t *testing.T) {
		m := base
		for i := range 20 {
			m.Cache = append(m.Cache, cached{Key: cacheKey(i), Read: allow.ReadPartial, Veto: fullVeto("q")})
		}
		got := m.fit()
		if len(got.Cache) != 20 || got.Forgot {
			t.Fatalf("%d of 20 vetoes kept, forgot %t", len(got.Cache), got.Forgot)
		}
		texts := 0
		for i, c := range got.Cache {
			if c.Key != cacheKey(i) || c.Veto == nil || c.Veto.Category != "exfiltration" || c.Read != allow.ReadPartial {
				t.Errorf("veto %d: %+v", i, c)
			}
			if withText(c) {
				if texts != i {
					t.Errorf("veto %d has its text and one before it does not", i)
				}
				texts++
			}
		}
		if texts == 0 || texts == 20 {
			t.Errorf("%d vetoes keep their text, want the first ones and not all", texts)
		}
		if !withText(m.Cache[19]) {
			t.Error("fit changed its receiver's vetoes")
		}
		back, ok := parseMarker(got.String())
		if !ok || len(back.Cache) != 20 || back.Forgot {
			t.Errorf("read back %d entries (ok %t, forgot %t)", len(back.Cache), ok, back.Forgot)
		}
	})

	t.Run("whole vetoes only when nothing else is left, and it says so", func(t *testing.T) {
		m := base
		for i := range maxCached {
			m.Cache = append(m.Cache, cached{Key: cacheKey(i), Read: allow.ReadFull, Veto: fullVeto("q")})
		}
		line := m.String()
		if len(line) > maxMarkerBytes+40 {
			t.Fatalf("marker line of %d bytes", len(line))
		}
		back, ok := parseMarker(line)
		if !ok || !back.Forgot || len(back.Cache) == 0 || len(back.Cache) == maxCached {
			t.Fatalf("read back %d entries (ok %t, forgot %t), want some, not all, and forgot", len(back.Cache), ok, back.Forgot)
		}
		for _, c := range back.Cache {
			if withText(c) {
				t.Errorf("%s keeps its text while whole vetoes were given up", c.Key)
			}
		}
		if !slices.Equal(keys(back.Cache), keys(m.Cache[:len(back.Cache)])) {
			t.Error("the vetoes kept are not the first ones")
		}
		t.Logf("%d vetoes without their text fit the marker", len(back.Cache))
	})

	t.Run("the boolean is carried and never cleared", func(t *testing.T) {
		m := base
		m.Forgot = true
		for _, next := range []marker{m.next(ActionWait, headB), m.next(ActionFailed, headA), m.next(ActionPerson, headC)} {
			if !next.Forgot {
				t.Errorf("next lost the boolean: %+v", next)
			}
		}
		back, ok := parseMarker(m.String())
		if !ok || !back.Forgot {
			t.Errorf("read back %+v (ok %t)", back, ok)
		}
	})
}

func keys(cache []cached) []string {
	var out []string
	for _, c := range cache {
		out = append(out, c.Key)
	}
	return out
}

// TestMarkerWorstText measures how many vetoes with full text fit, for
// text that JSON escapes the most. It is a measure, and the test fails
// only when not even one fits.
func TestMarkerWorstText(t *testing.T) {
	_, reviewer := defaults(t)
	least := maxCached
	for name, c := range map[string]string{"ASCII letters": "q", "<": "<", ">": ">", "&": "&", `"`: `"`, `\`: `\`, "a newline": "\n", "U+0001": "\x01", "U+001F": "\x1f", "U+2028": "\u2028"} {
		// whole is the most vetoes with full text a marker holds as they
		// are, with nothing else in it.
		whole := 0
		for k := 1; k <= maxCached; k++ {
			m := marker{Outcome: ActionPerson, Head: headA, Fingerprint: reviewer}
			for i := range k {
				m.Cache = append(m.Cache, cached{Key: cacheKey(i), Read: allow.ReadFull, Veto: fullVeto(c)})
			}
			if got := m.fit(); len(got.Cache) != k || !withText(got.Cache[k-1]) {
				break
			}
			whole = k
		}
		t.Logf("%s: %d vetoes with full text fit the marker", name, whole)
		least = min(least, whole)
	}
	t.Logf("worst case: %d", least)
	if least < 1 {
		t.Errorf("not one veto with full text fits")
	}
}

// What Decide keeps is what Act writes: Decide makes room for everything
// Act and a later run can still add to the marker, so the marker line is
// never cut again on the way out.
func TestDecideCutIsTheWrittenCut(t *testing.T) {
	_, reviewer := defaults(t)
	old := marker{Outcome: ActionWait, Head: headB, Fingerprint: reviewer, Asks: 1, AskedAt: t0}
	for i := range maxNotified - 1 {
		h := fmt.Sprintf("%040x", i)
		old.Notified, old.NotifiedFailed, old.NotifiedUnread = append(old.Notified, h), append(old.NotifiedFailed, h), append(old.NotifiedUnread, h)
	}
	var firstSeen []seen
	for i := range maxFirstSeen {
		firstSeen = append(firstSeen, seen{Pin: cacheKey(1000 + i), At: t0.Add(time.Duration(i) * time.Nanosecond)})
	}
	var cache []cached
	for i := range maxCached {
		cache = append(cache, cached{Key: cacheKey(i), Read: allow.ReadFull, Veto: fullVeto("\x01")})
	}
	kept, _ := fitted(old, headA, reviewer, firstSeen, cache)

	// Act, and then a Failed and a Tell, grow it as much as they can.
	mk := old.next(ActionRefused, headA)
	mk.Fingerprint, mk.Cache, mk.FirstSeen = reviewer, kept, firstSeen
	mk.NotBefore, mk.Deadline = t0.In(time.FixedZone("", -45*60)), t0.Add(123456789)
	mk.Asks, mk.AskedAt = maxAsks, t0.Add(987654321)
	for _, list := range []*[]string{&mk.Notified, &mk.NotifiedFailed, &mk.NotifiedUnread} {
		*list = append(*list, headA)
	}
	back, ok := parseMarker(mk.String())
	if !ok || len(back.Cache) != len(kept) || !slices.Equal(keys(back.Cache), keys(kept)) {
		t.Fatalf("written %d entries (ok %t), Decide kept %d", len(back.Cache), ok, len(kept))
	}
	for i := range kept {
		if withText(kept[i]) != withText(back.Cache[i]) {
			t.Fatalf("entry %d lost its text on the way out", i)
		}
	}
}

// vetoFacts is a pull request of n updates, each read under its own key,
// and a verdicts file that vetoes every one.
func vetoFacts(t *testing.T, n int) (wire.Facts, *wire.Verdicts) {
	t.Helper()
	_, reviewer := defaults(t)
	facts := goodFacts(t)
	facts.Facts.Updates = nil
	v := &wire.Verdicts{Version: wire.Version}
	for i := range n {
		u := goodUpdate(fmt.Sprintf("example.com/m%d", i))
		facts.Facts.Updates = append(facts.Facts.Updates, wire.NewUpdate(u, preparedRead(i, cacheKey(i))))
		v.Verdicts = append(v.Verdicts, wire.Verdict{Key: cacheKey(i), Fingerprint: reviewer, Read: allow.ReadFull, Veto: fullVeto("q")})
	}
	return facts, v
}

// More vetoes than the marker holds even without their text: it says so,
// and from then on the pull request is a person's, whatever a later run
// finds, on an event and on the schedule.
func TestVetoesForgotten(t *testing.T) {
	for _, n := range []int{maxCached, maxCached + 5} {
		t.Run(fmt.Sprintf("%d vetoes", n), func(t *testing.T) {
			f := newFake(t)
			facts, verdicts := vetoFacts(t, n)
			res, err := publish(t, f.config(t0, nil), files(t, facts, verdicts))
			if err != nil || res.Action != ActionPerson || res.Decision.Reasons[0] != allow.ReasonVetoesForgotten {
				t.Fatalf("%+v, %v; want a person's for vetoes_forgotten", res, err)
			}
			m, ok := parseMarker(f.gateComment(testPR))
			if !ok || !m.Forgot || len(m.Cache) == 0 {
				t.Fatalf("marker %+v (ok %t), want one that says it forgot", m, ok)
			}

			for _, scheduled := range []bool{false, true} {
				// A later run on other content, which the model has nothing
				// against.
				later := goodFacts(t)
				moveTo(f, &later, headB)
				cfg := f.config(t0, nil)
				cfg.Scheduled = scheduled
				res, err := publish(t, cfg, files(t, later, clean(t)))
				if err != nil || res.Action != ActionPerson || len(res.Decision.Reasons) == 0 || res.Decision.Reasons[0] != allow.ReasonVetoesForgotten {
					t.Fatalf("a later run (scheduled %t): %+v, %v; want a person's for vetoes_forgotten", scheduled, res, err)
				}
				if f.count("PUT", "/merge") != 0 {
					t.Fatal("merged")
				}
				if m, ok := parseMarker(f.gateComment(testPR)); !ok || !m.Forgot {
					t.Fatalf("the later run cleared the boolean: %+v (ok %t)", m, ok)
				}
				if got := f.statuses(headB); got[len(got)-1] != "failure: needs a person: vetoes_forgotten" {
					t.Errorf("statuses %q", got)
				}
			}
			if body := f.gateComment(testPR); !strings.Contains(body, allow.ReasonVetoesForgotten.Explain()) {
				t.Errorf("the comment does not say why:\n%s", body)
			}
		})
	}

	t.Run("a marker that says so, read by Decide", func(t *testing.T) {
		_, reviewer := defaults(t)
		for _, scheduled := range []bool{false, true} {
			f := newFake(t)
			m := marker{Outcome: ActionPerson, Head: headB, Fingerprint: reviewer, Forgot: true}
			f.comments[testPR] = []*fakeComment{{1, testBot, m.String() + "\n### dep-review: needs a person\n"}}
			cfg := f.config(t0, nil)
			cfg.Scheduled = scheduled
			dir := files(t, goodFacts(t), clean(t))
			ev, err := Decide(t.Context(), cfg, filepath.Join(dir, wire.FactsFile), filepath.Join(dir, wire.VerdictsFile))
			if err != nil || ev.Decision.Outcome != allow.Person || ev.Decision.Reasons[0] != allow.ReasonVetoesForgotten {
				t.Errorf("scheduled %t: %+v, %v", scheduled, ev.Decision, err)
			}
		}
	})
}

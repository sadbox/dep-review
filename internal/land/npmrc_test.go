package land

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/gather"
	"github.com/sadbox/dep-review/internal/wire"
)

// A merge whose NoRegress rests on the repository's root .npmrc reads that
// file again on the default branch as it is now (spec section 11,
// amendment 70). The facts read it at the commit the pull request
// records, which GitHub does not move when the default branch does.

// scriptsOffFacts is an npm pull request whose one update has NoRegress
// by the scripts-off fact, as the fetch job writes it.
func scriptsOffFacts(t *testing.T) wire.Facts {
	t.Helper()
	facts := goodFacts(t)
	facts.Facts.Ecosystem = allow.NPM
	u := &facts.Facts.Updates[0]
	u.Name, u.From, u.To = "example-package", "1.2.3", "1.3.0"
	u.NoRegress = allow.Yes("install scripts not compared: the repository turns them off; provenance kept", "the registry and package-lock.json").
		And(allow.Yes("install scripts are off in this repository (ignore-scripts=true)", gather.ScriptsOffSource))
	return facts
}

// rootTree is GitHub's answer for the default branch's root tree with
// these entries after a README.
func rootTree(truncated bool, entries ...string) string {
	list := []string{`{"path":"README.md","mode":"100644","type":"blob","sha":"` + strings.Repeat("c", 40) + `","size":10}`}
	list = append(list, entries...)
	return fmt.Sprintf(`{"sha":%q,"url":"x","tree":[%s],"truncated":%t}`, strings.Repeat("d", 40), strings.Join(list, ","), truncated)
}

func npmrcEntry(mode, typ, sha string) string {
	return fmt.Sprintf(`{"path":".npmrc","mode":%q,"type":%q,"sha":%q,"size":20}`, mode, typ, sha)
}

var knownNpmrc = npmrcEntry("100644", "blob", gather.ScriptsOffBlob)

func TestScriptsOffAtTheTip(t *testing.T) {
	other := strings.Repeat("e", 40)
	tests := []struct {
		name  string
		tree  string
		merge bool
	}{
		{"the tip has the file", rootTree(false, knownNpmrc), true},
		{"the tip has no .npmrc", rootTree(false), false},
		{"the tip's .npmrc has other bytes", rootTree(false, npmrcEntry("100644", "blob", other)), false},
		{"the tip's .npmrc is executable", rootTree(false, npmrcEntry("100755", "blob", gather.ScriptsOffBlob)), false},
		{"the tip's .npmrc is a symbolic link", rootTree(false, npmrcEntry("120000", "blob", gather.ScriptsOffBlob)), false},
		{"the tip's .npmrc is a directory", rootTree(false, npmrcEntry("040000", "tree", gather.ScriptsOffBlob)), false},
		{"the listing is cut short", rootTree(true, knownNpmrc), false},
		{"the listing does not say whether it is cut short", strings.Replace(rootTree(false, knownNpmrc), `,"truncated":false`, "", 1), false},
		{"a name that only looks like it", rootTree(false, strings.Replace(knownNpmrc, `".npmrc"`, `".NPMRC"`, 1)), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.tree, f.treeCode = tc.tree, 200
			rec := &recorder{}
			res, err := publish(t, f.config(t0, rec), files(t, scriptsOffFacts(t), clean(t)))
			if err != nil {
				t.Fatal(err)
			}
			if n := f.count("GET", "/git/trees/main"); n != 1 {
				t.Errorf("%d reads of the default branch's tree, want 1", n)
			}
			// The read comes before anything is written.
			for _, c := range f.calls {
				if c.method != "GET" {
					t.Errorf("a write (%s %s) before the tree was read", c.method, c.path)
					break
				}
				if strings.HasSuffix(c.path, "/git/trees/main") {
					break
				}
			}
			if tc.merge {
				if res.Action != ActionMerged || f.count("PUT", "/merge") != 1 {
					t.Errorf("result %+v, want merged", res)
				}
				return
			}
			if res.Action != ActionWait || res.Held || len(res.Decision.Reasons) != 1 || res.Decision.Reasons[0] != allow.ReasonScriptsOffChanged {
				t.Errorf("result %+v, want a wait for scripts_off_changed", res)
			}
			if n := f.count("PUT", "/merge"); n != 0 {
				t.Errorf("%d merge calls, want none", n)
			}
			if want := []string{"pending: waiting (scripts_off_changed), at most until 2026-11-29 11:00 UTC"}; strings.Join(f.statuses(headA), "\n") != strings.Join(want, "\n") {
				t.Errorf("statuses %q, want %q", f.statuses(headA), want)
			}
			if len(rec.got) != 0 {
				t.Errorf("notified %+v: a wait needs nobody", rec.got)
			}
			body := f.gateComment(testPR)
			for _, want := range []string{"**Waiting, at most until 2026-11-29 11:00 UTC.** " + allow.ReasonScriptsOffChanged.Explain(), allow.ReasonScriptsOffChanged.Hint()} {
				if !strings.Contains(body, want) {
					t.Errorf("the comment lacks %q:\n%s", want, body)
				}
			}
			if m, ok := parseMarker(body); !ok || m.Outcome != ActionWait {
				t.Errorf("marker %+v (parsed: %t), want a wait the scheduled job takes up", m, ok)
			}
		})
	}
}

// The reason's words say what happened and what ends the wait.
func TestScriptsOffChangedWords(t *testing.T) {
	explain, hint := allow.ReasonScriptsOffChanged.Explain(), allow.ReasonScriptsOffChanged.Hint()
	for _, want := range []string{".npmrc", "no longer"} {
		if !strings.Contains(explain, want) {
			t.Errorf("explanation %q lacks %q", explain, want)
		}
	}
	for _, want := range []string{"Dependabot", "rebase", "on its own"} {
		if !strings.Contains(hint, want) {
			t.Errorf("hint %q lacks %q", hint, want)
		}
	}
}

// At the wait deadline it is a person's, like every wait.
func TestScriptsOffChangedUntilTheDeadline(t *testing.T) {
	now := t0.Add(7 * 24 * time.Hour)
	f := newFake(t)
	f.tree, f.treeCode = rootTree(false), 200
	facts := scriptsOffFacts(t)
	facts.GatheredAt = now.Add(-time.Minute)
	rec := &recorder{}
	res, err := publish(t, f.config(now, rec), files(t, facts, clean(t)))
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != ActionPerson || len(res.Decision.Reasons) != 1 || res.Decision.Reasons[0] != allow.ReasonScriptsOffDeadline {
		t.Errorf("result %+v, want a person's for scripts_off_deadline", res)
	}
	if n := f.count("PUT", "/merge"); n != 0 {
		t.Errorf("%d merge calls, want none", n)
	}
	if got, want := f.statuses(headA), "failure: needs a person: scripts_off_deadline"; len(got) != 1 || got[0] != want {
		t.Errorf("statuses %q, want only %q", got, want)
	}
	if len(rec.got) != 1 {
		t.Errorf("%d notifications, want 1", len(rec.got))
	}
}

// Without GitHub's answer nothing is merged and nothing is written, as
// for the reads baseChanged makes.
func TestScriptsOffTipNotRead(t *testing.T) {
	for name, answer := range map[string]struct {
		code int
		body string
	}{
		"GitHub does not answer": {502, `{"message":"Bad Gateway"}`},
		"not found":              {404, `{"message":"Not Found"}`},
		"not an object":          {200, `[]`},
		"no tree member":         {200, `{"sha":"x","truncated":false}`},
		"a tree that is null":    {200, `{"sha":"x","tree":null,"truncated":false}`},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.tree, f.treeCode = answer.body, answer.code
			rec := &recorder{}
			res, err := publish(t, f.config(t0, rec), files(t, scriptsOffFacts(t), clean(t)))
			if err == nil || res.Action != "" {
				t.Errorf("result %+v, error %v; want an error and nothing done", res, err)
			}
			if got := f.writes(); len(got) != 0 {
				t.Errorf("writes %+v, want none", got)
			}
			if len(rec.got) != 0 {
				t.Errorf("notified %+v", rec.got)
			}
		})
	}
}

// Only a merge that rests on the fact reads the tree. The fake fails a
// test on a request it was not given an answer for.
func TestScriptsOffTipNotAskedAbout(t *testing.T) {
	t.Run("a merge that does not rest on the fact", func(t *testing.T) {
		f := newFake(t)
		res, err := publish(t, f.config(t0, nil), files(t, goodFacts(t), clean(t)))
		if err != nil || res.Action != ActionMerged {
			t.Fatalf("result %+v, error %v; want merged", res, err)
		}
	})
	t.Run("a wait for the age", func(t *testing.T) {
		f := newFake(t)
		facts := scriptsOffFacts(t)
		facts.Facts.Updates[0].FirstSeen = allow.At(t0.Add(-time.Hour), "the registry")
		res, err := publish(t, f.config(t0, nil), files(t, facts, clean(t)))
		if err != nil || res.Action != ActionWait {
			t.Fatalf("result %+v, error %v; want a wait for the age", res, err)
		}
	})
	t.Run("a merge held for the base", func(t *testing.T) {
		f := newFake(t)
		f.compare = compared(1, named("go.sum")...)
		res, err := publish(t, f.config(t0, nil), files(t, scriptsOffFacts(t), clean(t)))
		if err != nil || !res.Held {
			t.Fatalf("result %+v, error %v; want held for the base", res, err)
		}
	})
}

package land

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
)

// A merge is not asked for while the default branch has changed one of
// the pull request's files since the commit the pull request branches
// from (spec section 11, amendment 62). The pull request of these tests
// changes go.mod and go.sum (the fake's default).

// changedFile is one entry of GitHub's file lists.
type changedFile struct {
	Filename         string `json:"filename"`
	PreviousFilename string `json:"previous_filename,omitempty"`
}

// compared is GitHub's comparison of the head with main: main is ahead by
// that many commits, which changed these files.
func compared(ahead int, files ...changedFile) string {
	if files == nil {
		files = []changedFile{}
	}
	b, err := json.Marshal(map[string]any{"status": "diverged", "ahead_by": ahead, "behind_by": 1, "total_commits": ahead, "files": files})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func named(names ...string) []changedFile {
	var out []changedFile
	for _, n := range names {
		out = append(out, changedFile{Filename: n})
	}
	return out
}

// numbered is n files that are not the pull request's.
func numbered(n int) []changedFile {
	var out []changedFile
	for i := range n {
		out = append(out, changedFile{Filename: fmt.Sprintf("docs/page-%d.md", i)})
	}
	return out
}

const (
	heldWait    = "**Waiting, at most until 2026-11-29 11:00 UTC.** Every fact below holds and the model raised no veto, but the gate did not ask GitHub to merge: "
	heldWayOut  = "**Way out:** Dependabot rebuilds most such pull requests by itself within minutes, and the new head gets a run of its own. If it has not, ask Dependabot to rebase the pull request, or look at what the merge would give and merge by hand."
	heldAtCap   = "GitHub lists only 300 of the files the default branch has changed since the commit this pull request branches from, so the gate cannot tell whether one the pull request changes is among them."
	heldBecause = "since the commit this pull request branches from, the default branch has changed %s, which the pull request changes too."
)

func TestHeldForTheBase(t *testing.T) {
	tests := []struct {
		name    string
		prFiles []changedFile // nil: go.mod and go.sum
		compare string
		// held is the comment's sentence for a merge that was not asked
		// for; empty for a merge.
		held string
		note string
	}{
		{name: "the default branch has nothing the head lacks", compare: compared(0)},
		{name: "only behind: the default branch changed other files", compare: compared(3, named("Dockerfile", "README.md", "internal/go.mod")...)},
		{name: "only behind: 299 other files", compare: compared(40, numbered(299)...)},
		{
			name: "the default branch changed a file of the pull request", compare: compared(1, named("Dockerfile", "go.sum")...),
			held: fmt.Sprintf(heldBecause, "`go.sum`"), note: "go.sum",
		},
		{
			name: "the default branch renamed a file of the pull request", compare: compared(1, changedFile{Filename: "tools/go.mod", PreviousFilename: "go.mod"}),
			held: fmt.Sprintf(heldBecause, "`go.mod`"), note: "go.mod",
		},
		{
			name:    "the pull request renames a file the default branch changed",
			prFiles: []changedFile{{Filename: "new.lock", PreviousFilename: "old.lock"}}, compare: compared(2, named("old.lock")...),
			held: fmt.Sprintf(heldBecause, "`old.lock`"), note: "old.lock",
		},
		{
			name: "GitHub's comparison is at its cap of 300 files", compare: compared(400, numbered(300)...),
			held: heldAtCap,
		},
		{
			// The name is whoever pushed to the default branch's to choose,
			// and Dependabot acts on commands in comments.
			name:    "a file name is shown like any third-party text",
			prFiles: named("a`b|@dependabot merge.json"), compare: compared(1, named("a`b|@dependabot merge.json")...),
			held: fmt.Sprintf(heldBecause, "`a'b¦＠dependabot merge.json`"), note: "a`b|@dependabot merge.json",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.compare = tc.compare
			if tc.prFiles != nil {
				b, err := json.Marshal(tc.prFiles)
				if err != nil {
					t.Fatal(err)
				}
				f.prFiles = string(b)
			}
			rec := &recorder{}
			res, err := publish(t, f.config(t0, rec), files(t, goodFacts(t), clean(t)))
			if err != nil {
				t.Fatal(err)
			}
			if f.count("GET", fmt.Sprintf("/pulls/%d/files", testPR)) != 1 || f.count("GET", "/compare/"+headA+"...main") != 1 {
				t.Errorf("the pull request's files and the comparison of its head with main were not each read once: %+v", f.calls)
			}
			statuses, body := f.statuses(headA), f.gateComment(testPR)

			if tc.held == "" {
				if res.Action != ActionMerged || res.Held || f.count("PUT", "/merge") != 1 {
					t.Errorf("result %+v with %d merge calls, want merged", res, f.count("PUT", "/merge"))
				}
				// Both reads come before anything is written, the status
				// that says success included.
				reads := 0
				for _, c := range f.calls {
					if c.method != "GET" {
						break
					}
					if strings.HasSuffix(c.path, "/files") || strings.HasSuffix(c.path, "...main") {
						reads++
					}
				}
				if reads != 2 {
					t.Errorf("%d of the two reads came before the first write: %+v", reads, f.calls)
				}
				return
			}

			if res.Action != ActionWait || !res.Held || res.Note != tc.note ||
				len(res.Decision.Reasons) != 1 || res.Decision.Reasons[0] != allow.ReasonBaseChanged {
				t.Errorf("result %+v, want a held merge that waits for a reason of its own", res)
			}
			if n := f.count("PUT", "/merge"); n != 0 {
				t.Errorf("%d merge calls, want none", n)
			}
			if want := []string{"pending: waiting (base_changed), at most until 2026-11-29 11:00 UTC"}; strings.Join(statuses, "\n") != strings.Join(want, "\n") {
				t.Errorf("statuses %q, want %q: no success on a head the gate will not merge", statuses, want)
			}
			if len(rec.got) != 0 {
				t.Errorf("notified %+v: a wait needs nobody", rec.got)
			}
			m, ok := parseMarker(body)
			if !ok || m.Outcome != ActionWait || m.Head != headA || !m.Deadline.Equal(t0.Add(-time.Hour).Add(7*24*time.Hour)) {
				t.Errorf("marker %+v (parsed: %t), want a wait the scheduled job takes up, with the deadline", m, ok)
			}
			for _, want := range []string{heldWait + tc.held, heldWayOut, "The gate does not rebase, update or comment to bring a pull request up to date."} {
				if !strings.Contains(body, want) {
					t.Errorf("the comment lacks %q", want)
				}
			}
			// GitHub was not asked, so nothing is said about its answer or
			// about checks, and no text addresses Dependabot.
			visible := body[strings.Index(body, "\n"):] // the marker's line is base64
			for _, not := range []string{"GitHub's answer", "GitHub refused", allow.ReasonChecksPending.Explain(), allow.ReasonChecksPending.Hint(), "@"} {
				if strings.Contains(visible, not) {
					t.Errorf("the comment says %q", not)
				}
			}
			if t.Failed() {
				t.Logf("comment:\n%s", body)
			}
		})
	}
}

// TestHeldUntilTheDeadline: a held merge is a person's once the wait
// deadline has passed, like a merge GitHub keeps refusing.
func TestHeldUntilTheDeadline(t *testing.T) {
	// goodFacts' pull request was opened an hour before t0, so its wait
	// deadline is seven days after that.
	now := t0.Add(7 * 24 * time.Hour)
	f := newFake(t)
	f.compare = compared(1, named("go.sum")...)
	facts := goodFacts(t)
	facts.GatheredAt = now.Add(-time.Minute)
	rec := &recorder{}
	res, err := publish(t, f.config(now, rec), files(t, facts, clean(t)))
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != ActionPerson || !res.Held || len(res.Decision.Reasons) != 1 || res.Decision.Reasons[0] != allow.ReasonBaseChangedDeadline {
		t.Errorf("result %+v, want a person's at the deadline", res)
	}
	if n := f.count("PUT", "/merge"); n != 0 {
		t.Errorf("%d merge calls, want none", n)
	}
	if got, want := f.statuses(headA), "failure: needs a person: base_changed_deadline"; len(got) != 1 || got[0] != want {
		t.Errorf("statuses %q, want only %q", got, want)
	}
	if len(rec.got) != 1 || !strings.Contains(rec.got[0].Body, "base_changed_deadline") {
		t.Errorf("%d notifications, want 1: %+v", len(rec.got), rec.got)
	}
	body := f.gateComment(testPR)
	want := "**Needs a person.** The wait deadline has passed. Every fact below holds and the model raised no veto, but the gate did not ask GitHub to merge: " +
		fmt.Sprintf(heldBecause, "`go.sum`")
	if !strings.Contains(body, want) || !strings.Contains(body, heldWayOut) || strings.Contains(body, allow.ReasonChecksDeadline.Explain()) {
		t.Errorf("the comment lacks %q or the way out, or speaks of checks:\n%s", want, body)
	}
}

// TestBaseNotRead: without both of GitHub's answers nothing is merged and
// nothing is written. The job fails and is run again.
func TestBaseNotRead(t *testing.T) {
	tests := []struct {
		name   string
		github func(*fakeGitHub)
	}{
		{"the pull request's files: GitHub does not answer", func(f *fakeGitHub) { f.prFilesCode, f.prFiles = 502, `{"message":"Bad Gateway"}` }},
		{"the pull request's files: not found", func(f *fakeGitHub) { f.prFilesCode, f.prFiles = 404, `{"message":"Not Found"}` }},
		{"the pull request's files: not a list", func(f *fakeGitHub) { f.prFiles = `{"message":"moved"}` }},
		{"the pull request's files: an empty list", func(f *fakeGitHub) { f.prFiles = `[]` }},
		{"the comparison: GitHub does not answer", func(f *fakeGitHub) { f.compareCode, f.compare = 502, `{"message":"Bad Gateway"}` }},
		{"the comparison: not found", func(f *fakeGitHub) { f.compareCode, f.compare = 404, `{"message":"Not Found"}` }},
		{"the comparison: an object without either member", func(f *fakeGitHub) { f.compare = `{}` }},
		{"the comparison: no ahead_by", func(f *fakeGitHub) { f.compare = `{"files":[{"filename":"README.md"}]}` }},
		{"the comparison: ahead_by is null", func(f *fakeGitHub) { f.compare = `{"ahead_by":null,"files":[]}` }},
		{"the comparison: ahead_by below zero", func(f *fakeGitHub) { f.compare = `{"ahead_by":-1,"files":[]}` }},
		{"the comparison: ahead, and no files member", func(f *fakeGitHub) { f.compare = `{"ahead_by":2}` }},
		{"the comparison: ahead, and files is null", func(f *fakeGitHub) { f.compare = `{"ahead_by":2,"files":null}` }},
		{"the comparison: files is not a list", func(f *fakeGitHub) { f.compare = `{"ahead_by":2,"files":"README.md"}` }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			tc.github(f)
			rec := &recorder{}
			res, err := publish(t, f.config(t0, rec), files(t, goodFacts(t), clean(t)))
			if err == nil || res.Action != "" {
				t.Errorf("result %+v, error %v; want an error and nothing done", res, err)
			}
			if got := f.writes(); len(got) != 0 {
				t.Errorf("writes %+v, want none: no merge, no status, no comment", got)
			}
			if len(rec.got) != 0 {
				t.Errorf("notified %+v", rec.got)
			}
		})
	}
}

// TestBaseNotAskedAbout: the two reads are for a merge. A pull request
// that waits or needs a person is not held up by them.
func TestBaseNotAskedAbout(t *testing.T) {
	for name, change := range map[string]func(*fakeGitHub){
		"waiting for its age": func(f *fakeGitHub) {},
		"waiting for its age, and GitHub answers neither read": func(f *fakeGitHub) {
			f.prFilesCode, f.compareCode = 502, 502
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			change(f)
			facts := goodFacts(t)
			facts.Facts.Updates[0].FirstSeen = allow.At(t0.Add(-time.Hour), "index.golang.org")
			res, err := publish(t, f.config(t0, nil), files(t, facts, clean(t)))
			if err != nil || res.Action != ActionWait || res.Held {
				t.Fatalf("result %+v, error %v; want a wait for the age", res, err)
			}
			if n := f.count("GET", "/files") + f.count("GET", "...main"); n != 0 {
				t.Errorf("%d reads of the files or the comparison, want none", n)
			}
		})
	}
}

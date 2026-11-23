package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/config"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/land"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/veto"
	"github.com/sadbox/dep-review/internal/wire"
)

// fakeAPI is GitHub as far as these tests go: the pull request, and the
// writes of a failed run's report. Everything else is 404, which is where
// a decision stops; what a decision does is internal/land's to test.
type fakeAPI struct {
	mu sync.Mutex
	// pull answers GET pulls/7; empty is 404.
	pull string
	// open answers the list of open pull requests; empty is none.
	open string
	// comment is the body of the gate's one comment on #7, with ID 1;
	// empty is no comment. A comment the gate writes takes its place.
	comment string
	// calls are the requests, "METHOD path", and bodies what was written.
	calls  []string
	bodies []string
	// proof answers the rest of classify's proof for #7 as for a pull
	// request that is Dependabot's alone, and the default branch's rules
	// with a required check.
	proof bool
	// unruled, with proof, has no rule on the pull request's branch: by the
	// proof, a pull request that is not Dependabot's alone.
	unruled bool
	// commentFails is how many writes of the comment, from the next one,
	// GitHub answers 502.
	commentFails int
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	call := r.Method + " " + strings.TrimPrefix(r.URL.Path, "/repos/o/r/")
	f.calls = append(f.calls, call)
	switch {
	case f.proof && f.unruled && call == branchRules:
		io.WriteString(w, "[]")
	case f.proof && proofAnswers[call] != "":
		io.WriteString(w, proofAnswers[call])
	case (call == "POST issues/7/comments" || call == "PATCH issues/comments/1") && f.commentFails > 0:
		f.commentFails--
		w.WriteHeader(http.StatusBadGateway)
		io.WriteString(w, `{"message":"Server Error"}`)
	case call == "GET pulls/7" && f.pull != "":
		io.WriteString(w, f.pull)
	case call == "GET pulls":
		io.WriteString(w, "["+f.open+"]")
	case call == "GET issues/7/comments" && f.comment != "":
		b, _ := json.Marshal([]map[string]any{{"id": 1, "body": f.comment, "user": map[string]string{"login": "gate[bot]"}}})
		w.Write(b)
	case call == "GET issues/7/comments":
		io.WriteString(w, "[]")
	case call == "POST issues/7/comments" || call == "PATCH issues/comments/1":
		var in struct {
			Body string `json:"body"`
		}
		json.Unmarshal(body, &in)
		f.comment = in.Body
		f.bodies = append(f.bodies, string(body))
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, "{}")
	case strings.HasPrefix(call, "POST statuses/"):
		f.bodies = append(f.bodies, string(body))
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, "{}")
	default:
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `{"message":"Not Found"}`)
	}
}

// branchRules is the read of the rules on #7's branch.
const branchRules = "GET rules/branches/dependabot/go_modules/example.com/m-1.0.1"

// proofAnswers are fakeAPI's answers with proof set: one commit by
// Dependabot that GitHub signed, the branch's creation by Dependabot, an
// empty timeline, the rules that keep everyone else off the branch, and a
// required check on main.
var proofAnswers = map[string]string{
	"GET pulls/7/commits":     `[{"sha":"` + testHead + `","author":{"login":"dependabot[bot]"},"committer":{"login":"web-flow"},"commit":{"verification":{"verified":true,"reason":"valid"}}}]`,
	"GET activity":            `[{"before":"0000000000000000000000000000000000000000","after":"` + testHead + `","activity_type":"branch_creation","actor":{"login":"dependabot[bot]"}}]`,
	"GET issues/7/timeline":   `[]`,
	"GET rules/branches/main": `[{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"ci"}]}}]`,
	branchRules:               `[{"type":"creation"},{"type":"update"},{"type":"deletion"}]`,
}

// config is internal/land's configuration against the fake.
func (f *fakeAPI) config(t *testing.T) land.Config {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c := gh.New("token")
	c.BaseURL = srv.URL + "/"
	c.MaxRetries = 0
	return land.Config{GitHub: c, Repo: "o/r", BotLogin: "gate[bot]", RunURL: "https://github.com/o/r/actions/runs/42",
		Now: func() time.Time { return testGathered.Add(time.Minute) }}
}

// pullJSON is pull request 7 as both classify and land read it: open, on
// a dependabot/ branch of the repository, with the default branch as its
// base.
func pullJSON(state, author, head string) string {
	return fmt.Sprintf(`{"number":7,"state":%q,"merged":false,"user":{"login":%q},
		"head":{"sha":%q,"ref":"dependabot/go_modules/example.com/m-1.0.1","repo":{"full_name":"o/r"}},
		"base":{"sha":%q,"ref":"main","repo":{"full_name":"o/r","default_branch":"main"}}}`,
		state, author, head, strings.Repeat("9", 40))
}

// On a scheduled run publish takes nobody's word for a pull request's
// identity: the refresh job classified it and read what it wrote in one
// process, so publish runs the proof again and believes the facts only as
// far as it goes.
func TestPublishRefreshed(t *testing.T) {
	no := func(f *wire.Facts) { f.Facts.Identity = allow.No("pushed by a person", "classify") }
	tests := []struct {
		name  string
		dir   string
		facts func(*wire.Facts) // nil: Identity holds
		pull  string
		want  string // part of the error; "" for none
		is    error
		calls string // the requests made
	}{
		{name: "the directory's name and its facts disagree", dir: "8", pull: pullJSON("open", "dependabot[bot]", testHead),
			want: "facts are about #7"},
		{name: "the facts claim an identity classify rejects", dir: "7", pull: pullJSON("open", "mallory", testHead),
			want: "classify said", calls: "GET pulls/7"},
		{name: "classify rejects it and the facts say so: decided", dir: "7", facts: no, pull: pullJSON("open", "mallory", testHead),
			// The decision is carried out: a person's. All it asks GitHub
			// for is the pull request, the gate's comment (once to decide,
			// for a veto it may remember, and once to write), the branch's
			// rules, and the status GitHub shows, which the fake does not
			// answer; there are no settings to fetch (spec section 11,
			// amendments 56, 63 and 79).
			calls: "GET pulls/7, GET pulls/7, GET issues/7/comments, GET rules/branches/main, GET commits/" + testHead + "/status, POST statuses/" + testHead + ", GET issues/7/comments, POST issues/7/comments"},
		// A scheduled run's publish job run again by itself: nothing is
		// written, the comment still says wait, and the next run decides.
		{name: "facts of an earlier attempt: not decided", dir: "7", pull: pullJSON("open", "mallory", testHead),
			facts: func(f *wire.Facts) { no(f); f.GatheredAt = testGathered.Add(-land.MaxFactsAge) },
			is:    land.ErrFactsStale, calls: "GET pulls/7, GET pulls/7"},
		{name: "closed since: skipped", dir: "7", pull: pullJSON("closed", "dependabot[bot]", testHead), calls: "GET pulls/7"},
		{name: "a newer head since: skipped", dir: "7", pull: pullJSON("open", "dependabot[bot]", strings.Repeat("4", 40)), calls: "GET pulls/7"},
		{name: "the pull request cannot be read", dir: "7", want: "404", calls: "GET pulls/7"},
		{name: "not a pull request's directory", dir: "seven", want: "not a refreshed pull request's directory"},
		// One pull request has one directory.
		{name: "a number spelled another way", dir: "07", want: "not a refreshed pull request's directory"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeAPI{pull: tc.pull}
			in := t.TempDir()
			facts := goodFacts()
			if tc.facts != nil {
				tc.facts(&facts)
			}
			writeFacts(t, filepath.Join(in, "refreshed", tc.dir, "facts.json"), facts)
			entries, err := os.ReadDir(filepath.Join(in, "refreshed"))
			if err != nil {
				t.Fatal(err)
			}
			err = refreshed(context.Background(), api.config(t), in, entries[0], nil)
			switch {
			case tc.want == "" && tc.is == nil && err != nil,
				tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)),
				tc.is != nil && !errors.Is(err, tc.is):
				t.Errorf("err = %v, want %q %v", err, tc.want, tc.is)
			}
			if got := strings.Join(api.calls, ", "); got != tc.calls {
				t.Errorf("requests %q, want %q", got, tc.calls)
			}
		})
	}

	// The artifact as the publish job has it: the directories, and the
	// checksum manifest the refresh job put beside them.
	t.Run("the manifest is no pull request", func(t *testing.T) {
		api := &fakeAPI{pull: pullJSON("closed", "dependabot[bot]", testHead)}
		in := t.TempDir()
		writeFacts(t, filepath.Join(in, "refreshed", "7", "facts.json"), goodFacts())
		writeFile(t, filepath.Join(in, "refreshed", "SHA256SUMS"), strings.Repeat("0", 64)+"  ./7/facts.json\n")
		if err := publishRefreshed(context.Background(), api.config(t), in, nil); err != nil {
			t.Errorf("err = %v", err)
		}
		// Then publish's own look at the open pull requests.
		if got := strings.Join(api.calls, ", "); got != "GET pulls/7, GET pulls" {
			t.Errorf("requests %q, want #7 looked at and then the open pull requests", got)
		}
	})
	t.Run("one that is refused does not stop the others", func(t *testing.T) {
		api := &fakeAPI{pull: pullJSON("closed", "dependabot[bot]", testHead)}
		in := t.TempDir()
		writeFacts(t, filepath.Join(in, "refreshed", "7", "facts.json"), goodFacts())
		writeFacts(t, filepath.Join(in, "refreshed", "12", "facts.json"), goodFacts())
		writeFile(t, filepath.Join(in, "refreshed", "13"), "a file, not a directory")
		writeFile(t, filepath.Join(in, "refreshed", "SHA256SUMS"), "")
		writeFile(t, filepath.Join(in, "refreshed", "SHA256SUMS.old"), "any other file is refused")
		err := publishRefreshed(context.Background(), api.config(t), in, nil)
		if err == nil || !strings.Contains(err.Error(), "3 of 4") {
			t.Errorf("err = %v, want three of four refused", err)
		}
		// #12 has a directory that could not be decided: publish looks
		// whether there is something to report on it (there is no #12).
		// The file and the stray manifest name no pull request.
		if got := strings.Join(api.calls, ", "); got != "GET pulls/12, GET pulls/7, GET pulls" {
			t.Errorf("requests %q, want #12 and #7 looked at and then the open pull requests", got)
		}
	})
	// A scheduled run in which the refresh job wrote nothing: there is no
	// artifact, and publish still looks at the open pull requests itself.
	t.Run("nothing refreshed", func(t *testing.T) {
		api := &fakeAPI{}
		if err := publishRefreshed(context.Background(), api.config(t), t.TempDir(), nil); err != nil {
			t.Errorf("err = %v", err)
		}
		if got := strings.Join(api.calls, ", "); got != "GET pulls" {
			t.Errorf("requests %q, want the open pull requests", got)
		}
	})
}

// Publish's own proof can only take away. When it says the pull request is
// not Dependabot's alone, that is the decision's Identity, whatever the
// refresh job's proof could not finish: a person's for the identity, not
// a wait (spec section 11, amendment 75).
func TestPublishRefreshedProofSaysNo(t *testing.T) {
	for name, identity := range map[string]allow.Fact{
		"the refresh job's proof was unfinished": allow.Unavailable("the branch's rules could not be read: GitHub did not answer (HTTP 502)", "classify"),
		"the refresh job's proof said no too":    allow.No("no active rule restricts creating, updating and deleting this dependabot/ branch", "classify"),
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{pull: pullJSON("open", "dependabot[bot]", testHead), proof: true, unruled: true}
			in := t.TempDir()
			facts := goodFacts()
			facts.Facts.Identity = identity
			// Young enough to wait, so that only Identity can make it a
			// person's.
			facts.Facts.Opened = testGathered.Add(-time.Hour)
			facts.Facts.Updates[0].FirstSeen = allow.At(testGathered.Add(-time.Hour), "test")
			writeFacts(t, filepath.Join(in, "refreshed", "7", "facts.json"), facts)
			entries, err := os.ReadDir(filepath.Join(in, "refreshed"))
			if err != nil {
				t.Fatal(err)
			}
			if err := refreshed(context.Background(), api.config(t), in, entries[0], nil); err != nil {
				t.Fatalf("err = %v (requests %v)", err, api.calls)
			}
			if !slices.Contains(api.calls, "GET "+strings.TrimPrefix(branchRules, "GET ")) {
				t.Errorf("the proof did not get to the branch's rules: %v", api.calls)
			}
			written := strings.Join(api.bodies, "\n")
			if !strings.Contains(written, `"state":"failure"`) || !strings.Contains(written, "needs a person: identity") {
				t.Errorf("wrote %s", written)
			}
		})
	}
}

// handMarker is a marker line as internal/land writes it, for a comment
// these tests put on the fake: the members given, in JSON.
func handMarker(members string) string {
	return "<!-- dep-review:v2 " + base64.RawURLEncoding.EncodeToString([]byte("{"+members+"}")) + " -->"
}

// A pull request the scheduled run tried to evaluate from scratch and
// could not is reported on the pull request, once, by publish: the
// refresh job has no token to write with, and left a directory with no
// facts. One the gate left waiting keeps its wait comment (spec section
// 11, amendment 66).
func TestPublishReportsWhatCouldNotBeEvaluated(t *testing.T) {
	// By Dependabot, and not on a dependabot/ branch: classify calls that
	// unverified from the pull request alone, which the gate handles.
	open := strings.Replace(pullJSON("open", "dependabot[bot]", testHead), `"ref":"dependabot/go_modules/example.com/m-1.0.1"`, `"ref":"renamed"`, 1)
	tried := func(t *testing.T) string {
		in := t.TempDir()
		writeFile(t, filepath.Join(in, "refreshed", "7", unevaluatedFile), "tried\n")
		return in
	}
	t.Run("no decision for the head", func(t *testing.T) {
		api := &fakeAPI{pull: open}
		err := publishRefreshed(context.Background(), api.config(t), tried(t), nil)
		if err == nil || !strings.Contains(err.Error(), "1 of 1") {
			t.Errorf("err = %v, want the run to fail for the one pull request", err)
		}
		written := strings.Join(api.bodies, "\n")
		for _, want := range []string{`"state":"error"`, "the scheduled run could not evaluate this pull request; see the comment",
			"### dep-review: the run failed", "because the gate had no decision for its head", "The scheduled run does not try this head again"} {
			if !strings.Contains(written, want) {
				t.Errorf("the report lacks %q: %s", want, written)
			}
		}
	})
	for name, comment := range map[string]string{
		"a wait":                  handMarker(`"outcome":"wait","head":"`+testHead+`"`) + "\n### dep-review: waiting\n",
		"a decision for the head": handMarker(`"outcome":"person","head":"`+testHead+`","notified":["`+testHead+`"]`) + "\n### dep-review: needs a person\n",
	} {
		t.Run(name+" is not replaced by a report", func(t *testing.T) {
			api := &fakeAPI{pull: open, comment: comment}
			if err := publishRefreshed(context.Background(), api.config(t), tried(t), nil); err == nil {
				t.Error("the run did not fail for the pull request that could not be evaluated")
			}
			if len(api.bodies) != 0 || api.comment != comment {
				t.Errorf("wrote %v", api.bodies)
			}
		})
	}
	// Facts this job came to too late are not the pull request's failure:
	// nothing is reported, and the next run gathers again.
	t.Run("facts gathered too long ago are not reported", func(t *testing.T) {
		api := &fakeAPI{pull: open}
		in := t.TempDir()
		facts := goodFacts()
		facts.Facts.Identity = allow.No("not on a dependabot/ branch", "classify")
		facts.GatheredAt = testGathered.Add(-land.MaxFactsAge)
		writeFacts(t, filepath.Join(in, "refreshed", "7", "facts.json"), facts)
		if err := publishRefreshed(context.Background(), api.config(t), in, nil); err == nil {
			t.Error("the run did not fail for facts that are too old")
		}
		if len(api.bodies) != 0 {
			t.Errorf("wrote %v", api.bodies)
		}
	})
	t.Run("a closed pull request gets nothing", func(t *testing.T) {
		api := &fakeAPI{pull: strings.Replace(open, `"state":"open"`, `"state":"closed"`, 1)}
		publishRefreshed(context.Background(), api.config(t), tried(t), nil)
		if len(api.bodies) != 0 {
			t.Errorf("wrote %v", api.bodies)
		}
	})
	t.Run("somebody else's pull request gets nothing", func(t *testing.T) {
		api := &fakeAPI{pull: pullJSON("open", "mallory", testHead)}
		publishRefreshed(context.Background(), api.config(t), tried(t), nil)
		if len(api.bodies) != 0 {
			t.Errorf("wrote %v", api.bodies)
		}
	})
}

// A scheduled run that asked the model about a pull request and then
// could not decide it still counts the ask, so that the next one waits
// its turn (spec section 11, amendment 64): the marker line is rewritten
// and nothing else is.
func TestPublishCountsAnAskItCouldNotDecideOn(t *testing.T) {
	const rest = "\n### dep-review: waiting\n\nthe comment's text\n"
	asked := handMarker(`"outcome":"wait","head":"`+testHead+`","asks":1,"asked_at":"2026-11-22T00:00:00Z"`) + rest
	run := func(t *testing.T, withVerdicts bool) *fakeAPI {
		t.Helper()
		api := &fakeAPI{pull: pullJSON("open", "mallory", testHead), comment: asked}
		in := t.TempDir()
		facts := goodFacts()
		facts.Facts.Identity = allow.No("pushed by a person", "classify")
		// Too old to decide on: deciding fails before anything is written.
		facts.GatheredAt = testGathered.Add(-land.MaxFactsAge)
		writeFacts(t, filepath.Join(in, "refreshed", "7", "facts.json"), facts)
		if withVerdicts {
			writeFile(t, filepath.Join(in, "reverdicts", "7", "verdicts.json"), `{"version":1,"verdicts":[]}`)
		}
		if err := publishRefreshed(context.Background(), api.config(t), in, nil); err == nil || !strings.Contains(err.Error(), "1 of 1") {
			t.Fatalf("err = %v, want the run to fail for the one pull request", err)
		}
		return api
	}
	api := run(t, true)
	if got := asksOf(t, api.comment); got != 2 || !strings.HasSuffix(api.comment, rest) || len(api.bodies) != 1 {
		t.Errorf("after a run that asked and could not decide: %d asks, %d writes, comment %q", got, len(api.bodies), api.comment)
	}
	// A run that asked nobody counts nothing.
	if api := run(t, false); api.comment != asked || len(api.bodies) != 0 {
		t.Errorf("after a run that asked nobody: comment %q, writes %v", api.comment, api.bodies)
	}

	// The same when what stops publish comes before deciding: its own
	// proof does not bear the facts out (the refreshed facts say the pull
	// request is Dependabot's alone, and this job's proof does not), or
	// the proof cannot be run at all.
	for name, pull := range map[string]string{
		"this job's proof contradicts the facts": pullJSON("open", "mallory", testHead),
		"this job's proof cannot be finished":    pullJSON("open", "dependabot[bot]", testHead), // the fake has no commit list
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{pull: pull, comment: asked}
			in := t.TempDir()
			writeFacts(t, filepath.Join(in, "refreshed", "7", "facts.json"), goodFacts())
			writeFile(t, filepath.Join(in, "reverdicts", "7", "verdicts.json"), `{"version":1,"verdicts":[]}`)
			if err := publishRefreshed(context.Background(), api.config(t), in, nil); err == nil || !strings.Contains(err.Error(), "1 of 1") {
				t.Fatalf("err = %v, want the run to fail for the one pull request", err)
			}
			if got := asksOf(t, api.comment); got != 2 || !strings.HasSuffix(api.comment, rest) {
				t.Errorf("%d asks counted, want 2; comment %q", got, api.comment)
			}
		})
	}
}

// sweepNotifier records what publish told the owner.
type sweepNotifier struct{ got []land.Message }

func (n *sweepNotifier) Notify(_ context.Context, m land.Message) error {
	n.got = append(n.got, m)
	return nil
}

// On a scheduled run publish looks at the open pull requests itself, with
// its own token, whatever the refresh job wrote: a wait past its deadline
// that this run did not decide is a person's, and a notification that
// could not be delivered is sent (spec section 11, amendment 67).
func TestSweep(t *testing.T) {
	open := pullJSON("open", "dependabot[bot]", testHead)
	past := testGathered.Add(-time.Hour).Format(time.RFC3339)
	ahead := testGathered.Add(time.Hour).Format(time.RFC3339)
	wait := func(deadline string) string {
		return handMarker(`"outcome":"wait","head":"`+testHead+`","deadline":"`+deadline+`"`) + "\n### dep-review: waiting\n"
	}
	run := func(t *testing.T, api *fakeAPI) (*sweepNotifier, int, error) {
		t.Helper()
		n := &sweepNotifier{}
		cfg := api.config(t)
		cfg.Scheduled, cfg.Notifier = true, n
		failed, err := sweep(context.Background(), cfg, nil)
		return n, failed, err
	}

	// The identity proof cannot be finished here (the fake has no commit
	// list): that is the refresh that keeps failing, and it does not keep
	// the deadline from being enforced.
	t.Run("an overdue wait is a person's, also when the proof fails", func(t *testing.T) {
		api := &fakeAPI{pull: open, open: open, comment: wait(past)}
		n, failed, err := run(t, api)
		if err != nil || failed != 0 {
			t.Fatalf("%d failures, %v", failed, err)
		}
		written := strings.Join(api.bodies, "\n")
		for _, want := range []string{`"state":"failure"`, "the wait deadline passed", "### dep-review: needs a person"} {
			if !strings.Contains(written, want) {
				t.Errorf("what was written lacks %q: %s", want, written)
			}
		}
		if len(n.got) != 1 || !strings.Contains(n.got[0].Body, "its wait deadline has passed") {
			t.Errorf("notifications %+v", n.got)
		}
	})
	t.Run("a wait whose deadline is ahead is left waiting", func(t *testing.T) {
		api := &fakeAPI{pull: open, open: open, comment: wait(ahead)}
		if n, failed, err := run(t, api); err != nil || failed != 0 || len(api.bodies) != 0 || len(n.got) != 0 {
			t.Errorf("%d failures, %v, wrote %v, told %+v", failed, err, api.bodies, n.got)
		}
	})
	// Only a proof that positively says the pull request is not the
	// gate's any more leaves an overdue wait alone.
	t.Run("an overdue wait on a pull request that was closed meanwhile", func(t *testing.T) {
		api := &fakeAPI{pull: strings.Replace(open, `"state":"open"`, `"state":"closed"`, 1), open: open, comment: wait(past)}
		if n, failed, err := run(t, api); err != nil || failed != 0 || len(api.bodies) != 0 || len(n.got) != 0 {
			t.Errorf("%d failures, %v, wrote %v, told %+v", failed, err, api.bodies, n.got)
		}
	})
	t.Run("a notification that was not delivered is sent", func(t *testing.T) {
		owing := handMarker(`"outcome":"person","head":"`+testHead+`"`) + "\n### dep-review: needs a person\n\nwhy\n"
		api := &fakeAPI{pull: open, open: open, comment: owing}
		n, failed, err := run(t, api)
		if err != nil || failed != 0 || len(n.got) != 1 || !strings.Contains(n.got[0].Body, "needs a person") {
			t.Fatalf("%d failures, %v, told %+v", failed, err, n.got)
		}
		// The comment keeps its text and now remembers the notification.
		if !strings.HasSuffix(api.comment, "\n### dep-review: needs a person\n\nwhy\n") || api.comment == owing {
			t.Errorf("the comment after: %q", api.comment)
		}
		if n, failed, err := run(t, api); err != nil || failed != 0 || len(n.got) != 0 {
			t.Errorf("a second look: %d failures, %v, told %+v", failed, err, n.got)
		}
	})
	t.Run("nothing open", func(t *testing.T) {
		api := &fakeAPI{}
		if n, failed, err := run(t, api); err != nil || failed != 0 || len(api.bodies) != 0 || len(n.got) != 0 {
			t.Errorf("%d failures, %v", failed, err)
		}
	})
}

// An event's run that cannot decide says so on the pull request, and
// still fails. It writes nothing about a pull request the gate does not
// handle, or one that has moved on.
func TestPublishEvent(t *testing.T) {
	class := model.Classification{Repo: "o/r", PR: 7, HeadSHA: testHead, Kind: model.KindDependabot}
	open := pullJSON("open", "dependabot[bot]", testHead)
	tests := []struct {
		name     string
		class    func(*model.Classification)
		facts    func(*wire.Facts) // nil: the fetch job left no facts
		pull     string
		want     string // part of the error
		reported bool   // the failed run was reported on the pull request
		says     string // what the report says of the run; "": how its jobs ended
	}{
		{name: "the fetch job left no facts", pull: open, want: "no facts file", reported: true},
		{name: "facts about another pull request", facts: func(f *wire.Facts) { f.PullRequest.Number = 8 }, pull: open,
			want: "classify looked at", reported: true},
		// A default branch whose name is not put into a request path: an
		// error of deciding itself, before anything is written.
		{name: "deciding fails", facts: func(*wire.Facts) {}, pull: strings.Replace(open, `"default_branch":"main"`, `"default_branch":"main?ref=x"`, 1),
			want: "not a name the gate puts in a URL", reported: true},
		// A job run again by itself gets the first attempt's facts. The
		// report says so, and what to do instead (spec section 11,
		// amendment 52).
		{name: "the first attempt's facts, hours later", facts: func(f *wire.Facts) { f.GatheredAt = testGathered.Add(-land.MaxFactsAge) }, pull: open,
			want: "too old to decide on", reported: true, says: "The facts this run decided on were gathered more than 4 hours earlier"},
		{name: "no facts, and the pull request has a newer head", pull: pullJSON("open", "dependabot[bot]", strings.Repeat("4", 40)),
			want: "no facts file"},
		{name: "a kind the gate does nothing for", class: func(c *model.Classification) { c.Kind = model.KindOther }, pull: open,
			want: "classify said"},
		{name: "another repository's classification", class: func(c *model.Classification) { c.Repo = "o/other" }, pull: open,
			want: "classify said"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("FETCH_RESULT", "failure")
			t.Setenv("REVIEW_RESULT", "../skipped")
			api := &fakeAPI{pull: tc.pull}
			in := t.TempDir()
			if tc.facts != nil {
				facts := goodFacts()
				tc.facts(&facts)
				writeFacts(t, filepath.Join(in, "facts", "facts.json"), facts)
			}
			c := class
			if tc.class != nil {
				tc.class(&c)
			}
			err := publishEvent(context.Background(), api.config(t), in, c)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
			written := strings.Join(api.bodies, "\n")
			if !tc.reported {
				if written != "" {
					t.Errorf("wrote %s", written)
				}
				return
			}
			calls := strings.Join(api.calls, ", ")
			if !strings.HasSuffix(calls, "GET pulls/7, POST statuses/"+testHead+", GET issues/7/comments, POST issues/7/comments") {
				t.Errorf("requests %q, want the status and the comment last", calls)
			}
			says := tc.says
			if says == "" {
				says = "the fetch job ended failure and the review job unknown."
			}
			for _, s := range []string{`"state":"error"`, "### dep-review: the run failed", says, "actions/runs/42", "re-run all jobs, not only the failed ones"} {
				if !strings.Contains(written, s) {
					t.Errorf("the report lacks %q: %s", s, written)
				}
			}
		})
	}
}

func TestReadFacts(t *testing.T) {
	dir := t.TempDir()
	if _, err := readFacts(filepath.Join(dir, "none.json")); err == nil || !strings.Contains(err.Error(), "no facts file") {
		t.Errorf("a missing file: %v", err)
	}
	writeFile(t, filepath.Join(dir, "bad.json"), `{"version":1,"read":"full"}`)
	if _, err := readFacts(filepath.Join(dir, "bad.json")); err == nil {
		t.Error("a file that does not decode was read")
	}
	writeFacts(t, filepath.Join(dir, "facts.json"), goodFacts())
	if f, err := readFacts(filepath.Join(dir, "facts.json")); err != nil || f.PullRequest.Number != 7 {
		t.Errorf("a facts file: %+v, %v", f.PullRequest, err)
	}
}

// vetoVerdicts is a verdicts file in which the model vetoes testKey,
// under the built-in reviewer's fingerprint.
func vetoVerdicts(t *testing.T) string {
	t.Helper()
	conf, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	b, err := wire.EncodeVerdicts(wire.Verdicts{Version: wire.Version, Verdicts: []wire.Verdict{{Key: testKey, Fingerprint: veto.FromConfig(conf).Fingerprint(),
		Read: allow.ReadFull, Veto: &allow.Veto{Category: "exfiltration", Quotes: []string{"sends ~/.ssh to a host"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// vetoesOf is the content keys the marker of a comment remembers a veto
// for.
func vetoesOf(t *testing.T, written string) []string {
	t.Helper()
	found := markerRE.FindStringSubmatch(written)
	if found == nil {
		t.Fatalf("no marker in %s", written)
	}
	raw, err := base64.RawURLEncoding.DecodeString(found[1])
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Cache []struct {
			Key  string          `json:"key"`
			Veto json.RawMessage `json:"veto"`
		} `json:"cache"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, c := range m.Cache {
		if string(c.Veto) != "null" && len(c.Veto) > 0 {
			keys = append(keys, c.Key)
		}
	}
	return keys
}

// A veto the model gave in a run whose publish then could not write the
// comment is in the marker of what publish writes for that run instead: the
// report of a run that could not decide on an event, the counted ask on
// the schedule (spec section 11, amendment 73).
func TestPublishKeepsAVetoItCouldNotWrite(t *testing.T) {
	t.Run("on an event", func(t *testing.T) {
		api := &fakeAPI{pull: pullJSON("open", "dependabot[bot]", testHead), commentFails: 1}
		in := t.TempDir()
		writeFacts(t, filepath.Join(in, "facts", "facts.json"), goodFacts())
		writeFile(t, filepath.Join(in, "verdicts", "verdicts.json"), vetoVerdicts(t))
		class := model.Classification{Repo: "o/r", PR: 7, HeadSHA: testHead, Kind: model.KindDependabot}
		if err := publishEvent(context.Background(), api.config(t), in, class); err == nil || !strings.Contains(err.Error(), "502") {
			t.Fatalf("err = %v, want the comment write's", err)
		}
		if !strings.Contains(api.comment, "### dep-review: the run failed") || !slices.Equal(vetoesOf(t, api.comment), []string{testKey}) {
			t.Errorf("the comment after: %s", api.comment)
		}
	})
	t.Run("on the schedule", func(t *testing.T) {
		const rest = "\n### dep-review: waiting\n\nthe comment's text\n"
		api := &fakeAPI{pull: pullJSON("open", "dependabot[bot]", testHead), proof: true, commentFails: 1,
			comment: handMarker(`"outcome":"wait","head":"`+testHead+`"`) + rest}
		in := t.TempDir()
		writeFacts(t, filepath.Join(in, "refreshed", "7", "facts.json"), goodFacts())
		writeFile(t, filepath.Join(in, "reverdicts", "7", "verdicts.json"), vetoVerdicts(t))
		entries, err := os.ReadDir(filepath.Join(in, "refreshed"))
		if err != nil {
			t.Fatal(err)
		}
		if err := refreshed(context.Background(), api.config(t), in, entries[0], nil); err == nil || !strings.Contains(err.Error(), "502") {
			t.Fatalf("err = %v, want the comment write's (requests %v)", err, api.calls)
		}
		if asksOf(t, api.comment) != 1 || !strings.HasSuffix(api.comment, rest) || !slices.Equal(vetoesOf(t, api.comment), []string{testKey}) {
			t.Errorf("the comment after: %s", api.comment)
		}
	})
}

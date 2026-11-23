package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/land"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/wire"
)

// fakeAPI is GitHub as far as these tests go: the pull request, and the
// writes of a failed run's report. Everything else is 404, which is where
// a decision stops; what a decision does is internal/land's to test.
type fakeAPI struct {
	mu sync.Mutex
	// pull answers GET pulls/7; empty is 404.
	pull string
	// calls are the requests, "METHOD path", and bodies what was written.
	calls  []string
	bodies []string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	call := r.Method + " " + strings.TrimPrefix(r.URL.Path, "/repos/o/r/")
	f.calls = append(f.calls, call)
	switch {
	case call == "GET pulls/7" && f.pull != "":
		io.WriteString(w, f.pull)
	case call == "GET issues/7/comments":
		io.WriteString(w, "[]")
	case r.Method == "POST" && (call == "POST issues/7/comments" || strings.HasPrefix(call, "POST statuses/")):
		f.bodies = append(f.bodies, string(body))
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, "{}")
	default:
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `{"message":"Not Found"}`)
	}
}

// config is internal/land's configuration against the fake.
func (f *fakeAPI) config(t *testing.T) land.Config {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c := gh.New("token")
	c.BaseURL = srv.URL + "/"
	c.MaxRetries = 0
	return land.Config{GitHub: c, Repo: "o/r", BotLogin: "gate[bot]", RunURL: "https://github.com/o/r/actions/runs/42"}
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
			// The facts here were gathered under settings of their own,
			// which is as far as a decision gets against this fake.
			is: land.ErrConfigChanged, calls: "GET pulls/7, GET pulls/7, GET contents/.github/dep-review.json"},
		{name: "closed since: skipped", dir: "7", pull: pullJSON("closed", "dependabot[bot]", testHead), calls: "GET pulls/7"},
		{name: "a newer head since: skipped", dir: "7", pull: pullJSON("open", "dependabot[bot]", strings.Repeat("4", 40)), calls: "GET pulls/7"},
		{name: "the pull request cannot be read", dir: "7", want: "404", calls: "GET pulls/7"},
		{name: "not a pull request's directory", dir: "seven", want: "not a refreshed pull request's directory"},
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
			err = refreshed(context.Background(), api.config(t), filepath.Join(in, "refreshed"), entries[0], nil)
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
		if got := strings.Join(api.calls, ", "); got != "GET pulls/7" {
			t.Errorf("requests %q, want #7 looked at", got)
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
		if got := strings.Join(api.calls, ", "); got != "GET pulls/7" {
			t.Errorf("requests %q, want #7 looked at", got)
		}
	})
	t.Run("nothing", func(t *testing.T) {
		api := &fakeAPI{}
		if err := publishRefreshed(context.Background(), api.config(t), t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "neither") {
			t.Errorf("err = %v", err)
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
	}{
		{name: "the fetch job left no facts", pull: open, want: "no facts file", reported: true},
		{name: "facts about another pull request", facts: func(f *wire.Facts) { f.PullRequest.Number = 8 }, pull: open,
			want: "classify looked at", reported: true},
		{name: "deciding fails", facts: func(*wire.Facts) {}, pull: open, want: "another configuration", reported: true},
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
			for _, s := range []string{`"state":"error"`, "### dep-review: the run failed", "the fetch job ended failure and the review job unknown.", "actions/runs/42"} {
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

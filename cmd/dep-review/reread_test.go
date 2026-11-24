package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/config"
	"github.com/sadbox/dep-review/internal/land"
	"github.com/sadbox/dep-review/internal/veto"
	"github.com/sadbox/dep-review/internal/wire"
)

// reviewerSettings is the reviewer's settings and fingerprint in this
// build.
func reviewerSettings(t *testing.T) (veto.Config, string) {
	t.Helper()
	conf, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	settings := veto.FromConfig(conf)
	return settings, settings.Fingerprint()
}

// countingReviewer answers no veto and records what it was asked about.
type countingReviewer struct{ names []string }

func (r *countingReviewer) Review(_ context.Context, req veto.Request) (veto.Verdict, error) {
	r.names = append(r.names, req.Read.Pair.Name)
	return veto.Verdict{Answer: veto.NoVeto, Quotes: []string{}, Read: req.Read.State, Key: req.Read.Key}, nil
}

// writeRefreshed writes pull request number's directory of a refreshed
// artifact under in: the facts, the one chunk they list and, when skip is
// not nil, the skip list.
func writeRefreshed(t *testing.T, in string, number int, change func(*wire.Facts), skip *wire.Verdicts) {
	t.Helper()
	facts := goodFacts()
	facts.PullRequest.Number = number
	if change != nil {
		change(&facts)
	}
	dir := filepath.Join(in, "refreshed", itoa(number))
	writeFacts(t, filepath.Join(dir, wire.FactsFile), facts)
	writeFile(t, filepath.Join(dir, wire.ChunksDir, wire.ChunkName(0, 0)), "text")
	if skip != nil {
		b, err := wire.EncodeVerdicts(*skip)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, wire.AnsweredFile), string(b))
	}
}

func itoa(n int) string { return string(rune('0' + n)) }

// The skip list the refresh job writes: an entry for every prepared read
// the model is not to be asked about in this run, and none of them says
// that anything was read (spec section 11, amendment 64).
func TestAnswered(t *testing.T) {
	_, fingerprint := reviewerSettings(t)
	other := strings.Repeat("3", 64)
	facts := goodFacts()
	second := facts.Facts.Updates[0]
	second.Name, second.Prepared.Key = "example.com/n", other
	second.Prepared.Chunks = []wire.ChunkFile{wire.NewChunkFile(1, 0, "text")}
	unprepared := facts.Facts.Updates[0]
	unprepared.Name, unprepared.Prepared = "example.com/o", wire.Read{Status: wire.Unavailable, Detail: "the registry did not answer"}
	// Two updates with one read, one with another, one with none.
	facts.Facts.Updates = append(facts.Facts.Updates, second, facts.Facts.Updates[0], unprepared)

	for _, tc := range []struct {
		name     string
		w        land.Reevaluation
		skipped  []string
		wantsAsk bool
	}{
		{"an ask is due and nothing is remembered: everything is asked", land.Reevaluation{Ask: true}, nil, true},
		{"an ask is due and one read is remembered", land.Reevaluation{Ask: true, Answered: []string{testKey}}, []string{testKey}, true},
		{"an ask is due and every read is remembered", land.Reevaluation{Ask: true, Answered: []string{other, testKey}}, []string{testKey, other}, false},
		{"no ask is due: nothing is asked, whatever is remembered", land.Reevaluation{Answered: []string{testKey}}, []string{testKey, other}, false},
		{"no ask is due and nothing is remembered", land.Reevaluation{}, []string{testKey, other}, false},
		{"a remembered read the pull request does not have is not listed", land.Reevaluation{Ask: true, Answered: []string{strings.Repeat("4", 64)}}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			skip, ask := answered(tc.w, facts, fingerprint)
			var keys []string
			for _, v := range skip.Verdicts {
				keys = append(keys, v.Key)
				// A key and nothing more: no state, no veto, nobody's answer.
				if v.Fingerprint != fingerprint || v.Read != allow.ReadNone || v.Veto != nil {
					t.Errorf("entry %+v says more than a key", v)
				}
			}
			if !slices.Equal(keys, tc.skipped) || ask != tc.wantsAsk {
				t.Errorf("skipped %v, ask %t; want %v, %t", keys, ask, tc.skipped, tc.wantsAsk)
			}
			b, err := wire.EncodeVerdicts(skip)
			if err != nil {
				t.Fatalf("the skip list is not a file the review job reads: %v", err)
			}
			// Taken for a verdicts file, it reads nothing: every prepared
			// read is still unread.
			read, err := wire.DecodeVerdicts(b)
			if err != nil {
				t.Fatal(err)
			}
			for _, u := range wire.Join(facts, read, fingerprint).Updates {
				if u.Read != allow.ReadNone || u.Veto != nil {
					t.Errorf("the skip list as a verdicts file: %s is read %q", u.Name, u.Read)
				}
			}
		})
	}
}

// The scheduled run's review job asks about every pull request the
// refresh job wrote, each by its own skip list, and writes a verdicts
// file for a pull request only when it asked the model about it. What it
// cannot use is that pull request's alone.
func TestReread(t *testing.T) {
	_, fingerprint := reviewerSettings(t)
	none := wire.Verdicts{Version: wire.Version, Verdicts: []wire.Verdict{}}
	skipIt := wire.Verdicts{Version: wire.Version, Verdicts: []wire.Verdict{{Key: testKey, Fingerprint: fingerprint, Read: allow.ReadNone}}}
	// The same key under another fingerprint is another reviewer's list.
	foreign := wire.Verdicts{Version: wire.Version, Verdicts: []wire.Verdict{{Key: testKey, Fingerprint: strings.Repeat("9", 64), Read: allow.ReadNone}}}
	named := func(name string) func(*wire.Facts) {
		return func(f *wire.Facts) { f.Facts.Updates[0].Name = name }
	}

	in := t.TempDir()
	writeRefreshed(t, in, 1, named("example.com/asked"), &none)
	writeRefreshed(t, in, 2, named("example.com/skipped"), &skipIt)
	writeRefreshed(t, in, 3, named("example.com/no-list"), nil)
	writeRefreshed(t, in, 4, named("example.com/foreign-list"), &foreign)
	writeRefreshed(t, in, 5, named("example.com/bad-chunk"), &none)
	writeFile(t, filepath.Join(in, "refreshed", "5", wire.ChunksDir, wire.ChunkName(0, 0)), "other text")
	writeRefreshed(t, in, 6, named("example.com/bad-list"), nil)
	writeFile(t, filepath.Join(in, "refreshed", "6", wire.AnsweredFile), `{"version":1,"verdicts":[],"approved":true}`)
	writeFile(t, filepath.Join(in, "refreshed", sumsFile), "the manifest")
	writeFile(t, filepath.Join(in, "refreshed", "notes.txt"), "not a pull request")

	reviewer := &countingReviewer{}
	out := filepath.Join(in, "reverdicts")
	if err := reread(context.Background(), reviewer, fingerprint, filepath.Join(in, "refreshed"), out); err != nil {
		t.Fatal(err)
	}
	if want := []string{"example.com/asked", "example.com/foreign-list"}; !slices.Equal(reviewer.names, want) {
		t.Errorf("asked about %v, want %v", reviewer.names, want)
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	var wrote []string
	for _, e := range entries {
		wrote = append(wrote, e.Name())
	}
	if !slices.Equal(wrote, []string{"1", "4"}) {
		t.Errorf("verdicts written for %v, want #1 and #4: a file means the model was asked", wrote)
	}
	b, err := os.ReadFile(filepath.Join(out, "1", wire.VerdictsFile))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := wire.DecodeVerdicts(b); err != nil || len(v.Verdicts) != 1 || v.Verdicts[0] != (wire.Verdict{Key: testKey, Fingerprint: fingerprint, Read: allow.ReadFull}) {
		t.Errorf("#1's verdicts: %+v, %v", v, err)
	}

	// Out of time before a pull request: nobody is asked, and no file
	// says somebody was. The directory is there for the step that sums it.
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	reviewer, out = &countingReviewer{}, filepath.Join(t.TempDir(), "reverdicts")
	if err := reread(ended, reviewer, fingerprint, filepath.Join(in, "refreshed"), out); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(out); err != nil || len(entries) != 0 || len(reviewer.names) != 0 {
		t.Errorf("out of time: %d files, %v, asked about %v", len(entries), err, reviewer.names)
	}
}

// markerRE finds the gate's marker in a comment as the request to the API
// carries it (JSON, which writes the angle brackets as escapes), and
// asksOf reads the count of scheduled asks out of it.
var markerRE = regexp.MustCompile(`!-- dep-review:v2 ([A-Za-z0-9_-]+) --`)

func asksOf(t *testing.T, written string) int {
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
		Asks int `json:"asks"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m.Asks
}

// A token exchange the federation rule denies is a miss like any other
// (spec section 11, amendment 64). The review job writes a verdicts file
// with no answer in it, the read waits, and publish counts the ask, so
// the next one waits its turn. Before the rule admits the schedule's
// token this is what every scheduled ask looks like.
func TestRereadDeniedExchange(t *testing.T) {
	exchanges := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/oauth/token" {
			t.Errorf("%s %s: nothing is sent to the model without a token", r.Method, r.URL.Path)
		}
		exchanges++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"type":"error","error":{"type":"authentication_error","message":"Authentication failed"}}`))
	}))
	defer api.Close()
	settings, fingerprint := reviewerSettings(t)
	settings.BaseURL = api.URL
	creds, err := veto.NewFederated(veto.Federation{
		IdentityToken: func(context.Context) (string, error) { return "a.jwt.of-the-schedule", nil },
		RuleID:        "fdrl_test", OrganizationID: "00000000-0000-0000-0000-000000000000",
	}, api.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := veto.New(settings, creds, nil)
	if err != nil {
		t.Fatal(err)
	}

	// A pull request the refresh job wrote, with an ask due and nothing
	// remembered. Its identity does not hold, which is the one decision
	// the GitHub of these tests carries through.
	unverified := func(f *wire.Facts) { f.Facts.Identity = allow.No("pushed by a person", "classify") }
	publish := func(in string) string {
		t.Helper()
		gh := &fakeAPI{pull: pullJSON("open", "mallory", testHead)}
		if err := publishRefreshed(context.Background(), gh.config(t), in, nil); err != nil {
			t.Fatal(err)
		}
		return strings.Join(gh.bodies, "\n")
	}

	in := t.TempDir()
	writeRefreshed(t, in, 7, unverified, &wire.Verdicts{Version: wire.Version, Verdicts: []wire.Verdict{}})
	if err := reread(context.Background(), client, fingerprint, filepath.Join(in, "refreshed"), filepath.Join(in, "reverdicts")); err != nil {
		t.Fatal(err)
	}
	if exchanges == 0 {
		t.Fatal("no token exchange was tried")
	}
	b, err := os.ReadFile(filepath.Join(in, "reverdicts", "7", wire.VerdictsFile))
	if err != nil {
		t.Fatalf("a denied exchange left no verdicts file, so the ask would not be counted: %v", err)
	}
	if v, err := wire.DecodeVerdicts(b); err != nil || len(v.Verdicts) != 1 || v.Verdicts[0] != (wire.Verdict{Key: testKey, Fingerprint: fingerprint, Read: allow.ReadNone}) {
		t.Fatalf("verdicts %+v, %v; want the one read, with no answer", v, err)
	}
	written := publish(in)
	if got := asksOf(t, written); got != 1 {
		t.Errorf("the comment counts %d asks after the denied exchange, want 1", got)
	}
	if !strings.Contains(written, "| Read | `none` |") {
		t.Errorf("the read is not unread after a denied exchange: %s", written)
	}

	// The same pull request in a run that asked nobody: nothing counted.
	quiet := t.TempDir()
	writeRefreshed(t, quiet, 7, unverified, nil)
	if got := asksOf(t, publish(quiet)); got != 0 {
		t.Errorf("the comment counts %d asks in a run that asked nobody, want 0", got)
	}
}

// On a scheduled run publish takes a verdict from the second review job's
// own artifact and from the gate's own comment, and from nowhere else.
// The refresh job parses what a pull request wrote; a file it puts beside
// the facts that says a read was read in full is not opened.
func TestPublishTakesNoVerdictFromRefresh(t *testing.T) {
	_, fingerprint := reviewerSettings(t)
	claim := wire.Verdicts{Version: wire.Version, Verdicts: []wire.Verdict{{Key: testKey, Fingerprint: fingerprint, Read: allow.ReadFull}}}
	b, err := wire.EncodeVerdicts(claim)
	if err != nil {
		t.Fatal(err)
	}
	unverified := func(f *wire.Facts) { f.Facts.Identity = allow.No("pushed by a person", "classify") }
	publish := func(in string) string {
		t.Helper()
		gh := &fakeAPI{pull: pullJSON("open", "mallory", testHead)}
		if err := publishRefreshed(context.Background(), gh.config(t), in, nil); err != nil {
			t.Fatal(err)
		}
		return strings.Join(gh.bodies, "\n")
	}

	in := t.TempDir()
	writeRefreshed(t, in, 7, unverified, &claim)
	// The refresh job's directory, in the place the verdicts file had
	// before, and in the skip list.
	writeFile(t, filepath.Join(in, "refreshed", "7", wire.VerdictsFile), string(b))
	if written := publish(in); !strings.Contains(written, "| Read | `none` |") || strings.Contains(written, "| Read | `full` |") {
		t.Errorf("a verdict was taken from the refresh job's directory: %s", written)
	}
	if _, err := os.Stat(filepath.Join(in, "reverdicts")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("the test wrote a reverdicts artifact")
	}

	// The same verdict from the review job's artifact counts.
	writeFile(t, filepath.Join(in, "reverdicts", "7", wire.VerdictsFile), string(b))
	if written := publish(in); !strings.Contains(written, "| Read | `full` |") {
		t.Errorf("the review job's verdict was not taken: %s", written)
	}
}

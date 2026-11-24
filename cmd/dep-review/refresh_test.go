package main

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sadbox/dep-review/internal/land"
	"github.com/sadbox/dep-review/internal/wire"
)

// The order of one scheduled run: the pull requests the gate has nothing
// for come first, lowest number first (the run evaluates maxUndecided of
// them and leaves the rest), and the waiting ones follow. A wait past its
// deadline is publish's to act on whether or not this job gets to it
// (spec section 11, amendments 66 and 67).
func TestInOrder(t *testing.T) {
	var evaluate []land.Reevaluation
	// As land.Schedule lists them: by number, the two kinds mixed.
	for n := 1; n <= 4; n++ {
		evaluate = append(evaluate, land.Reevaluation{Number: 2 * n, Undecided: true}, land.Reevaluation{Number: 2*n + 1})
	}
	todo, overdue := inOrder(evaluate)
	var got []int
	for _, w := range todo {
		got = append(got, w.Number)
	}
	want := []int{2, 4, 6, 8, 3, 5, 7, 9}
	if !slices.Equal(got, want) || overdue {
		t.Errorf("order %v, overdue %t; want %v and nothing overdue", got, overdue, want)
	}

	evaluate[1].PastDeadline = true
	if _, overdue := inOrder(evaluate); !overdue {
		t.Error("a waiting pull request past its deadline is not reported as overdue")
	}
	if todo, overdue := inOrder(nil); len(todo) != 0 || overdue {
		t.Errorf("nothing to evaluate: %v, %t", todo, overdue)
	}
}

// A pull request the refresh job tried and could not evaluate leaves a
// directory with one file that is no facts file: nothing half-written is
// handed on, and publish finds the directory.
func TestLeaveUnevaluated(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "7")
	writeFile(t, filepath.Join(dir, wire.FactsFile), "half a facts file")
	writeFile(t, filepath.Join(dir, wire.ChunksDir, wire.ChunkName(0, 0)), "text")
	if err := leaveUnevaluated(dir); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != unevaluatedFile || !entries[0].Type().IsRegular() {
		t.Fatalf("the directory holds %v, %v; want the one file", entries, err)
	}
	// An artifact upload drops an empty directory and may drop an empty
	// file, so the file has a line in it.
	if info, err := entries[0].Info(); err != nil || info.Size() == 0 {
		t.Errorf("the file is empty: %v", err)
	}
	if _, err := readFacts(filepath.Join(dir, wire.FactsFile)); err == nil {
		t.Error("publish reads facts in a directory that says the pull request could not be evaluated")
	}
}

// One run of the refresh job keeps to its bounds (spec section 11,
// amendment 66): of the pull requests the gate has nothing for it
// evaluates maxUndecided, counting the ones it gathered or failed on and
// not the ones that are not the gate's; a failure leaves a directory that
// says so; and a run that ends under a pull request blames nobody.
func TestRefreshAll(t *testing.T) {
	// Undecided: #1 and #2 are not the gate's (an ignored ecosystem), #3
	// fails, #4 to #9 can be evaluated. Then two waiting ones.
	var todo []land.Reevaluation
	for n := 1; n <= 9; n++ {
		todo = append(todo, land.Reevaluation{Number: n, Undecided: true})
	}
	todo = append(todo, land.Reevaluation{Number: 20}, land.Reevaluation{Number: 21})
	var asked []int
	one := func(_ context.Context, w land.Reevaluation, dir string) (bool, bool, error) {
		asked = append(asked, w.Number)
		switch {
		case w.Number <= 2:
			return false, false, nil
		case w.Number == 3 || w.Number == 21:
			writeFile(t, filepath.Join(dir, wire.FactsFile), "half a facts file")
			return false, false, errors.New("the gatherer failed")
		}
		writeFile(t, filepath.Join(dir, wire.FactsFile), "facts")
		return true, w.Number == 20, nil
	}
	out := t.TempDir()
	got, err := refreshAll(context.Background(), todo, out, one)
	if err != nil {
		t.Fatal(err)
	}
	// #8 and #9 are over the cap; the waiting ones are evaluated all the same.
	if want := []int{1, 2, 3, 4, 5, 6, 7, 20, 21}; !slices.Equal(asked, want) {
		t.Errorf("evaluated %v, want %v", asked, want)
	}
	if want := (tally{tried: 7, failed: 2, review: true}); got != want {
		t.Errorf("tally %+v, want %+v", got, want)
	}
	for number, file := range map[string]string{"3": unevaluatedFile, "21": unevaluatedFile, "4": wire.FactsFile, "20": wire.FactsFile} {
		entries, err := os.ReadDir(filepath.Join(out, number))
		if err != nil || len(entries) != 1 || entries[0].Name() != file {
			t.Errorf("#%s: the directory holds %v, %v; want %s alone", number, entries, err, file)
		}
	}
	for _, number := range []string{"1", "2", "8", "9"} {
		if _, err := os.Stat(filepath.Join(out, number)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("#%s has a directory: %v", number, err)
		}
	}

	// The run ends while #2 is gathered: #2 is not a failure and leaves
	// no directory, and #3 is not started.
	ctx, cancel := context.WithCancel(context.Background())
	asked = nil
	out = t.TempDir()
	got, err = refreshAll(ctx, []land.Reevaluation{{Number: 1}, {Number: 2}, {Number: 3}}, out, func(ctx context.Context, w land.Reevaluation, dir string) (bool, bool, error) {
		asked = append(asked, w.Number)
		writeFile(t, filepath.Join(dir, wire.FactsFile), "facts")
		if w.Number == 2 {
			cancel()
			return false, false, ctx.Err()
		}
		return true, false, nil
	})
	if err != nil || got != (tally{tried: 1}) || !slices.Equal(asked, []int{1, 2}) {
		t.Errorf("out of time: tally %+v, evaluated %v, %v; want #1 done and nothing failed", got, asked, err)
	}
	if _, err := os.Stat(filepath.Join(out, "2")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the pull request the run ended under left a directory: %v", err)
	}
}

// What the refresh job tells the workflow. Publish runs for more than an
// upload: a wait past its deadline and a notification that was not sent
// are its to deal with when this job wrote nothing, and a pull request
// that could not be evaluated always leaves something to upload, so that
// publish runs and fails the run (spec section 11, amendments 66 and 67).
func TestRefreshOutputs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		t       tally
		overdue bool
		untold  int
		want    map[string]bool
	}{
		{"nothing to do", tally{}, false, 0, map[string]bool{"upload": false, "publish": false, "review": false, "incomplete": false}},
		{"a pull request refreshed", tally{tried: 1}, false, 0, map[string]bool{"upload": true, "publish": true, "review": false, "incomplete": false}},
		{"a read left for the model", tally{tried: 1, review: true}, false, 0, map[string]bool{"upload": true, "publish": true, "review": true, "incomplete": false}},
		{"the one pull request could not be evaluated", tally{tried: 1, failed: 1}, false, 0, map[string]bool{"upload": true, "publish": true, "review": false, "incomplete": true}},
		{"nothing written, and a wait past its deadline", tally{}, true, 0, map[string]bool{"upload": false, "publish": true, "review": false, "incomplete": false}},
		{"nothing written, and a notification owed", tally{}, false, 2, map[string]bool{"upload": false, "publish": true, "review": false, "incomplete": false}},
	} {
		if got := tc.t.outputs(tc.overdue, tc.untold); !maps.Equal(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	// The names are the ones gate.yml reads.
	refresh := gateJobs(t)["refresh"]
	for name := range (tally{}).outputs(false, 0) {
		if !strings.Contains(refresh, "steps.refresh.outputs."+name) {
			t.Errorf("gate.yml's refresh job does not read the step output %q", name)
		}
	}
}

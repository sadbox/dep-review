package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"github.com/sadbox/dep-review/internal/gather"
	"github.com/sadbox/dep-review/internal/veto"
	"github.com/sadbox/dep-review/internal/wire"
)

// runReread: dep-review reread --refreshed <dir> --out <dir> --federation-rule-id <id> --organization-id <id>
//
// The scheduled run's review job. For every pull request the refresh job
// wrote a directory for, it puts before the model the prepared reads that
// are not on that pull request's skip list (wire.AnsweredFile) and writes
// a verdicts file into --out/<number>; a pull request with nothing to ask
// gets no file. Like review, the job holds the model's credential and
// nothing of GitHub. All the pull requests share the one time budget.
func runReread(args []string) error {
	fl := newFlagSet("reread")
	refreshed := fl.String("refreshed", "", "the refresh job's directory: a directory for each pull request, with its facts file, chunks and skip list (required)")
	out := fl.String("out", "", "directory to write one directory with a verdicts file into for each pull request the model was asked about (required)")
	model := modelFlags(fl)
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *refreshed == "" || *out == "" || fl.NArg() > 0 {
		return errors.New("reread: --refreshed and --out are required")
	}
	client, fingerprint, err := model.reviewer()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), reviewTimeout)
	defer cancel()
	return reread(ctx, client, fingerprint, *refreshed, *out)
}

// reread asks reviewer about every refreshed pull request in turn. What
// goes wrong with one pull request is logged and is that pull request's
// alone: it gets no verdicts file, its reads wait, and the others are
// still asked about. Failing the job for it would keep every answer of
// this run from being uploaded. The error is --out not being writable.
func reread(ctx context.Context, reviewer veto.Reviewer, fingerprint, refreshed, out string) error {
	// Made also when nothing is written, for the step that sums it.
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(refreshed)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() == sumsFile && e.Type().IsRegular() {
			continue
		}
		number, err := refreshedNumber(e)
		if err != nil {
			log.Printf("reread: %s: %v", e.Name(), err)
			continue
		}
		if ctx.Err() != nil {
			// Out of time before this one: nobody was asked, so no file
			// says somebody was.
			log.Printf("reread: #%d: out of time, not asked about; its reads wait", number)
			continue
		}
		dir := filepath.Join(refreshed, e.Name())
		answered, err := readAnswered(filepath.Join(dir, wire.AnsweredFile), fingerprint)
		if err != nil {
			log.Printf("reread: #%d: %v; its reads wait", number, err)
			continue
		}
		verdicts, err := gather.Review{
			Reviewer:    reviewer,
			Fingerprint: fingerprint,
			Answered:    answered,
			Logf:        log.Printf,
		}.Run(ctx, dir, filepath.Join(out, e.Name()))
		// Out of time with the verdicts file written: it is good, and the
		// reads without a verdict wait (as in review).
		partial := errors.Is(err, context.DeadlineExceeded) && verdicts.Version != 0
		if err != nil && !partial {
			log.Printf("reread: #%d: %v; its reads wait", number, err)
			continue
		}
		log.Printf("reread: #%d: %d verdicts", number, len(verdicts.Verdicts))
	}
	return nil
}

// refreshedNumber is the pull request a directory of the refreshed
// artifact is for: the refresh job names a directory by its number.
func refreshedNumber(e fs.DirEntry) (int, error) {
	number, err := strconv.Atoi(e.Name())
	if err != nil || number < 1 || strconv.Itoa(number) != e.Name() || !e.IsDir() {
		return 0, errors.New("not a refreshed pull request's directory")
	}
	return number, nil
}

// readAnswered reads a pull request's skip list: the content keys the
// refresh job listed under this job's reviewer fingerprint. Whatever else
// an entry says is not looked at; a skip list is not a verdict. A file
// that is missing or does not decode is an error, and then nothing of the
// pull request is asked about: the list is what bounds the asking.
func readAnswered(path, fingerprint string) (map[string]bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("the skip list: %w", err)
	}
	listed, err := wire.DecodeVerdicts(b)
	if err != nil {
		return nil, fmt.Errorf("the skip list: %w", err)
	}
	answered := map[string]bool{}
	for _, v := range listed.Verdicts {
		if v.Fingerprint == fingerprint {
			answered[v.Key] = true
		}
	}
	return answered, nil
}

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/classify"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/land"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/veto"
	"github.com/sadbox/dep-review/internal/wire"
)

// refreshTimeout leaves the job (30 minutes) time to upload what it
// wrote. Pull requests it did not get to are evaluated by the next run.
const refreshTimeout = 25 * time.Minute

// maxUndecided is how many pull requests the gate has nothing for are
// evaluated from scratch in one run, lowest number first. They come
// before the waiting ones, which is why they are capped: a batch of them
// must not use up the run. The rest are the next run's. What counts is a
// pull request the job gathered facts for or failed on. One that classify
// says is not the gate's (an ignored ecosystem, which never gets a
// comment and so is listed at every run) costs its proof and no place.
const maxUndecided = 5

// unevaluatedFile is what the refresh job leaves in the directory of a
// pull request it tried to evaluate and could not: the directory is then
// in the artifact without a facts file, which is how publish learns that
// the pull request was tried. Publish does not open the file.
const unevaluatedFile = "unevaluated"

// runRefresh: dep-review refresh --repo-dir <dir> --out <dir> --app-slug <slug>
//
// The scheduled job. It evaluates the open Dependabot pull requests the
// gate left waiting and the ones the gate has nothing for at their head
// (land.Schedule): for each it runs classify's proof again, gathers the
// facts again and writes them into --out/<number>, for publish to decide;
// publish runs the proof once more itself and believes the facts only as
// far as it goes. Beside the facts it writes the skip list for the second
// review job (wire.AnsweredFile): which prepared reads the model is not
// to be asked about in this run. This job asks no model and holds no
// credential but its read-only token.
//
// The work of one run is bounded. Everything shares refreshTimeout, and
// what is not reached is the next run's. At most maxUndecided pull
// requests are evaluated from scratch, and only ones that have not
// changed for land.UndecidedAfter. No model is asked about a pull request
// in the run that first evaluates its head. And a pull request the run
// tried and could not evaluate gets a directory with no facts, by which
// publish reports it once instead of every run trying again.
//
// It appends to $GITHUB_OUTPUT upload=<true|false>, whether it wrote
// anything; publish=<true|false>, whether publish has something to do
// (that, an overdue wait, or a notification that was not delivered);
// review=<true|false>, whether a read is left for the model; and
// incomplete=<true|false>, whether a pull request could not be evaluated.
func runRefresh(args []string) error {
	fl := newFlagSet("refresh")
	repoDir := fl.String("repo-dir", "", "a clone with full history and every branch; only its git objects are read (required)")
	out := fl.String("out", "", "directory to write one directory for each pull request into (required)")
	slug := fl.String("app-slug", "", slugUsage)
	ignoreList := fl.String("ignore-ecosystems", "", ignoreUsage)
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *repoDir == "" || *out == "" || *slug == "" || fl.NArg() > 0 {
		return errors.New("refresh: --repo-dir, --out and --app-slug are required")
	}
	ignore, err := model.ParseEcosystems(*ignoreList)
	if err != nil {
		return fmt.Errorf("--ignore-ecosystems: %w", err)
	}
	c, err := gh.NewFromEnv()
	if err != nil {
		return err
	}
	cfg, err := landConfig(c, *slug)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
	defer cancel()

	agenda, err := land.Schedule(ctx, cfg)
	if err != nil {
		return err
	}
	todo, overdue := inOrder(agenda.Evaluate)
	log.Printf("refresh: %d pull requests to evaluate, %d comments with a notification that was not sent", len(todo), len(agenda.Untold))
	var done tally
	if len(todo) > 0 {
		g, err := newGathering(cfg.GitHub)
		if err != nil {
			return err
		}
		defer g.close()
		done, err = refreshAll(ctx, todo, *out, func(ctx context.Context, w land.Reevaluation, dir string) (bool, bool, error) {
			return g.refresh(ctx, cfg, w, ignore, *repoDir, dir)
		})
		if err != nil {
			return err
		}
	}
	for name, value := range done.outputs(overdue, len(agenda.Untold)) {
		if err := stepOutput(name, strconv.FormatBool(value)); err != nil {
			return err
		}
	}
	return nil
}

// outputs is the job's step outputs. Publish has something to do when a
// directory was written (a pull request to decide, or one to report as
// not evaluated), when a wait is past its deadline, and when a comment
// owes a notification: the last two need no artifact, and do not depend
// on this job having got to the pull request.
func (t tally) outputs(overdue bool, untold int) map[string]bool {
	return map[string]bool{
		"upload":     t.tried > 0,
		"publish":    t.tried > 0 || overdue || untold > 0,
		"review":     t.review,
		"incomplete": t.failed > 0,
	}
}

// tally is what one run of the refresh job came to.
type tally struct {
	// tried is the pull requests that have a directory in out: the ones
	// whose facts were written, and the ones that could not be evaluated.
	// failed is the second kind alone.
	tried, failed int
	// review says a prepared read is left for the model.
	review bool
}

// refreshAll evaluates the pull requests of todo in order, each into its
// own directory of out, with one. It keeps to the run's bounds: when the
// context ends the rest is the next run's, and of the pull requests the
// gate has nothing for it evaluates maxUndecided. One pull request's
// failure is its own. The error is out not being writable.
func refreshAll(ctx context.Context, todo []land.Reevaluation, out string, one func(ctx context.Context, w land.Reevaluation, dir string) (done, ask bool, err error)) (tally, error) {
	var t tally
	fromScratch := 0 // of maxUndecided
	for _, w := range todo {
		if ctx.Err() != nil {
			log.Printf("refresh: out of time; #%d is the next run's", w.Number)
			continue
		}
		if w.Undecided && fromScratch == maxUndecided {
			log.Printf("refresh: #%d has no decision for its head and is the next run's: this run evaluates %d such pull requests", w.Number, maxUndecided)
			continue
		}
		dir := filepath.Join(out, strconv.Itoa(w.Number))
		done, ask, err := one(ctx, w, dir)
		switch {
		case err != nil && ctx.Err() != nil:
			// The run ended under it. That is not this pull request's
			// failure, and nothing says it could not be evaluated.
			log.Printf("refresh: out of time in #%d; it is the next run's", w.Number)
			if err := os.RemoveAll(dir); err != nil {
				return t, err
			}
			continue
		case err != nil:
			// The others are still evaluated, and a half-written
			// directory is not handed on. What is handed on says that the
			// pull request was tried.
			t.failed++
			t.tried++
			log.Printf("refresh: #%d: %v", w.Number, err)
			if err := leaveUnevaluated(dir); err != nil {
				return t, err
			}
		case done:
			t.tried++
			t.review = t.review || ask
		default:
			continue // not the gate's: it cost its proof and no place
		}
		if w.Undecided {
			fromScratch++
		}
	}
	return t, nil
}

// inOrder is the pull requests of one run in the order they are taken:
// first the ones the gate has nothing for, of which the run evaluates
// maxUndecided at most, then the waiting ones. overdue says a waiting one
// is past its deadline, which publish acts on whether or not this job
// gets to it.
func inOrder(evaluate []land.Reevaluation) (todo []land.Reevaluation, overdue bool) {
	var waiting []land.Reevaluation
	for _, w := range evaluate {
		if w.Undecided {
			todo = append(todo, w)
			continue
		}
		waiting = append(waiting, w)
		overdue = overdue || w.PastDeadline
	}
	return append(todo, waiting...), overdue
}

// leaveUnevaluated empties dir and leaves the one file that says the pull
// request was tried.
func leaveUnevaluated(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, unevaluatedFile), []byte("the refresh job could not evaluate this pull request; its log says why\n"), 0o644)
}

// refresh evaluates one pull request, into dir. done is false when there
// is nothing to hand on: the pull request is not, or no longer, one the
// gate acts on at that head. ask says a prepared read is left for the
// model.
func (g *gathering) refresh(ctx context.Context, cfg land.Config, w land.Reevaluation, ignore map[model.Ecosystem]bool, repoDir, dir string) (done, ask bool, err error) {
	// The whole proof, as for an event: nothing here takes a pull request
	// to be Dependabot's because it was so the last time.
	class, err := classify.Pull(ctx, cfg.GitHub, cfg.Repo, w.Number, w.Head, classify.Options{IgnoreEcosystems: ignore})
	if err != nil {
		return false, false, err
	}
	if !handled(class.Kind) {
		// Closed, moved on (the new head has a run of its own) or
		// ignored.
		log.Printf("refresh: #%d: %s, nothing to do", w.Number, class.Kind)
		return false, false, nil
	}
	facts, err := g.fetch(ctx, class, repoDir, dir)
	if err != nil {
		return false, false, err
	}
	// No model is asked here, and no verdict leaves this job: it parses
	// what a pull request wrote. What it hands the job that asks is which
	// reads to skip.
	skip, ask := answered(w, facts, veto.FromConfig(g.conf).Fingerprint())
	b, err := wire.EncodeVerdicts(skip)
	if err != nil {
		return false, false, err
	}
	log.Printf("refresh: #%d: %d prepared reads are not asked about in this run; some are: %t", w.Number, len(skip.Verdicts), ask)
	if err := os.WriteFile(filepath.Join(dir, wire.AnsweredFile), b, 0o644); err != nil {
		return false, false, err
	}
	return true, ask, nil
}

// answered is the skip list for one refreshed pull request: an entry for
// every prepared read the model is not to be asked about in this run.
// That is a read the gate's comment remembers an answer for, and every
// read when no ask is due for the pull request (land.Reevaluation). ask
// says a prepared read is left over.
//
// The list has the form of a verdicts file and every entry is Read none
// under this build's reviewer fingerprint: the reader takes the keys from
// it, and read as verdicts it says that nothing was read. What the
// comment remembers reaches publish from the comment, which publish reads
// itself, and never from here. So a list that is wrong makes the model
// answer a question twice or leaves a read waiting, and can do no more.
func answered(w land.Reevaluation, facts wire.Facts, fingerprint string) (skip wire.Verdicts, ask bool) {
	remembered := map[string]bool{}
	for _, key := range w.Answered {
		remembered[key] = true
	}
	skip = wire.Verdicts{Version: wire.Version, Verdicts: []wire.Verdict{}}
	listed := map[string]bool{}
	for _, u := range facts.Facts.Updates {
		key := u.Prepared.Key
		switch {
		case u.Prepared.Status != wire.Prepared || listed[key]:
		case remembered[key] || !w.Ask:
			listed[key] = true
			skip.Verdicts = append(skip.Verdicts, wire.Verdict{Key: key, Fingerprint: fingerprint, Read: allow.ReadNone})
		default:
			ask = true
		}
	}
	return skip, ask
}

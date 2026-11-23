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

// runRefresh: dep-review refresh --repo-dir <dir> --out <dir> --app-slug <slug>
//
// The scheduled job. For every open Dependabot pull request the gate left
// waiting it runs classify's proof again, gathers the facts again and
// writes them into --out/<number>, for publish to decide; publish runs
// the proof once more itself and believes the facts only as far as it
// goes. Beside the facts it writes the skip list for the second review
// job (wire.AnsweredFile): which prepared reads the model is not to be
// asked about in this run. This job asks no model and holds no credential
// but its read-only token. It appends to $GITHUB_OUTPUT
// publish=<true|false>, whether it wrote anything, review=<true|false>,
// whether a read is left for the model, and incomplete=<true|false>,
// whether a pull request could not be refreshed or has a gate comment
// whose marker could not be read.
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

	waiting, unread, err := land.Waiting(ctx, cfg)
	if err != nil {
		return err
	}
	log.Printf("refresh: %d pull requests are waiting", len(waiting))
	// A gate comment without a marker this version reads does not say
	// whether its pull request waits. It counts as not refreshed, so the
	// run ends red instead of the pull request leaving the schedule unseen.
	for _, number := range unread {
		log.Printf("refresh: #%d: the marker in the gate's comment could not be read, so the pull request is not evaluated again; re-run its gate workflow run", number)
	}
	wrote, failed, review := 0, len(unread), false
	if len(waiting) > 0 {
		g, err := newGathering(cfg.GitHub)
		if err != nil {
			return err
		}
		defer g.close()
		for _, w := range waiting {
			if w.PastDeadline {
				log.Printf("refresh: #%d is still waiting after its deadline, %s", w.Number, w.Deadline.UTC().Format(time.RFC3339))
			}
			dir := filepath.Join(*out, strconv.Itoa(w.Number))
			done, ask, err := g.refresh(ctx, cfg, w, ignore, *repoDir, dir)
			review = review || ask
			switch {
			case err != nil:
				// One pull request's failure is its own: the others are
				// still refreshed, and a half-written directory is not
				// handed on.
				failed++
				log.Printf("refresh: #%d: %v", w.Number, err)
				if err := os.RemoveAll(dir); err != nil {
					return err
				}
			case done:
				wrote++
			}
		}
	}
	if err := stepOutput("publish", strconv.FormatBool(wrote > 0)); err != nil {
		return err
	}
	if err := stepOutput("review", strconv.FormatBool(review)); err != nil {
		return err
	}
	return stepOutput("incomplete", strconv.FormatBool(failed > 0))
}

// refresh evaluates one waiting pull request again, into dir. done is
// false when there is nothing to hand on: the pull request is no longer
// one the gate acts on at that head. ask says a prepared read is left
// for the model.
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

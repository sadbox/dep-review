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

	"github.com/sadbox/dep-review/internal/classify"
	"github.com/sadbox/dep-review/internal/gather"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/land"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/veto"
)

// refreshTimeout leaves the job (30 minutes) time to upload what it
// wrote. Pull requests it did not get to are evaluated by the next run.
const refreshTimeout = 25 * time.Minute

// runRefresh: dep-review refresh --repo-dir <dir> --out <dir> --app-slug <slug>
//
// The scheduled job. For every open Dependabot pull request the gate left
// waiting it runs classify's proof again, gathers the facts again and
// writes them with the verdicts the gate's comment remembers into
// --out/<number>, for publish to decide; publish runs the proof once more
// itself and believes the facts only as far as it goes. No model is
// asked: the job holds no credential but its read-only token. It appends
// to $GITHUB_OUTPUT publish=<true|false>, whether it wrote anything, and
// incomplete=<true|false>, whether a pull request could not be refreshed.
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

	waiting, err := land.Waiting(ctx, cfg)
	if err != nil {
		return err
	}
	log.Printf("refresh: %d pull requests are waiting", len(waiting))
	wrote, failed := 0, 0
	if len(waiting) > 0 {
		g, err := newGathering(ctx, cfg)
		if err != nil {
			return err
		}
		defer g.close()
		// The reviewer's fingerprint as publish computes it: a remembered
		// verdict counts only under the same one.
		fingerprint := veto.FromConfig(g.conf).Fingerprint()

		for _, w := range waiting {
			if w.PastDeadline {
				log.Printf("refresh: #%d is still waiting after its deadline, %s", w.Number, w.Deadline.UTC().Format(time.RFC3339))
			}
			dir := filepath.Join(*out, strconv.Itoa(w.Number))
			done, err := g.refresh(ctx, cfg, w, fingerprint, ignore, *repoDir, dir)
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
	return stepOutput("incomplete", strconv.FormatBool(failed > 0))
}

// refresh evaluates one waiting pull request again, into dir. done is
// false when there is nothing to hand on: the pull request is no longer
// one the gate acts on at that head.
func (g *gathering) refresh(ctx context.Context, cfg land.Config, w land.Reevaluation, fingerprint string, ignore map[model.Ecosystem]bool, repoDir, dir string) (done bool, err error) {
	// The whole proof, as for an event: nothing here takes a pull request
	// to be Dependabot's because it was so the last time.
	class, err := classify.Pull(ctx, cfg.GitHub, cfg.Repo, w.Number, w.Head, classify.Options{IgnoreEcosystems: ignore})
	if err != nil {
		return false, err
	}
	if !handled(class.Kind) {
		// Closed, moved on (the new head has a run of its own) or
		// ignored.
		log.Printf("refresh: #%d: %s, nothing to do", w.Number, class.Kind)
		return false, nil
	}
	if _, err := g.fetch(ctx, class, repoDir, dir); err != nil {
		return false, err
	}
	// No reviewer: a read whose verdict the comment does not remember
	// stays unread, which waits.
	_, err = gather.Review{Fingerprint: fingerprint, Cached: w.Verdicts.Verdicts, Logf: log.Printf}.Run(ctx, dir, dir)
	return err == nil, err
}

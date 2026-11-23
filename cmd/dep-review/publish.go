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
	"time"

	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/land"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/wire"
)

// publishTimeout leaves the job (15 minutes) time to report.
const publishTimeout = 12 * time.Minute

// The directories of --in: gate.yml's publish job downloads each artifact
// into a directory of its own name.
const (
	classificationArtifact = "classification"
	factsArtifact          = "facts"
	verdictsArtifact       = "verdicts"
	refreshedArtifact      = "refreshed"
	classificationFile     = "classification.json"
)

// runPublish: dep-review publish --in <dir>
//
// Decides and acts (internal/land): for the one pull request of an
// event's run, or for every pull request the scheduled job refreshed. It
// is the only command that holds the gate app's token, which it takes
// from GH_TOKEN, with the app's slug in DEP_REVIEW_APP_SLUG.
func runPublish(args []string) error {
	fl := newFlagSet("publish")
	in := fl.String("in", "", "directory holding the artifacts, each in a directory of its name: classification, facts and verdicts from an event's run, or refreshed from a scheduled one (required)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *in == "" || fl.NArg() > 0 {
		return errors.New("publish: --in is required")
	}
	work, err := publishWork(*in)
	if err != nil {
		return err
	}
	c, err := gh.NewFromEnv()
	if err != nil {
		return err
	}
	cfg, err := landConfig(c, os.Getenv("DEP_REVIEW_APP_SLUG"))
	if err != nil {
		return fmt.Errorf("DEP_REVIEW_APP_SLUG: %w", err)
	}
	if token, user := os.Getenv("PUSHOVER_APP_TOKEN"), os.Getenv("PUSHOVER_USER_KEY"); token != "" && user != "" {
		cfg.Notifier = &land.Pushover{Token: token, User: user}
	}
	ctx, cancel := context.WithTimeout(context.Background(), publishTimeout)
	defer cancel()

	// One pull request that cannot be decided does not keep the others
	// from being decided.
	failed := 0
	for _, w := range work {
		ev, err := land.Decide(ctx, cfg, w.facts, w.verdicts)
		if err == nil {
			var res land.Result
			res, err = land.Act(ctx, cfg, ev)
			if res.Action != "" {
				log.Printf("publish: #%d: %s %v %q", ev.PullRequest.Number, res.Action, res.Decision.Reasons, res.Note)
			}
		}
		if err != nil {
			failed++
			log.Printf("publish: %s: %v", w.facts, err)
		}
	}
	if failed > 0 {
		return fmt.Errorf("publish: %d of %d pull requests could not be decided or acted on", failed, len(work))
	}
	return nil
}

// decidable is one pull request's two files.
type decidable struct {
	// facts is the facts file. verdicts is the verdicts file, which need
	// not exist.
	facts, verdicts string
}

// publishWork finds what there is to decide in the artifacts directory.
// An event's run has a classification, and its facts must be about the
// pull request classify proved. A scheduled run has one directory for
// each pull request the refresh job wrote.
func publishWork(in string) ([]decidable, error) {
	class, err := readClassification(filepath.Join(in, classificationArtifact, classificationFile))
	switch {
	case err == nil:
		w := decidable{
			facts:    filepath.Join(in, factsArtifact, wire.FactsFile),
			verdicts: filepath.Join(in, verdictsArtifact, wire.VerdictsFile),
		}
		if err := checkFacts(class, w.facts); err != nil {
			return nil, err
		}
		return []decidable{w}, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}

	entries, err := os.ReadDir(filepath.Join(in, refreshedArtifact))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("publish: %s holds neither a classification nor refreshed pull requests", in)
	}
	if err != nil {
		return nil, err
	}
	var work []decidable
	for _, e := range entries {
		// The refresh job names a directory by its pull request's number.
		if n, err := strconv.Atoi(e.Name()); err != nil || n < 1 || !e.IsDir() {
			return nil, fmt.Errorf("publish: %s is not a refreshed pull request's directory", filepath.Join(in, refreshedArtifact, e.Name()))
		}
		dir := filepath.Join(in, refreshedArtifact, e.Name())
		work = append(work, decidable{facts: filepath.Join(dir, wire.FactsFile), verdicts: filepath.Join(dir, wire.VerdictsFile)})
	}
	return work, nil
}

// checkFacts ties the facts file to classify's answer. The fetch job
// reads what a pull request and its dependencies wrote, and classify does
// not; so the facts are believed only about the pull request and the head
// classify looked at, and never to say more for its identity than
// classify did.
func checkFacts(class model.Classification, factsPath string) error {
	b, err := os.ReadFile(factsPath)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("publish: the fetch job left no facts for #%d, so nothing is decided; run the gate again", class.PR)
	}
	if err != nil {
		return err
	}
	facts, err := wire.DecodeFacts(b)
	if err != nil {
		return err
	}
	if want := (wire.PullRequest{Repo: class.Repo, Number: class.PR, Head: class.HeadSHA}); facts.PullRequest != want {
		return fmt.Errorf("publish: the facts are about %s #%d at %s, and classify looked at %s #%d at %s",
			facts.PullRequest.Repo, facts.PullRequest.Number, facts.PullRequest.Head, want.Repo, want.Number, want.Head)
	}
	if class.Kind != model.KindDependabot && facts.Facts.Identity.Holds() {
		return fmt.Errorf("publish: the facts say the pull request is Dependabot's alone, and classify said %q", class.Kind)
	}
	return nil
}

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/gh"
)

// fetchTimeout leaves the job (20 minutes) time to upload what it wrote.
const fetchTimeout = 17 * time.Minute

// runFetch: dep-review fetch --classification <file> --repo-dir <dir> --out <dir>
//
// Writes the facts file and the chunk files into --out and appends
// review=<true|false> to $GITHUB_OUTPUT: whether there is anything for
// the review job to read. Any error exits non-zero with no facts file,
// and then nothing is decided.
func runFetch(args []string) error {
	fl := newFlagSet("fetch")
	classPath := fl.String("classification", "", "classification.json from classify (required)")
	repoDir := fl.String("repo-dir", "", "a clone with full history that holds the pull request's head; only its git objects are read (required)")
	out := fl.String("out", "", "directory to write the facts file and the chunks into (required)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *classPath == "" || *repoDir == "" || *out == "" || fl.NArg() > 0 {
		return errors.New("fetch: --classification, --repo-dir and --out are required")
	}
	class, err := readClassification(*classPath)
	if err != nil {
		return err
	}
	// The job's own read-only token: the caller repository and public
	// upstreams.
	c, err := gh.NewFromEnv()
	if err != nil {
		return err
	}
	// This job does not look at the gate's comment, so it has no use for
	// the gate app's name: what a comment remembers of earlier reads is
	// the scheduled job's and publish's to read.
	cfg, err := repoConfig(c)
	if err != nil {
		return err
	}
	if !strings.EqualFold(class.Repo, cfg.Repo) {
		return fmt.Errorf("fetch: the classification is about %.100q, and this job runs for %s", class.Repo, cfg.Repo)
	}
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()
	g, err := newGathering(ctx, cfg)
	if err != nil {
		return err
	}
	defer g.close()
	facts, err := g.fetch(ctx, class, *repoDir, *out)
	if err != nil {
		return err
	}
	log.Printf("fetch: %s #%d: %s, %d updates", cfg.Repo, class.PR, facts.Facts.Ecosystem, len(facts.Facts.Updates))
	return stepOutput("review", strconv.FormatBool(prepared(facts)))
}

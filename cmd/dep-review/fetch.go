package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/land"
	"github.com/sadbox/dep-review/internal/wire"
)

// fetchTimeout leaves the job (20 minutes) time to upload what it wrote.
const fetchTimeout = 17 * time.Minute

// runFetch: dep-review fetch --classification <file> --repo-dir <dir> --out <dir> --app-slug <slug>
//
// Writes the facts file, the chunk files and the cached verdicts into
// --out and appends review=<true|false> to $GITHUB_OUTPUT: whether there
// is anything for the review job to read. Any error exits non-zero with
// no facts file, and then nothing is decided.
func runFetch(args []string) error {
	fl := newFlagSet("fetch")
	classPath := fl.String("classification", "", "classification.json from classify (required)")
	repoDir := fl.String("repo-dir", "", "a clone with full history that holds the pull request's head; only its git objects are read (required)")
	out := fl.String("out", "", "directory to write the facts file, the chunks and the cached verdicts into (required)")
	slug := fl.String("app-slug", "", slugUsage)
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *classPath == "" || *repoDir == "" || *out == "" || *slug == "" || fl.NArg() > 0 {
		return errors.New("fetch: --classification, --repo-dir, --out and --app-slug are required")
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
	cfg, err := landConfig(c, *slug)
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

	// What the gate's comment remembers of earlier reads spares the
	// review job a model call for content that was read before. It is a
	// saving and nothing more: when the comments cannot be read, the
	// model is asked again.
	cached, err := land.Cached(ctx, cfg, class.PR)
	if err != nil {
		log.Printf("fetch: the gate's comment could not be read, so no verdict is reused: %v", err)
		cached = wire.Verdicts{Version: wire.Version, Verdicts: []wire.Verdict{}}
	}
	b, err := wire.EncodeVerdicts(cached)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, cachedFile), b, 0o644); err != nil {
		return err
	}
	return stepOutput("review", strconv.FormatBool(prepared(facts)))
}

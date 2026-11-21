package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/sadbox/dep-review/internal/eco/ecoutil"
	"github.com/sadbox/dep-review/internal/evidence"
	"github.com/sadbox/dep-review/internal/fetch"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
)

// fetchTimeout leaves the job (20 minutes) time to upload the evidence.
const fetchTimeout = 17 * time.Minute

// runFetch: dep-review fetch --classification <file> --repo-dir <dir> --out <dir>
//
// Writes the evidence directory and appends route=<route> to $GITHUB_OUTPUT.
// Any error exits non-zero, which publish treats as infrastructure.
func runFetch(args []string) error {
	fl := flag.NewFlagSet("fetch", flag.ContinueOnError)
	classPath := fl.String("classification", "", "classification.json from classify")
	repoDir := fl.String("repo-dir", "", "the PR's head checkout (full history)")
	outDir := fl.String("out", "", "evidence directory to create")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *classPath == "" || *repoDir == "" || *outDir == "" || fl.NArg() > 0 {
		return errors.New("usage: dep-review fetch --classification <file> --repo-dir <dir> --out <dir>")
	}
	b, err := os.ReadFile(*classPath)
	if err != nil {
		return err
	}
	var class model.Classification
	if err := json.Unmarshal(b, &class); err != nil {
		return fmt.Errorf("%s: %w", *classPath, err)
	}
	repo, err := filepath.Abs(*repoDir)
	if err != nil {
		return err
	}

	// The fetch job's own read-only token (contents/pull-requests: read):
	// REST reads of the caller repository and public upstreams.
	ghc, err := gh.NewFromEnv()
	if err != nil {
		return err
	}

	scratch, err := os.MkdirTemp(os.Getenv("RUNNER_TEMP"), "dep-review-scratch-")
	if err != nil {
		return err
	}
	defer removeScratch(scratch)

	ev, err := evidence.Create(*outDir)
	if err != nil {
		return err
	}
	defer ev.Close()

	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()
	env := fetch.Env{
		Class:   class,
		RepoDir: repo,
		Scratch: scratch,
		HTTP:    ecoutil.NewClient(),
		GitHub:  ghc,
	}
	out, err := fetch.Run(ctx, env, ecosystems, ev)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "dep-review fetch: %d updates, %d findings, route %s\n", len(out.Updates), len(out.Findings), out.Route)
	return stepOutput("route", string(out.Route))
}

// removeScratch deletes the scratch tree, first making any read-only
// directories writable (a module cache may contain some).
func removeScratch(dir string) {
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o700)
		}
		return nil
	})
	if err := os.RemoveAll(dir); err != nil {
		fmt.Fprintln(os.Stderr, logLine("dep-review fetch: removing scratch: "+err.Error()))
	}
}

package main

import (
	"context"
	"errors"
	"flag"
	"time"

	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/publish"
)

// The trigger workflow is a no-op that succeeds on every PR, so its runs
// must never count as CI. There is no default: a default that does not
// match the caller's trigger would let that no-op run pass as green CI.
const triggerPathUsage = "the caller's trigger workflow (required), whose runs never count as CI"

func runPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	in := fs.String("in", "", "directory holding the classification, evidence and verdict artifacts")
	fetchResult := fs.String("fetch-result", "", "needs.fetch.result")
	reviewResult := fs.String("review-result", "", "needs.review.result")
	trigger := fs.String("trigger-path", "", triggerPathUsage)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" || *trigger == "" {
		return errors.New("publish: --in and --trigger-path are required")
	}
	inputs, err := publish.ReadInputs(*in, *fetchResult, *reviewResult)
	if err != nil {
		return err
	}
	c, err := gh.NewFromEnv()
	if err != nil {
		return err
	}
	cfg, err := publish.ConfigFromEnv(c)
	if err != nil {
		return err
	}
	cfg.TriggerPath = *trigger
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()
	return publish.Publish(ctx, cfg, inputs)
}

func runSweep(args []string) error {
	fs := flag.NewFlagSet("sweep", flag.ContinueOnError)
	repo := fs.String("repo", "", "owner/name")
	trigger := fs.String("trigger-path", "", triggerPathUsage)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *repo == "" || *trigger == "" {
		return errors.New("sweep: --repo and --trigger-path are required")
	}
	c, err := gh.NewFromEnv()
	if err != nil {
		return err
	}
	cfg, err := publish.ConfigFromEnv(c)
	if err != nil {
		return err
	}
	cfg.TriggerPath = *trigger
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	return publish.Sweep(ctx, cfg, *repo)
}

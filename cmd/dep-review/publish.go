package main

import (
	"context"
	"errors"
	"flag"
	"time"

	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/publish"
)

// defaultTriggerPath is gate.yml's default trigger_workflow_path. Its check
// runs never count as CI; publish prefers the path in the classification.
const defaultTriggerPath = ".github/workflows/dep-review-trigger.yaml"

const triggerPathUsage = "the caller's trigger workflow, whose runs never count as CI"

func runPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	in := fs.String("in", "", "directory holding the classification, evidence and verdict artifacts")
	fetchResult := fs.String("fetch-result", "", "needs.fetch.result")
	reviewResult := fs.String("review-result", "", "needs.review.result")
	trigger := fs.String("trigger-path", defaultTriggerPath, triggerPathUsage)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return errors.New("publish: --in is required")
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
	trigger := fs.String("trigger-path", defaultTriggerPath, triggerPathUsage)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *repo == "" {
		return errors.New("sweep: --repo is required")
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

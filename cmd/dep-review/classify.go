package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"time"

	"github.com/sadbox/dep-review/internal/classify"
	"github.com/sadbox/dep-review/internal/gh"
)

func runClassify(args []string) error {
	fs := flag.NewFlagSet("classify", flag.ContinueOnError)
	event := fs.String("event", "", "workflow_run event payload (GITHUB_EVENT_PATH)")
	trigger := fs.String("trigger-path", "", "path of the caller's trigger workflow")
	out := fs.String("out", "", "where to write classification.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *event == "" || *trigger == "" || *out == "" {
		return errors.New("classify: --event, --trigger-path and --out are required")
	}
	ev, err := os.ReadFile(*event)
	if err != nil {
		return err
	}
	c, err := gh.NewFromEnv()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cl, err := classify.Classify(ctx, c, ev, classify.Options{
		TriggerPath: *trigger,
		ExpectRepo:  os.Getenv("GITHUB_REPOSITORY"),
	})
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(cl, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return stepOutput("kind", string(cl.Kind))
}

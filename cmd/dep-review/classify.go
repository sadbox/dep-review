package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sadbox/dep-review/internal/classify"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
)

// ignoreUsage is shared by classify and refresh, which must agree.
const ignoreUsage = "optional: comma-separated ecosystems, as in Dependabot's branch names (e.g. submodules), whose verified Dependabot PRs another process owns; the gate leaves them alone. An unknown name is an error"

// runClassify: dep-review classify --event <file> --trigger-path <path> --out <file>
//
// Writes classification.json and appends kind=<kind> to $GITHUB_OUTPUT.
func runClassify(args []string) error {
	fs := newFlagSet("classify")
	event := fs.String("event", "", "workflow_run event payload (GITHUB_EVENT_PATH) (required)")
	trigger := fs.String("trigger-path", "", "path of the caller's trigger workflow (required)")
	out := fs.String("out", "", "where to write classification.json (required)")
	ignoreList := fs.String("ignore-ecosystems", "", ignoreUsage)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *event == "" || *trigger == "" || *out == "" || fs.NArg() > 0 {
		return errors.New("classify: --event, --trigger-path and --out are required")
	}
	ignore, err := model.ParseEcosystems(*ignoreList)
	if err != nil {
		return fmt.Errorf("--ignore-ecosystems: %w", err)
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
		TriggerPath:      *trigger,
		ExpectRepo:       os.Getenv("GITHUB_REPOSITORY"),
		IgnoreEcosystems: ignore,
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

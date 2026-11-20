package main

import (
	"errors"
	"flag"
	"os"

	"github.com/sadbox/dep-review/internal/reviewprep"
)

func runReviewPrep(args []string) error {
	fs := flag.NewFlagSet("review-prep", flag.ContinueOnError)
	prompt := fs.String("prompt", "", "prompt template (prompts/review.md)")
	schema := fs.String("schema", "", "verdict schema (schema/verdict.json)")
	notes := fs.String("notes", "", "repository review notes, relative to the working directory (optional file)")
	out := fs.String("github-output", "", "GITHUB_OUTPUT file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *prompt == "" || *schema == "" || *out == "" {
		return errors.New("review-prep: --prompt, --schema and --github-output are required")
	}
	return reviewprep.Run(*prompt, *schema, *notes, *out, os.Getenv("RUNNER_TEMP"))
}

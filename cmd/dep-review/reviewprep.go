package main

import (
	"errors"
	"flag"

	"github.com/sadbox/dep-review/internal/reviewprep"
)

// runReviewPrep: dep-review review-prep --prompt <file> --schema <file> [--notes <file>] --out-dir <dir>
func runReviewPrep(args []string) error {
	fs := flag.NewFlagSet("review-prep", flag.ContinueOnError)
	prompt := fs.String("prompt", "", "prompt template (prompts/review.md)")
	schema := fs.String("schema", "", "verdict schema (schema/verdict.json)")
	notes := fs.String("notes", "", "repository review notes, relative to the working directory (optional file)")
	out := fs.String("out-dir", "", "directory for prompt.md, settings.json and schema.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *prompt == "" || *schema == "" || *out == "" || fs.NArg() > 0 {
		return errors.New("review-prep: --prompt, --schema and --out-dir are required")
	}
	return reviewprep.Run(*prompt, *schema, *notes, *out)
}

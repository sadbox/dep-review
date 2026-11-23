package main

import (
	"context"
	"errors"
	"log"
	"path/filepath"
	"time"

	"github.com/sadbox/dep-review/internal/config"
	"github.com/sadbox/dep-review/internal/gather"
	"github.com/sadbox/dep-review/internal/veto"
)

// reviewTimeout bounds every model call of one pull request together and
// leaves the job (120 minutes) time to upload the verdicts. A read still
// unanswered when it ends has no verdict, which is a wait.
const reviewTimeout = 100 * time.Minute

// runReview: dep-review review --facts <dir> --out <dir> --federation-rule-id <id> --organization-id <id>
//
// Puts every read the fetch job prepared before the model and writes the
// verdicts file into --out. The job holds one credential, the model's,
// and nothing of GitHub: it reads a directory and writes a file.
func runReview(args []string) error {
	fl := newFlagSet("review")
	facts := fl.String("facts", "", "the fetch job's directory: the facts file, the chunks and the cached verdicts (required)")
	out := fl.String("out", "", "directory to write the verdicts file into (required)")
	rule := fl.String("federation-rule-id", "", "workload identity federation rule (fdrl_...). Without it the API key in "+veto.APIKeyEnv+" is used, which is for local evaluation only")
	org := fl.String("organization-id", "", "Anthropic organization ID, with --federation-rule-id")
	ws := fl.String("workspace-id", "", "workspace (wrkspc_...), optional")
	svac := fl.String("service-account-id", "", "service account (svac_...), optional")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *facts == "" || *out == "" || fl.NArg() > 0 {
		return errors.New("review: --facts and --out are required")
	}
	// The built-in settings, not the repository's: this job has no access
	// to the repository, and needs none. A repository can only lower the
	// chunk budget, which a read prepared under it stays within, and
	// nothing it may set is part of the fingerprint.
	conf, err := config.Load(nil)
	if err != nil {
		return err
	}
	settings := veto.FromConfig(conf)

	var creds veto.Credentials
	if *rule != "" {
		federated, err := veto.NewFederated(veto.Federation{
			IdentityToken:    veto.GitHubOIDCFromEnv().Token,
			RuleID:           *rule,
			OrganizationID:   *org,
			WorkspaceID:      *ws,
			ServiceAccountID: *svac,
		}, settings.BaseURL, nil)
		if err != nil {
			return err
		}
		federated.Logf = log.Printf
		creds = federated
	} else if creds, err = veto.APIKeyFromEnv(); err != nil {
		return err
	}
	client, err := veto.New(settings, creds, nil)
	if err != nil {
		return err
	}
	client.Logf = log.Printf

	cached, err := readVerdicts(filepath.Join(*facts, cachedFile))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), reviewTimeout)
	defer cancel()
	verdicts, err := gather.Review{
		Reviewer:    client,
		Fingerprint: settings.Fingerprint(),
		Cached:      cached.Verdicts,
		Logf:        log.Printf,
	}.Run(ctx, *facts, *out)
	if errors.Is(err, context.DeadlineExceeded) && verdicts.Version != 0 {
		// The file was written and is good; the reads without a verdict
		// wait. Failing here would keep the file from being uploaded.
		log.Printf("review: out of time with %d verdicts written; the rest wait", len(verdicts.Verdicts))
		return nil
	}
	if err != nil {
		return err
	}
	log.Printf("review: %d verdicts written", len(verdicts.Verdicts))
	return nil
}

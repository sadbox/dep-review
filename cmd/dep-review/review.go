package main

import (
	"context"
	"errors"
	"flag"
	"log"
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
// verdicts file into --out; no verdict of an earlier run stands in for
// the model's answer. The job holds one credential, the model's, and
// nothing of GitHub: it reads a directory and writes a file.
func runReview(args []string) error {
	fl := newFlagSet("review")
	facts := fl.String("facts", "", "the fetch job's directory: the facts file and the chunks (required)")
	out := fl.String("out", "", "directory to write the verdicts file into (required)")
	model := modelFlags(fl)
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *facts == "" || *out == "" || fl.NArg() > 0 {
		return errors.New("review: --facts and --out are required")
	}
	client, fingerprint, err := model.reviewer()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), reviewTimeout)
	defer cancel()
	verdicts, err := gather.Review{
		Reviewer:    client,
		Fingerprint: fingerprint,
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

// modelFlagSet is the flags of the two commands that ask the model.
type modelFlagSet struct {
	rule, org, ws, svac *string
}

func modelFlags(fl *flag.FlagSet) modelFlagSet {
	return modelFlagSet{
		rule: fl.String("federation-rule-id", "", "workload identity federation rule (fdrl_...). Without it the API key in "+veto.APIKeyEnv+" is used, which is for local evaluation only"),
		org:  fl.String("organization-id", "", "Anthropic organization ID, with --federation-rule-id"),
		ws:   fl.String("workspace-id", "", "workspace (wrkspc_...), optional"),
		svac: fl.String("service-account-id", "", "service account (svac_...), optional"),
	}
}

// reviewer is the client that asks the model, and its fingerprint, under
// the built-in settings, which are the ones the reads were prepared
// under. A job that asks has no access to the repository, and needs
// none.
func (m modelFlagSet) reviewer() (*veto.Client, string, error) {
	conf, err := config.Load()
	if err != nil {
		return nil, "", err
	}
	settings := veto.FromConfig(conf)

	var creds veto.Credentials
	if *m.rule != "" {
		federated, err := veto.NewFederated(veto.Federation{
			IdentityToken:    veto.GitHubOIDCFromEnv().Token,
			RuleID:           *m.rule,
			OrganizationID:   *m.org,
			WorkspaceID:      *m.ws,
			ServiceAccountID: *m.svac,
		}, settings.BaseURL, nil)
		if err != nil {
			return nil, "", err
		}
		federated.Logf = log.Printf
		creds = federated
	} else if creds, err = veto.APIKeyFromEnv(); err != nil {
		return nil, "", err
	}
	client, err := veto.New(settings, creds, nil)
	if err != nil {
		return nil, "", err
	}
	client.Logf = log.Printf
	return client, settings.Fingerprint(), nil
}

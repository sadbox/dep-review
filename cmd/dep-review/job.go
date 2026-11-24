package main

import (
	"context"
	json "encoding/json/v2"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/sadbox/dep-review/internal/advisory"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/config"
	"github.com/sadbox/dep-review/internal/gather"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/land"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/wire"
)

// slugUsage is the scheduled job's: it has no app token and so cannot
// ask who the gate app is.
const slugUsage = "the gate app's slug (the name in github.com/apps/<slug>), by which its comment is recognised (required)"

var (
	slugRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	runIDRE = regexp.MustCompile(`^[0-9]{1,20}$`)
)

// repoConfig is internal/land's configuration for a job that does not
// look at the gate's comment: the repository the workflow runs in, from
// the job's environment.
func repoConfig(c *gh.Client) (land.Config, error) {
	repo := os.Getenv("GITHUB_REPOSITORY")
	if !gh.ValidRepo(repo) {
		return land.Config{}, fmt.Errorf("GITHUB_REPOSITORY %.100q is not owner/name", repo)
	}
	cfg := land.Config{GitHub: c, Repo: repo}
	// It goes into a comment and a notification as a link.
	if run := os.Getenv("GITHUB_RUN_ID"); runIDRE.MatchString(run) {
		cfg.RunURL = fmt.Sprintf("https://github.com/%s/actions/runs/%s", repo, run)
	}
	return cfg, nil
}

// landConfig is repoConfig for a job that reads or writes the gate's
// comment: with the gate app, by its slug.
func landConfig(c *gh.Client, slug string) (land.Config, error) {
	if !slugRE.MatchString(slug) {
		return land.Config{}, fmt.Errorf("%.70q is not a GitHub App's slug", slug)
	}
	cfg, err := repoConfig(c)
	cfg.BotLogin = slug + "[bot]"
	return cfg, err
}

// readClassification reads classify's answer: the keys classify writes
// and no others.
func readClassification(path string) (model.Classification, error) {
	var class model.Classification
	b, err := os.ReadFile(path)
	if err != nil {
		return class, err
	}
	if err := json.Unmarshal(b, &class, json.RejectUnknownMembers(true)); err != nil {
		return class, fmt.Errorf("%s: %w", path, err)
	}
	return class, nil
}

// gathering is what the fetch job and the scheduled job share: the
// gate's settings and the clients facts are gathered with.
type gathering struct {
	conf     config.Config
	github   *gh.Client
	http     *http.Client
	preparer artifact.Preparer
	scratch  string
}

// newGathering loads the settings and makes the artifact reader a
// scratch directory. github is the job's read-only client.
func newGathering(github *gh.Client) (*gathering, error) {
	conf, err := config.Load()
	if err != nil {
		return nil, err
	}
	scratch, err := os.MkdirTemp(os.Getenv("RUNNER_TEMP"), "dep-review-scratch-")
	if err != nil {
		return nil, err
	}
	g := &gathering{conf: conf, github: github, http: &http.Client{Timeout: 2 * time.Minute}, scratch: scratch}
	if g.preparer, err = gather.NewPreparer(scratch, g.http, g.github); err != nil {
		g.close()
		return nil, err
	}
	return g, nil
}

func (g *gathering) close() {
	if err := os.RemoveAll(g.scratch); err != nil {
		log.Printf("removing the scratch directory: %v", err)
	}
}

// fetch is the fetch job for one pull request: it reads the change set
// from the clone in repoDir, where one is needed, and writes the facts
// file and the chunk files into out.
func (g *gathering) fetch(ctx context.Context, class model.Classification, repoDir, out string) (wire.Facts, error) {
	var changes gather.Changes
	if gather.NeedsChanges(class) {
		var err error
		if changes, err = gather.ReadChanges(ctx, repoDir, class.BaseSHA, class.HeadSHA); err != nil {
			return wire.Facts{}, err
		}
	}
	return gather.Fetch{
		Class:      class,
		Changes:    changes,
		Config:     g.conf,
		HTTP:       g.http,
		GitHub:     g.github,
		Advisories: advisory.New(g.github),
		Gatherers:  gather.Gatherers(),
		Preparer:   g.preparer,
		Logf:       log.Printf,
	}.Run(ctx, out)
}

// prepared reports whether fetch prepared any read, which is when there
// is something for the review job to do.
func prepared(f wire.Facts) bool {
	for _, u := range f.Facts.Updates {
		if u.Prepared.Status == wire.Prepared {
			return true
		}
	}
	return false
}

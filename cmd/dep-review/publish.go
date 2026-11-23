package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/classify"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/land"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/wire"
)

// publishTimeout leaves the job (15 minutes) time to report.
const publishTimeout = 12 * time.Minute

// The directories of --in: gate.yml's publish job downloads each artifact
// into a directory of its own name.
const (
	classificationArtifact = "classification"
	factsArtifact          = "facts"
	verdictsArtifact       = "verdicts"
	refreshedArtifact      = "refreshed"
	classificationFile     = "classification.json"
	// sumsFile is the checksum manifest gate.yml's refresh job puts
	// beside the pull requests' directories, and its publish job has
	// checked by the time this command runs.
	sumsFile = "SHA256SUMS"
)

// runPublish: dep-review publish --in <dir> [--ignore-ecosystems <list>]
//
// Decides and acts (internal/land): for the one pull request of an
// event's run, or for every pull request the scheduled job refreshed. It
// is the only command that holds the gate app's token, which it takes
// from GH_TOKEN, with the app's slug in DEP_REVIEW_APP_SLUG. On an
// event's run FETCH_RESULT and REVIEW_RESULT are how those jobs ended.
func runPublish(args []string) error {
	fl := newFlagSet("publish")
	in := fl.String("in", "", "directory holding the artifacts, each in a directory of its name: classification, facts and verdicts from an event's run, or refreshed from a scheduled one (required)")
	ignoreList := fl.String("ignore-ecosystems", "", ignoreUsage)
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *in == "" || fl.NArg() > 0 {
		return errors.New("publish: --in is required")
	}
	ignore, err := model.ParseEcosystems(*ignoreList)
	if err != nil {
		return fmt.Errorf("--ignore-ecosystems: %w", err)
	}
	c, err := gh.NewFromEnv()
	if err != nil {
		return err
	}
	cfg, err := landConfig(c, os.Getenv("DEP_REVIEW_APP_SLUG"))
	if err != nil {
		return fmt.Errorf("DEP_REVIEW_APP_SLUG: %w", err)
	}
	if token, user := os.Getenv("PUSHOVER_APP_TOKEN"), os.Getenv("PUSHOVER_USER_KEY"); token != "" && user != "" {
		cfg.Notifier = &land.Pushover{Token: token, User: user}
	}
	ctx, cancel := context.WithTimeout(context.Background(), publishTimeout)
	defer cancel()

	// An event's run has a classification; a scheduled one has a
	// directory for each pull request the refresh job wrote.
	class, err := readClassification(filepath.Join(*in, classificationArtifact, classificationFile))
	switch {
	case err == nil:
		return publishEvent(ctx, cfg, *in, class)
	case errors.Is(err, fs.ErrNotExist):
		return publishRefreshed(ctx, cfg, *in, ignore)
	}
	return err
}

// decidable is one pull request's two files.
type decidable struct {
	// facts is the facts file. verdicts is the verdicts file, which need
	// not exist.
	facts, verdicts string
}

// handled reports whether kind is one the gate gathers facts for and
// decides. For every other kind it writes nothing at all.
func handled(kind model.Kind) bool {
	return kind == model.KindDependabot || kind == model.KindDependabotUnverified || kind == model.KindPending
}

// publishEvent decides the one pull request of an event's run. A run that
// cannot (the fetch job left no facts, or deciding or acting failed
// before anything was written) says so on the pull request: nothing else
// would, and the scheduled job looks only at what was left waiting.
func publishEvent(ctx context.Context, cfg land.Config, in string, class model.Classification) error {
	if !handled(class.Kind) || !strings.EqualFold(class.Repo, cfg.Repo) {
		return fmt.Errorf("publish: classify said %q of %.100q, and this job decides Dependabot's pull requests in %s", class.Kind, class.Repo, cfg.Repo)
	}
	// The review job ran, or should have.
	cfg.ModelAsked = true
	w := decidable{
		facts:    filepath.Join(in, factsArtifact, wire.FactsFile),
		verdicts: filepath.Join(in, verdictsArtifact, wire.VerdictsFile),
	}
	facts, err := readFacts(w.facts)
	if err == nil {
		err = checkFacts(class, facts)
	}
	written := false
	if err == nil {
		written, err = decide(ctx, cfg, w)
	}
	if err != nil && !written {
		what := fmt.Sprintf("In this run the fetch job ended %s and the review job %s.", jobResult("FETCH_RESULT"), jobResult("REVIEW_RESULT"))
		if ferr := land.Failed(ctx, cfg, class.PR, class.HeadSHA, what); ferr != nil {
			log.Printf("publish: #%d: the failed run could not be reported on the pull request: %v", class.PR, ferr)
		}
	}
	return err
}

// jobResult is how a job this one needs ended, as gate.yml hands it over
// in the environment: one of GitHub's four words, or "unknown".
func jobResult(env string) string {
	switch r := os.Getenv(env); r {
	case "success", "failure", "cancelled", "skipped":
		return r
	}
	return "unknown"
}

// publishRefreshed decides every pull request the scheduled job
// refreshed. One that cannot be decided does not keep the others from
// being decided. Nothing is written about it: its comment still says
// wait, so the next scheduled run takes it up again.
func publishRefreshed(ctx context.Context, cfg land.Config, in string, ignore map[model.Ecosystem]bool) error {
	entries, err := os.ReadDir(filepath.Join(in, refreshedArtifact))
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("publish: %s holds neither a classification nor refreshed pull requests", in)
	}
	if err != nil {
		return err
	}
	failed, total := 0, 0
	for _, e := range entries {
		if e.Name() == sumsFile && e.Type().IsRegular() {
			continue
		}
		total++
		if err := refreshed(ctx, cfg, filepath.Join(in, refreshedArtifact), e, ignore); err != nil {
			failed++
			log.Printf("publish: %s: %v", e.Name(), err)
		}
	}
	if failed > 0 {
		return fmt.Errorf("publish: %d of %d pull requests could not be decided or acted on", failed, total)
	}
	return nil
}

// refreshed decides one pull request of a scheduled run. The refresh job
// ran the identity proof and read what the pull request and its
// dependencies wrote in one process, so its word for the identity is not
// taken: the proof is run again here, and the facts are believed only as
// far as it goes (checkFacts), as on an event.
func refreshed(ctx context.Context, cfg land.Config, dir string, e fs.DirEntry, ignore map[model.Ecosystem]bool) error {
	// The refresh job names a directory by its pull request's number.
	number, err := strconv.Atoi(e.Name())
	if err != nil || number < 1 || !e.IsDir() {
		return errors.New("not a refreshed pull request's directory")
	}
	w := decidable{facts: filepath.Join(dir, e.Name(), wire.FactsFile), verdicts: filepath.Join(dir, e.Name(), wire.VerdictsFile)}
	facts, err := readFacts(w.facts)
	if err != nil {
		return err
	}
	if facts.PullRequest.Number != number {
		return fmt.Errorf("the directory's facts are about #%d", facts.PullRequest.Number)
	}
	class, err := classify.Pull(ctx, cfg.GitHub, cfg.Repo, number, facts.PullRequest.Head, classify.Options{IgnoreEcosystems: ignore})
	if err != nil {
		return err
	}
	if !handled(class.Kind) {
		// Closed, moved on (the new head has a run of its own) or
		// ignored: no longer the gate's to decide.
		log.Printf("publish: #%d: %s now, nothing to do", number, class.Kind)
		return nil
	}
	if err := checkFacts(class, facts); err != nil {
		return err
	}
	_, err = decide(ctx, cfg, w)
	return err
}

// decide is Decide and Act for one pull request. written says Act wrote
// the comment and the status, which it also has when it returns an error
// for a notification that failed.
func decide(ctx context.Context, cfg land.Config, w decidable) (written bool, err error) {
	ev, err := land.Decide(ctx, cfg, w.facts, w.verdicts)
	if err != nil {
		return false, err
	}
	res, err := land.Act(ctx, cfg, ev)
	if res.Action != "" {
		log.Printf("publish: #%d: %s %v %q", ev.PullRequest.Number, res.Action, res.Decision.Reasons, res.Note)
	}
	return res.Action != "", err
}

// readFacts reads a facts file.
func readFacts(path string) (wire.Facts, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return wire.Facts{}, errors.New("publish: there is no facts file, so nothing is decided; run the gate again")
	}
	if err != nil {
		return wire.Facts{}, err
	}
	return wire.DecodeFacts(b)
}

// checkFacts ties a facts file to classify's answer. The job that wrote
// the file reads what a pull request and its dependencies wrote, and
// classify does not; so the facts are believed only about the pull
// request and the head classify looked at, never to say more for its
// identity than classify did, and only in the ecosystem classify named.
func checkFacts(class model.Classification, facts wire.Facts) error {
	if want := (wire.PullRequest{Repo: class.Repo, Number: class.PR, Head: class.HeadSHA}); facts.PullRequest != want {
		return fmt.Errorf("publish: the facts are about %s #%d at %s, and classify looked at %s #%d at %s",
			facts.PullRequest.Repo, facts.PullRequest.Number, facts.PullRequest.Head, want.Repo, want.Number, want.Head)
	}
	if class.Kind != model.KindDependabot && facts.Facts.Identity.Holds() {
		return fmt.Errorf("publish: the facts say the pull request is Dependabot's alone, and classify said %q", class.Kind)
	}
	// The file's ecosystem alone decides whether "nothing to read" is a
	// read (Docker), so it is not the fetch job's word alone. classify
	// names an ecosystem once the proof is whole or only unfinished
	// (pending), not for a pull request it calls unverified, and in
	// Dependabot's words; the file has the gate's, which differ for npm
	// (gather).
	if class.Ecosystem != "" {
		want := string(class.Ecosystem)
		if class.Ecosystem == model.NPM {
			want = allow.NPM
		}
		if facts.Facts.Ecosystem != want {
			return fmt.Errorf("publish: the facts are for the ecosystem %.40q, and classify named %q", facts.Facts.Ecosystem, want)
		}
	}
	return nil
}

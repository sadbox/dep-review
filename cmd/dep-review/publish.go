package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
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
	// reverdictsArtifact is the scheduled run's verdicts: a directory for
	// each pull request the second review job asked the model about.
	reverdictsArtifact = "reverdicts"
	classificationFile = "classification.json"
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
	in := fl.String("in", "", "directory holding the artifacts, each in a directory of its name: classification, facts and verdicts from an event's run, or refreshed and reverdicts from a scheduled one (required)")
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
// would for hours, until the scheduled job takes up a pull request the
// gate has nothing for.
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
		if errors.Is(err, land.ErrFactsStale) {
			// Not a job that failed: the run's jobs were not all run again,
			// and that is what the person has to do differently.
			what = fmt.Sprintf("The facts this run decided on were gathered more than %d hours earlier, or by a clock ahead of this job's: "+
				"a job that is run again by itself gets the facts of the run's first attempt.", int(land.MaxFactsAge.Hours()))
		}
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

// publishRefreshed is publish on a scheduled run. It decides every pull
// request the refresh job wrote; one that cannot be decided does not keep
// the others from being decided. Then it looks at the open pull requests
// itself (sweep), for what must not depend on the refresh job having got
// anywhere: a wait that is past its deadline, and a notification that was
// not delivered. A run in which the refresh job wrote nothing has no
// refreshed artifact, and only the second part to do.
func publishRefreshed(ctx context.Context, cfg land.Config, in string, ignore map[model.Ecosystem]bool) error {
	cfg.Scheduled = true
	entries, err := os.ReadDir(filepath.Join(in, refreshedArtifact))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	failed, total := 0, 0
	for _, e := range entries {
		if e.Name() == sumsFile && e.Type().IsRegular() {
			continue
		}
		total++
		err := refreshed(ctx, cfg, in, e, ignore)
		if err == nil {
			continue
		}
		failed++
		log.Printf("publish: %s: %v", e.Name(), err)
		if errors.Is(err, land.ErrFactsStale) {
			// This job came to the facts too late (a long queue). That is
			// not the pull request's failure: the next run gathers again.
			continue
		}
		if number, nerr := refreshedNumber(e); nerr == nil {
			if rerr := unevaluated(ctx, cfg, number, ignore); rerr != nil {
				log.Printf("publish: #%d: that it could not be evaluated was not reported on the pull request: %v", number, rerr)
			}
		}
	}
	swept, err := sweep(ctx, cfg, ignore)
	switch {
	case failed > 0 && (err != nil || swept > 0):
		return fmt.Errorf("publish: %d of %d pull requests could not be decided or acted on, and the look at the others did not go through (%d failures; %v)", failed, total, swept, err)
	case failed > 0:
		return fmt.Errorf("publish: %d of %d pull requests could not be decided or acted on", failed, total)
	case err != nil:
		return err
	case swept > 0:
		return fmt.Errorf("publish: %d overdue waits or undelivered notifications could not be dealt with", swept)
	}
	return nil
}

// unevaluated reports, on the pull request, a scheduled evaluation that
// failed, when the gate has nothing else for that head: no decision and
// no wait (land.Undecided). The pull request then has a status, a comment
// and one notification, and the schedule does not try that head again.
// One that waits keeps its wait comment: the next run tries again, and
// its deadline is sweep's to enforce.
//
// The number is the refresh job's, so everything else is this job's own:
// that the pull request is Dependabot's, open and undecided, and the
// identity proof, by which a pull request the gate does not handle (an
// ignored ecosystem) is left without a comment as always.
func unevaluated(ctx context.Context, cfg land.Config, number int, ignore map[model.Ecosystem]bool) error {
	head, ok, err := land.Undecided(ctx, cfg, number)
	if err != nil || !ok {
		return err
	}
	class, err := classify.Pull(ctx, cfg.GitHub, cfg.Repo, number, head, classify.Options{IgnoreEcosystems: ignore})
	// A proof GitHub did not let this job finish is not the pull request's
	// failure: nothing is reported, and the next run tries again.
	if err != nil || !handled(class.Kind) || class.Kind == model.KindPending {
		return err
	}
	return land.Failed(ctx, cfg, number, head, "The scheduled run looked at this pull request because the gate had no decision for its head, and could not evaluate it: gathering its facts or deciding on them failed.")
}

// sweep is what a scheduled publish does from its own look at the open
// pull requests, with its own token, whatever the refresh job wrote. A
// wait whose deadline has passed and that this run did not decide becomes
// a person's (land.Expired): a pull request this run decided has a new
// comment, so what still says wait past its deadline is one the run could
// not evaluate. And a notification a run could not deliver is sent
// (land.Tell). It returns how many of these failed.
//
// The identity proof does not stand in the deadline's way. A wait whose
// refresh keeps failing may be failing in that very proof, so only a
// proof that positively says the pull request is not the gate's (closed,
// a newer head, an ignored ecosystem) leaves it alone.
func sweep(ctx context.Context, cfg land.Config, ignore map[model.Ecosystem]bool) (failed int, err error) {
	agenda, err := land.Schedule(ctx, cfg)
	if err != nil {
		return 0, err
	}
	for _, w := range agenda.Evaluate {
		if w.Undecided || !w.PastDeadline {
			continue
		}
		class, err := classify.Pull(ctx, cfg.GitHub, cfg.Repo, w.Number, w.Head, classify.Options{IgnoreEcosystems: ignore})
		if err == nil && !handled(class.Kind) {
			log.Printf("publish: #%d: past its wait deadline and %s now, nothing to do", w.Number, class.Kind)
			continue
		}
		log.Printf("publish: #%d: still waiting after its deadline, %s: it needs a person", w.Number, w.Deadline.UTC().Format(time.RFC3339))
		if err := land.Expired(ctx, cfg, w.Number, w.Head); err != nil {
			failed++
			log.Printf("publish: #%d: %v", w.Number, err)
		}
	}
	for _, number := range agenda.Untold {
		if err := land.Tell(ctx, cfg, number); err != nil {
			failed++
			log.Printf("publish: #%d: the notification could not be sent again: %v", number, err)
		}
	}
	return failed, nil
}

// refreshed decides one pull request of a scheduled run, from its
// directory e of the refreshed artifact under in. The refresh job ran the
// identity proof and read what the pull request and its dependencies
// wrote in one process, so its word for the identity is not taken: the
// proof is run again here, and the facts are believed only as far as it
// goes (checkFacts), as on an event.
//
// Its word for a verdict is not taken either. The verdicts are the ones
// the second review job wrote in this run, in an artifact of its own, and
// the ones the gate's comment remembers, which internal/land reads with
// this job's token. The skip list the refresh job wrote for the review
// job is not opened.
func refreshed(ctx context.Context, cfg land.Config, in string, e fs.DirEntry, ignore map[model.Ecosystem]bool) error {
	number, err := refreshedNumber(e)
	if err != nil {
		return err
	}
	w := decidable{
		facts:    filepath.Join(in, refreshedArtifact, e.Name(), wire.FactsFile),
		verdicts: filepath.Join(in, reverdictsArtifact, e.Name(), wire.VerdictsFile),
	}
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
	cfg.Scheduled = true
	// The review job writes a file for a pull request only when it put a
	// read of it before the model, answered or not.
	if _, err := os.Stat(w.verdicts); err == nil {
		cfg.ModelAsked = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	written, err := decide(ctx, cfg, w)
	if err != nil && !written && cfg.ModelAsked {
		// Nothing was written, so nothing counted the ask. It is counted
		// all the same, or a pull request that cannot be decided would be
		// asked about at every run.
		if aerr := land.Asked(ctx, cfg, number, facts.PullRequest.Head); aerr != nil {
			log.Printf("publish: #%d: the ask could not be counted: %v", number, aerr)
		}
	}
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

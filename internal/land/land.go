// Package land is the publish job and the scheduled re-evaluation, as
// library code. Decide reads the two files the earlier jobs wrote, adds
// what only this job can observe (the default branch's required checks,
// whether the pull request is still what the facts describe, when it
// first evaluated a pin no registry dates), loads the policy from the
// default branch and asks allow.Decide. Act carries the answer out.
//
// Nothing in this package decides. An outcome is allow.Decide's, or
// allow.ChecksRefused's after GitHub refused a merge; what this package
// adds is only ever "nothing was done" (the pull request changed),
// "GitHub refused" (reported, never retried as if it were a wait) or "the
// run failed" (Failed). The gate does not judge CI: GitHub's rules answer
// the merge call. And there is no stored approval: the comment remembers
// the last outcome, the model's verdicts by content key and when a pin
// was first evaluated, and a merge always follows a fresh allow.Decide on
// facts gathered no longer ago than MaxFactsAge.
package land

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"regexp"

	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/config"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/veto"
	"github.com/sadbox/dep-review/internal/wire"
)

// dependabotLogin is the only author whose pull requests the scheduled
// job looks at.
const dependabotLogin = "dependabot[bot]"

// Config is what the jobs need besides their files.
type Config struct {
	// GitHub is the REST client. Decide and Act need the gate app's token
	// (it comments, sets a status and merges); Waiting and LoadConfig only
	// read.
	GitHub *gh.Client
	// Repo is the repository the job runs for, owner/name. A facts file
	// about another repository is refused.
	Repo string
	// BotLogin is the gate app's login, "<app-slug>[bot]". The gate's
	// comment, and the marker in it, is believed only from this author.
	// Only LoadConfig, which reads no comment, runs without it.
	BotLogin string
	// Notifier is told when a pull request needs a person. Nil turns
	// notifications off.
	Notifier Notifier
	// RunURL is this workflow run, built by the caller from validated
	// values, or "". It is the status's target and a link in the comment
	// and in a notification about the run itself.
	RunURL string
	// ModelAsked says this run had a review job: an event's run, never a
	// scheduled one. Only then is a prepared read without a verdict the
	// reviewer's failure, which Act tells the owner about.
	ModelAsked bool
	// Now is the clock; time.Now when nil.
	Now func() time.Time
}

// check is for everything that reads or writes the gate's comment: a job
// that is not told who the gate app is believes nobody's comment, so it
// does not start.
func (cfg Config) check() error {
	if err := cfg.checkRepo(); err != nil {
		return err
	}
	if !strings.HasSuffix(cfg.BotLogin, "[bot]") || len(cfg.BotLogin) == len("[bot]") {
		return fmt.Errorf("land: gate app login %.70q is not an app's login", cfg.BotLogin)
	}
	return nil
}

// checkRepo is the part of check that LoadConfig needs too: it reads the
// repository's settings and no comment.
func (cfg Config) checkRepo() error {
	switch {
	case cfg.GitHub == nil:
		return errors.New("land: no GitHub client")
	case !gh.ValidRepo(cfg.Repo):
		return fmt.Errorf("land: repository %.100q is not owner/name", cfg.Repo)
	}
	return nil
}

func (cfg Config) now() time.Time {
	if cfg.Now != nil {
		return cfg.Now()
	}
	return time.Now()
}

// ErrConfigChanged is Decide's error when the facts were gathered under
// other settings than the default branch has now (another list, another
// chunk budget). Nothing is decided on such facts; the gate has to run
// again from fetch. Test with errors.Is.
var ErrConfigChanged = errors.New("land: the facts were gathered under another configuration")

// MaxFactsAge is how long after they were gathered facts are decided on:
// four hours. A run that goes as it should never meets it. From fetch
// gathering to publish deciding is at most the timeouts of the fetch, the
// review and the publish job in gate.yml (20, 120 and 15 minutes: 2 h 35
// min; a scheduled run's refresh and publish have 45 minutes), which
// leaves 1 h 25 min for runners to start and for the publishes queued
// ahead. A test in cmd/dep-review holds the two together.
//
// What does meet it is a job run again by itself. GitHub's "re-run failed
// jobs" and "re-run job" hand the jobs that are run again the artifacts
// of the first attempt, so publish would decide on what the registries
// said then with the clock of now: old enough, and as clean as it was.
const MaxFactsAge = 4 * time.Hour

// clockSlack is how far ahead of this job's clock the facts may have been
// gathered: two runners' clocks, not a facts file from the future.
const clockSlack = time.Minute

// ErrFactsStale is Decide's error for facts that were gathered more than
// MaxFactsAge before its clock, or after it. Nothing is decided on them.
// The whole gate has to run again; a job run again by itself gets the
// same facts. Test with errors.Is.
var ErrFactsStale = errors.New("land: the facts are too old to decide on")

// Evaluation is Decide's result: the decision and what it was made from.
type Evaluation struct {
	// Stale says why there is nothing to do: the pull request is closed
	// or its head moved since the facts were gathered. A new head gets a
	// run of its own. Empty otherwise; when set, Facts and Decision are
	// not filled in.
	Stale string
	// PullRequest is the pull request, and the one head, the facts file
	// is about.
	PullRequest wire.PullRequest
	// Facts is exactly what allow.Decide was given.
	Facts allow.PRFacts
	// Decision is allow.Decide's answer.
	Decision allow.Decision

	file        wire.Facts // for the comment: the prepared reads, the time gathered
	fingerprint string     // the reviewer's, under the current settings
	cache       []cached   // the verdicts worth remembering
	firstSeen   []seen     // the first evaluations worth remembering
	branch      string     // the default branch
	now         time.Time  // the instant decided at
}

// Decide loads and checks the facts file and the verdicts file, which the
// publish job gets from two different jobs, and asks allow.Decide. It
// writes nothing.
//
// A prepared read's Read and Veto come from the verdicts file alone
// (wire.Join): a verdict that is missing, or was written under another
// reviewer fingerprint, is Read none. A missing verdicts file is no
// verdicts. An update's FirstSeen is the facts file's when a registry
// gave a time, and otherwise this job's own (dateUnseen).
//
// An error means there is no decision: a file that does not decode, facts
// for another repository, gathered under other settings (ErrConfigChanged)
// or too long ago (ErrFactsStale), or GitHub not answering for something
// that is not a fact (the pull request, the policy file, the gate's
// comment).
func Decide(ctx context.Context, cfg Config, factsPath, verdictsPath string) (Evaluation, error) {
	if err := cfg.check(); err != nil {
		return Evaluation{}, err
	}
	facts, verdicts, err := readFiles(factsPath, verdictsPath)
	if err != nil {
		return Evaluation{}, err
	}
	if !strings.EqualFold(facts.PullRequest.Repo, cfg.Repo) {
		return Evaluation{}, fmt.Errorf("land: the facts are about %s, and this job runs for %s", facts.PullRequest.Repo, cfg.Repo)
	}
	ev := Evaluation{PullRequest: facts.PullRequest, file: facts, now: cfg.now()}
	ev.PullRequest.Repo = cfg.Repo

	pr, err := getPull(ctx, cfg, ev.PullRequest.Number)
	if err != nil {
		return Evaluation{}, err
	}
	if ev.Stale = pr.changed(ev.PullRequest.Head); ev.Stale != "" {
		return ev, nil
	}
	// After the look at the pull request: one that was closed or has a
	// newer head is nothing to do, however old the facts.
	if age := ev.now.Sub(facts.GatheredAt); age > MaxFactsAge || age < -clockSlack {
		return Evaluation{}, fmt.Errorf("%w: they were gathered at %s and this job decides at %s; run all of the gate's jobs again",
			ErrFactsStale, stamp(facts.GatheredAt), stamp(ev.now))
	}
	if ev.branch, err = pr.defaultBranch(cfg.Repo); err != nil {
		return Evaluation{}, err
	}

	// The policy comes from the default branch and nowhere else. A file
	// that is there and cannot be used is not replaced by the defaults,
	// which may be laxer than what the owner wrote: the zero Policy makes
	// allow.Decide answer person (policy_invalid).
	var policy allow.Policy
	conf, usable, err := loadConfig(ctx, cfg, ev.branch)
	if err != nil {
		return Evaluation{}, err
	}
	if usable {
		if conf.Fingerprint() != facts.Config {
			return Evaluation{}, fmt.Errorf("%w: run the gate again from fetch", ErrConfigChanged)
		}
		policy = conf.Policy()
		ev.fingerprint = veto.FromConfig(conf).Fingerprint()
	}

	ev.Facts = wire.Join(facts, verdicts, ev.fingerprint)
	// Whatever the facts file says about required checks, this job asks
	// GitHub itself, now.
	ev.Facts.ChecksConfigured = checksConfigured(ctx, cfg, ev.branch)
	if pr.Base.Ref != ev.branch {
		// Identity includes "the base is the default branch". It was true
		// when classify looked; it is not now.
		ev.Facts.Identity = ev.Facts.Identity.And(allow.No("the pull request's base is no longer the default branch", "GitHub pull request, read by publish"))
	}
	if err := ctx.Err(); err != nil {
		// A context that ended reads as "GitHub did not answer" above.
		return Evaluation{}, err
	}
	// The one fact this job makes from its own clock, for the updates no
	// registry dates. allow.Decide is given the result like any other fact.
	if err := dateUnseen(ctx, cfg, &ev); err != nil {
		return Evaluation{}, err
	}

	ev.Decision = allow.Decide(ev.Facts, policy, ev.now)
	ev.cache = cacheEntries(facts, verdicts, ev.fingerprint)
	return ev, nil
}

// readFiles reads the facts file, which must be there, and the verdicts
// file.
func readFiles(factsPath, verdictsPath string) (wire.Facts, wire.Verdicts, error) {
	b, err := os.ReadFile(factsPath)
	if err != nil {
		return wire.Facts{}, wire.Verdicts{}, fmt.Errorf("land: %w", err)
	}
	facts, err := wire.DecodeFacts(b)
	if err != nil {
		return wire.Facts{}, wire.Verdicts{}, err
	}
	verdicts, err := readVerdicts(verdictsPath)
	return facts, verdicts, err
}

// readVerdicts reads a verdicts file. One that is not there is no
// verdicts: the review job was skipped or failed, and every read waits.
func readVerdicts(path string) (wire.Verdicts, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return wire.Verdicts{Version: wire.Version}, nil
	}
	if err != nil {
		return wire.Verdicts{}, fmt.Errorf("land: %w", err)
	}
	return wire.DecodeVerdicts(b)
}

// pull is the part of GitHub's pull request object this package reads.
type pull struct {
	Number         int    `json:"number"`
	State          string `json:"state"`
	Merged         bool   `json:"merged"`
	MergeableState string `json:"mergeable_state"`
	User           *struct {
		Login string `json:"login"`
	} `json:"user"`
	Head struct {
		SHA  string `json:"sha"`
		Repo *struct {
			FullName string `json:"full_name"`
		} `json:"repo"`
	} `json:"head"`
	Base struct {
		Ref  string `json:"ref"`
		Repo *struct {
			FullName      string `json:"full_name"`
			DefaultBranch string `json:"default_branch"`
		} `json:"repo"`
	} `json:"base"`
}

func getPull(ctx context.Context, cfg Config, number int) (pull, error) {
	var pr pull
	err := cfg.GitHub.Get(ctx, fmt.Sprintf("repos/%s/pulls/%d", cfg.Repo, number), &pr)
	return pr, err
}

// changed says why pr is no longer the open pull request at head, or "".
func (pr pull) changed(head string) string {
	switch {
	case pr.State != "open":
		return "the pull request is no longer open"
	case pr.Head.SHA != head:
		return "the pull request's head moved"
	}
	return ""
}

// branchRE is the shape of a branch name this package puts in a URL.
var branchRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$`)

// defaultBranch returns the default branch of the repository pr is in. It
// goes into request paths, so a name of any other shape is an error, not
// something to escape and hope.
func (pr pull) defaultBranch(repo string) (string, error) {
	if pr.Base.Repo == nil || !strings.EqualFold(pr.Base.Repo.FullName, repo) {
		return "", errors.New("land: the pull request's base repository could not be confirmed")
	}
	return checkBranch(pr.Base.Repo.DefaultBranch)
}

// checkBranch returns b when it is a branch name of the shape this
// package puts in a URL.
func checkBranch(b string) (string, error) {
	if !branchRE.MatchString(b) || strings.Contains(b, "..") || strings.Contains(b, "//") || strings.HasSuffix(b, "/") {
		return "", fmt.Errorf("land: default branch %.100q is not a name the gate puts in a URL", b)
	}
	return b, nil
}

// LoadConfig resolves the gate's settings for a job that gathers facts:
// config.RepoFile on the default branch of cfg.Repo, read exactly as
// Decide reads it, so the fingerprint the facts are gathered under is the
// one Decide compares with. It only reads.
//
// usable is false when the file is there and cannot be used. conf is then
// the built-in settings: the facts can still be gathered, and Decide
// answers policy_invalid for them whatever they say.
func LoadConfig(ctx context.Context, cfg Config) (conf config.Config, usable bool, err error) {
	if err := cfg.checkRepo(); err != nil {
		return config.Config{}, false, err
	}
	var repo struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := cfg.GitHub.Get(ctx, "repos/"+cfg.Repo, &repo); err != nil {
		return config.Config{}, false, err
	}
	branch, err := checkBranch(repo.DefaultBranch)
	if err != nil {
		return config.Config{}, false, err
	}
	if conf, usable, err = loadConfig(ctx, cfg, branch); err != nil || usable {
		return conf, usable, err
	}
	conf, err = config.Load(nil)
	return conf, false, err
}

// loadConfig resolves the settings from config.RepoFile on the default
// branch. usable is false when the file is there and cannot be used. Only
// GitHub saying "not found" means the repository has no file; any other
// failure to read it is an error, because deciding with the defaults then
// could undercut an age the owner raised.
func loadConfig(ctx context.Context, cfg Config, branch string) (conf config.Config, usable bool, err error) {
	var raw json.RawMessage
	err = cfg.GitHub.Get(ctx, fmt.Sprintf("repos/%s/contents/%s?ref=%s", cfg.Repo, config.RepoFile, url.QueryEscape(branch)), &raw)
	switch {
	case errors.Is(err, gh.ErrNotFound):
		conf, err = config.Load(nil)
		return conf, err == nil, err
	case err != nil:
		return config.Config{}, false, err
	}
	// A directory or a symbolic link at that path is an answer of another
	// shape, and a file over the API's inline limit has no content here.
	var file struct {
		Type     string `json:"type"`
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
	}
	if json.Unmarshal(raw, &file) != nil || file.Type != "file" || file.Encoding != "base64" {
		return config.Config{}, false, nil
	}
	b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(file.Content, "\n", ""))
	if err != nil {
		return config.Config{}, false, nil
	}
	if conf, err = config.Load(b); err != nil {
		return config.Config{}, false, nil
	}
	return conf, true, nil
}

// checksConfigured is the ChecksConfigured fact: the default branch has an
// active rule that requires at least one status check other than the
// gate's own (gh.RequiredChecks).
func checksConfigured(ctx context.Context, cfg Config, branch string) allow.Fact {
	path := fmt.Sprintf("repos/%s/rules/branches/%s", cfg.Repo, branch)
	contexts, err := gh.RequiredChecks(ctx, cfg.GitHub, cfg.Repo, branch)
	switch {
	case err != nil && gh.Unavailable(err):
		return allow.Unavailable("GitHub did not answer", path)
	case err != nil:
		// An answer, but not one that says anything about the rules: left
		// without a source, which is "never gathered".
		return allow.Fact{Value: fmt.Sprintf("the branch rules could not be read (HTTP %d)", gh.StatusCode(err))}
	case len(contexts) == 0:
		return allow.No("no rule on "+branch+" requires a status check besides the gate's own", path)
	}
	return allow.Yes("required: "+strings.Join(contexts, ", "), path)
}

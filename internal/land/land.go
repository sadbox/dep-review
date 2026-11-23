// Package land is the publish job and the scheduled re-evaluation, as
// library code. Decide reads the two files the earlier jobs wrote, adds
// what only this job can observe (the default branch's required checks,
// whether the pull request is still what the facts describe, when it
// first evaluated a pin no registry dates) and asks allow.Decide with the
// gate's built-in policy. Act carries the answer out.
//
// Nothing in this package decides for a merge. An outcome is
// allow.Decide's, or allow.ChecksRefused's after GitHub refused a merge
// or this package did not ask for it; what this package adds is only ever
// "not yet" (the default branch changed a file the pull request changes:
// baseChanged), "nothing was done" (the pull request changed), "GitHub
// refused" (reported, never retried as if it were a wait) or "the run
// failed" (Failed). The gate does not judge CI: GitHub's rules answer
// the merge call. And there is no stored approval: the comment remembers
// the last outcome, the model's verdicts by content key and when a pin
// was first evaluated, and a merge always follows a fresh allow.Decide on
// facts gathered no longer ago than MaxFactsAge. What is stored and does
// decide is an objection: a veto the comment remembers stands for the
// same content until a person merges or closes the pull request (answers).
package land

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
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
	// (it comments, sets a status and merges); Schedule only reads.
	GitHub *gh.Client
	// Repo is the repository the job runs for, owner/name. A facts file
	// about another repository is refused.
	Repo string
	// BotLogin is the gate app's login, "<app-slug>[bot]". The gate's
	// comment, and the marker in it, is believed only from this author.
	BotLogin string
	// Notifier is told when a pull request needs a person. Nil turns
	// notifications off.
	Notifier Notifier
	// RunURL is this workflow run, built by the caller from validated
	// values, or "". It is the status's target and a link in the comment
	// and in a notification about the run itself.
	RunURL string
	// Scheduled says this is a scheduled run and not an event's. On a
	// scheduled run the clean verdicts the gate's own comment remembers
	// count for the reads this run has no answer for (answers), and the
	// comment counts the runs that asked the model (marker.Asks). An
	// event's run asks about every read itself and counts nothing.
	Scheduled bool
	// ModelAsked says the model was asked about this pull request in this
	// run: on an event's run always (the review job ran, or should have),
	// on a scheduled one when the second review job wrote a verdicts file
	// for it.
	ModelAsked bool
	// Unverified is the reason of publish's own identity proof when it says
	// the pull request is not Dependabot's alone, or "". Decide takes it as
	// a "no" for Identity whatever the facts file says, since the proof of
	// the job that gathered the facts may not have finished (spec section
	// 11, amendment 75). It can only take away.
	Unverified string
	// Now is the clock; time.Now when nil.
	Now func() time.Time
}

// check is for everything that reads or writes the gate's comment: a job
// that is not told who the gate app is believes nobody's comment, so it
// does not start.
func (cfg Config) check() error {
	switch {
	case cfg.GitHub == nil:
		return errors.New("land: no GitHub client")
	case !gh.ValidRepo(cfg.Repo):
		return fmt.Errorf("land: repository %.100q is not owner/name", cfg.Repo)
	case !strings.HasSuffix(cfg.BotLogin, "[bot]") || len(cfg.BotLogin) == len("[bot]"):
		return fmt.Errorf("land: gate app login %.70q is not an app's login", cfg.BotLogin)
	}
	return nil
}

func (cfg Config) now() time.Time {
	if cfg.Now != nil {
		return cfg.Now()
	}
	return time.Now()
}

// MaxFactsAge is how long after they were gathered facts are decided on:
// four hours. A run that goes as it should never meets it. From fetch
// gathering to publish deciding is at most the timeouts of the fetch, the
// review and the publish job in gate.yml (20, 120 and 15 minutes: 2 h 35
// min; a scheduled run's refresh, reread and publish have 30, 120 and 15:
// 2 h 45 min), which leaves 1 h 15 min for runners to start and for the
// publishes queued ahead. A test in cmd/dep-review holds the two
// together.
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
	fingerprint string     // the reviewer's
	cache       []cached   // the verdicts worth remembering
	forgot      bool       // a veto was given up, by this run or before (marker.Forgot)
	// stood has the content keys whose veto is one the gate's comment
	// remembered and this run's verdicts file does not repeat.
	stood     map[string]bool
	firstSeen []seen    // the first evaluations worth remembering
	branch    string    // the default branch
	now       time.Time // the instant decided at
	// status is the status Act last set on this head, as the comment
	// remembers it, or nil (marker.Status).
	status *lastStatus
}

// Decide loads and checks the facts file and the verdicts file, which the
// publish job gets from two different jobs, and asks allow.Decide. It
// writes nothing.
//
// A prepared read's Read and Veto come from the verdicts file and from
// what the gate's own comment remembers (answers, wire.Join): a veto the
// comment remembers for the same content stands whatever the file says,
// on a scheduled run a clean verdict it remembers counts where the file
// has no answer, and a verdict that is missing, or was written under
// another reviewer fingerprint, is Read none. A missing verdicts file is
// no verdicts. Nothing else is believed about a read: not what the job
// that gathered the facts says the comment remembers. An update's
// FirstSeen is the facts file's when a registry gave a time, and
// otherwise this job's own (dateUnseen).
//
// An error means there is no decision: a file that does not decode, facts
// for another repository or gathered too long ago (ErrFactsStale), or
// GitHub not answering for something that is not a fact (the pull request,
// the gate's comment). The comment is read at every decision: without it
// a veto the gate recorded would be decided without.
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

	// The policy is the one built into this binary, which is also the one
	// the facts were gathered under: the jobs of a run are one build
	// (gate.yml's checksum chain), and no repository has a file that could
	// have changed in between (spec section 11, amendment 56).
	conf, err := config.Load()
	if err != nil {
		return Evaluation{}, err
	}
	policy := conf.Policy()
	ev.fingerprint = veto.FromConfig(conf).Fingerprint()

	old, err := memory(ctx, cfg, ev.PullRequest.Number)
	if err != nil {
		return Evaluation{}, err
	}
	if old.Head == ev.PullRequest.Head {
		ev.status = old.Status
	}
	verdicts, ev.stood = answers(verdicts, old, ev.fingerprint, cfg.Scheduled)
	ev.Facts = wire.Join(facts, verdicts, ev.fingerprint)
	// Whatever the facts file says about required checks, this job asks
	// GitHub itself, now.
	ev.Facts.ChecksConfigured = checksConfigured(ctx, cfg, ev.branch)
	if pr.Base.Ref != ev.branch {
		// Identity includes "the base is the default branch". It was true
		// when classify looked; it is not now.
		ev.Facts.Identity = ev.Facts.Identity.And(allow.No("the pull request's base is no longer the default branch", "GitHub pull request, read by publish"))
	}
	if cfg.Unverified != "" {
		ev.Facts.Identity = ev.Facts.Identity.And(allow.No(cfg.Unverified, "classify, run by publish"))
	}
	if err := ctx.Err(); err != nil {
		// A context that ended reads as "GitHub did not answer" above.
		return Evaluation{}, err
	}
	// The one fact this job makes from its own clock, for the updates no
	// registry dates. allow.Decide is given the result like any other fact.
	dateUnseen(&ev, old.FirstSeen)

	ev.Decision = allow.Decide(ev.Facts, policy, ev.now)
	cache, cut := cacheEntries(facts, verdicts, old, ev.fingerprint)
	ev.cache, ev.forgot = fitted(old, ev.PullRequest.Head, ev.fingerprint, ev.firstSeen, cache)
	if ev.forgot = ev.forgot || cut; ev.forgot {
		// A veto the gate cannot remember would be asked about again
		// (spec section 11, amendment 71).
		ev.Decision = allow.VetoesForgotten(ev.Decision)
	}
	return ev, nil
}

// memory is what the gate's own comment on a pull request remembers: its
// marker, or the zero marker when the gate has no comment there or the
// comment has no marker this version reads. Nothing is then remembered:
// no verdict, no veto and no first-seen time. The error is GitHub not
// answering.
func memory(ctx context.Context, cfg Config, number int) (marker, error) {
	c, err := findComment(ctx, cfg, number)
	if err != nil || c == nil {
		return marker{}, err
	}
	old, _ := parseMarker(c.Body)
	return old, nil
}

// answers settles which verdict counts for each content key under the
// reviewer's fingerprint: the one in this run's verdicts file, or the one
// the gate's comment remembers (spec section 11, amendments 63 and 64).
//
//	the comment remembers   this run's file says        counts
//	a veto                  a veto                      this run's veto
//	a veto                  anything else, nothing      the remembered veto
//	no veto                 a veto, refused, no veto    this run's
//	no veto                 no answer, nothing          the remembered one on a
//	                                                    scheduled run; else this run's
//	nothing                 anything, nothing           this run's, as it is
//
// So a veto stands. The model is not asked the same way twice (nothing
// fixes its sampling), and an objection that one later answer could take
// back would hold only until the next rebase. What gets past a veto is a
// person merging or closing the pull request, content with another key,
// or a reviewer with another fingerprint: the comment's entries are all
// under the one fingerprint it names, and under any other none of them is
// looked at.
//
// A clean verdict is remembered for the scheduled run, which asks the
// model only about what has no answer yet. An event's run asks about
// every read, and an answer it did not get is not made up from an earlier
// one (amendment 39).
//
// The result has one entry for each key, all under fingerprint; a verdict
// of the file under another fingerprint is left out, as wire.Join would
// not look at it. stood has the keys whose veto is the remembered one.
func answers(file wire.Verdicts, old marker, fingerprint string, scheduled bool) (merged wire.Verdicts, stood map[string]bool) {
	merged = wire.Verdicts{Version: wire.Version, Verdicts: []wire.Verdict{}}
	at := map[string]int{} // a key's place in merged
	for _, v := range file.Verdicts {
		if v.Fingerprint != fingerprint {
			continue
		}
		at[v.Key] = len(merged.Verdicts)
		merged.Verdicts = append(merged.Verdicts, v)
	}
	stood = map[string]bool{}
	if old.Fingerprint != fingerprint {
		return merged, stood
	}
	for _, e := range old.Cache {
		remembered := wire.Verdict{Key: e.Key, Fingerprint: fingerprint, Read: e.Read, Veto: e.Veto}
		i, has := at[e.Key]
		switch {
		case e.Veto == nil && !scheduled:
			continue
		case e.Veto == nil && has && merged.Verdicts[i].Read != allow.ReadNone:
			continue // this run has an answer of its own
		case e.Veto != nil && has && merged.Verdicts[i].Veto != nil:
			continue // the model objects again, in this run's words
		}
		if has {
			merged.Verdicts[i] = remembered
		} else {
			at[e.Key] = len(merged.Verdicts)
			merged.Verdicts = append(merged.Verdicts, remembered)
		}
		if e.Veto != nil {
			stood[e.Key] = true
		}
	}
	return merged, stood
}

// reviewer is the reviewer's fingerprint under the gate's built-in
// settings: the one every verdict that counts in this build was written
// under.
func reviewer() (string, error) {
	conf, err := config.Load()
	if err != nil {
		return "", err
	}
	return veto.FromConfig(conf).Fingerprint(), nil
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
	// UpdatedAt is GitHub's time of the last change to the pull request:
	// a push, a comment, a label. The scheduled job waits by it before it
	// evaluates a pull request the gate has nothing for (Schedule).
	UpdatedAt time.Time `json:"updated_at"`
	User      *struct {
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

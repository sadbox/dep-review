package publish

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
)

const statusContext = "dep-review"

// Config is what Publish and Sweep need besides their inputs.
type Config struct {
	GitHub   *gh.Client
	BotLogin string // "<app-slug>[bot]"; our comments and statuses are recognised by it
	// TriggerPath is the caller's no-op trigger workflow, whose check runs
	// never count as CI. Publish uses the classification's when it has one.
	TriggerPath string
	Notifier    Notifier // nil: notifications off
	ServerURL   string   // https://github.com
	RunURL      string   // this workflow run, or ""

	MergeWait  time.Duration // how long publish waits for CI before leaving it to sweep
	PollMin    time.Duration
	PollMax    time.Duration
	StuckAfter time.Duration // sweep: report heads without a decision older than this
	Now        func() time.Time
	Sleep      func(ctx context.Context, d time.Duration) error
	Logf       func(format string, args ...any)
}

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// BotLoginFromSlug turns create-github-app-token's app-slug output into
// the app's bot login.
func BotLoginFromSlug(slug string) (string, error) {
	if !slugRe.MatchString(slug) {
		return "", fmt.Errorf("DEP_REVIEW_APP_SLUG %.70q is not an app slug", slug)
	}
	return slug + "[bot]", nil
}

// ConfigFromEnv fills Config from the workflow environment.
func ConfigFromEnv(c *gh.Client) (Config, error) {
	bot, err := BotLoginFromSlug(os.Getenv("DEP_REVIEW_APP_SLUG"))
	if err != nil {
		return Config{}, err
	}
	cfg := Config{GitHub: c, BotLogin: bot, ServerURL: "https://github.com"}
	if u := os.Getenv("GITHUB_SERVER_URL"); strings.HasPrefix(u, "https://") && !strings.ContainsAny(u, " ()[]<>\"'") {
		cfg.ServerURL = strings.TrimSuffix(u, "/")
	}
	repo, run := os.Getenv("GITHUB_REPOSITORY"), os.Getenv("GITHUB_RUN_ID")
	if gh.ValidRepo(repo) && regexp.MustCompile(`^[0-9]{1,20}$`).MatchString(run) {
		cfg.RunURL = fmt.Sprintf("%s/%s/actions/runs/%s", cfg.ServerURL, repo, run)
	}
	if tok, user := os.Getenv("PUSHOVER_APP_TOKEN"), os.Getenv("PUSHOVER_USER_KEY"); tok != "" && user != "" {
		cfg.Notifier = &Pushover{Token: tok, User: user}
	}
	return cfg, nil
}

func (cfg *Config) defaults() {
	if cfg.MergeWait == 0 {
		cfg.MergeWait = 20 * time.Minute
	}
	if cfg.PollMin == 0 {
		cfg.PollMin = 15 * time.Second
	}
	if cfg.PollMax == 0 {
		cfg.PollMax = 2 * time.Minute
	}
	if cfg.StuckAfter == 0 {
		cfg.StuckAfter = 2 * time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Sleep == nil {
		cfg.Sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.ServerURL == "" {
		cfg.ServerURL = "https://github.com"
	}
}

// ReadInputs loads <dir>/classification/classification.json (required),
// <dir>/evidence/evidence.json and <dir>/verdict/verdict.json (optional).
func ReadInputs(dir, fetchResult, reviewResult string) (Inputs, error) {
	in := Inputs{FetchResult: fetchResult, ReviewResult: reviewResult}
	b, err := os.ReadFile(filepath.Join(dir, "classification", "classification.json"))
	if err != nil {
		return in, err
	}
	if err := json.Unmarshal(b, &in.Class); err != nil {
		return in, fmt.Errorf("classification.json: %w", err)
	}
	b, err = os.ReadFile(filepath.Join(dir, "evidence", "evidence.json"))
	switch {
	case err == nil:
		var ev model.Evidence
		if json.Unmarshal(b, &ev) == nil {
			in.Evidence = &ev
		}
		// An unreadable evidence.json is treated as missing: pending.
	case !errors.Is(err, fs.ErrNotExist):
		return in, err
	}
	b, err = os.ReadFile(filepath.Join(dir, "verdict", "verdict.json"))
	switch {
	case err == nil:
		in.Verdict = b
	case !errors.Is(err, fs.ErrNotExist):
		return in, err
	}
	return in, nil
}

type ghPull struct {
	Number  int    `json:"number"`
	State   string `json:"state"`
	HTMLURL string `json:"html_url"`
	User    *struct {
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

// baseProblem says why pr's base is not one the gate merges into, or "".
// The base must be the repository's default branch and, when want is
// set, the branch classify saw.
func baseProblem(pr *ghPull, repo, want string) string {
	switch {
	case pr.Base.Repo == nil || !strings.EqualFold(pr.Base.Repo.FullName, repo) || pr.Base.Repo.DefaultBranch == "":
		return "the pull request's base repository could not be confirmed"
	case pr.Base.Ref != pr.Base.Repo.DefaultBranch:
		return "the pull request's base is not the default branch"
	case want != "" && pr.Base.Ref != want:
		return "the pull request's base changed after classification"
	}
	return ""
}

type ghComment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
	User *struct {
		Login string `json:"login"`
	} `json:"user"`
}

// Publish acts on the decision for one classified PR.
func Publish(ctx context.Context, cfg Config, in Inputs) error {
	cfg.defaults()
	o := Decide(in)
	cl := in.Class
	cfg.Logf("decision=%s state=%s reason=%q", o.Decision, o.State, o.Reason)
	if o.Decision == model.DecisionIgnore {
		return nil
	}
	if !gh.ValidRepo(cl.Repo) || cl.PR <= 0 || !gh.ValidSHA(cl.HeadSHA) {
		return errors.New("classification has no valid repository, PR or head")
	}
	c := cfg.GitHub

	var pr ghPull
	if err := c.Get(ctx, fmt.Sprintf("repos/%s/pulls/%d", cl.Repo, cl.PR), &pr); err != nil {
		return err
	}
	if pr.State != "open" || pr.Head.SHA != cl.HeadSHA {
		cfg.Logf("stale: the pull request is closed or its head moved on; doing nothing")
		return nil
	}
	if o.Decision == model.DecisionMerge {
		why := baseProblem(&pr, cl.Repo, cl.BaseRef)
		if cl.BaseRef == "" {
			why = "the classification has no base branch"
		}
		if why != "" {
			cfg.Logf("not merging: %s", why)
			o = human(o.Route, why, nil)
		}
	}
	trigger := cfg.TriggerPath
	if cl.TriggerPath != "" {
		trigger = cl.TriggerPath
	}

	prev, err := findComment(ctx, cfg, cl.Repo, cl.PR)
	if err != nil {
		return err
	}
	data := commentData{Class: cl, Evidence: in.Evidence, Outcome: o, RunURL: cfg.RunURL}
	if prev != nil {
		data.Marker, _ = parseMarker(prev.Body)
	}
	data.Marker.Approved = ""
	if o.Decision == model.DecisionMerge {
		data.Marker.Approved = cl.HeadSHA
	}
	id, err := upsertComment(ctx, cfg, cl.Repo, cl.PR, prev, renderComment(data))
	if err != nil {
		return err
	}
	if err := setStatus(ctx, cfg, cl.Repo, cl.HeadSHA, o.State, o.Reason); err != nil {
		return err
	}

	notify := o.Decision == model.DecisionHuman
	reason := o.Reason
	if o.Decision == model.DecisionMerge {
		res, err := mergeWhenGreen(ctx, cfg, cl.Repo, cl.PR, cl.HeadSHA, cl.BaseRef, trigger, cfg.MergeWait)
		if err != nil {
			return err
		}
		cfg.Logf("merge: %s", res.Note)
		if res.Failed {
			notify, reason = true, "approved but not merged: "+res.Note
			data.MergeNote = res.Note
		}
	}
	if notify && cfg.Notifier != nil && !has(data.Marker.Notified, cl.HeadSHA) {
		if err := cfg.Notifier.Notify(ctx, notification(cfg, cl.Repo, cl.PR, o.Decision, reason)); err != nil {
			cfg.Logf("notify: %v", err)
		} else {
			data.Marker.Notified = add(data.Marker.Notified, cl.HeadSHA)
		}
	}
	if data.MergeNote != "" || has(data.Marker.Notified, cl.HeadSHA) {
		cur := &ghComment{ID: id}
		if _, err := upsertComment(ctx, cfg, cl.Repo, cl.PR, cur, renderComment(data)); err != nil {
			return err
		}
	}
	return nil
}

func findComment(ctx context.Context, cfg Config, repo string, pr int) (*ghComment, error) {
	comments, err := gh.List[ghComment](ctx, cfg.GitHub, fmt.Sprintf("repos/%s/issues/%d/comments", repo, pr))
	if err != nil {
		return nil, err
	}
	for i := range comments {
		cm := &comments[i]
		if cm.User != nil && cm.User.Login == cfg.BotLogin && strings.HasPrefix(cm.Body, markerPrefix) {
			return cm, nil
		}
	}
	return nil, nil
}

func upsertComment(ctx context.Context, cfg Config, repo string, pr int, prev *ghComment, body string) (int64, error) {
	var out ghComment
	if prev != nil && prev.ID > 0 {
		err := cfg.GitHub.Patch(ctx, fmt.Sprintf("repos/%s/issues/comments/%d", repo, prev.ID), map[string]string{"body": body}, &out)
		return prev.ID, err
	}
	err := cfg.GitHub.Post(ctx, fmt.Sprintf("repos/%s/issues/%d/comments", repo, pr), map[string]string{"body": body}, &out)
	return out.ID, err
}

func setStatus(ctx context.Context, cfg Config, repo, sha, state, desc string) error {
	desc = Inline(desc)
	desc = strings.ReplaceAll(desc, `\|`, "|")
	if r := []rune(desc); len(r) > 140 {
		desc = string(r[:139]) + "…"
	}
	body := map[string]string{"state": state, "context": statusContext, "description": desc}
	if cfg.RunURL != "" {
		body["target_url"] = cfg.RunURL
	}
	return cfg.GitHub.Post(ctx, fmt.Sprintf("repos/%s/statuses/%s", repo, sha), body, nil)
}

type mergeResult struct {
	Merged bool
	Failed bool   // will not merge without a person (red CI, not mergeable)
	Note   string // the gate's own words
}

// mergeWhenGreen polls CI on sha until it settles or wait runs out, then
// merges exactly sha. Running out of time is not a failure: sweep picks
// it up.
func mergeWhenGreen(ctx context.Context, cfg Config, repo string, pr int, sha, base, trigger string, wait time.Duration) (mergeResult, error) {
	deadline := cfg.Now().Add(wait)
	delay := cfg.PollMin
	for {
		st, note, err := ciState(ctx, cfg, repo, sha, trigger)
		if err != nil {
			return mergeResult{}, err
		}
		switch st {
		case ciRed:
			return mergeResult{Failed: true, Note: note}, nil
		case ciGreen:
			return merge(ctx, cfg, repo, pr, sha, base)
		}
		if !cfg.Now().Add(delay).Before(deadline) {
			return mergeResult{Note: "CI still running; sweep will merge when it finishes"}, nil
		}
		if err := cfg.Sleep(ctx, delay); err != nil {
			return mergeResult{}, err
		}
		delay = min(delay*3/2, cfg.PollMax)
	}
}

// merge merges exactly sha after re-reading the pull request: it must
// still be open at sha and its base must still be the default branch (and
// base, when set). The merge API's sha= guards only the head, and CI may
// have taken many minutes since the last look.
func merge(ctx context.Context, cfg Config, repo string, pr int, sha, base string) (mergeResult, error) {
	var cur ghPull
	if err := cfg.GitHub.Get(ctx, fmt.Sprintf("repos/%s/pulls/%d", repo, pr), &cur); err != nil {
		return mergeResult{}, err
	}
	switch {
	case cur.State != "open":
		return mergeResult{Note: "the pull request is no longer open"}, nil
	case cur.Head.SHA != sha:
		return mergeResult{Failed: true, Note: "the head moved before the merge"}, nil
	}
	if why := baseProblem(&cur, repo, base); why != "" {
		return mergeResult{Failed: true, Note: why}, nil
	}
	var out struct {
		Merged bool `json:"merged"`
	}
	err := cfg.GitHub.Put(ctx, fmt.Sprintf("repos/%s/pulls/%d/merge", repo, pr),
		map[string]string{"merge_method": "squash", "sha": sha}, &out)
	switch code := gh.StatusCode(err); {
	case err == nil && out.Merged:
		return mergeResult{Merged: true, Note: "merged"}, nil
	case err == nil:
		return mergeResult{Failed: true, Note: "GitHub did not merge the pull request"}, nil
	case code == http.StatusMethodNotAllowed || code == http.StatusConflict:
		// A concurrent publish or sweep may have merged it already.
		var cur struct {
			Merged bool `json:"merged"`
		}
		if gerr := cfg.GitHub.Get(ctx, fmt.Sprintf("repos/%s/pulls/%d", repo, pr), &cur); gerr == nil && cur.Merged {
			return mergeResult{Merged: true, Note: "already merged"}, nil
		}
		cfg.Logf("merge refused: %v", err)
		if code == http.StatusConflict {
			return mergeResult{Failed: true, Note: "the head moved before the merge"}, nil
		}
		return mergeResult{Failed: true, Note: "GitHub refused the merge (not mergeable)"}, nil
	default:
		return mergeResult{}, err
	}
}

type ci int

const (
	ciPending ci = iota
	ciGreen
	ciRed
)

// ciState reads every check run and commit status on sha. Anything
// failing is red and anything unfinished is pending. Green additionally
// needs at least one successful check run or status that is real CI: not
// the trigger workflow (a no-op that succeeds on every PR), not the gate's
// own `dep-review` status and nothing the gate app created. With none, CI
// is pending, so a repository without CI never auto-merges; sweep retries.
//
// A check run from GitHub Actions counts only when its check suite maps to
// a workflow run on sha whose workflow file is not the trigger; one that
// cannot be mapped never counts.
func ciState(ctx context.Context, cfg Config, repo, sha, trigger string) (ci, string, error) {
	c := cfg.GitHub
	gateSlug := strings.TrimSuffix(cfg.BotLogin, "[bot]")
	var runs []checkRun
	err := c.Pages(ctx, fmt.Sprintf("repos/%s/commits/%s/check-runs", repo, sha), func(body []byte) error {
		var page struct {
			CheckRuns []checkRun `json:"check_runs"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		runs = append(runs, page.CheckRuns...)
		return nil
	})
	if err != nil {
		return ciPending, "", err
	}
	// Workflow file of every Actions check suite on sha.
	suitePath := map[int64]string{}
	err = c.Pages(ctx, fmt.Sprintf("repos/%s/actions/runs?head_sha=%s", repo, sha), func(body []byte) error {
		var page struct {
			WorkflowRuns []struct {
				Path         string `json:"path"`
				CheckSuiteID int64  `json:"check_suite_id"`
			} `json:"workflow_runs"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		for _, r := range page.WorkflowRuns {
			if r.CheckSuiteID > 0 {
				suitePath[r.CheckSuiteID] = r.Path
			}
		}
		return nil
	})
	if err != nil {
		return ciPending, "", err
	}
	// Statuses newest first; the newest per context is its current state.
	statuses, err := gh.List[ghStatus](ctx, c, fmt.Sprintf("repos/%s/commits/%s/statuses", repo, sha))
	if err != nil {
		return ciPending, "", err
	}

	pending, red, real := 0, 0, 0
	for _, r := range runs {
		if r.Status != "completed" {
			pending++
			continue
		}
		switch r.Conclusion {
		case "success":
			if r.countsAsCI(gateSlug, trigger, suitePath) {
				real++
			}
		case "neutral", "skipped":
		default:
			red++
		}
	}
	seen := map[string]bool{}
	for _, s := range statuses {
		if seen[s.Context] {
			continue
		}
		seen[s.Context] = true
		if s.Context == statusContext {
			continue
		}
		switch s.State {
		case "success":
			if s.Creator != nil && s.Creator.Login != "" && s.Creator.Login != cfg.BotLogin {
				real++
			}
		case "pending":
			pending++
		default:
			red++
		}
	}
	switch {
	case red > 0:
		return ciRed, fmt.Sprintf("CI failed (%d failing checks)", red), nil
	case pending > 0:
		return ciPending, fmt.Sprintf("%d checks still running", pending), nil
	case real == 0:
		return ciPending, "no CI check besides the gate's own has passed yet", nil
	}
	return ciGreen, "CI green", nil
}

type checkRun struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	App        *struct {
		Slug string `json:"slug"`
	} `json:"app"`
	CheckSuite *struct {
		ID int64 `json:"id"`
	} `json:"check_suite"`
}

// countsAsCI reports whether a successful check run is real CI (see
// ciState). Without a trigger path no Actions run counts.
func (r checkRun) countsAsCI(gateSlug, trigger string, suitePath map[int64]string) bool {
	if r.Name == statusContext || r.App == nil || r.App.Slug == "" || r.App.Slug == gateSlug {
		return false
	}
	if r.App.Slug != "github-actions" {
		return true
	}
	if r.CheckSuite == nil || trigger == "" {
		return false
	}
	p, ok := suitePath[r.CheckSuite.ID]
	return ok && p != "" && p != trigger
}

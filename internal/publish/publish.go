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
	GitHub    *gh.Client
	BotLogin  string   // "<app-slug>[bot]"; our comments and statuses are recognised by it
	Notifier  Notifier // nil: notifications off
	ServerURL string   // https://github.com
	RunURL    string   // this workflow run, or ""

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

	prev, err := findComment(ctx, cfg, cl.Repo, cl.PR)
	if err != nil {
		return err
	}
	data := commentData{Class: cl, Evidence: in.Evidence, Outcome: o, RunURL: cfg.RunURL}
	if prev != nil {
		data.Marker, _ = parseMarker(prev.Body)
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
		res, err := mergeWhenGreen(ctx, cfg, cl.Repo, cl.PR, cl.HeadSHA, cfg.MergeWait)
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
func mergeWhenGreen(ctx context.Context, cfg Config, repo string, pr int, sha string, wait time.Duration) (mergeResult, error) {
	deadline := cfg.Now().Add(wait)
	delay := cfg.PollMin
	for {
		st, note, err := ciState(ctx, cfg.GitHub, repo, sha)
		if err != nil {
			return mergeResult{}, err
		}
		switch st {
		case ciRed:
			return mergeResult{Failed: true, Note: note}, nil
		case ciGreen:
			return merge(ctx, cfg, repo, pr, sha)
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

func merge(ctx context.Context, cfg Config, repo string, pr int, sha string) (mergeResult, error) {
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

// ciState looks at every check run and commit status on sha except our
// own `dep-review` status.
func ciState(ctx context.Context, c *gh.Client, repo, sha string) (ci, string, error) {
	var runs []struct {
		Name       string `json:"name"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
	}
	err := c.Pages(ctx, fmt.Sprintf("repos/%s/commits/%s/check-runs", repo, sha), func(body []byte) error {
		var page struct {
			CheckRuns []struct {
				Name       string `json:"name"`
				Status     string `json:"status"`
				Conclusion string `json:"conclusion"`
			} `json:"check_runs"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		for _, r := range page.CheckRuns {
			runs = append(runs, r)
		}
		return nil
	})
	if err != nil {
		return ciPending, "", err
	}
	type status struct {
		Context string `json:"context"`
		State   string `json:"state"`
	}
	var statuses []status
	err = c.Pages(ctx, fmt.Sprintf("repos/%s/commits/%s/status", repo, sha), func(body []byte) error {
		var page struct {
			Statuses []status `json:"statuses"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return err
		}
		statuses = append(statuses, page.Statuses...)
		return nil
	})
	if err != nil {
		return ciPending, "", err
	}
	pending, red := 0, 0
	for _, r := range runs {
		if r.Status != "completed" {
			pending++
			continue
		}
		switch r.Conclusion {
		case "success", "neutral", "skipped":
		default:
			red++
		}
	}
	for _, s := range statuses {
		if s.Context == statusContext {
			continue
		}
		switch s.State {
		case "success":
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
	}
	return ciGreen, "CI green", nil
}

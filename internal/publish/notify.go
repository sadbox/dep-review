package publish

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/model"
)

// Message is a notification. Every field comes from a fixed template
// filled with validated identifiers and the gate's own reason text; never
// model output or text from a dependency.
type Message struct {
	Title string
	Body  string
	URL   string
}

type Notifier interface {
	Notify(ctx context.Context, m Message) error
}

var decisionText = map[model.Decision]string{
	model.DecisionMerge:   "approved",
	model.DecisionHuman:   "needs a person",
	model.DecisionPending: "no decision",
}

func notification(cfg Config, repo string, pr int, d model.Decision, reason string) Message {
	reason = strings.ReplaceAll(Inline(reason), `\|`, "|")
	return Message{
		Title: fmt.Sprintf("dep-review: %s#%d", repo, pr),
		Body:  fmt.Sprintf("%s#%d %s: %s", repo, pr, decisionText[d], reason),
		URL:   fmt.Sprintf("%s/%s/pull/%d", cfg.ServerURL, repo, pr),
	}
}

// Pushover sends through https://pushover.net.
type Pushover struct {
	Token, User string
	Endpoint    string // default https://api.pushover.net/1/messages.json
	HTTP        *http.Client
}

func (p *Pushover) Notify(ctx context.Context, m Message) error {
	endpoint := p.Endpoint
	if endpoint == "" {
		endpoint = "https://api.pushover.net/1/messages.json"
	}
	hc := p.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	form := url.Values{
		"token":     {p.Token},
		"user":      {p.User},
		"title":     {m.Title},
		"message":   {m.Body},
		"url":       {m.URL},
		"url_title": {"Open the pull request"},
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := hc.Do(req)
		if err != nil {
			lastErr = err
		} else {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			var r struct {
				Errors []string `json:"errors"`
			}
			_ = json.Unmarshal(body, &r)
			lastErr = fmt.Errorf("pushover: %d %v", resp.StatusCode, r.Errors)
			if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
				return lastErr
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 2 * time.Second):
		}
	}
	return lastErr
}

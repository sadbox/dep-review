package land

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/wire"
)

// Message is a notification. Every part is a fixed sentence of the gate's
// filled with a validated repository, a number, a reason from allow's
// closed set and the run's URL. Nothing a dependency, a registry, GitHub
// or the model wrote is ever in one.
type Message struct {
	// Title names the pull request.
	Title string
	// Body is one sentence: what happened and why.
	Body string
	// URL is the pull request's page.
	URL string
}

// Notifier delivers a Message to the owner.
type Notifier interface {
	// Notify sends m. An error means it was not delivered; Act then does
	// not remember it as sent.
	Notify(ctx context.Context, m Message) error
}

// notification is the message for a result, and whether there is one: a
// pull request that needs a person, or a merge GitHub refused. A merge
// and a wait need nobody.
func notification(cfg Config, pr wire.PullRequest, res Result) (Message, bool) {
	switch {
	case res.Action == ActionRefused:
		return message(cfg, pr.Number, ": GitHub refused the merge. See the comment on the pull request."), true
	case res.Action == ActionPerson && len(res.Decision.Reasons) > 0:
		r := res.Decision.Reasons[0]
		return message(cfg, pr.Number, fmt.Sprintf(" needs a person (%s): %s", r, r.Explain())), true
	case res.Action == ActionPerson:
		return message(cfg, pr.Number, " needs a person."), true
	}
	return Message{}, false
}

// message is a notification about a pull request: its name, then rest.
func message(cfg Config, number int, rest string) Message {
	return Message{
		Title: fmt.Sprintf("dep-review: %s#%d", cfg.Repo, number),
		Body:  fmt.Sprintf("%s#%d%s", cfg.Repo, number, rest),
		URL:   fmt.Sprintf("https://github.com/%s/pull/%d", cfg.Repo, number),
	}
}

// runLink ends a notification about the gate's own run, which says what
// to run again: with the run's URL, when the job knows it.
func runLink(cfg Config) string {
	if cfg.RunURL == "" {
		return " of its workflow run."
	}
	return ": " + cfg.RunURL
}

// notifyOnce sends m unless sent, a list the gate's comment keeps, has
// head already, and adds head once m is delivered. A notification that
// failed is an error and is not remembered: the next run sends it.
func notifyOnce(ctx context.Context, cfg Config, sent *[]string, head string, m Message) error {
	if cfg.Notifier == nil || slices.Contains(*sent, head) {
		return nil
	}
	if err := cfg.Notifier.Notify(ctx, m); err != nil {
		return fmt.Errorf("land: notify: %w", err)
	}
	if *sent = append(*sent, head); len(*sent) > maxNotified {
		*sent = (*sent)[len(*sent)-maxNotified:]
	}
	return nil
}

// Pushover sends through https://pushover.net.
type Pushover struct {
	// Token and User are the application token and the user key.
	Token, User string
	// Endpoint is the API; https://api.pushover.net/1/messages.json when
	// empty.
	Endpoint string
	// HTTP is the client; one with a 20 second timeout when nil.
	HTTP *http.Client
}

// Notify posts the message. A network failure, a rate limit and a server
// error are tried three times; any other answer is final.
func (p *Pushover) Notify(ctx context.Context, m Message) error {
	endpoint := p.Endpoint
	if endpoint == "" {
		endpoint = "https://api.pushover.net/1/messages.json"
	}
	client := p.HTTP
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	form := url.Values{
		"token": {p.Token}, "user": {p.User},
		"title": {m.Title}, "message": {m.Body},
		"url": {m.URL}, "url_title": {"Open the pull request"},
	}.Encode()

	const attempts = 3
	for attempt := 1; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err == nil {
			// The status says enough; the body is drained and not kept.
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			err = fmt.Errorf("pushover: HTTP %d", resp.StatusCode)
			if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
				return err
			}
		}
		if attempt == attempts {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt) * 2 * time.Second):
		}
	}
}

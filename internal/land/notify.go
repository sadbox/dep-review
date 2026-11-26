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
// or the model wrote is ever in one, but for one thing: the name of the
// file a held merge is held for, GitHub's, which whoever can push to the
// default branch chose. It goes in as the comment shows it (inline): one
// capped line, with nothing GitHub or a bot would act on.
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

// heldMessage is the notification about a merge the gate holds (spec
// section 11, amendment 78): the file, and Dependabot's command, which
// the comment must not hold. fix says the pull request is a security fix,
// told at once; any other waited a day.
func heldMessage(cfg Config, number int, file string, fix bool) Message {
	what := "the default branch has changed more files than GitHub lists since the pull request's base, so the gate cannot tell whether one the pull request changes is among them"
	if file != "" {
		what = "the default branch has changed `" + inline(file) + "`, which the pull request changes too"
	}
	when := " It has not been rebuilt for a day."
	if fix {
		when = " It is a security fix. Dependabot rebuilds most such pull requests by itself within minutes."
	}
	return message(cfg, number, " waits: "+what+", so the gate did not ask GitHub to merge."+when+
		" To have Dependabot rebuild it, comment `@dependabot rebase` on the pull request; or merge by hand."+runRef(cfg))
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

// runRef ends a notification that names this run only as where to look.
func runRef(cfg Config) string {
	if cfg.RunURL == "" {
		return ""
	}
	return " The run: " + cfg.RunURL
}

// notifyOnce sends m unless sent, a list the gate's comment keeps, has
// head already, and adds head once m is delivered. A notification that
// failed is an error and is not remembered: the next scheduled run sends
// it (Schedule, Tell).
//
// With notifications turned off there is nobody to tell, and the head
// counts as told. Left off the list, it would read as a notification
// that failed, and every scheduled run would come back for it.
func notifyOnce(ctx context.Context, cfg Config, sent *[]string, head string, m Message) error {
	if slices.Contains(*sent, head) {
		return nil
	}
	if cfg.Notifier != nil {
		if err := cfg.Notifier.Notify(ctx, m); err != nil {
			return fmt.Errorf("land: notify: %w", err)
		}
	}
	if *sent = append(*sent, head); len(*sent) > maxNotified {
		*sent = (*sent)[len(*sent)-maxNotified:]
	}
	return nil
}

// untold returns the list of notified heads that should have the marker's
// head for its outcome and does not: a decision the owner is told about
// (a person's, a merge GitHub refused) or a run that failed. owed is
// false for an outcome nobody is told about and for a head that was told.
func (m *marker) untold() (sent *[]string, owed bool) {
	switch m.Outcome {
	case ActionPerson, ActionRefused:
		sent = &m.Notified
	case ActionFailed:
		sent = &m.NotifiedFailed
	default:
		return nil, false
	}
	return sent, !slices.Contains(*sent, m.Head)
}

// Tell sends the notification the gate's comment on a pull request owes
// for its head: the one a run could not deliver when it wrote the comment
// (spec section 11, amendment 67). It decides nothing and changes no
// status. The message is a fixed sentence that points at the comment,
// because the marker keeps the outcome and not the reason. Once it is
// delivered the marker line is rewritten to remember it, and the rest of
// the comment stays as it is. A pull request that is closed, has a newer
// head than the comment, or was told about meanwhile is left alone.
func Tell(ctx context.Context, cfg Config, number int) error {
	if err := cfg.check(); err != nil {
		return err
	}
	pr, err := getPull(ctx, cfg, number)
	if err != nil || pr.State != "open" {
		return err
	}
	c, err := findComment(ctx, cfg, number)
	if err != nil || c == nil {
		return err
	}
	mk, ok := parseMarker(c.Body)
	if !ok || mk.Head != pr.Head.SHA {
		return nil
	}
	sent, owed := mk.untold()
	if !owed {
		return nil
	}
	what := " needs a person."
	if mk.Outcome == ActionFailed {
		what = ": the gate's run failed before it could decide."
	}
	if err := notifyOnce(ctx, cfg, sent, mk.Head, message(cfg, number, what+" See the gate's comment on the pull request. An earlier notification about this could not be sent.")); err != nil {
		return err
	}
	return remark(ctx, cfg, c, mk)
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
			// The status says enough; the body is drained and not kept
			// (a failed drain costs only the connection's reuse).
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
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

package gather

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/gh"
)

// pull is what the fetch job asks GitHub about the pull request itself,
// as opposed to what the pull request changes.
type pull struct {
	// base holds when the pull request's base is the repository's default
	// branch. It is the part of Identity that classify does not establish;
	// Fetch makes Identity from the two.
	base allow.Fact
	// checks is the ChecksConfigured fact: an active rule on the default
	// branch requires at least one status check.
	checks allow.Fact
	// opened is when GitHub created the pull request.
	opened allow.TimeFact
}

// branchRE is the shape of a default branch name the gate puts in a
// request path. A name outside it ("release/1.x") is not asked about, and
// ChecksConfigured stays not gathered.
var branchRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// askPull reads the pull request and the default branch's rules. repo and
// number are classify's and were checked by the caller.
//
// Each fact comes back in the state that says what happened (see package
// facts): gathered, unavailable when GitHub was asked and did not answer,
// or without a Source and with the reason in Value when the answer was
// not one to build on. The error is the context's.
//
// Whether the pull request is still open at the classified head is not
// asked again. A head that moved while this job ran is another run's to
// answer for, not a fault of the pull request's identity, and it cannot
// merge here: publish merges the one commit the facts file names.
func askPull(ctx context.Context, c *gh.Client, repo string, number int) (pull, error) {
	source := fmt.Sprintf("GitHub: repos/%s/pulls/%d", repo, number)
	var answer struct {
		CreatedAt time.Time `json:"created_at"`
		Base      struct {
			Ref  string `json:"ref"`
			Repo *struct {
				FullName      string `json:"full_name"`
				DefaultBranch string `json:"default_branch"`
			} `json:"repo"`
		} `json:"base"`
	}
	err := c.Get(ctx, fmt.Sprintf("repos/%s/pulls/%d", repo, number), &answer)
	switch {
	case ctx.Err() != nil:
		return pull{}, ctx.Err()
	case gh.Unavailable(err):
		// Everything here hangs on this one answer, so all of it waits.
		const why = "the pull request could not be read: GitHub did not answer"
		return pull{
			base:   allow.Unavailable(why, source),
			checks: allow.Unavailable(why+", so the default branch is not known", source),
			opened: allow.UnavailableTime(why, source),
		}, nil
	case err != nil:
		why := notRead("the pull request", err)
		return pull{
			base:   allow.Fact{Value: why},
			checks: allow.Fact{Value: "not asked: " + why},
			opened: allow.TimeFact{Value: why},
		}, nil
	}

	var p pull
	if answer.CreatedAt.IsZero() {
		p.opened = allow.TimeFact{Value: "the pull request has no created_at"}
	} else {
		p.opened = allow.At(answer.CreatedAt, source+" created_at")
	}

	base := answer.Base.Repo
	switch {
	case base == nil || !strings.EqualFold(base.FullName, repo) || base.DefaultBranch == "":
		p.base = allow.Fact{Value: "GitHub's answer does not name this repository's default branch"}
		p.checks = allow.Fact{Value: "not asked: the default branch is not known"}
		return p, nil
	case answer.Base.Ref != base.DefaultBranch:
		p.base = allow.No("the base branch is not the default branch", source)
		p.checks = allow.Fact{Value: "not asked: the base branch is not the default branch"}
		return p, nil
	}
	p.base = allow.Yes("the base branch is the default branch", source)

	p.checks, err = askChecks(ctx, c, repo, base.DefaultBranch)
	return p, err
}

// askChecks is the ChecksConfigured fact. GitHub's rules/branches answer
// lists every active rule that applies to the branch, whichever ruleset
// it comes from, and leaves out rulesets that are disabled or only
// evaluated. Classic branch protection is not a rule and does not count:
// the spec names this source.
func askChecks(ctx context.Context, c *gh.Client, repo, branch string) (allow.Fact, error) {
	if !branchRE.MatchString(branch) || strings.Contains(branch, "..") {
		return allow.Fact{Value: "not asked: the default branch's name is not one the gate puts in a request"}, nil
	}
	source := fmt.Sprintf("GitHub: repos/%s/rules/branches/%s", repo, branch)
	type rule struct {
		Type       string `json:"type"`
		Parameters struct {
			RequiredStatusChecks []struct {
				Context string `json:"context"`
			} `json:"required_status_checks"`
		} `json:"parameters"`
	}
	rules, err := gh.List[rule](ctx, c, fmt.Sprintf("repos/%s/rules/branches/%s", repo, branch))
	switch {
	case ctx.Err() != nil:
		return allow.Fact{}, ctx.Err()
	case gh.Unavailable(err):
		return allow.Unavailable("the default branch's rules could not be read: GitHub did not answer", source), nil
	case err != nil:
		return allow.Fact{Value: notRead("the default branch's rules", err)}, nil
	}
	required := 0
	for _, r := range rules {
		if r.Type == "required_status_checks" {
			required += len(r.Parameters.RequiredStatusChecks)
		}
	}
	if required == 0 {
		return allow.No("no active rule on the default branch requires a status check", source), nil
	}
	return allow.Yes(fmt.Sprintf("%d required status checks", required), source), nil
}

// notRead words an answer from GitHub that is not one to build on: an
// error status that asking again would not change, or a body that could
// not be decoded.
func notRead(what string, err error) string {
	if code := gh.StatusCode(err); code != 0 {
		return fmt.Sprintf("%s could not be read (HTTP %d)", what, code)
	}
	return what + " could not be read: GitHub's answer was not understood"
}

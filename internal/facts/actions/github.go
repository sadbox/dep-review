package actions

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/facts"
	"github.com/sadbox/dep-review/internal/gh"
)

// This file asks GitHub. Every path is built from tokens the shapes in
// shape.go validated (owner/repo, vX.Y.Z, 40 hex) or from a value of an
// API answer that is checked here before it goes into a path.

// lookup is how one question to GitHub ended.
type lookup int

const (
	// failed: GitHub answered, and the answer is neither the thing asked
	// for nor a 404 (a 403 that is not a rate limit, a body that is not
	// what the API documents). Asking again would get the same: person.
	failed lookup = iota
	// found: a 2xx answer.
	found
	// missing: a 404. For a public action that is an answer: the tag, the
	// release, the branch or the repository is not there.
	missing
	// unreachable: GitHub was asked and did not answer (a server error, a
	// rate limit, the network), after the client's own retries. Asking
	// again may tell: a wait.
	unreachable
)

// answer is the outcome of one GET.
type answer struct {
	state lookup
	// status is the HTTP status of a failed lookup, 0 when there was none
	// (a transport error). It is only shown.
	status int
}

// unanswered is the fact for a failed or unreachable lookup: never
// gathered, or unavailable. Its Value never includes the error text,
// which can carry GitHub's own message.
func (a answer) unanswered(what, source string) allow.Fact {
	why := "GitHub's answer could not be read"
	switch {
	case a.status != 0:
		why = fmt.Sprintf("GitHub answered HTTP %d", a.status)
	case a.state == unreachable:
		why = "GitHub did not answer"
	}
	return facts.Unanswered(what+": "+why, source, a.state == unreachable)
}

// get asks one question. The error is non-nil only when the context is
// done: then the run itself is over and there is no result to report.
// Every other failure is an answer in the failed or the unreachable
// state; gh.Unavailable tells the two apart.
func get(ctx context.Context, c *gh.Client, path string, v any) (answer, error) {
	err := c.Get(ctx, path, v)
	switch {
	case err == nil:
		return answer{state: found}, nil
	case ctx.Err() != nil:
		return answer{}, fmt.Errorf("actions: GET %s: %w", path, ctx.Err())
	case errors.Is(err, gh.ErrNotFound):
		return answer{state: missing, status: 404}, nil
	case gh.Unavailable(err):
		return answer{state: unreachable, status: gh.StatusCode(err)}, nil
	}
	return answer{state: failed, status: gh.StatusCode(err)}, nil
}

// repoAnswer is GET repos/{owner}/{repo}.
type repoAnswer struct {
	answer
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	Owner         struct {
		ID int64 `json:"id"`
	} `json:"owner"`
}

func getRepo(ctx context.Context, c *gh.Client, name string) (repoAnswer, error) {
	var r repoAnswer
	a, err := get(ctx, c, "repos/"+name, &r)
	r.answer = a
	return r, err
}

// gitObject is the "object" of a ref or of an annotated tag.
type gitObject struct {
	Type string `json:"type"`
	SHA  string `json:"sha"`
}

// tagAnswer is what a tag resolves to.
type tagAnswer struct {
	answer
	// commit is set when the tag exists and leads to a commit.
	commit string
	// problem is set when the tag exists and does not lead to a commit
	// the gate can follow.
	problem string
}

// maxTagHops is how many annotated tag objects are followed. One is
// normal (an annotated tag of a commit); a tag of a tag is legal git and
// rare.
const maxTagHops = 3

// resolveTag follows refs/tags/<tag> to a commit: directly for a
// lightweight tag, through git/tags for an annotated one.
func resolveTag(ctx context.Context, c *gh.Client, name, tag string) (tagAnswer, error) {
	var ref struct {
		Ref    string    `json:"ref"`
		Object gitObject `json:"object"`
	}
	a, err := get(ctx, c, "repos/"+name+"/git/ref/tags/"+tag, &ref)
	t := tagAnswer{answer: a}
	if err != nil || a.state != found {
		return t, err
	}
	// git/ref answers for the exact ref only (git/ref/tags/v7.1 is a 404
	// when only v7.1.0 exists). Checked all the same: the tag is the
	// thing being bound.
	if ref.Ref != "refs/tags/"+tag {
		t.problem = "GitHub answered with another ref than refs/tags/" + tag
		return t, nil
	}
	obj := ref.Object
	for hops := 0; obj.Type == "tag"; hops++ {
		if hops == maxTagHops {
			t.problem = fmt.Sprintf("tag %s is more than %d annotated tags deep", tag, maxTagHops)
			return t, nil
		}
		if !shaRe.MatchString(obj.SHA) {
			t.problem = "tag " + tag + " points at an object with an unreadable ID"
			return t, nil
		}
		var next struct {
			Object gitObject `json:"object"`
		}
		a, err := get(ctx, c, "repos/"+name+"/git/tags/"+obj.SHA, &next)
		if err != nil {
			return t, err
		}
		if a.state != found {
			// The ref exists and its tag object could not be read: the
			// tag's commit is unknown either way, a 404 included. It is
			// worth asking again only when GitHub did not answer.
			if t.answer = a; a.state == missing {
				t.answer.state = failed
			}
			return t, nil
		}
		obj = next.Object
	}
	if obj.Type != "commit" || !shaRe.MatchString(obj.SHA) {
		t.problem = "tag " + tag + " does not point at a commit"
		return t, nil
	}
	t.commit = obj.SHA
	return t, nil
}

// compareAnswer is GET repos/{owner}/{repo}/compare/{base}...{head}:
// GitHub's own evaluation of how head relates to base.
type compareAnswer struct {
	answer
	// Status is "ahead", "behind", "identical" or "diverged".
	Status   string `json:"status"`
	AheadBy  int    `json:"ahead_by"`
	BehindBy int    `json:"behind_by"`
}

// compare asks how head relates to base. per_page=1 keeps the list of
// commits out of the answer; the counts do not depend on it.
func compare(ctx context.Context, c *gh.Client, name, base, head string) (compareAnswer, error) {
	var cmp compareAnswer
	a, err := get(ctx, c, "repos/"+name+"/compare/"+base+"..."+head+"?per_page=1", &cmp)
	cmp.answer = a
	return cmp, err
}

// isAhead reports whether head descends from base and is not base: head
// is ahead and nothing on base's side is missing from it.
func (c compareAnswer) isAhead() bool {
	return c.state == found && c.Status == "ahead" && c.AheadBy > 0 && c.BehindBy == 0
}

// holds reports whether the base of the comparison, a branch, contains
// the head, a commit: the commit is then behind the branch tip, or is it.
func (c compareAnswer) holds() bool {
	return c.state == found && (c.Status == "behind" || c.Status == "identical") && c.AheadBy == 0
}

// branchNameRe is what a default branch's name must look like before it
// goes into a request path: it comes from an API answer. A name with a
// slash or with ".." (which the compare path uses as its separator) is
// not put in a request, and the branch then counts as not holding the
// commit.
var branchNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

func plainBranch(name string) bool {
	return branchNameRe.MatchString(name) && !strings.Contains(name, "..")
}

// onBranch is the part of NoRegress that says the new commit is on a
// branch releases are cut from: the repository's default branch, or
// failing that releases/v<major>, the branch actions/checkout and others
// cut an older major's releases from. Those two names are the whole
// search: no branch list is read.
//
// This is the check that tells a commit of the repository from a commit
// that only a fork has. GitHub serves a fork's commits through the parent
// repository, and compare/<old>...<new> answers "ahead" for one that
// descends from the old pin; only a comparison with a branch shows that
// no branch of the repository holds it.
func onBranch(ctx context.Context, c *gh.Client, name string, repo repoAnswer, releaseBranch, commit string) (allow.Fact, error) {
	source := "GitHub: repos/" + name + "/compare"
	switch repo.state {
	case failed, unreachable:
		return repo.unanswered("the default branch is unknown", source), nil
	case missing:
		return allow.No("the repository was not found", source), nil
	}
	def := repo.DefaultBranch
	if !plainBranch(def) {
		return allow.No("the default branch has a name the gate does not put in a request", source), nil
	}
	onDefault, err := compare(ctx, c, name, def, commit)
	if err != nil {
		return allow.Fact{}, err
	}
	if onDefault.holds() {
		return allow.Yes("on branch "+def, source), nil
	}
	onRelease, err := compare(ctx, c, name, releaseBranch, commit)
	if err != nil {
		return allow.Fact{}, err
	}
	if onRelease.holds() {
		return allow.Yes("on branch "+releaseBranch, source), nil
	}
	// No branch holds it as far as GitHub answered. An answer that could
	// not be read comes before one that did not arrive: waiting mends
	// only the second.
	for _, state := range []lookup{failed, unreachable} {
		if onDefault.state == state {
			return onDefault.unanswered("the comparison with "+def+" failed", source), nil
		}
		if onRelease.state == state {
			return onRelease.unanswered("the comparison with "+releaseBranch+" failed", source), nil
		}
	}
	return allow.No("the commit is not reachable from "+def+" or "+releaseBranch, source), nil
}

// releaseAnswer is GET repos/{owner}/{repo}/releases/tags/{tag}.
type releaseAnswer struct {
	answer
	TagName    string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	// Immutable: GitHub will not let the release or its tag be changed or
	// published again. Absent on an API that does not know the field,
	// which reads as false.
	Immutable   bool   `json:"immutable"`
	PublishedAt string `json:"published_at"`
}

func getRelease(ctx context.Context, c *gh.Client, name, tag string) (releaseAnswer, error) {
	var r releaseAnswer
	a, err := get(ctx, c, "repos/"+name+"/releases/tags/"+tag, &r)
	r.answer = a
	return r, err
}

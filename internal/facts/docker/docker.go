// Package docker gathers the facts for Dependabot's docker ecosystem: a
// base image moved to another tag or digest in a Dockerfile
// (docs/v0.2-spec.md, sections 3, 4 and 6).
//
// An image's content is opaque to the gate: nothing here downloads or
// inspects it, and no model reads it (Read is not-applicable). What can
// grant a merge is therefore only who publishes the image, that the pin
// is what the registry serves under that tag now, and for how long:
//
//   - Shape: only files named Dockerfile* changed, and in them only the
//     tag and digest of FROM lines of one anchored shape (shape.go).
//     There is no Dockerfile parser.
//   - Known: the image is on the owner's list, and only that (spec
//     section 11, amendment 3). For the other ecosystems being a
//     dependency at the base commit is enough to be known; for an image
//     that nothing reads it is not.
//   - Increase and Major: a comparator for dotted numeric tags with an
//     identical suffix; the same tag with a new digest is an increase
//     (tag.go).
//   - Bound, Clean and FirstSeen: the registry, asked now (registry.go).
//     Clean is "the registry serves this digest under this tag", and on
//     GCR also "and does not mark it deprecated". Nothing else exists to
//     ask: no advisory source covers images, so SecurityFix is a
//     gathered "no" and Input.Advisories is not called, and NoRegress
//     holds with nothing to compare.
//
// Only docker.io and gcr.io are asked. An image anywhere else has no
// Bound and no FirstSeen, which is person.
//
// Two outcomes are a wait and not a person (spec section 11, amendments 1
// and 2). A registry that could not be asked after a few tries leaves the
// facts it is the source of unavailable, and the next evaluation asks
// again. And a tag that resolves to another digest than the pinned one
// has moved on since Dependabot wrote the pin: the update is Superseded,
// and Dependabot refreshes the digest itself.
package docker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/facts"
)

// listSource is the Source of the facts read from the policy list.
const listSource = `"listed.docker" in the policy`

// Gatherer is the Docker fact gatherer. The zero value is ready to use.
type Gatherer struct {
	// sleep waits between tries of one registry request. Nil means a
	// real wait; tests replace it.
	sleep func(ctx context.Context, d time.Duration) error
}

var _ facts.Gatherer = (*Gatherer)(nil)

// New returns the Docker fact gatherer.
func New() *Gatherer { return &Gatherer{} }

// Gather reads the change set from the Dockerfiles at base and head and
// asks the registries about each image the pull request moves.
//
// When Shape does not hold nothing is asked and Updates is empty. A
// registry that could not be asked leaves the facts it is the source of
// unavailable. An error means there is no HTTP client to ask with, or the
// context ended.
func (g *Gatherer) Gather(ctx context.Context, in facts.Input) (facts.Result, error) {
	moved, res := changes(in.Files, in.Policy)
	if !res.Shape.OK {
		return res, nil
	}
	if in.HTTP == nil {
		return facts.Result{}, errors.New("docker: no HTTP client to ask the registries with")
	}

	// A copy, so the caller's client is left as it was. No redirect is
	// followed: none of the endpoints asked here sends one, and following
	// one would let an answer choose the next host.
	client := *in.HTTP
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	a := &asker{
		client:    &client,
		sleep:     g.sleep,
		hubTokens: map[string]string{},
		gcrLists:  map[string]gcrList{},
	}
	if a.sleep == nil {
		a.sleep = sleepCtx
	}

	for i, c := range moved {
		f, err := a.ask(ctx, c)
		if err != nil {
			return facts.Result{}, fmt.Errorf("docker: %s: %w", c.image.Name(), err)
		}
		u := &res.Updates[i]
		u.Bound, u.Clean, u.FirstSeen, u.Superseded = f.bound, f.clean, f.firstSeen, f.superseded
	}
	return res, nil
}

// Changes is the half of Gather that reads nothing but the pull request's
// files: the Shape fact, and every image the pull request moves with the
// facts no registry is ever asked for (Known, Listed, NewName, Increase,
// Major, NoRegress and SecurityFix). Bound, Clean, FirstSeen and
// Superseded are left unset. Gather starts from the same reading; the
// replay command runs this half alone.
func Changes(files []facts.File, policy allow.Policy) facts.Result {
	_, res := changes(files, policy)
	return res
}

// changes is Changes, with the changes its updates were made from: one
// update for each change, in the same order. When Shape does not hold
// there are none.
func changes(files []facts.File, policy allow.Policy) ([]change, facts.Result) {
	lines, shape := readShape(files)
	res := facts.Result{Shape: shape}
	moved := distinct(lines)
	for _, c := range moved {
		res.Updates = append(res.Updates, fileFacts(c, policy))
	}
	return moved, res
}

// fileFacts is one change with the facts no registry is asked for.
func fileFacts(c change, policy allow.Policy) allow.UpdateFacts {
	name := c.image.Name()
	u := allow.UpdateFacts{
		Name: name,
		From: version(c.fromTag, c.fromDigest),
		To:   version(c.toTag, c.toDigest),
		// Shape holds, so the line named this image at base too.
		NewName: allow.No("the image is in the Dockerfile at the base commit", shapeSource),
		// There is no install script and no artifact to compare, and
		// image attestations are not read. Said in the value, so the
		// comment does not suggest a check that was not made.
		NoRegress: allow.Yes("nothing to compare: a base image has no install script, and its attestations are not read", "not applicable to Docker"),
		// The Advisory Database has no container image ecosystem, and
		// with nothing read there is no fast path to take anyway.
		SecurityFix: allow.No("no advisory source covers container images", "not applicable to Docker"),
		// Read is not set here: that nothing of an image is read is the
		// deciding job's to say (allow.ReadNotApplicable, from the
		// ecosystem), like every other read state.
	}

	if allow.Listed(policy, allow.Docker, name) {
		u.Listed = allow.Yes(name+" is on the list", listSource)
		u.Known = allow.Yes("listed image", listSource)
	} else {
		u.Listed = allow.No(name+" is not on the list", listSource)
		u.Known = allow.No("the image is not on the list; being in the Dockerfile already does not make an image known, because nothing in it is read", listSource)
	}

	u.Increase, u.Major = compareTags(c.fromTag, c.toTag)
	return u
}

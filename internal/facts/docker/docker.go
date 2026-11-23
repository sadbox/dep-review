// Package docker gathers the facts for Dependabot's docker ecosystem: a
// base image moved to another tag or digest in a Dockerfile. An image's
// content is opaque to the gate: nothing here downloads or inspects it,
// and no model reads it. What can grant a merge is only who publishes the
// image (Known is the owner's list alone, spec section 11, amendment 3),
// that the pin is what the registry serves under that tag now and for how
// long (registry.go), and the line shape (shape.go). A tag that resolves to
// another digest has moved on since Dependabot wrote the pin, which is a
// wait (amendment 2).
package docker

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/facts"
)

// listSource is the Source of the facts read from the policy list.
const listSource = `"listed.docker" in the policy`

// Gatherer is the Docker fact gatherer.
type Gatherer struct{}

// New returns the Docker fact gatherer.
func New() *Gatherer { return &Gatherer{} }

// Gather implements facts.Gatherer. When Shape does not hold nothing is
// asked and Updates is empty.
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
	a := &asker{client: &client, hubTokens: map[string]string{}, gcrLists: map[string]gcrList{}}

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
// files: Shape, and every image the pull request moves with the facts no
// registry is asked for (Known, Listed, NewName, Increase, Major,
// NoRegress and SecurityFix). The replay command runs this half alone.
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

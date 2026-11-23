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
//   - Known: the image is on the owner's list. For the other ecosystems
//     being a dependency at the base commit is enough to be known; for an
//     image that nothing reads it is not.
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
// Bound and no FirstSeen, which is person. So has an image whose registry
// could not be asked after a few tries: a gatherer has no way to say
// "wait and ask again", and a source that could not be asked is a fact
// not established for every gatherer.
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
// not established. An error means there is no HTTP client to ask with, or
// the context ended.
func (g *Gatherer) Gather(ctx context.Context, in facts.Input) (facts.Result, error) {
	changes, shape := readShape(in.Files)
	res := facts.Result{Shape: shape}
	if !shape.OK {
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

	for _, c := range distinct(changes) {
		u, err := a.update(ctx, c, in.Policy)
		if err != nil {
			return facts.Result{}, fmt.Errorf("docker: %s: %w", c.image.Name(), err)
		}
		res.Updates = append(res.Updates, u)
	}
	return res, nil
}

// update gathers every fact of one change.
func (a *asker) update(ctx context.Context, c change, policy allow.Policy) (allow.UpdateFacts, error) {
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
		Read:        allow.ReadNotApplicable,
	}

	if allow.Listed(policy, allow.Docker, name) {
		u.Listed = allow.Yes(name+" is on the list", listSource)
		u.Known = allow.Yes("listed image", listSource)
	} else {
		u.Listed = allow.No(name+" is not on the list", listSource)
		u.Known = allow.No("the image is not on the list; being in the Dockerfile already does not make an image known, because nothing in it is read", listSource)
	}

	u.Increase, u.Major = compareTags(c.fromTag, c.toTag)

	var err error
	u.Bound, u.Clean, u.FirstSeen, err = a.ask(ctx, c)
	if err != nil {
		return allow.UpdateFacts{}, err
	}
	return u, nil
}

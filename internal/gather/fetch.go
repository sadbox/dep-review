package gather

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sadbox/dep-review/internal/advisory"
	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/config"
	"github.com/sadbox/dep-review/internal/facts"
	"github.com/sadbox/dep-review/internal/gh"
	"github.com/sadbox/dep-review/internal/model"
	"github.com/sadbox/dep-review/internal/veto"
	"github.com/sadbox/dep-review/internal/wire"
)

// Fetch is the fetch job for one pull request: everything it is given.
// It holds no secret beyond the job's read-only GitHub token.
type Fetch struct {
	// Class is classify's answer for the pull request. Nothing Dependabot
	// declared is taken from it: the updates come from the manifests.
	Class model.Classification
	// Changes is the change set, from ReadChanges.
	Changes Changes
	// Config is the gate's configuration as config.Load resolved it from
	// the default branch's file. It must never come from the pull
	// request's head.
	Config config.Config
	// HTTP is the client the gatherer asks registries and indexes with.
	HTTP *http.Client
	// GitHub is the REST client with the job's read-only token.
	GitHub *gh.Client
	// Advisories answers the gatherer's questions about advisories.
	Advisories advisory.Checker
	// Gatherers holds each ecosystem's gatherer by the gate's name for
	// the ecosystem; see Gatherers.
	Gatherers map[string]facts.Gatherer
	// Preparer prepares what the model reads; see NewPreparer.
	Preparer artifact.Preparer
	// Now is the clock. Nil means time.Now.
	Now func() time.Time
	// Logf, when set, receives one line for each read that could not be
	// prepared, with the error. Error text is quoted: it can carry what a
	// publisher wrote.
	Logf func(format string, args ...any)
}

// The sources of the facts Run establishes itself.
const (
	classifySource = "classify"
	changesSource  = "git: the paths that differ between the merge base and the head"
)

// Run gathers the pull request's facts, prepares what the model is to
// read, and writes the facts file and the chunk files into out, which it
// creates. out must not hold a chunk directory already. The facts are
// returned as they were written.
//
// What is a property of the pull request or of the moment has a place in
// the file and does not make Run fail: a pull request that is not shown
// to be Dependabot's alone, an ecosystem without a rule, GitHub not
// answering, a change set too large to read, a read that could not be
// prepared. An error means there is no result: the classification or the
// change set is not usable, the gatherer failed (facts.Gatherer says when
// it may), the context ended, or out could not be written.
func (f Fetch) Run(ctx context.Context, out string) (wire.Facts, error) {
	if f.Now == nil {
		f.Now = time.Now
	}
	c := f.Class
	if !gh.ValidRepo(c.Repo) || c.PR < 1 || !gh.ValidSHA(c.HeadSHA) {
		return wire.Facts{}, errors.New("gather: the classification does not name a repository, a pull request and a head commit")
	}
	eco, hasRule := ecosystem(c.Ecosystem)
	file := wire.Facts{
		Version:     wire.Version,
		PullRequest: wire.PullRequest{Repo: c.Repo, Number: c.PR, Head: c.HeadSHA},
		Config:      f.Config.Fingerprint(),
		GatheredAt:  f.Now(),
		Facts:       wire.PRFacts{Ecosystem: eco},
	}
	// classified is classify's half of Identity. The other half, that the
	// base is the default branch, is GitHub's to say, and the fact is made
	// from the two together in gather alone: a pull request nothing is
	// gathered for never carries an Identity that holds.
	var classified allow.Fact
	switch c.Kind {
	case model.KindDependabot:
		classified = allow.Yes(c.Reason, classifySource)
	case model.KindDependabotUnverified:
		classified = allow.No(c.Reason, classifySource)
	case model.KindPending:
		// GitHub's record of who pushed the branch has not reached the
		// head yet, or GitHub did not answer for a part of the proof. That
		// is a source that did not answer, not an answer (spec section 11,
		// amendments 1 and 51): gathering goes on and the pull request
		// waits.
		classified = allow.Unavailable(c.Reason, classifySource)
		if c.Ecosystem == "" {
			// classify names the branch's ecosystem for an unfinished proof.
			// Without one nothing could be gathered, and the facts would
			// call a pull request that waits one whose ecosystem has no
			// rule.
			return wire.Facts{}, errors.New("gather: the classification is pending and names no ecosystem")
		}
	default:
		// The gate does nothing at all for the other kinds; a workflow
		// that runs this job for one of them is wrong.
		return wire.Facts{}, fmt.Errorf("gather: classification kind %q: the fetch job is for a Dependabot pull request", c.Kind)
	}

	// Fresh, so that the directory holds this run's chunks and nothing
	// else: wire.VerifyChunks refuses a directory with one file too many.
	chunks := filepath.Join(out, wire.ChunksDir)
	if err := os.MkdirAll(out, 0o755); err != nil {
		return wire.Facts{}, err
	}
	if err := os.Mkdir(chunks, 0o755); err != nil {
		return wire.Facts{}, fmt.Errorf("gather: the output directory must not hold chunks already: %w", err)
	}

	why := ""
	switch {
	case classified.Gathered() && !classified.OK:
		why = "classify did not show the pull request to be Dependabot's alone"
		file.Facts.Identity = classified
	case !hasRule:
		why = "the ecosystem has no rule"
		file.Facts.Identity = allow.Fact{Value: "classify: " + c.Reason + "; the base branch was not asked about: " + why}
	}
	if why != "" {
		file.Facts.Shape = allow.Fact{Value: "not gathered: " + why}
		file.Facts.ChecksConfigured = allow.Fact{Value: "not asked: " + why}
	} else if err := f.gather(ctx, chunks, classified, &file); err != nil {
		return wire.Facts{}, err
	}

	b, err := wire.EncodeFacts(file)
	if err != nil {
		// The reads are what can still be too much here. A file that is
		// not written would leave the pull request without an answer, so
		// the answer is a file that sends it to a person.
		f.logf("gather: the facts do not fit the facts file: %q", err.Error())
		if err := tooMuch(&file, chunks); err != nil {
			return wire.Facts{}, err
		}
		if b, err = wire.EncodeFacts(file); err != nil {
			return wire.Facts{}, err
		}
	}
	// Last: a directory with a facts file is a finished one.
	if err := os.WriteFile(filepath.Join(out, wire.FactsFile), b, 0o644); err != nil {
		return wire.Facts{}, err
	}
	return file, nil
}

// gather fills in everything about a Dependabot pull request in an
// ecosystem that has a rule. classified is classify's half of Identity.
func (f Fetch) gather(ctx context.Context, chunks string, classified allow.Fact, file *wire.Facts) error {
	if f.GitHub == nil || f.Preparer == nil {
		return errors.New("gather: no GitHub client or no artifact reader")
	}
	pr := &file.Facts

	asked, err := askPull(ctx, f.GitHub, file.PullRequest.Repo, file.PullRequest.Number)
	if err != nil {
		return err
	}
	pr.Identity = classified.And(asked.base)
	pr.ChecksConfigured = asked.checks
	pr.Opened = asked.opened
	// Only an answer stops the gathering. With GitHub merely not
	// answering, a Shape left ungathered here would be person, where the
	// outage alone is a wait.
	if pr.Identity.Gathered() && !pr.Identity.OK {
		pr.Shape = allow.Fact{Value: "not gathered: the pull request's base is not the default branch"}
		return nil
	}

	if f.Changes.Head != file.PullRequest.Head || !gh.ValidSHA(f.Changes.Base) {
		return errors.New("gather: the change set is not between a merge base and the classified head")
	}
	if f.Changes.Refused != "" {
		pr.Shape = allow.No(f.Changes.Refused, changesSource)
		return nil
	}

	gatherer := f.Gatherers[pr.Ecosystem]
	if gatherer == nil {
		return fmt.Errorf("gather: no gatherer for %s", pr.Ecosystem)
	}
	res, err := gatherer.Gather(ctx, facts.Input{
		Repo:       file.PullRequest.Repo,
		Base:       f.Changes.Base,
		Head:       f.Changes.Head,
		Files:      f.Changes.Files,
		Policy:     f.Config.Policy(),
		HTTP:       f.HTTP,
		GitHub:     f.GitHub,
		Advisories: f.Advisories,
		Now:        f.Now,
	})
	if err != nil {
		return fmt.Errorf("gather: %s: %w", pr.Ecosystem, err)
	}
	pr.Shape = res.Shape
	if pr.Ecosystem == allow.NPM && len(res.NoRegressSoFar) != len(res.Updates) {
		return errors.New("gather: the npm gatherer did not say what the registry and the lock show of NoRegress for every update")
	}

	// An artifact belongs to the update with the same name and versions.
	type update struct{ name, from, to string }
	pairs := map[update]artifact.Pair{}
	for _, p := range res.Artifacts {
		pairs[update{p.Name, p.From, p.To}] = p
	}
	pr.Updates = make([]wire.Update, len(res.Updates))
	for i, u := range res.Updates {
		// FirstSeen stays what the gatherer made of the registry's clock.
		// Where that is no time, publish dates the pin itself (spec section
		// 11, amendment 38), and tells one pin from another by the hash
		// Bound was established for.
		pr.Updates[i] = wire.NewUpdate(u, wire.Read{Status: wire.Nothing})
		pr.Updates[i].Hash = pairs[update{u.Name, u.From, u.To}].New.Hash
	}
	// Before anything is downloaded: a change set of more updates than
	// the file carries is not prepared one read at a time first.
	if _, err := wire.EncodeFacts(*file); err != nil {
		f.logf("gather: the facts do not fit the facts file: %q", err.Error())
		return tooMuch(file, chunks)
	}

	// The same budget the review job's client is built with, so that a
	// read is prepared within what the reviewer accepts.
	lim := veto.FromConfig(f.Config).Limits()

	for i := range pr.Updates {
		u := &pr.Updates[i]
		if pr.Ecosystem == allow.Docker {
			u.Prepared.Detail = "nothing of an image is read"
			continue
		}
		// inspected is what the reader found in the artifacts themselves.
		var inspected allow.Fact
		pair, named := pairs[update{u.Name, u.From, u.To}]
		switch {
		case !pr.Shape.Holds():
			// The change set is not to be trusted, the outcome is person
			// already, and nothing it names is downloaded.
			u.Prepared.Detail = "the pull request's shape does not hold, so nothing it names was fetched"
		case !named:
			u.Prepared.Detail = "the gatherer named no artifact: the pin is not bound, or the old version has no hash to check it against"
		default:
			if u.Prepared, inspected, err = f.read(ctx, chunks, i, pair, lim); err != nil {
				return err
			}
		}
		if pr.Ecosystem == allow.NPM {
			// This is the only place an npm NoRegress is made (spec section
			// 11, amendment 21): from what the registry and the lock say
			// and what was found in the tarballs, so it holds only when
			// they were looked at.
			if inspected == (allow.Fact{}) {
				inspected = allow.Fact{Value: "the package.json and binding.gyp files in the tarballs were not looked at"}
			}
			u.NoRegress = res.NoRegressSoFar[i].And(inspected)
		}
	}
	return nil
}

// read prepares the read of update number i and writes its chunk files.
// A read that could not be prepared is not an error: it comes back in the
// status that says what becomes of the update. inspected is the reader's
// answer about the artifacts themselves, and unavailable when they could
// not be downloaded. The error is the context's, or a chunk file that
// could not be written.
func (f Fetch) read(ctx context.Context, chunks string, i int, pair artifact.Pair, lim artifact.Limits) (read wire.Read, inspected allow.Fact, err error) {
	prepared, err := f.prepare(ctx, pair, lim)
	switch {
	case ctx.Err() != nil:
		// The run is over. Whatever Prepare returned, nothing says the
		// update could not be read.
		return wire.Read{}, allow.Fact{}, ctx.Err()
	case err == nil && len(prepared.Chunks) == 0 && prepared.State == allow.ReadFull:
		// The reader found no file that changed, was added or was removed
		// (artifact.Prepared). No model is asked about nothing, and the
		// record says that this is why there is no verdict.
		const same = "the old and the new artifact hold the same files: there is nothing to read, and no model is asked"
		return wire.Read{Status: wire.Identical, Detail: same}, prepared.Inspected, nil
	case err == nil && len(prepared.Chunks) == 0:
		// Something changed, and none of it is text for the model. A read
		// nobody was asked about is not a read in part: the update is a
		// person's.
		const none = "nothing that changed is text the model is shown: every changed file is not text or did not fit, so no model was asked and nothing was read"
		return wire.Read{Status: wire.Refused, Detail: none}, prepared.Inspected, nil
	case err == nil:
		read = wire.Read{Status: wire.Prepared, Key: prepared.Key, State: prepared.State, Unread: prepared.Unread}
		for j, c := range prepared.Chunks {
			file := wire.NewChunkFile(i, j, c.Text)
			if err := os.WriteFile(filepath.Join(chunks, file.Name), []byte(c.Text), 0o644); err != nil {
				return wire.Read{}, allow.Fact{}, err
			}
			read.Chunks = append(read.Chunks, file)
		}
		return read, prepared.Inspected, nil
	}

	f.logf("gather: update %d (%q): no read was prepared: %q", i, pair.Name, err.Error())
	// The details are the gate's own sentences. The error's text can
	// quote a publisher and stays in the log.
	switch {
	case errors.Is(err, artifact.ErrUnavailable):
		const why = "the artifact could not be downloaded: its registry did not answer"
		return wire.Read{Status: wire.Unavailable, Detail: why}, allow.Unavailable(why, "the update's artifacts"), nil
	case errors.Is(err, artifact.ErrHashMismatch):
		read.Detail = "the downloaded artifact does not match the hash the pull request pins"
	case errors.Is(err, artifact.ErrUnsafeArchive):
		read.Detail = "the artifact's archive is not one the gate unpacks"
	case errors.Is(err, artifact.ErrBadRef):
		read.Detail = "the artifact's name, version or hash is not one the gate fetches"
	case errors.Is(err, artifact.ErrPathName):
		read.Detail = "a file that changed, was added or was removed has a path with characters other than letters, digits and ._/@+- ; " +
			"the gate writes no such path into the text it shows the model, so nothing was read"
	default:
		// An error without a name is never guessed into a wait
		// (internal/artifact). Failing the run for it would fail every
		// run the same way, so it is the update's, and a person's.
		read.Detail = "preparing the read failed in a way the gate has no name for; the fetch job's log has the error"
	}
	read.Status = wire.Refused
	return read, allow.Fact{}, nil
}

// prepare calls the reader and turns a panic into an error. The reader
// parses archives a publisher built; one that crashes it must cost that
// update its read, not the pull request its answer.
func (f Fetch) prepare(ctx context.Context, pair artifact.Pair, lim artifact.Limits) (prepared artifact.Prepared, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("the reader panicked: %v", r)
		}
	}()
	return f.Preparer.Prepare(ctx, pair, lim)
}

// tooMuch turns facts that internal/wire does not carry (more updates
// than a file holds, or more text about them) into facts it does: none of
// the updates, no chunk, and a Shape that says why and was never
// gathered. That is person, which is where a pull request of that size
// belongs.
func tooMuch(file *wire.Facts, chunks string) error {
	file.Facts.Updates = nil
	file.Facts.Shape = allow.Fact{Value: "not gathered: the pull request has more updates, or more to say about them, than the gate's facts file holds"}
	entries, err := os.ReadDir(chunks)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.Remove(filepath.Join(chunks, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func (f Fetch) logf(format string, args ...any) {
	if f.Logf != nil {
		f.Logf(format, args...)
	}
}

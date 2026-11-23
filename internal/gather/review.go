package gather

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/veto"
	"github.com/sadbox/dep-review/internal/wire"
)

// Review is the review job for one pull request. It needs nothing of
// GitHub: it reads a directory and writes a file.
type Review struct {
	// Reviewer asks the model. Nil means nobody is asked and only cached
	// verdicts are written, which is the scheduled job (spec section 8: no
	// model call on a schedule).
	Reviewer veto.Reviewer
	// Fingerprint is the reviewer's (veto.Config.Fingerprint). Every
	// verdict Run writes carries it, and a cached verdict counts only
	// under the same one (spec section 11, amendment 11).
	Fingerprint string
	// Cached is verdicts from earlier runs, of this pull request or of
	// any other: a verdict is about a read's content. One is reused when
	// its Key and Fingerprint are a prepared read's and this reviewer's
	// and it holds an answer of the model (Read full or partial, with or
	// without a veto). Anything else in the list is ignored.
	Cached []wire.Verdict
	// Logf, when set, receives one line for each read: reused, reviewed,
	// or why not. Error text is quoted.
	Logf func(format string, args ...any)
}

// Run reads the facts directory the fetch job wrote, gets a verdict for
// every prepared read, once for each content key, and writes the verdicts
// file into out, which it creates.
//
// The directory is believed only as far as internal/wire verified it;
// anything else is an error, before the reviewer sees a byte and with no
// verdicts file written. A chunk is bytes here: hashed and handed on,
// never parsed.
//
// A reviewer's error is recorded, not returned: veto.ErrUnusable as Read
// refused (person), any other as Read none (the pull request waits and
// the next run asks again). A verdict the verdicts file cannot carry is
// recorded as Read refused, never dropped: an objection must not turn
// into a wait. With no reviewer, or after the context ended, a read
// without a cached verdict gets no entry, which wire.Join reads as not
// reviewed.
//
// When the context ends the verdicts gathered so far are still written,
// and Run returns them with the context's error: the file is good, the
// review is incomplete. Every other error means no file.
func (r Review) Run(ctx context.Context, dir, out string) (wire.Verdicts, error) {
	// A fingerprint wire refuses would make every verdict unwritable.
	if !recordable(wire.Verdict{Key: r.Fingerprint, Fingerprint: r.Fingerprint, Read: allow.ReadNone}) {
		return wire.Verdicts{}, errors.New("gather: the reviewer's fingerprint is not a lower-case hex SHA-256")
	}
	// The fetch job's own file; wire.DecodeFacts refuses one over its size.
	b, err := os.ReadFile(filepath.Join(dir, wire.FactsFile))
	if err != nil {
		return wire.Verdicts{}, fmt.Errorf("gather: facts file: %w", err)
	}
	f, err := wire.DecodeFacts(b)
	if err != nil {
		return wire.Verdicts{}, err
	}
	chunks := filepath.Join(dir, wire.ChunksDir)
	if err := wire.VerifyChunks(chunks, f); err != nil {
		return wire.Verdicts{}, err
	}

	cached := map[string]wire.Verdict{}
	for _, v := range r.Cached {
		answered := v.Read == allow.ReadFull || v.Read == allow.ReadPartial
		if v.Fingerprint == r.Fingerprint && answered && recordable(v) {
			cached[v.Key] = v
		}
	}

	verdicts := wire.Verdicts{Version: wire.Version, Verdicts: []wire.Verdict{}}
	done := map[string]bool{}
	for i, u := range f.Facts.Updates {
		// Two updates with the same read have one verdict: the file holds
		// one entry for each key.
		if u.Prepared.Status != wire.Prepared || done[u.Prepared.Key] {
			continue
		}
		// The key is the facts file's and the fingerprint this reviewer's,
		// whatever a cache entry or the reviewer's answer carries.
		v := wire.Verdict{Key: u.Prepared.Key, Fingerprint: r.Fingerprint}
		if c, ok := cached[v.Key]; ok {
			v.Read, v.Veto = c.Read, c.Veto
			r.logf("gather: update %d (%q): cached verdict reused", i, u.Name)
		} else if r.Reviewer == nil || ctx.Err() != nil {
			r.logf("gather: update %d (%q): not reviewed", i, u.Name)
			continue
		} else if v.Read, v.Veto, err = r.review(ctx, chunks, f, i); err != nil {
			return wire.Verdicts{}, err
		}
		done[v.Key] = true
		verdicts.Verdicts = append(verdicts.Verdicts, v)
	}

	b, err = wire.EncodeVerdicts(verdicts)
	if err != nil {
		return wire.Verdicts{}, err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return wire.Verdicts{}, err
	}
	if err := os.WriteFile(filepath.Join(out, wire.VerdictsFile), b, 0o644); err != nil {
		return wire.Verdicts{}, err
	}
	return verdicts, ctx.Err()
}

// review puts the prepared read of update number i before the reviewer
// and returns what to record for it. The error is a chunk file that is
// no longer what wire.VerifyChunks saw.
func (r Review) review(ctx context.Context, chunks string, f wire.Facts, i int) (allow.ReadState, *allow.Veto, error) {
	u := f.Facts.Updates[i]
	// The read as internal/artifact prepared it, as far as the facts file
	// carries it: the two artifact references are not in the file, and
	// the reviewer does not use them.
	read := artifact.Prepared{
		Pair:   artifact.Pair{Ecosystem: f.Facts.Ecosystem, Name: u.Name, From: u.From, To: u.To},
		Unread: u.Prepared.Unread,
		State:  u.Prepared.State,
		Key:    u.Prepared.Key,
	}
	for j, c := range u.Prepared.Chunks {
		// Read again, so that what is sent is what the facts file lists
		// and not what was in the directory a moment ago.
		text, err := wire.ReadChunk(chunks, c)
		if err != nil {
			return "", nil, fmt.Errorf("gather: chunk %s: %w", c.Name, err)
		}
		read.Chunks = append(read.Chunks, artifact.Chunk{Index: j, Text: string(text)})
	}

	answer, err := r.Reviewer.Review(ctx, veto.Request{Read: read})
	switch {
	case errors.Is(err, veto.ErrUnusable):
		r.logf("gather: update %d (%q): the reviewer will not take the read: %q", i, u.Name, err.Error())
		return allow.ReadRefused, nil, nil
	case err != nil:
		r.logf("gather: update %d (%q): no verdict: %q", i, u.Name, err.Error())
		return allow.ReadNone, nil, nil
	}
	// Anything but a plain no_veto is an objection.
	var objection *allow.Veto
	if answer.Answer != veto.NoVeto {
		objection = &allow.Veto{Category: string(answer.Category), Quotes: answer.Quotes, Notes: answer.Notes}
	}
	if !recordable(wire.Verdict{Key: u.Prepared.Key, Fingerprint: r.Fingerprint, Read: answer.Read, Veto: objection}) {
		r.logf("gather: update %d (%q): the reviewer's verdict is not one the verdicts file carries", i, u.Name)
		return allow.ReadRefused, nil, nil
	}
	r.logf("gather: update %d (%q): reviewed: %q", i, u.Name, answer.Answer)
	return answer.Read, objection, nil
}

// recordable reports whether the verdicts file carries v: internal/wire
// checks a verdict when it is written, and one that fails there must not
// take the whole file with it.
func recordable(v wire.Verdict) bool {
	_, err := wire.EncodeVerdicts(wire.Verdicts{Version: wire.Version, Verdicts: []wire.Verdict{v}})
	return err == nil
}

func (r Review) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

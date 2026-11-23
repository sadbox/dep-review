package gather

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	// Fingerprint is the reviewer's (veto.Config.Fingerprint): the prompt,
	// the answer schema, the model and the effort it asks with. Every
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

// maxFactsBytes bounds how much of a facts file is read into memory
// before internal/wire looks at it. wire's own limit is lower and is the
// one that decides.
const maxFactsBytes = 64 << 20

// Run reads the facts directory the fetch job wrote, gets a verdict for
// every prepared read, and writes the verdicts file into out, which it
// creates.
//
// The directory is believed only as far as internal/wire verified it:
// the facts file must decode strictly, and the chunk directory must hold
// exactly the listed files with the listed hashes. Anything else is an
// error, before the reviewer sees a byte and with no verdicts file
// written. A chunk is bytes here: it is hashed and handed on, never
// parsed.
//
// What becomes of each prepared read, once for each content key:
//
//   - A cached verdict is reused, and the reviewer is not called.
//   - The reviewer's verdict is recorded: its Read, and its veto unless
//     the answer is no_veto.
//   - veto.ErrUnusable is recorded as Read refused, which is person.
//   - Any other error of the reviewer is recorded as Read none: there is
//     no answer, the pull request waits and the next run asks again.
//   - A verdict the verdicts file cannot carry (a veto without a proper
//     category, more quoted text than fits) is recorded as Read refused.
//     It is never dropped: an objection must not turn into a wait.
//   - With no reviewer, or after the context ended, a read without a
//     cached verdict gets no entry, which wire.Join reads as not reviewed.
//
// When the context ends the verdicts gathered so far are still written,
// and Run returns them with the context's error: the file is good, the
// review is incomplete. Every other error means no file.
func (r Review) Run(ctx context.Context, dir, out string) (wire.Verdicts, error) {
	// A fingerprint wire refuses would make every verdict unwritable.
	if !recordable(wire.Verdict{Key: r.Fingerprint, Fingerprint: r.Fingerprint, Read: allow.ReadNone}) {
		return wire.Verdicts{}, errors.New("gather: the reviewer's fingerprint is not a lower-case hex SHA-256")
	}
	b, err := readAtMost(filepath.Join(dir, wire.FactsFile), maxFactsBytes)
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
	// carries it. The two artifact references are not in the file and the
	// reviewer does not use them: the model is told the ecosystem, the
	// name and the versions.
	read := artifact.Prepared{
		Pair:   artifact.Pair{Ecosystem: f.Facts.Ecosystem, Name: u.Name, From: u.From, To: u.To},
		Unread: u.Prepared.Unread,
		State:  u.Prepared.State,
		Key:    u.Prepared.Key,
	}
	for j, c := range u.Prepared.Chunks {
		text, err := readChunk(chunks, c)
		if err != nil {
			return "", nil, fmt.Errorf("gather: chunk %s: %w", c.Name, err)
		}
		read.Chunks = append(read.Chunks, artifact.Chunk{Index: j, Text: text})
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

// readChunk returns one chunk file's bytes, as text for the request,
// after hashing them against what the facts file lists. wire.VerifyChunks
// has checked the directory as a whole; this ties the bytes that are
// sent, not the bytes that were there a moment ago, to the listed hash.
func readChunk(chunks string, c wire.ChunkFile) (string, error) {
	// os.Root: the name is the facts file's, and although its shape was
	// checked, it opens nothing outside the directory.
	root, err := os.OpenRoot(chunks)
	if err != nil {
		return "", err
	}
	defer root.Close()
	file, err := root.Open(c.Name)
	if err != nil {
		return "", err
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, c.Size+1))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	if int64(len(b)) != c.Size || hex.EncodeToString(sum[:]) != c.SHA256 {
		return "", errors.New("the file changed after it was verified")
	}
	return string(b), nil
}

// readAtMost reads a file of at most max bytes.
func readAtMost(path string, max int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("more than %d bytes", max)
	}
	return b, nil
}

func (r Review) logf(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

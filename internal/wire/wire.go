// Package wire is the files the gate's jobs hand to each other
// (docs/v0.2-spec.md, section 8):
//
//   - fetch writes the facts file and a directory of chunk files. It has
//     no secrets and it is the job that parses what a pull request and
//     its dependencies wrote.
//   - review reads both, asks the model, and writes the verdicts file. It
//     holds the model credential and treats chunks as bytes.
//   - publish reads the facts file and the verdicts file, joins them
//     (Join) and hands the result to allow.Decide. It holds the token
//     that can merge.
//
// The files are the only thing a later job believes about an earlier one,
// so the contract is strict on purpose. Every file is one JSON object of
// known members only, in exact case and without duplicates, within fixed
// size limits, and is checked in full when it is read and when it is
// written. A chunk file is named by its position and nothing else, and is
// believed only after its bytes hashed to what the facts file lists
// (VerifyChunks).
package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"time"

	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/gh"
)

// The names the jobs agree on, inside the directory one job uploads and
// the next downloads.
const (
	FactsFile    = "facts.json"
	VerdictsFile = "verdicts.json"
	// ChunksDir is the directory that holds the chunk files and nothing
	// else. It may be absent when no update has a chunk (an artifact
	// upload drops an empty directory).
	ChunksDir = "chunks"
)

// Version is the format of both files. A reader refuses any other: the
// jobs of one run are built from one commit, so a mismatch is never a
// file to be read leniently.
const Version = 1

// Limits. They are far above anything a real pull request produces, and
// exist so that a file is bounded before it is believed.
const (
	// maxFileBytes bounds either file. The unread lists are what makes a
	// facts file large: an update that touches ten thousand binary files
	// is about 1.5 MB of it.
	maxFileBytes = 32 << 20
	// maxUpdates bounds the updates of one pull request, and so the
	// verdicts. A chunk file's name has three digits for the update.
	maxUpdates = 1000
	// maxChunks bounds the chunks of one update. A chunk file's name has
	// three digits for the chunk.
	maxChunks = 1000
	// maxChunkBytes bounds one chunk file. It is the most text
	// internal/artifact prepares for a whole update.
	maxChunkBytes = 256 << 20
	// maxUnread bounds one update's list of unread files.
	maxUnread = 100_000
	// maxDetailBytes bounds the gate's own sentence about a read that was
	// not prepared.
	maxDetailBytes = 500
	// maxHashBytes bounds an update's Hash. The longest the gate knows is
	// an npm sha512 integrity, of 95 bytes.
	maxHashBytes = 200
)

// PullRequest names the pull request, and the one head commit, that a
// facts file is about. Publish merges with exactly this head.
type PullRequest struct {
	// Repo is the repository, owner/name.
	Repo   string `json:"repo"`
	Number int    `json:"number"`
	// Head is the full hex ID of the head commit the facts were gathered
	// for.
	Head string `json:"head"`
}

// Facts is the facts file.
type Facts struct {
	Version     int         `json:"version"`
	PullRequest PullRequest `json:"pull_request"`
	// GatheredAt is when fetch or refresh gathered the facts, by that
	// job's clock. Publish decides with its own clock, and not on facts
	// that are older than land.MaxFactsAge by it.
	GatheredAt time.Time `json:"gathered_at"`
	Facts      PRFacts   `json:"facts"`
}

// PRFacts is allow.PRFacts as fetch can know it: every member of it, with
// each update carrying the read that was prepared in place of a read
// state and a veto. A test keeps the two types in step.
type PRFacts struct {
	Ecosystem        string     `json:"ecosystem"`
	Identity         allow.Fact `json:"identity"`
	Shape            allow.Fact `json:"shape"`
	ChecksConfigured allow.Fact `json:"checks_configured"`
	Opened           time.Time  `json:"opened"`
	Updates          []Update   `json:"updates"`
}

// Update is allow.UpdateFacts without Read and Veto, which fetch cannot
// know and must not be able to write, and with Hash and Prepared, which
// allow.Decide does not take: a facts file that says "read": "full" does
// not decode. Whether a model read code comes from the verdicts file
// alone (Join). The one read that counts without a verdict is of two
// artifacts that hold the same files (Identical): no model was asked,
// and the status says so.
type Update struct {
	Name string `json:"name"`
	From string `json:"from"`
	To   string `json:"to"`

	Known       allow.Fact     `json:"known"`
	Listed      allow.Fact     `json:"listed"`
	NewName     allow.Fact     `json:"new_name"`
	Increase    allow.Fact     `json:"increase"`
	Major       allow.Fact     `json:"major"`
	Indirect    allow.Fact     `json:"indirect"`
	Bound       allow.Fact     `json:"bound"`
	FirstSeen   allow.TimeFact `json:"first_seen"`
	NameCreated allow.TimeFact `json:"name_created"`
	Clean       allow.Fact     `json:"clean"`
	NoRegress   allow.Fact     `json:"no_regress"`
	SecurityFix allow.Fact     `json:"security_fix"`
	Superseded  allow.Fact     `json:"superseded"`
	Own         allow.Fact     `json:"own"`

	// Hash is the hash Bound was established for (artifact.Pair.New.Hash:
	// go.sum's h1 of the module zip, the lock's integrity, the action's
	// commit), and empty where the gatherer named no artifact: Bound does
	// not hold, or the update is an image, whose To carries the digest.
	// allow.Decide never sees it. Publish tells one pin from another by it
	// when it remembers when it first saw one (spec section 11, amendment
	// 38).
	Hash string `json:"hash"`

	// Prepared is what fetch has for the model to read.
	Prepared Read `json:"prepared"`
}

// ReadStatus is how fetch's attempt to prepare an update's read ended.
type ReadStatus string

// The five ways it ends. Join turns each into a read state; none of them
// says that a model read anything.
const (
	// Prepared: the artifacts were fetched, verified and diffed, and there
	// is text to put before the model. Key, State, Unread and Chunks
	// describe the result. What the read comes to is the verdict's to
	// say.
	Prepared ReadStatus = "prepared"
	// Identical: the artifacts were fetched and verified, and the old and
	// the new one hold the same files: nothing changed, was added or was
	// removed. There is nothing to read, and no model is asked. Read is
	// full, on the fetch job's word, which is also all that stands behind
	// the text of a prepared read (spec section 11, amendment 53).
	Identical ReadStatus = "identical"
	// Nothing: nothing is read and nothing was fetched. That is every
	// Docker update, every own workflow (spec section 11, amendment 60),
	// and an update of another ecosystem whose gatherer named no artifact
	// (its Bound does not hold, or the old version has no verifiable
	// hash). For Docker and for an own workflow it is not-applicable;
	// anywhere else the update is unread, which is person.
	Nothing ReadStatus = "nothing"
	// Unavailable: the artifact could not be downloaded this time
	// (artifact.ErrUnavailable). Read is none: it waits and is retried.
	Unavailable ReadStatus = "unavailable"
	// Refused: the gate will not read this update, and asking again gives
	// the same: a hash mismatch, an unsafe archive or a bad reference
	// (artifact.ErrHashMismatch, ErrUnsafeArchive, ErrBadRef). Read is
	// refused, which is person at once.
	Refused ReadStatus = "refused"
)

// Read is the read fetch prepared for one update, or why there is none.
type Read struct {
	Status ReadStatus `json:"status"`
	// Detail is the gate's own sentence about a read that was not
	// prepared, for the comment: which class of error, never the error's
	// text. Empty for Prepared.
	Detail string `json:"detail"`

	// The rest is set for Prepared and empty otherwise.

	// Key is the read's content key (artifact.Prepared.Key).
	Key string `json:"key"`
	// State is what the read amounts to once every chunk is answered:
	// full or partial (artifact.Prepared.State). It is a ceiling, not a
	// result.
	State allow.ReadState `json:"state"`
	// Unread lists the changed files that are not in the chunks.
	Unread []artifact.Unread `json:"unread"`
	// Chunks lists the chunk files, in order: at least one. A read with
	// nothing to put before the model is not Prepared.
	Chunks []ChunkFile `json:"chunks"`
}

// ChunkFile is one chunk as a file in ChunksDir.
type ChunkFile struct {
	// Name is ChunkName for the chunk's position, and nothing else: a
	// name carries no information of its own and never leaves the
	// directory.
	Name string `json:"name"`
	// SHA256 of the file's bytes, lower-case hex. The file holds the
	// chunk's text and nothing more.
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// ChunkName is the file name of chunk number chunk of update number
// update, both counted from 0: "007-000.txt".
func ChunkName(update, chunk int) string {
	return fmt.Sprintf("%03d-%03d.txt", update, chunk)
}

// NewChunkFile describes a chunk file that holds text.
func NewChunkFile(update, chunk int, text string) ChunkFile {
	sum := sha256.Sum256([]byte(text))
	return ChunkFile{Name: ChunkName(update, chunk), SHA256: hex.EncodeToString(sum[:]), Size: int64(len(text))}
}

// NewUpdate is u as the facts file carries it, with the read fetch
// prepared. Whatever u says of Read and Veto is dropped: fetch does not
// know them.
func NewUpdate(u allow.UpdateFacts, prepared Read) Update {
	return Update{
		Name: u.Name, From: u.From, To: u.To,
		Known: u.Known, Listed: u.Listed, NewName: u.NewName,
		Increase: u.Increase, Major: u.Major, Indirect: u.Indirect, Bound: u.Bound,
		FirstSeen: u.FirstSeen, NameCreated: u.NameCreated,
		Clean: u.Clean, NoRegress: u.NoRegress, SecurityFix: u.SecurityFix,
		Superseded: u.Superseded, Own: u.Own,
		Prepared: prepared,
	}
}

// Verdicts is the verdicts file.
type Verdicts struct {
	Version int `json:"version"`
	// Verdicts has at most one entry for each pair of Key and
	// Fingerprint, in any order. An update whose read was not prepared,
	// or was not reviewed, has none.
	Verdicts []Verdict `json:"verdicts"`
}

// Verdict is the reviewer's answer for one prepared read. It is about a
// read's content, not about a pull request or a head commit, which is
// what lets the scheduled job, which asks no model, decide on a stored
// one.
type Verdict struct {
	// Key is the content key of the read that was reviewed.
	Key string `json:"key"`
	// Fingerprint is the reviewer's (veto.Config.Fingerprint). A verdict
	// counts only for a reader that computes the same one.
	Fingerprint string `json:"fingerprint"`
	// Read is the resulting read state: full or partial when the model
	// answered, none when there was no complete answer (the same as no
	// entry), refused when the reviewer called the read unusable.
	Read allow.ReadState `json:"read"`
	// Veto is the model's objection, or its refusal, and nil for no
	// veto. It is only ever set with Read full or partial. Its quotes and
	// notes are cut to size where the model's answer is read
	// (internal/veto), not here: a file that refused a long quote would
	// lose the veto.
	Veto *allow.Veto `json:"veto"`
}

// Join puts a facts file and a verdicts file together into what
// allow.Decide takes. fingerprint is the reviewer's fingerprint as the
// caller computes it from its own configuration; a verdict written under
// another one is not used.
//
// An update's Read and Veto are settled here and nowhere else:
//
//   - Docker is not-applicable, whatever was prepared. Nothing of an
//     image is read.
//   - An Actions update whose Own holds is not-applicable too: the gate
//     owner's own workflow is accepted unread (spec section 11, amendment
//     60). allow.Decide takes that state only for a name on its own
//     policy's list, and takes no other state for such an update.
//   - Refused is refused. Unavailable is none.
//   - Identical is full, with no verdict looked for: the two artifacts
//     hold the same files, and no model was asked about nothing.
//   - Nothing, for any other update, leaves Read unset, which
//     allow.Decide answers with person: no artifact was verified, so
//     nothing was read.
//   - Prepared takes the one verdict with the read's Key and the caller's
//     fingerprint. Without one, Read is none: not reviewed yet, or
//     reviewed as another question. With one, Read is the verdict's,
//     except that it is never better than the prepared State: a verdict
//     of full for a read that was prepared partial is partial. The veto
//     is the verdict's.
//
// Nothing in a verdict can make a decision more permissive than these
// rules allow: a verdict for another key is not looked at, and the best
// any verdict gives is the state fetch prepared with no veto. And no read
// a model was not asked about counts as one it answered: only Prepared
// takes a verdict, and a Prepared read has text.
func Join(f Facts, v Verdicts, fingerprint string) allow.PRFacts {
	type question struct{ key, fingerprint string }
	answers := make(map[question]Verdict, len(v.Verdicts))
	for _, verdict := range v.Verdicts {
		answers[question{verdict.Key, verdict.Fingerprint}] = verdict
	}

	out := allow.PRFacts{
		Ecosystem:        f.Facts.Ecosystem,
		Identity:         f.Facts.Identity,
		Shape:            f.Facts.Shape,
		ChecksConfigured: f.Facts.ChecksConfigured,
		Opened:           f.Facts.Opened,
	}
	for _, u := range f.Facts.Updates {
		joined := allow.UpdateFacts{
			Name: u.Name, From: u.From, To: u.To,
			Known: u.Known, Listed: u.Listed, NewName: u.NewName,
			Increase: u.Increase, Major: u.Major, Indirect: u.Indirect, Bound: u.Bound,
			FirstSeen: u.FirstSeen, NameCreated: u.NameCreated,
			Clean: u.Clean, NoRegress: u.NoRegress, SecurityFix: u.SecurityFix,
			Superseded: u.Superseded, Own: u.Own,
		}
		switch {
		case f.Facts.Ecosystem == allow.Docker:
			joined.Read = allow.ReadNotApplicable
		case ownWorkflow(f.Facts.Ecosystem, u):
			joined.Read = allow.ReadNotApplicable
		case u.Prepared.Status == Refused:
			joined.Read = allow.ReadRefused
		case u.Prepared.Status == Unavailable:
			joined.Read = allow.ReadNone
		case u.Prepared.Status == Identical:
			joined.Read = allow.ReadFull
		case u.Prepared.Status == Prepared:
			joined.Read = allow.ReadNone
			verdict, ok := answers[question{u.Prepared.Key, fingerprint}]
			if !ok {
				break
			}
			switch verdict.Read {
			case allow.ReadRefused:
				joined.Read = allow.ReadRefused
			case allow.ReadFull, allow.ReadPartial:
				joined.Read = verdict.Read
				if u.Prepared.State != allow.ReadFull {
					joined.Read = allow.ReadPartial
				}
				if verdict.Veto != nil {
					veto := *verdict.Veto
					veto.Quotes = slices.Clone(veto.Quotes)
					joined.Veto = &veto
				}
			}
		}
		out.Updates = append(out.Updates, joined)
	}
	return out
}

// ownWorkflow reports whether u is an update the gate accepts unread as
// the gate owner's own workflow: an Actions update whose Own holds. It is
// allow.Decide's own test, made here to say which read state such an
// update has.
func ownWorkflow(ecosystem string, u Update) bool {
	return ecosystem == allow.GitHubActions && u.Own.Holds()
}

// strict is how both files are decoded: a member the types do not have is
// an error. encoding/json/v2 already matches names in exact case and
// refuses a name that occurs twice and text that is not UTF-8, each of
// which the first encoding/json lets through.
var strict = json.RejectUnknownMembers(true)

// EncodeFacts checks f and writes it as the facts file's bytes.
func EncodeFacts(f Facts) ([]byte, error) {
	if err := f.check(); err != nil {
		return nil, fmt.Errorf("wire: facts: %w", err)
	}
	return encode("facts", f)
}

// DecodeFacts reads the facts file's bytes. Anything about them that is
// not what EncodeFacts writes is an error, and then nothing is returned.
func DecodeFacts(b []byte) (Facts, error) {
	var f Facts
	if err := decode(b, &f); err != nil {
		return Facts{}, fmt.Errorf("wire: facts: %w", err)
	}
	if err := f.check(); err != nil {
		return Facts{}, fmt.Errorf("wire: facts: %w", err)
	}
	return f, nil
}

// EncodeVerdicts checks v and writes it as the verdicts file's bytes.
func EncodeVerdicts(v Verdicts) ([]byte, error) {
	if err := v.check(); err != nil {
		return nil, fmt.Errorf("wire: verdicts: %w", err)
	}
	return encode("verdicts", v)
}

// DecodeVerdicts reads the verdicts file's bytes, as strictly as
// DecodeFacts.
func DecodeVerdicts(b []byte) (Verdicts, error) {
	var v Verdicts
	if err := decode(b, &v); err != nil {
		return Verdicts{}, fmt.Errorf("wire: verdicts: %w", err)
	}
	if err := v.check(); err != nil {
		return Verdicts{}, fmt.Errorf("wire: verdicts: %w", err)
	}
	return v, nil
}

func encode(what string, v any) ([]byte, error) {
	b, err := json.Marshal(v, jsontext.Multiline(true))
	if err != nil {
		return nil, fmt.Errorf("wire: %s: %w", what, err)
	}
	if len(b) > maxFileBytes {
		return nil, fmt.Errorf("wire: %s: %d bytes, more than %d", what, len(b), maxFileBytes)
	}
	return append(b, '\n'), nil
}

func decode(b []byte, v any) error {
	if len(b) > maxFileBytes {
		return fmt.Errorf("%d bytes, more than %d", len(b), maxFileBytes)
	}
	// A file that is JSON null would decode into the zero value without
	// a word.
	if trimmed := bytes.TrimSpace(b); len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("not a JSON object")
	}
	return json.Unmarshal(b, v, strict)
}

var (
	sha256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// A veto category is one of internal/veto's fixed words, or
	// allow.VetoModelRefused. This package does not know the list; it
	// knows what such a word looks like.
	categoryRE = regexp.MustCompile(`^[a-z][a-z_]{0,63}$`)
)

// check is everything about a facts file that is not its JSON syntax.
func (f Facts) check() error {
	switch {
	case f.Version != Version:
		return fmt.Errorf("version %d, want %d", f.Version, Version)
	case !gh.ValidRepo(f.PullRequest.Repo):
		return errors.New("pull_request.repo is not owner/name")
	case f.PullRequest.Number < 1:
		return fmt.Errorf("pull_request.number is %d", f.PullRequest.Number)
	case !gh.ValidSHA(f.PullRequest.Head):
		return errors.New("pull_request.head is not a full commit ID")
	case f.GatheredAt.IsZero():
		return errors.New("gathered_at is not set")
	case len(f.Facts.Updates) > maxUpdates:
		return fmt.Errorf("%d updates, more than %d", len(f.Facts.Updates), maxUpdates)
	}
	for i, u := range f.Facts.Updates {
		if len(u.Hash) > maxHashBytes {
			return fmt.Errorf("update %d: hash is %d bytes, more than %d", i, len(u.Hash), maxHashBytes)
		}
		if err := u.Prepared.check(i); err != nil {
			return fmt.Errorf("update %d: prepared: %w", i, err)
		}
		if f.Facts.Ecosystem == allow.Docker && u.Prepared.Status != Nothing {
			return fmt.Errorf("update %d: prepared: status %q for an image, of which nothing is read", i, u.Prepared.Status)
		}
		if ownWorkflow(f.Facts.Ecosystem, u) && u.Prepared.Status != Nothing {
			return fmt.Errorf("update %d: prepared: status %q for an own workflow, of which nothing is read", i, u.Prepared.Status)
		}
	}
	return nil
}

// check is the rules for the read of update number update.
func (r Read) check(update int) error {
	if len(r.Detail) > maxDetailBytes {
		return fmt.Errorf("detail is %d bytes, more than %d", len(r.Detail), maxDetailBytes)
	}
	switch r.Status {
	case Prepared:
	case Nothing, Unavailable, Refused, Identical:
		if r.Key != "" || r.State != "" || len(r.Unread) != 0 || len(r.Chunks) != 0 {
			return fmt.Errorf("status %q with a key, a state, unread files or chunks", r.Status)
		}
		return nil
	default:
		return fmt.Errorf("status %q", r.Status)
	}

	switch {
	case r.Detail != "":
		return errors.New("a prepared read with a detail")
	case !sha256RE.MatchString(r.Key):
		return errors.New("key is not a content key")
	case r.State != allow.ReadFull && r.State != allow.ReadPartial:
		return fmt.Errorf("state %q, want %q or %q", r.State, allow.ReadFull, allow.ReadPartial)
	case r.State == allow.ReadFull && len(r.Unread) > 0:
		return fmt.Errorf("state %q with %d unread files", r.State, len(r.Unread))
	case len(r.Unread) > maxUnread:
		return fmt.Errorf("%d unread files, more than %d", len(r.Unread), maxUnread)
	case len(r.Chunks) == 0:
		// Nothing a model could be asked about. The review job would have
		// nothing to send, and a verdict for it would be nobody's answer.
		return errors.New("a prepared read with no chunk")
	case len(r.Chunks) > maxChunks:
		return fmt.Errorf("%d chunks, more than %d", len(r.Chunks), maxChunks)
	}
	for i, u := range r.Unread {
		if u.Path == "" || u.Size < 0 || !sha256RE.MatchString(u.SHA256) {
			return fmt.Errorf("unread file %d has no path, a negative size or no SHA-256", i)
		}
	}
	for i, c := range r.Chunks {
		switch {
		case c.Name != ChunkName(update, i):
			// The name is the position. Anything else, a path most of
			// all, is not a name this package ever opens.
			return fmt.Errorf("chunk %d is not named %s", i, ChunkName(update, i))
		case !sha256RE.MatchString(c.SHA256):
			return fmt.Errorf("chunk %d has no SHA-256", i)
		case c.Size < 1 || c.Size > maxChunkBytes:
			return fmt.Errorf("chunk %d is %d bytes, want 1 to %d", i, c.Size, maxChunkBytes)
		}
	}
	return nil
}

// check is everything about a verdicts file that is not its JSON syntax.
func (v Verdicts) check() error {
	switch {
	case v.Version != Version:
		return fmt.Errorf("version %d, want %d", v.Version, Version)
	case len(v.Verdicts) > maxUpdates:
		return fmt.Errorf("%d verdicts, more than %d", len(v.Verdicts), maxUpdates)
	}
	type question struct{ key, fingerprint string }
	seen := map[question]bool{}
	for i, verdict := range v.Verdicts {
		if err := verdict.check(); err != nil {
			return fmt.Errorf("verdict %d: %w", i, err)
		}
		q := question{verdict.Key, verdict.Fingerprint}
		if seen[q] {
			// Two answers to one question: which one counts must not be
			// a matter of order.
			return fmt.Errorf("verdict %d: a second verdict for the same key and fingerprint", i)
		}
		seen[q] = true
	}
	return nil
}

func (v Verdict) check() error {
	switch {
	case !sha256RE.MatchString(v.Key):
		return errors.New("key is not a content key")
	case !sha256RE.MatchString(v.Fingerprint):
		return errors.New("fingerprint is not a fingerprint")
	}
	switch v.Read {
	case allow.ReadFull, allow.ReadPartial:
	case allow.ReadNone, allow.ReadRefused:
		if v.Veto != nil {
			return fmt.Errorf("read %q with a veto: a veto is the model's answer, and there was none", v.Read)
		}
		return nil
	default:
		return fmt.Errorf("read %q", v.Read)
	}
	if v.Veto != nil && !categoryRE.MatchString(v.Veto.Category) {
		return errors.New("veto category is not a category")
	}
	return nil
}

// VerifyChunks checks the directory dir against the chunk files f lists:
// every listed file is there, is a regular file of the listed size and
// hashes to the listed SHA-256, and the directory holds nothing else. A
// job calls it before it opens any chunk, because a file name is not
// evidence of anything: after it returns nil, the file called c.Name in
// dir is the bytes fetch hashed.
//
// The directory may be missing when f lists no chunk at all.
func VerifyChunks(dir string, f Facts) error {
	want := map[string]ChunkFile{}
	for _, u := range f.Facts.Updates {
		for _, c := range u.Prepared.Chunks {
			want[c.Name] = c
		}
	}

	// os.Root: nothing in the directory, a symbolic link least of all,
	// leads a read outside it.
	root, err := os.OpenRoot(dir)
	if errors.Is(err, fs.ErrNotExist) && len(want) == 0 {
		return nil
	}
	if err != nil {
		return fmt.Errorf("wire: chunks: %w", err)
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return fmt.Errorf("wire: chunks: %w", err)
	}

	found := map[string]bool{}
	for _, e := range entries {
		// A name fetch did not list is whatever someone put there, so it
		// is shown quoted.
		c, listed := want[e.Name()]
		if !listed {
			return fmt.Errorf("wire: chunks: the directory holds %q, which the facts file does not list", e.Name())
		}
		// Lstat, so a link is seen as a link and not as what it points at.
		info, err := root.Lstat(c.Name)
		switch {
		case err != nil:
			return fmt.Errorf("wire: chunks: %s: %w", c.Name, err)
		case !info.Mode().IsRegular():
			return fmt.Errorf("wire: chunks: %s is not a regular file", c.Name)
		case info.Size() != c.Size:
			// Before hashing: a file of another size is not read at all.
			return fmt.Errorf("wire: chunks: %s is %d bytes, the facts file lists %d", c.Name, info.Size(), c.Size)
		}
		if _, err := readChunk(root, c); err != nil {
			return fmt.Errorf("wire: chunks: %w", err)
		}
		found[c.Name] = true
	}
	for _, u := range f.Facts.Updates {
		for _, c := range u.Prepared.Chunks {
			if !found[c.Name] {
				return fmt.Errorf("wire: chunks: %s is listed in the facts file and missing", c.Name)
			}
		}
	}
	return nil
}

// ReadChunk returns the bytes of the chunk file c in dir, checked against
// the size and hash the facts file lists. VerifyChunks has checked the
// directory as a whole; this ties the bytes a job goes on to use, not the
// bytes that were there a moment ago, to the listed hash.
func ReadChunk(dir string, c ChunkFile) ([]byte, error) {
	// os.Root: the name is the facts file's, and although its shape was
	// checked, it opens nothing outside the directory.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return readChunk(root, c)
}

// readChunk reads a chunk file of the listed size, and no more than one
// byte past it.
func readChunk(root *os.Root, c ChunkFile) ([]byte, error) {
	file, err := root.Open(c.Name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, c.Size+1))
	if err != nil {
		return nil, err
	}
	if sum := sha256.Sum256(b); int64(len(b)) != c.Size || hex.EncodeToString(sum[:]) != c.SHA256 {
		return nil, fmt.Errorf("%s does not hash to what the facts file lists", c.Name)
	}
	return b, nil
}

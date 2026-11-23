// Package artifact turns one update into the text the model reads
// (docs/v0.2-spec.md, section 7): it fetches the old and the new artifact
// that actually runs, checks each against the hash the pull request is
// bound to, and produces escaped, chunked diff text.
//
// This file is the package's API: the types, the error classes and the
// description of the text. The one implementation is built with New
// (reader.go). The package holds no secrets and makes no decision: what
// it produces only chooses what the model sees.
package artifact

import (
	"context"
	"errors"
	"io/fs"

	"github.com/sadbox/dep-review/internal/allow"
)

// Kind is what sort of artifact a Ref names.
type Kind string

// The artifacts the gate can read. Docker images are not read.
const (
	// GoModuleZip is a module zip as the go command downloads it, with
	// the checksum database on.
	GoModuleZip Kind = "go-module-zip"
	// NPMTarball is a package tarball from the npm registry.
	NPMTarball Kind = "npm-tarball"
	// ActionTarball is the repository tarball of an action at one commit,
	// which is what the runner downloads, dist/ included.
	ActionTarball Kind = "action-tarball"
)

// Ref names one artifact and the hash it must match. It carries no URL on
// purpose: the location is derived from Kind, Name and Version, so
// nothing in a pull request chooses where the gate downloads from.
type Ref struct {
	Kind Kind `json:"kind"`
	// Name is the module path, the npm package name, or owner/repo (for
	// an action in a directory too: the repository is what is downloaded).
	Name string `json:"name"`
	// Version is the module version, the package version, or the tag.
	Version string `json:"version"`
	// Hash is what the Bound fact was established for: the go.sum "h1:"
	// hash of the module zip, the lockfile's "sha512-" integrity of the
	// tarball, or the 40-hex commit of the action. An artifact that does
	// not match it is never read.
	Hash string `json:"hash"`
}

// Pair is the old and the new artifact of one update.
//
// The parts must describe one update, and Prepare refuses a Pair where
// they do not (ErrBadRef): Ecosystem must be the one that goes with the
// artifacts' Kind; New.Name must equal Name and New.Version must equal
// To; Old, when there is one, must be of the same Kind with Old.Name
// equal to Name and Old.Version equal to From; and From is empty exactly
// when Old is the zero Ref. The model is told the pair's name and
// versions, so they have to be the ones of the artifacts it is shown.
type Pair struct {
	// Ecosystem, Name, From and To identify the update exactly as its
	// allow.UpdateFacts does; they are how the two are matched up.
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	From      string `json:"from"`
	To        string `json:"to"`
	// Old is the artifact at the base commit. For a new name there is
	// none: Old is the zero Ref and the whole of New counts as added.
	Old Ref `json:"old"`
	// New is the artifact at the head commit.
	New Ref `json:"new"`
}

// MinChunkBytes is the smallest Limits.ChunkBytes Prepare accepts. Below
// it a file header alone may not fit in a chunk.
const MinChunkBytes = 256

// Limits bound one prepared read. Both come from configuration
// (internal/config's chunk_bytes and max_chunks, through
// veto.Config.Limits, so the reviewer accepts what was prepared) and are
// sized from the documented context window of the configured model.
type Limits struct {
	// ChunkBytes is the most escaped text one chunk may hold.
	ChunkBytes int
	// MaxChunks is the most chunks one update may be split into.
	MaxChunks int
}

// Chunk is one model request's worth of text.
type Chunk struct {
	// Index is the chunk's position, from 0.
	Index int `json:"index"`
	// Text is diff text after the package's one escaper, laid out as
	// TextFormat says. It was written by the dependency's publisher and
	// is data, never instructions.
	Text string `json:"text"`
}

// TextFormat describes Chunk.Text, in words the model can be given. It is
// part of this package's contract with whoever writes the prompt: every
// chunk follows it, whatever the artifact's publisher wrote. internal/veto
// sends it word for word and has no description of its own, so the two
// cannot drift apart; a change here changes veto's fingerprint, and with
// it every stored verdict's key.
const TextFormat = `The text is a list of changed files. Each chunk stands alone.
A line that starts with "==" was written by the gate. "== file: PATH (...)" starts a file and says whether it was added or changed, and whether only part of it is shown. A file that continues in another chunk is marked "[part N]" there and here. No other line starts with "==".
A line that starts with "@@" starts a hunk, as in a unified diff.
Every other line is the file's own text behind one marker character: "+" for a line added, "-" for a line removed, a space for an unchanged line of context, "\" for git's note about a missing final newline.
A line that starts with "~" continues the line above it, which was too long to keep in one piece; the character after "~" repeats that line's marker.
"<0xNN>" and "<U+XXXX>" stand for one control, invisible or direction-changing character that was in the file at that place. Carriage returns are shown that way unless they end a line.`

// Unread is a changed or added file the model was not shown.
type Unread struct {
	// Path inside the artifact, escaped like chunk text.
	Path string `json:"path"`
	// Size in bytes.
	Size int64 `json:"size"`
	// SHA256 of the file, lower-case hex.
	SHA256 string `json:"sha256"`
}

// Inspect looks at the two extracted artifacts of one update and answers
// with a fact about them. It is how a fact that only the verified bytes
// can establish gets established without a second download and a second
// extractor: internal/facts/npm's check that no package.json or
// binding.gyp in the tarball brings a new install step is one.
//
// old and new are the artifacts' own trees, read-only, holding regular
// files and directories only; old is nil for a new name. The trees are
// removed when Prepare returns, so the function must not keep them.
type Inspect func(old, new fs.FS) allow.Fact

// Prepared is everything the model is to read for one update.
type Prepared struct {
	Pair Pair `json:"pair"`
	// Chunks is the text, in order. It can be empty when nothing readable
	// changed.
	Chunks []Chunk `json:"chunks"`
	// Unread lists the changed or added files that are not in Chunks:
	// files that are not text, and files the budget left out.
	Unread []Unread `json:"unread"`
	// State is what the read amounts to once every chunk has been
	// answered: allow.ReadFull when every changed text file is in Chunks
	// and Unread is empty, allow.ReadPartial otherwise. It is never one
	// of the other states; "no answer" is known only after the model was
	// asked.
	State allow.ReadState `json:"state"`
	// Key is the content key (lower-case hex SHA-256). It covers the
	// chunk set and everything else that decides what a verdict for those
	// chunks means: the Pair with both Refs and their hashes, State and
	// the Unread list. Chunks alone would not do: two updates with equal
	// text of which one also changed a binary file, or two updates with
	// no text at all, must not share a verdict. Nothing in it depends on
	// the pull request, the repository or the machine, so the same update
	// prepared again, after a rebase or in another repository, has the
	// same Key. A verdict is stored under Key together with the
	// reviewer's fingerprint (veto.Config.Fingerprint).
	Key string `json:"key"`
	// Inspected is the answer of the Inspect function configured for the
	// pair's Kind (Options.Inspect), and the zero Fact when there is
	// none. It is not part of Key: it says nothing about what the model
	// reads. The fetch command ANDs it into the update's NoRegress
	// (allow.Fact.And).
	Inspected allow.Fact `json:"inspected"`
}

// The classes of error Prepare returns, for errors.Is. They are what the
// caller decides on (spec section 11, amendment 9):
//
//   - ErrHashMismatch, ErrUnsafeArchive and ErrBadRef: the gate will not
//     read this update, and asking again gives the same answer. The
//     update's Read is allow.ReadRefused, which is person at once: a
//     hash that does not match is not something to wait out.
//   - ErrUnavailable: the artifact could not be downloaded this time.
//     Read is allow.ReadNone, which waits and is retried.
//   - Anything else (a local failure: no disk, no git, a bug) is none of
//     them. The caller must not guess it into ErrUnavailable: an error it
//     cannot name is a failed run or a person, never a wait. The same
//     goes for the caller's own context ending, which Prepare returns as
//     the context's error.
var (
	// ErrBadRef means a Pair, a Ref or the Limits are not something the
	// gate can prepare a read for: an unknown kind, a name or version
	// that is not in the kind's exact shape, a hash of the wrong form,
	// two sides that do not belong together. Nothing is downloaded.
	ErrBadRef = errors.New("artifact: bad reference")
	// ErrHashMismatch means a downloaded artifact is not the one the pull
	// request is bound to. Nothing of it is read.
	ErrHashMismatch = errors.New("artifact: does not match its bound hash")
	// ErrUnsafeArchive means an artifact was refused because of how its
	// archive is built: an entry that is not a regular file or a
	// directory, a name that points outside the archive, the same name
	// twice, data after the end of the archive, or more entries or bytes
	// than the gate extracts. Nothing of such an artifact is read.
	ErrUnsafeArchive = errors.New("artifact: unsafe archive")
	// ErrUnavailable means the registry was asked for the artifact and
	// did not deliver it: no connection, a timeout, a 429 or a 5xx on
	// every attempt. It says nothing about the artifact.
	ErrUnavailable = errors.New("artifact: the registry did not answer")
)

// Preparer prepares the read for one update.
type Preparer interface {
	// Prepare fetches both artifacts of p, verifies each against its
	// Hash, extracts them, runs the Inspect function configured for
	// their Kind, diffs them and chunks the result within lim.
	//
	// An error means no read could be prepared and there is nothing to
	// send. Which kind of error it is decides what becomes of the update;
	// see the error classes above.
	Prepare(ctx context.Context, p Pair, lim Limits) (Prepared, error)
}

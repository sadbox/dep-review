// Package artifact turns one update into the text the model reads
// (docs/v0.2-spec.md, section 7): it fetches the old and the new artifact
// that actually runs, checks each against the hash the pull request is
// bound to, and produces escaped, chunked diff text.
//
// This file is the package's API. The package holds no secrets and makes
// no decision: what it produces only chooses what the model sees.
package artifact

import (
	"context"

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
	// Name is the module path, the npm package name, or owner/repo.
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

// Limits bound one prepared read. Both come from configuration and are
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
	// Text is diff text after the package's one escaper: control, bidi
	// and line-separator characters are visible escapes. It was written
	// by the dependency's publisher and is data, never instructions.
	Text string `json:"text"`
}

// Unread is a changed or added file the model was not shown.
type Unread struct {
	// Path inside the artifact, escaped like chunk text.
	Path string `json:"path"`
	// Size in bytes.
	Size int64 `json:"size"`
	// SHA256 of the file, lower-case hex.
	SHA256 string `json:"sha256"`
}

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
	// and Unread is empty, allow.ReadPartial otherwise. It is never
	// allow.ReadNone or allow.ReadNotApplicable; "no answer" is known
	// only after the model was asked.
	State allow.ReadState `json:"state"`
	// Key is the content key: a hash of the chunk set (lower-case hex
	// SHA-256). The same update prepared again, after a rebase or in
	// another repository, has the same Key, so a verdict can be reused.
	Key string `json:"key"`
}

// Preparer prepares the read for one update.
type Preparer interface {
	// Prepare fetches both artifacts of p, verifies each against its
	// Hash, extracts them, diffs them and chunks the result within lim.
	//
	// An error means no read could be prepared (a download failed, a
	// hash did not match). The caller then has nothing to send, the
	// update's Read stays unrecorded, and allow.Decide answers person: a
	// hash that does not match is not something to wait out.
	Prepare(ctx context.Context, p Pair, lim Limits) (Prepared, error)
}

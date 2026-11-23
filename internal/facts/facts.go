// Package facts is what the ecosystems' fact gatherers (the subpackages)
// have in common: what a gatherer is given, what it hands back, and the
// few helpers they word their facts with.
//
// A fact is in one of allow.Fact's states, and which one is a gatherer's
// most important choice (docs/v0.2-spec.md, section 11, amendment 1):
// allow.Yes or allow.No when the source answered (a 404 is an answer),
// allow.Unavailable when it was asked and did not answer, which is a
// wait, and NotEstablished when asking again would not help, which is
// person. Conditions that make one fact are combined with allow.Fact.And.
package facts

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/sadbox/dep-review/internal/advisory"
	"github.com/sadbox/dep-review/internal/allow"
	"github.com/sadbox/dep-review/internal/artifact"
	"github.com/sadbox/dep-review/internal/gh"
)

// File is one path the pull request changes, as it is at both commits.
type File struct {
	// Path is relative to the repository root, with "/" separators.
	Path string
	// BaseMode and HeadMode are git's file modes ("100644", "120000",
	// "160000"), empty when the path does not exist at that commit. The
	// content alone does not tell a regular file from a symlink or a
	// submodule, or an absent file from an empty one.
	BaseMode string
	HeadMode string
	// Base and Head are the blob contents, nil for an absent path.
	Base []byte
	Head []byte
}

// Input is what every gatherer receives.
type Input struct {
	// Repo, Base and Head describe the pull request. No gatherer reads
	// them.
	Repo string
	Base string
	Head string
	// Files is every path that differs between the merge base and the
	// head, not only the ones this ecosystem expects: Shape is about there
	// being no others. It comes from git, never from the pull request's
	// metadata.
	Files []File
	// Policy is the gate's built-in policy. A gatherer needs it for the
	// Listed fact and nothing else.
	Policy allow.Policy
	// HTTP is the client for registries and indexes that take no
	// credentials.
	HTTP *http.Client
	// GitHub is the REST client holding the job's read-only token. Nil
	// for a gatherer that needs none.
	GitHub *gh.Client
	// Advisories answers SecurityFix and the advisory half of Clean.
	Advisories advisory.Checker
	// Now is the clock. A gatherer never calls time.Now itself.
	Now func() time.Time
}

// Result is what every gatherer returns.
type Result struct {
	// Shape: only this ecosystem's manifest and lock files changed, and
	// only version or hash tokens in them.
	Shape allow.Fact
	// Updates is every package the pull request moves, computed from the
	// base and head manifests, with every fact filled in except Read and
	// Veto, which the deciding job sets. When Shape does not hold the
	// change set cannot be trusted and Updates may be empty.
	Updates []allow.UpdateFacts
	// NoRegressSoFar is npm's alone: what the registry and the lock say
	// about install steps, one fact for each of Updates in the same
	// order. The npm gatherer leaves every update's NoRegress unset,
	// because only the files in the verified tarball settle it; the fetch
	// command makes the fact from this and the artifact reader's
	// inspection, and without an inspection it does not hold.
	NoRegressSoFar []allow.Fact
	// Artifacts lists what the model is to read: for each update with
	// something readable, the old and the new artifact, each with the
	// hash Bound was established for. An entry belongs to the update with
	// the same Name, From and To. Empty for Docker.
	Artifacts []artifact.Pair
}

// Gatherer establishes one ecosystem's facts for one pull request.
type Gatherer interface {
	// Gather reads the change set and gathers the facts. A source that is
	// down is a fact in its state, never an error: an error is a failure
	// of the run itself (the context ended, a tool is not installed, the
	// Input is incomplete), where the job should fail and be run again.
	Gather(ctx context.Context, in Input) (Result, error)
}

// RegularFile is git's mode of a plain, non-executable file: the only one
// a file a gatherer reads may have, at both commits.
const RegularFile = "100644"

// NotRegular says that f is not a regular file at both commits, or "". A
// symlink, a submodule, an executable bit, or a file that is added or
// deleted is not a version update.
func NotRegular(f File) string {
	if f.BaseMode == RegularFile && f.HeadMode == RegularFile {
		return ""
	}
	mode := func(m string) string {
		if m == "" {
			return "absent"
		}
		return Show(m)
	}
	return fmt.Sprintf("%s is not a regular file at both commits (mode %s at base, %s at head)", Show(f.Path), mode(f.BaseMode), mode(f.HeadMode))
}

// NotEstablished is a fact nothing could establish, where asking again
// would get the same: an answer in a shape the gatherer does not know, a
// question it has no way to put. It has no Source, which allow.Decide
// reads as never gathered: person. A source that was asked and did not
// answer is allow.Unavailable instead.
func NotEstablished(why string) allow.Fact {
	return allow.Fact{Value: "not established: " + why}
}

// Unanswered is the fact for a question that got no usable answer:
// unavailable when the source was asked and did not answer (unreachable),
// and not established when an answer arrived that cannot be used.
func Unanswered(why, source string, unreachable bool) allow.Fact {
	if unreachable {
		return allow.Unavailable(why, source)
	}
	return NotEstablished(why)
}

// NotEstablishedTime is NotEstablished for a clock.
func NotEstablishedTime(why string) allow.TimeFact {
	return allow.TimeFact{Value: "not established: " + why}
}

// AdvisoryClean is the advisory half of Clean: no malware advisory, and
// no advisory on the new version that the old one did not have. A fact
// the checker left blank still has to say what is missing.
func AdvisoryClean(adv advisory.Result) allow.Fact {
	blank := func(f allow.Fact, what string) allow.Fact {
		if f == (allow.Fact{}) {
			return NotEstablished(what + " were not checked")
		}
		return f
	}
	return blank(adv.NoMalware, "malware advisories").And(blank(adv.NoNewAdvisory, "new advisories"))
}

// ScratchName stands for a tool's scratch directory in text that is
// shown.
const ScratchName = "(scratch)"

// HideScratch returns text a tool printed with every mention of dir
// replaced by ScratchName. dir is the temporary directory the gate ran
// the tool in. A tool names files there in what it reports (npm the
// packages of a broken tree, the go command a file of its module cache),
// and a gatherer puts the tool's words into a fact's Value, which is
// shown on the pull request: where on the runner the gate worked is not
// for a comment. It comes before Show, which cuts the text: a path that
// was cut is not found. A dir that is not an absolute path is no
// directory of the gate's, and nothing is replaced.
func HideScratch(text, dir string) string {
	if !filepath.IsAbs(dir) {
		return text
	}
	return strings.ReplaceAll(text, dir, ScratchName)
}

// Show renders text the pull request, a tool or a source wrote (a path,
// an error, a status) for a fact's Value: on one line, with control and
// bidi characters as visible escapes, cut to a length. It is the one
// escaper of the gatherers; the Value reaches a person and the job's log
// and never decides anything.
func Show(s string) string {
	const max = 200
	if len(s) > max {
		s = s[:max] + "..."
	}
	q := fmt.Sprintf("%+q", s)
	return q[1 : len(q)-1]
}

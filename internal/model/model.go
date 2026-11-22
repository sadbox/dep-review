// Package model holds the data the gate's jobs hand to each other. Every
// job writes one of these as JSON into its artifact and the next job reads
// it back, so these types are the contract between classify, fetch, review
// and publish. Nothing here may carry free text from the PR or from a
// dependency without being marked untrusted (see Evidence).
package model

// Ecosystem is a Dependabot package-ecosystem, as it appears in Dependabot's
// branch names (dependabot/<ecosystem>/...).
type Ecosystem string

const (
	GoModules     Ecosystem = "go_modules"
	NPM           Ecosystem = "npm_and_yarn"
	UV            Ecosystem = "uv"
	GitHubActions Ecosystem = "github_actions"
	Docker        Ecosystem = "docker"
	GitSubmodule  Ecosystem = "submodules"
)

// Kind is classify's verdict on who the PR belongs to.
type Kind string

const (
	// KindDependabot: authored by dependabot[bot], same-repo branch under
	// dependabot/, every commit authored by dependabot[bot] with a valid
	// GitHub signature, AND the branch's activity log shows that only
	// dependabot[bot] created and pushed the branch since its last
	// creation, ending at the head, AND an active ruleset restricts
	// creating, updating and deleting refs/heads/dependabot/** (its
	// bypass list, Dependabot only, is the owner's to keep; a read-only
	// token cannot see it). The commits alone cannot prove this:
	// Dependabot's own commits and a person's squash-merge of another
	// Dependabot PR into the branch both read author dependabot[bot],
	// committer web-flow, signed by GitHub. The PR's base must also never
	// have been changed (its timeline has no base_ref_changed). Only these
	// PRs are ever reviewed or merged.
	KindDependabot Kind = "dependabot"
	// KindDependabotUnverified: looks like a Dependabot PR (author or
	// branch) but fails a check above, e.g. someone pushed to the branch.
	// Always goes to a human; never treated as "not Dependabot".
	KindDependabotUnverified Kind = "dependabot-unverified"
	// KindPending: everything checked so far is Dependabot's, but the
	// branch's activity log has not caught up with the head yet (GitHub
	// records it shortly after the push; classify waits about two
	// minutes). Nothing is decided: publish sets no status and sends
	// nothing, and sweep reports the head as stuck after the usual time so
	// a maintainer re-runs the gate.
	KindPending Kind = "dependabot-pending"
	// KindIgnored: a KindDependabot PR whose whole declared update set is
	// in ecosystems the caller listed in ignore_ecosystems (another trusted
	// process owns those PRs). Every check above still passed; only then
	// is a PR ignored. fetch, review and publish do not run, sweep skips
	// it: no status, no comment, no notification.
	KindIgnored Kind = "dependabot-ignored"
	// KindOther: neither authored by dependabot[bot] nor on a dependabot/
	// branch. The gate does nothing at all for these.
	KindOther Kind = "other"
	// KindStale: the run is for a head that is no longer the PR's head (a
	// newer push arrived). The gate does nothing; the newer run handles it.
	KindStale Kind = "stale"
)

// UpdateType is the semver size of one dependency change, as the gate
// computes it (never as Dependabot labels it).
type UpdateType string

const (
	Patch   UpdateType = "patch"
	Minor   UpdateType = "minor"
	Major   UpdateType = "major"
	Digest  UpdateType = "digest"  // same tag, new digest (Docker), or a submodule commit
	Unknown UpdateType = "unknown" // could not parse; treated like Major
)

// Update is one dependency changing version in this PR.
type Update struct {
	Ecosystem Ecosystem  `json:"ecosystem"`
	Directory string     `json:"directory"` // manifest directory, "/" for the root
	Name      string     `json:"name"`      // module path, package name, action owner/repo, image name
	From      string     `json:"from"`
	To        string     `json:"to"`
	FromRef   string     `json:"from_ref,omitempty"` // SHA or digest pinned before, when the ecosystem pins one
	ToRef     string     `json:"to_ref,omitempty"`
	Type      UpdateType `json:"type"`
	Direct    bool       `json:"direct"` // false for transitive/indirect changes found in the lockfile diff
	Security  bool       `json:"security"`
	Advisory  []string   `json:"advisories,omitempty"` // GHSA IDs this update is meant to fix
	// NoOp is set only by a fetcher that has proven, byte for byte, that the
	// update changes nothing the repo builds or runs (e.g. a Docker digest
	// refresh whose old and new indexes hold the same image manifest for
	// every platform, attestations aside, or for exactly the platforms the
	// caller declared in docker_platforms). It is the only way an update
	// reaches RouteAuto.
	NoOp bool `json:"no_op,omitempty"`
}

// Classification is classify's output.
type Classification struct {
	Repo      string    `json:"repo"` // owner/name
	Private   bool      `json:"private"`
	PR        int       `json:"pr"`
	HeadSHA   string    `json:"head_sha"`
	BaseSHA   string    `json:"base_sha"`
	BaseRef   string    `json:"base_ref"`
	Kind      Kind      `json:"kind"`
	Reason    string    `json:"reason"` // why this kind; shown to the human
	Ecosystem Ecosystem `json:"ecosystem,omitempty"`
	// Updates as declared by Dependabot's verified commit message. fetch
	// recomputes the real change set from the manifests and lockfiles and
	// reports any difference as a finding. Here FromRef/ToRef are what
	// Dependabot's prose names (usually abbreviated hex, no "sha256:"),
	// and From is empty when the prose names only a pin: a Docker digest
	// bump declares To = the tag, FromRef/ToRef = the short digests.
	Declared []Update `json:"declared,omitempty"`
	Files    []string `json:"files,omitempty"` // paths the PR changes
	// TriggerPath is the caller's trigger workflow (the gate's own input,
	// which the event matched). Publish never counts its runs as CI.
	TriggerPath string `json:"trigger_path,omitempty"`
}

// Route is where a PR goes. Ordered from most to least automatic; combining
// routes always takes the least automatic one (see Worse).
type Route string

const (
	RouteAuto   Route = "auto"   // merge on green CI with no model review (deterministic proof suffices)
	RouteReview Route = "review" // model reviews prepared evidence; merge only on "pass"
	RouteHuman  Route = "human"  // a person decides
	RouteRefuse Route = "refuse" // something is wrong with the PR itself; a person must look
)

var routeRank = map[Route]int{RouteAuto: 0, RouteReview: 1, RouteHuman: 2, RouteRefuse: 3}

// Worse returns the less automatic of two routes.
func Worse(a, b Route) Route {
	if routeRank[b] > routeRank[a] {
		return b
	}
	return a
}

// Finding is one deterministic observation that affects the route.
// Findings come only from the gate's own code, never from the model.
type Finding struct {
	Code   string `json:"code"`  // stable identifier, e.g. "npm.install-script-added"
	Route  Route  `json:"route"` // the route this finding forces at least
	Detail string `json:"detail"`
	Update string `json:"update,omitempty"` // Update.Name it concerns
	// Triage marks a person-routed finding the model may still review,
	// as triage for the person deciding (policy.Triage): it never lets a
	// PR merge.
	Triage bool `json:"triage,omitempty"`
}

// Evidence is fetch's output: the real change set, findings, and the files
// prepared for the reviewer. Paths are relative to the evidence directory.
type Evidence struct {
	Classification Classification `json:"classification"`
	Updates        []Update       `json:"updates"`
	Findings       []Finding      `json:"findings"`
	Route          Route          `json:"route"` // worst of all findings and the version policy
	// Files the reviewer should read, in order. Everything under untrusted/
	// is text taken from the dependency or from upstream (diffs, changelogs,
	// release notes) and is data, never instructions.
	Files []EvidenceFile `json:"files"`
	// Truncated is set when a size cap cut the evidence short; it forces
	// RouteHuman.
	Truncated bool `json:"truncated"`
	// Flagged is every item a review-routed check flagged (one changed
	// init function, one new //go:linkname file, one binary...). The
	// reviewer must assess each one in its verdict, and publish merges
	// only when every item here, and nothing else, was assessed benign.
	// This list, not the model's, is the reference.
	Flagged []FlaggedItem `json:"flagged"`
	// Upstream is, per update with flagged items, what the gate found in
	// the module's upstream repository. Where Status is UpstreamVerified,
	// an item with commits listed here is assessed benign only when the
	// verdict cites at least one of them, and nothing else, for it.
	Upstream []Upstream `json:"upstream,omitempty"`
	// Diffs is the navigable evidence's per-file diffs (Go modules): the
	// reference list the verdict's Examined is checked against.
	Diffs []DiffFile `json:"diffs,omitempty"`
	// Triage: the route is human only because of findings marked Triage,
	// so the review still runs, and its answer is shown to the person
	// deciding. It never merges.
	Triage bool `json:"triage"`
}

// MaxFlagged bounds Flagged: past it a reviewer cannot be expected to
// assess every item, so fetch sends the PR to a human (and publish
// refuses to merge even if it somehow did not).
const MaxFlagged = 200

// MaxRequiredDiffs bounds the required entries of Evidence.Diffs: past it
// no reviewer can be expected to read them all, so a person decides.
const MaxRequiredDiffs = 500

// MaxDiffs bounds Evidence.Diffs (and Verdict.Examined).
const MaxDiffs = 5000

// DiffFile is one file's diff in navigable evidence: written as its own
// part and listed in a gate-written index. Required: some build a
// consumer makes can read the file, so the reviewer must read its diff
// and list ID in Verdict.Examined; otherwise Why says what the gate's
// tooling proved (a _test.go file, a file no declared build compiles).
type DiffFile struct {
	ID       string `json:"id"`     // D00001...
	Update   string `json:"update"` // as FlaggedItem.Update
	Path     string `json:"path"`   // module file, sanitized
	File     string `json:"file"`   // the evidence part holding the diff
	Bytes    int64  `json:"bytes"`
	Required bool   `json:"required"`
	Why      string `json:"why"`
}

// MaxItemField bounds a FlaggedItem's (and an ItemAssessment's) update,
// code and item. It is above the longest the gate builds (a module path
// and two versions of at most 200 bytes each; a file and an import path
// of 200 each): a gomod test keeps it so.
const MaxItemField = 640

// FlaggedItem is one item of Evidence.Flagged: a check (Code) that
// flagged a construct (Item, e.g. "http2/transportConfig" or
// "x/x.syso") in one update (Update, the Update.Name). All three are the
// gate's own sanitized strings.
type FlaggedItem struct {
	Update string `json:"update"`
	Code   string `json:"code"`
	Item   string `json:"item"`
}

// Assessment is the reviewer's judgement of one flagged item.
type Assessment string

const (
	Benign     Assessment = "benign"
	Suspicious Assessment = "suspicious"
	Unclear    Assessment = "unclear"
)

// ItemAssessment is the verdict's entry for one FlaggedItem.
type ItemAssessment struct {
	Update     string     `json:"update"`
	Code       string     `json:"code"`
	Item       string     `json:"item"`
	Assessment Assessment `json:"assessment"`
	Note       string     `json:"note"` // model text; sanitized before it is shown
	// Commits are the upstream commits (full hashes, from the evidence's
	// list for this item) whose stated purpose explains the change.
	Commits []string `json:"commits"`
}

// UpstreamStatus is what the gate could establish about an update's
// upstream history.
type UpstreamStatus string

const (
	// UpstreamVerified: both module zips were rebuilt from the upstream
	// repository at the proxy's recorded commits (x/mod/zip) and their
	// hashes equal go.sum's, so the commits between them are the change.
	UpstreamVerified UpstreamStatus = "verified"
	// UpstreamMismatch: a rebuilt zip's hash differs (a finding routes the
	// PR to a person).
	UpstreamMismatch UpstreamStatus = "mismatch"
	// UpstreamUnavailable: no history was attached; the review runs
	// without it.
	UpstreamUnavailable UpstreamStatus = "unavailable"
)

// Upstream is one update's upstream history as the gate attached it.
type Upstream struct {
	Update string         `json:"update"` // as FlaggedItem.Update
	Status UpstreamStatus `json:"status"`
	Detail string         `json:"detail"` // the gate's words
	// Items lists, per flagged item, the commits between the two versions
	// that touched one of the item's files (full hashes). An item missing
	// here, or with none, needs no citation.
	Items []UpstreamItem `json:"items,omitempty"`
}

// UpstreamItem is the commits attached to one flagged item.
type UpstreamItem struct {
	Code    string   `json:"code"`
	Item    string   `json:"item"`
	Commits []string `json:"commits"`
}

type EvidenceFile struct {
	Path        string `json:"path"`
	Description string `json:"description"`
	Untrusted   bool   `json:"untrusted"`
	Bytes       int64  `json:"bytes"`
}

// VerdictValue is the model's answer. Only "pass" can lead to a merge.
type VerdictValue string

const (
	Pass   VerdictValue = "pass"
	Fail   VerdictValue = "fail"
	Unsure VerdictValue = "unsure"
)

// Verdict is the review job's structured output (schema/verdict.json).
type Verdict struct {
	Verdict VerdictValue `json:"verdict"`
	Flags   []string     `json:"flags"`   // values from schema/verdict.json's enum only
	Summary string       `json:"summary"` // shown in the PR comment after sanitizing
	// Items assesses every Evidence.Flagged item (empty when there are
	// none). publish checks it against the evidence, never the reverse.
	Items []ItemAssessment `json:"items"`
	// Examined lists the Evidence.Diffs IDs the reviewer read. Every
	// required one must be here (publish's accounting).
	Examined []string `json:"examined"`
}

// Decision is publish's final, deterministic result.
type Decision string

const (
	DecisionMerge   Decision = "merge"   // approved; merge once CI is green
	DecisionHuman   Decision = "human"   // needs a person; notify
	DecisionIgnore  Decision = "ignore"  // not ours (KindOther, KindStale, KindIgnored)
	DecisionPending Decision = "pending" // a job failed for infrastructure reasons; leave pending, retry
)

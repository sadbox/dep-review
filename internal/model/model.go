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
	// dependabot/, every commit authored and committed by Dependabot (or
	// GitHub's web-flow committer on a Dependabot rebase) with a verified
	// signature. Only these PRs are ever reviewed or merged.
	KindDependabot Kind = "dependabot"
	// KindDependabotUnverified: looks like a Dependabot PR (author or
	// branch) but fails a check above, e.g. someone pushed to the branch.
	// Always goes to a human; never treated as "not Dependabot".
	KindDependabotUnverified Kind = "dependabot-unverified"
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
	// refresh whose manifests for every built platform are identical). It is
	// the only way an update reaches RouteAuto.
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
	Summary string       `json:"summary"` // shown only on private repos, after sanitizing
}

// Decision is publish's final, deterministic result.
type Decision string

const (
	DecisionMerge   Decision = "merge"   // approved; merge once CI is green
	DecisionHuman   Decision = "human"   // needs a person; notify
	DecisionIgnore  Decision = "ignore"  // not ours (KindOther, KindStale)
	DecisionPending Decision = "pending" // a job failed for infrastructure reasons; leave pending, retry
)

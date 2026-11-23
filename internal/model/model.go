// Package model holds classify's answer about a pull request, which the
// classify job writes as JSON and the fetch and publish jobs read back,
// and Dependabot's names for its ecosystems. Everything else the gate's
// jobs hand each other is in internal/wire.
package model

// Ecosystem is a Dependabot package-ecosystem, as it appears in Dependabot's
// branch names (dependabot/<ecosystem>/...). The gate's own names for the
// ecosystems that have a rule are internal/allow's; internal/gather maps
// one to the other.
type Ecosystem string

// The ecosystems the gate knows by name. Only the first four have a rule.
const (
	GoModules     Ecosystem = "go_modules"
	GitHubActions Ecosystem = "github_actions"
	Docker        Ecosystem = "docker"
	NPM           Ecosystem = "npm_and_yarn"
	UV            Ecosystem = "uv"
	GitSubmodule  Ecosystem = "submodules"
)

// Kind is classify's verdict on who the PR belongs to.
type Kind string

// The kinds. The gate gathers facts for the first three and does nothing
// at all for the others.
const (
	// KindDependabot: authored by dependabot[bot], same-repo branch under
	// dependabot/, every commit authored by dependabot[bot] with a valid
	// GitHub signature, AND the branch's activity log shows that only
	// dependabot[bot] created and pushed the branch since its last
	// creation, ending at the head, AND GitHub's rules for the branch
	// restrict creating, updating and deleting it (the bypass list,
	// Dependabot only, is the owner's to keep; a read-only token cannot
	// see it). The commits alone cannot prove this: Dependabot's own
	// commits and a person's squash-merge of another Dependabot PR into
	// the branch both read author dependabot[bot], committer web-flow,
	// signed by GitHub. The PR's base must also never have been changed
	// (its timeline has no base_ref_changed). Only these PRs can merge.
	KindDependabot Kind = "dependabot"
	// KindDependabotUnverified: looks like a Dependabot PR (author or
	// branch) but fails a check above, e.g. someone pushed to the branch.
	// Always goes to a person; never treated as "not Dependabot".
	KindDependabotUnverified Kind = "dependabot-unverified"
	// KindPending: everything checked so far is Dependabot's, but the
	// branch's activity log has not caught up with the head yet (GitHub
	// records it shortly after the push; classify waits about two
	// minutes). The proof is unfinished, not failed: the PR waits, and the
	// scheduled job runs the proof again.
	KindPending Kind = "dependabot-pending"
	// KindIgnored: a KindDependabot PR in an ecosystem the caller listed
	// in ignore_ecosystems (another trusted process owns those PRs).
	// Every check above still passed; only then is a PR ignored: no
	// status, no comment, no notification.
	KindIgnored Kind = "dependabot-ignored"
	// KindOther: neither authored by dependabot[bot] nor on a dependabot/
	// branch.
	KindOther Kind = "other"
	// KindStale: the PR is closed, or the head asked about is no longer
	// its head (a newer push arrived, and has a run of its own).
	KindStale Kind = "stale"
)

// Classification is classify's output. It says who a pull request belongs
// to and names the two commits its change set is between; what the pull
// request changes is read from those commits, never from anything
// Dependabot declared.
type Classification struct {
	Repo    string `json:"repo"` // owner/name
	PR      int    `json:"pr"`
	HeadSHA string `json:"head_sha"`
	// BaseSHA is the base branch's commit as the pull request records
	// it. The fetch job takes the merge base of it and the head.
	BaseSHA string `json:"base_sha"`
	Kind    Kind   `json:"kind"`
	Reason  string `json:"reason"` // why this kind; shown to the person
	// Ecosystem is the one the branch name names, when the gate knows it.
	Ecosystem Ecosystem `json:"ecosystem,omitempty"`
}

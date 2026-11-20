// Package fetch turns a Classification into Evidence. It dispatches on the
// ecosystem to an Ecosystem implementation in internal/eco/<name>.
package fetch

import (
	"context"
	"net/http"

	"github.com/sadbox/dep-review/internal/model"
)

// Env is everything an ecosystem gets. Implementations must not execute
// anything from RepoDir or from a downloaded dependency: no builds, no
// tests, no install scripts, no `go` command inside RepoDir's modules.
type Env struct {
	Class   model.Classification
	RepoDir string // the PR's head checked out (full history, so BaseSHA is reachable via git)
	// Scratch is a private empty directory for downloads and extraction.
	Scratch string
	// Evidence writes files the reviewer will read; see Writer.
	Evidence Writer
	HTTP     *http.Client
	// GitHub is the read-only REST client for the caller repository and
	// public upstream repositories.
	GitHub GitHub
}

// Writer is implemented by internal/evidence. Untrusted content (anything
// taken from a dependency or upstream) goes through AddUntrusted; Add is for
// the gate's own summaries. Both enforce per-file and total size caps and
// report truncation.
type Writer interface {
	Add(name, description string, content []byte) error
	AddUntrusted(name, description string, content []byte) error
}

// GitHub is the subset of the REST client the fetchers need.
type GitHub interface {
	// Get decodes GET https://api.github.com/<path> into v.
	Get(ctx context.Context, path string, v any) error
}

// Result is what an ecosystem returns. Updates is the REAL change set,
// recomputed from manifests/lockfiles at BaseSHA vs HeadSHA (direct and
// transitive), not Dependabot's declaration. Findings carry the
// deterministic checks; each sets the minimum route it forces.
type Result struct {
	Updates  []model.Update
	Findings []model.Finding
}

// Ecosystem is one package ecosystem's fetcher.
type Ecosystem interface {
	Fetch(ctx context.Context, env Env) (Result, error)
}

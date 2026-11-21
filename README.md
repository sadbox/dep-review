# dep-review

A merge gate for Dependabot pull requests. It replaces an LLM session that
held write credentials and merged PRs itself with a split design:

- **Deterministic code decides who a PR belongs to and what changed.** It
  verifies the PR is Dependabot's alone (Dependabot's signed commits, and a
  branch activity log in which only Dependabot ever pushed), recomputes the real change set from
  the manifests and lockfiles, downloads both versions of every changed
  dependency and diffs them, and runs hard checks (provenance, hashes,
  install scripts, new packages, …). Nothing from the PR or a dependency is
  ever executed.
- **A model reviews only the prepared evidence**, with read-only file tools,
  no shell, no network, no write access and no secrets. Its credential is a
  short-lived federated token. It returns a schema-checked verdict.
- **Deterministic code merges**, through a dedicated GitHub App, and only
  the exact head SHA that was classified and reviewed. A deterministic
  finding always overrides a model "pass".

A fully prompt-injected reviewer can therefore at worst approve one
Dependabot update that already passed CI, the cooldown and every
deterministic check. It cannot push, change workflows or reach other repos.

## Flow

```
PR opened/synchronized
  └─ caller's dep-review-trigger (no-op, every PR)
       └─ workflow_run → gate.yml
            build    build the gate from its own pinned commit
            classify Dependabot's alone? head still current?        (read-only)
            fetch    real change set, downloads, diffs, findings,   (read-only)
                     route: auto | review | human | refuse
            review   model reads ./evidence and ./repo → verdict    (read-only + OIDC)
            publish  decide, comment, status, merge on green CI     (gate app)
  schedule → sweep   merge approved PRs whose CI finished later;    (gate app)
                     report PRs stuck without a decision
```

`publish` sets a commit status `dep-review` on the head SHA (by the gate
app): `success` = approved, `failure` = needs a human, `pending`/none = not
decided. It is informational, not a required check, so human PRs never wait
on the gate. Merging uses the REST merge API with `sha=<reviewed head>`, so
a newer head can never be merged on an old verdict.

## Routes

| Route | When | Result |
|---|---|---|
| auto | a fetcher proved the update is a no-op for everything the repo builds (e.g. a Docker digest refresh whose old and new indexes hold identical manifests for every platform, or, when the caller sets `docker_platforms`, for exactly those platforms) | merge on green CI |
| review | patch/minor/digest updates whose deterministic checks all passed | model review; merge only on `pass` |
| human | majors, 0.x minors (except `golang.org/x/*`), anything a check flags, truncated evidence, model `fail`/`unsure`, a Dependabot PR someone else pushed or merged into, or whose branch history cannot be read | comment + notification, no merge |
| refuse | the PR is malformed (no updates, tag instead of SHA pin, change set disagrees with Dependabot's metadata in a way that matters) | comment + notification |

## Layout

| Path | What |
|---|---|
| `.github/workflows/gate.yml` | the reusable workflow |
| `cmd/dep-review` | entry point: `classify`, `fetch`, `review-prep`, `publish`, `sweep` |
| `internal/model` | the JSON contract between jobs (read this first) |
| `internal/policy` | version policy and route combination |
| `internal/gh` | minimal GitHub REST client (no GraphQL) |
| `internal/classify` | who the PR belongs to; Dependabot metadata |
| `internal/fetch`, `internal/eco/*` | per-ecosystem change sets, downloads, diffs, findings |
| `internal/evidence` | evidence directory writer, size caps, untrusted/ split |
| `internal/publish` | decision, comment rendering, status, merge, notifications, sweep |
| `prompts/review.md`, `schema/verdict.json` | the reviewer's instructions and output schema |
| `examples/` | what a repository adds to use the gate |

Dependencies: the standard library unless there is a strong reason; each
one is reviewed by this gate too.

## Using it in a repository

1. Copy `examples/dep-review-trigger.yaml` and `examples/dep-review.yaml`
   into `.github/workflows/`, pin `gate.yml` by commit SHA, set the
   Anthropic IDs.
2. Add `.github/dep-review.md` (review notes; see `examples/dep-review.md`).
3. Create environment `dep-review` (deployment branches: default branch
   only) with variable `DEP_REVIEW_APP_ID`, secret `DEP_REVIEW_APP_KEY`
   (the gate app's private key), and optionally `PUSHOVER_APP_TOKEN` /
   `PUSHOVER_USER_KEY`.
4. Install the gate app on the repository (permissions: contents, pull
   requests, workflows, commit statuses: write; checks, actions: read).

## Model credential

Claude API workload identity federation: the review job exchanges its
GitHub OIDC token for a short-lived Claude token. The federation rule pins
the repositories, `event_name == "workflow_run"`, the default branch and
`job_workflow_ref` starting with this repository's `gate.yml`, with scope
`workspace:inference` in a workspace that has a spend limit. No API key is
stored anywhere.

The baseline every project follows (images, CI, Dependabot, repository
settings) lives in [sadbox/ci](https://github.com/sadbox/ci/blob/main/STANDARDS.md).

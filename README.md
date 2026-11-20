# dep-review

A merge gate for Dependabot pull requests. It replaces an LLM session that
held write credentials and merged PRs itself with a split design:

- **Deterministic code decides who a PR belongs to and what changed.** It
  verifies the PR is Dependabot's alone (Dependabot's signed commits, a
  branch activity log in which only Dependabot ever pushed, and a ruleset
  that keeps everyone else off `dependabot/` branches), recomputes the real change set from
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
            review   model reads ./evidence and ./repo → verdict    (gVisor sandbox;
                     proxy holds the Claude token)
            publish  decide, comment, status, merge on green CI     (gate app)
  schedule → sweep   merge approved PRs whose CI finished later;    (gate app)
                     report PRs stuck without a decision (including
                     dependabot-pending ones) so a maintainer re-runs them
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
| `cmd/dep-review` | entry point: `classify`, `fetch`, `review-prep`, `review`, `proxy`, `publish`, `sweep` |
| `internal/model` | the JSON contract between jobs (read this first) |
| `internal/policy` | version policy and route combination |
| `internal/gh` | minimal GitHub REST client (no GraphQL) |
| `internal/classify` | who the PR belongs to; Dependabot metadata |
| `internal/fetch`, `internal/eco/*` | per-ecosystem change sets, downloads, diffs, findings |
| `internal/evidence` | evidence directory writer, size caps, untrusted/ split |
| `internal/publish` | decision, comment rendering, status, merge, notifications, sweep |
| `internal/sandbox`, `internal/proxy` | the reviewer sandbox (docker, gVisor, networks) and its credential proxy |
| `sandbox/` | reviewer image (Dockerfile, pinned CLI lockfile), gVisor installer, CI isolation probes |
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
5. Create an active branch ruleset (any name) targeting
   `refs/heads/dependabot/**` with the rules *Restrict creations*,
   *Restrict updates* and *Restrict deletions*, and Dependabot as the only
   bypass actor. classify reads the repository's rulesets with its
   read-only token and treats every PR as `dependabot-unverified` without
   one. It cannot see the bypass list (GitHub returns `bypass_actors` only
   to tokens that may edit the ruleset), so keeping that list to
   Dependabot alone is the owner's job.

## Model credential

Claude API workload identity federation, done by the credential proxy
(`dep-review proxy`), never by the reviewer. The job's OIDC request token
(`ACTIONS_ID_TOKEN_REQUEST_TOKEN`, which in actions/runner is also the
job's runtime token: it can replace the run's artifacts and write caches)
never leaves the host process `dep-review review`. That process serves
the proxy container one thing over a unix socket: a fresh GitHub OIDC JWT
for the audience `https://api.anthropic.com`. The proxy exchanges each JWT
at `POST /v1/oauth/token` (RFC 7523 jwt-bearer) for a short-lived
Claude token, sends that as `Authorization: Bearer`, and exchanges again,
with a fresh OIDC token each time, two minutes before expiry (federated
tokens live about ten minutes; a review can take twenty). The federation
rule pins the repositories, `event_name == "workflow_run"`, the default
branch and `job_workflow_ref` starting with this repository's `gate.yml`,
with scope `workspace:inference` in a workspace that has a spend limit. No
API key is stored anywhere. Inputs: `anthropic_federation_rule_id`,
`anthropic_organization_id`, optional `anthropic_workspace_id` and
`anthropic_service_account_id`; `max_model_requests` (default 200) caps
Messages requests per review.

## Sandbox

The reviewer is the Claude Code CLI (pinned in `sandbox/package-lock.json`)
alone on a glibc distroless image (no shell, no Node, no npm, no package
manager), in a container run under gVisor (`runsc`, pinned and sha512-checked by
`sandbox/install-gvisor.sh`), so even code execution inside it gets:

- **No credentials.** Its environment is a fixed list (`internal/sandbox`):
  the proxy URL, a placeholder API key, telemetry and updates off. No
  `GITHUB_*`, `ACTIONS_*` or `RUNNER_*` variable, no token, no OIDC.
- **No network but the Messages API.** It is attached only to a
  `docker network create --internal` network with no host gateway; its only
  peer is the proxy, at a fixed IP (no DNS). The proxy (its own runc
  container, also on a normal bridge) forwards only `POST /v1/messages`,
  only for the gate's model, refuses server tools, the MCP connector and
  URL/file content sources (each would make Anthropic fetch something for
  the caller), drops the client's headers but a short allowlist, injects the
  token, caps the request count and logs path, status and token usage only.
- **No writable persistent state.** Read-only root, `--cap-drop=ALL`,
  `no-new-privileges`, non-root, pids and memory limits; `./evidence`,
  `./repo` and the settings file are read-only mounts; `$HOME` and `/tmp` are
  tmpfs.
- **Only data we already publish**: the evidence and the default branch.

Its answer comes back only on stdout: one `claude -p --output-format json`
result, at most 64 KB, whose `structured_output` must pass the verdict
schema before `verdict.json` is written. Anything else is no verdict, which
sends the PR to a human. The Read/Grep/Glob-only tool set and the
permission settings from `review-prep` still apply inside, as a second
layer. CI (`ci.yml`, job `sandbox`, amd64 and arm64) runs the same setup
against a fake upstream: isolation probes, then a scripted end-to-end
review.

## Updating pins

Dependabot (`.github/dependabot.yml`) bumps the Go toolchain, the actions,
the sandbox images' bases (`sandbox/Dockerfile`, one grouped PR) and the
Claude Code CLI (`sandbox/package.json`, both architectures in one PR),
daily with a three-day cooldown. Two things are by hand:

- **gVisor.** `sandbox/install-gvisor.sh` pins a release and the sha512 of
  each architecture's tarball; set `release` and copy both sums from that
  release's `{x86_64,aarch64}/gvisor.tar.zstd.sha512` in the bucket.
- **The proxy's allowlist after a CLI bump.** The proxy accepts only the
  request fields, block types and betas the pinned CLI sends, and CI's
  `sandbox` job fails on any refused request or dropped beta. To re-record,
  run the end-to-end review from that job (`dep-review review ...
  --test-fake-upstream canned.json`, sandboxtest build) with
  `--test-fake-record <dir>` (a directory the container user 65532 can
  write). The fake writes each request body as `messages-NNN.json` and its
  forwarded headers as `messages-NNN.headers.json`. Then:
  1. copy the last `messages-NNN.json` to
     `internal/proxy/testdata/claude-code-request.json`;
  2. compare the CLI's betas (in the proxy log, `dropped anthropic-beta
     ...`) with `allowedBetas` in `internal/proxy/proxy.go`, and any
     refusal reason with the allowlists in `internal/proxy/validate.go`;
  3. add only what the new CLI really sends and is inert (no server tool,
     no fetch by Anthropic), with a test, and re-run until the job is
     green.

The baseline every project follows (images, CI, Dependabot, repository
settings) lives in [sadbox/ci](https://github.com/sadbox/ci/blob/main/STANDARDS.md).

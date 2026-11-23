# dep-review

A merge gate for Dependabot pull requests, as a reusable GitHub Actions
workflow. It merges an update without a person when a short list of facts
about it holds, quickly for security fixes, and hands everything else to a
person with the one fact that failed.

The full specification is [docs/v0.2-spec.md](docs/v0.2-spec.md).

## The rule

The default outcome is a person. Deterministic code grants a merge, from
facts it takes from authoritative sources (the manifests at two commits,
the registries, GitHub). A model reads the changed code and can only veto.

Deterministic code never tries to understand what a dependency's code
does: there is no reachability analysis, no attribution, no build
simulation. Anything the gate does not recognise goes to a person; it
never gets a detector of its own.

It is aimed at commodity attacks: a compromised maintainer account, a new
install script, credential theft, an obvious obfuscated payload, a
re-pointed Action tag, a malicious new transitive dependency, cheap prompt
injection. An attacker who studies the gate and crafts input against its
readers is out of scope.

## Outcomes

| Outcome | When | What happens |
|---|---|---|
| merge | every fact holds, no veto, and GitHub accepts the merge | squash merge of exactly the head commit the facts are about |
| wait | only time, CI, or a retry is missing | status `pending`; the scheduled run looks again |
| person | a fact is false or was never established, or the model raised a veto | status `failure`, one comment, one notification |

The gate writes one comment per pull request, which leads with the
outcome and, for wait and person, the fact that failed and the cheapest
way out. It sets the commit status `dep-review` and, when a person is
needed and Pushover is configured, notifies once per head commit.

The gate does not judge CI. It asks GitHub to merge with `sha=<head>`, and
GitHub's rules decide; a refusal because required checks are pending or
failing is a wait. Any other refusal is reported (status `error`) and not
retried.

Waiting for an age has no deadline. Waiting for a retry (a model read, a
source that did not answer, a superseded Docker digest, required checks)
ends `wait_deadline_days` after the latest time the update could have
merged, or after the pull request was opened if that is later; then it is
a person's.

## Facts

For the pull request:

| Fact | Meaning | Source |
|---|---|---|
| Identity | Dependabot's alone, on the default branch, at its current head | `internal/classify`: author, signed commits, the branch's activity log, the pull request's timeline, GitHub's rules for the branch |
| Shape | only that ecosystem's manifest and lock files changed, and only version or hash tokens | the real tool's reading of base and head, or exact line shapes |
| ChecksConfigured | the default branch has an active rule requiring a status check other than `dep-review` | GitHub `rules/branches` |

For every update, computed from the base and head manifests and never
from the pull request's title, body, labels or Dependabot's metadata:

| Fact | Meaning |
|---|---|
| Known | the name is a dependency at the base commit, or is on the list (Docker: on the list only) |
| Listed | the name is on the owner's list |
| NewName | the name is absent at base |
| Increase | plain release versions, and `to > from` |
| Major | the leading version component changed |
| Bound | the pinned hash, commit or digest is what the registry reports now |
| FirstSeen | when the version became public, by a clock the publisher cannot set; where the registry has none, when the pull request was opened |
| NameCreated | when the package name first appeared (new names only) |
| Clean | still published; not retracted, yanked or deprecated; no malware advisory; no advisory on `to` that `from` did not have |
| NoRegress | no new or changed install script; provenance not lost; Actions: the new commit descends from the old one |
| SecurityFix | GitHub's Advisory Database has a reviewed advisory that affects `from`, not `to`, and names `to` as first patched version |
| Read | how much of the changed code the model was shown and answered for: full, partial, none, refused, or not applicable (Docker) |
| Veto | none, or a category and the lines the model quoted |

A fact is in one of four states, and only the first contributes to a
merge: it holds; it does not hold (person); its source was asked and did
not answer (wait, then person at the deadline); it was never gathered
(person).

With every fact holding, an update needs an age, measured from FirstSeen:

| Case | Required age (default) |
|---|---|
| read in full, security fix | none |
| read in full | `min_age_hours` (72 h) |
| read in part, security fix | `min_age_hours` (72 h) |
| read in part | `unread_age_days` (14 d) |
| Docker (nothing is read) | `min_age_hours` (72 h) |
| major update of a listed name | at least `major_age_days` (14 d) |
| major update of an unlisted name | person |
| new name, unlisted | person unless read in full and the name is `new_name_age_days` (365 d) old |

In a pull request that carries a fully read security fix, the other
updates that are known, not new, not major and fully read need no age
either (`fast_path_companions: ride-along`).

## Ecosystems

| Ecosystem | Shape and change set | Bound | FirstSeen | Read |
|---|---|---|---|---|
| Go modules | `golang.org/x/mod/modfile` on base and head `go.mod`; `go.sum` lines by exact shape | `go mod download -json` in an empty module, checksum database on | index.golang.org | the module zips |
| npm | `npm ls --package-lock-only --ignore-scripts --offline` at base and head; lockfile v2 and v3 only | lock `integrity` equals the registry's and the downloaded bytes | registry `time[version]` | the tarballs, whose `package.json` and `binding.gyp` files are also checked for install scripts |
| GitHub Actions | changed lines must be pin lines (`uses: owner/repo@<40 hex> # vX.Y.Z`, or a tag line in a workflow onboarded to `actions.lock`) and `actions.lock` entries | the tag resolves to the pinned commit; repository and owner IDs unchanged | the release's `published_at` when the release is immutable | the action repository's tarball, `dist/` included |
| Docker | changed lines must be `FROM` lines, differing only in tag and digest | the registry resolves the tag to the new digest now | Docker Hub `tag_last_pushed`, GCR `timeUploadedMs` | nothing |

Limits that send real pull requests to a person:

- uv, OpenTofu, submodules and every other ecosystem have no rule.
- An Actions update needs `actions.lock`: without it there is no recorded
  repository and owner ID to compare with.
- A changed `uses:` line that points at a reusable workflow never merges.
  That includes a caller's pin of this gate.
- Docker images merge only from the list, and only from docker.io and
  gcr.io.
- Pre-releases and pseudo-versions are never an increase.

## Configuration

Built-in settings are in
[internal/config/policy/defaults.json](internal/config/policy/defaults.json).
A repository may add `.github/dep-review.json`
([example](examples/dep-review.json)). It is read from the default branch
only, never from the pull request. Unknown keys are errors, and a file
that cannot be used sends every pull request to a person instead of
falling back to the defaults.

| Key | Default | A repository may |
|---|---|---|
| `min_age_hours` | 72 | raise it |
| `unread_age_days` | 14 | raise it |
| `major_age_days` | 14 | raise it |
| `new_name_age_days` | 365 | raise it |
| `wait_deadline_days` | 7 | set it, 1 to 3650 |
| `fast_path` | true | turn it off |
| `fast_path_companions` | `ride-along` | set `wait` |
| `listed` | see below | add entries |
| `chunk_bytes`, `max_chunks` | 400000, 12 | lower them |
| `model`, `effort`, `context_tokens`, `max_output_tokens`, `request_timeout_seconds`, `attempts` | `claude-opus-5-5`, `high`, ... | not set them |

The list names the publishers whose major updates and new packages may
merge, and the only Docker images that may. An entry ending in `/` is a
namespace; any other entry is a name and everything below it. Matching is
exact and case-sensitive, with no wildcards. Entries can be added, never
removed.

```json
{
  "go_modules": ["golang.org/x/", "google.golang.org/", "cloud.google.com/go",
                 "github.com/aws/", "github.com/Azure/", "github.com/AzureAD/",
                 "github.com/microsoft/", "github.com/microsoftgraph/",
                 "go.opentelemetry.io/"],
  "github_actions": ["actions/", "github/", "docker/"],
  "docker": ["docker.io/library/", "gcr.io/distroless/"],
  "npm": ["tailwindcss", "@tailwindcss/"]
}
```

### Measuring a change before shipping it

`dep-review replay` decides a directory of recorded pull requests offline
and prints one line for each (outcome, reasons, and what it stopped on),
then the totals for each ecosystem:

```
dep-review replay --dir records --now 2026-11-23T00:00:00Z \
    [--policy changed-defaults.json] [--name-created 2020-01-01T00:00:00Z]
```

A record is one JSON file for one pull request: its ecosystem, when it was
created, and every changed path with its mode and content at the merge
base and at the head ([internal/replay](internal/replay/replay.go) has the
form, `internal/replay/testdata` an example). The replay runs the real
reading of those files and the real decision. Everything a registry,
GitHub or the model would be asked is taken to be favourable, and a
version is taken to be as old as its pull request. Run it with the
built-in policy and with the changed one, and compare who goes to a
person. `--policy` takes a complete file in the form of `defaults.json`,
and unlike a repository's file it may also be narrower than the built-in
one. `--name-created` is the one stand-in with a choice: without it the
age of a new name is unknown, which is person. With it, the pull requests
that do not go to a person are an upper bound on those that would not in
the gate. npm records need a local npm; nothing else is run and no
network is used.

## Jobs

```
PR opened or pushed to
  └─ caller's dep-review-trigger (no-op; its job runs for Dependabot's PRs)
       └─ workflow_run → gate.yml (nothing runs when the trigger's job was skipped)
            build     the gate, from the workflow's own commit
            classify  Dependabot's alone? head still current?     (read-only token)
            fetch     change set, facts, artifacts, text chunks    (read-only token)
            review    one tool-less model request per chunk        (OIDC token only)
            publish   decide, comment, status, merge               (gate app)
schedule → gate.yml
            build
            refresh   for every PR left waiting: the identity      (read-only token)
                      proof and the facts again, with the verdicts
                      the gate's comment remembers; no model
            publish   decide, comment, status, merge               (gate app)
```

A verdict is remembered in the gate's comment by a hash of what was read
and of the question (prompt, answer schema, model, effort), so a rebase or
a scheduled run does not ask the model again for the same content.

## Using it in a repository

1. Copy `examples/dep-review-trigger.yaml` and `examples/dep-review.yaml`
   into `.github/workflows/`. Pin `gate.yml` by commit SHA, and set
   `app_slug` and the Anthropic IDs.
2. Create the environment `dep-review` (deployment branches: default
   branch only) with variable `DEP_REVIEW_APP_ID`, secret
   `DEP_REVIEW_APP_KEY` (the gate app's private key), and optionally
   `PUSHOVER_APP_TOKEN` and `PUSHOVER_USER_KEY`.
3. Install the gate app on the repository, with write permission for
   contents, pull requests, workflows and commit statuses.
4. Create an active branch ruleset that applies to every `dependabot/`
   branch with *Restrict creations*, *Restrict updates* and *Restrict
   deletions*, and Dependabot as the only bypass actor. classify asks
   GitHub which rules apply to the pull request's branch and treats the
   pull request as not Dependabot's alone without all three. It cannot see
   the bypass list, so keeping that list to Dependabot is the owner's job.
5. Give the default branch a ruleset rule that requires at least one
   status check besides `dep-review`. Classic branch protection does not
   count.
6. Onboard the workflows to `.github/workflows/actions.lock` if Actions
   updates should merge.
7. Give the Anthropic workspace a workload identity federation rule that
   admits the review job: the repository's immutable OIDC subject, event
   `workflow_run`, and a `job_workflow_ref` of this repository's
   `gate.yml`. The workflow uses no API key.
8. Optionally add `.github/dep-review.json`.

`ignore_ecosystems` (comma-separated, default empty) is for an ecosystem
whose Dependabot pull requests another trusted process owns. Names are the
ones in Dependabot's branch names (`go_modules`, `npm_and_yarn`,
`github_actions`, `docker`, `submodules`, `uv`); an unknown name fails the
run. Only a pull request that passes the whole identity proof is ignored,
and it then gets no status, comment or notification.

## What it does not catch

- An attacker who studies the gate. A payload that the model does not
  object to, in a release that stays published and unflagged for the
  required age, merges.
- Anything in a Docker image: images are never read. A listed image whose
  tag still resolves to the pinned digest after 72 hours merges unseen.
- Code the model was not shown. Files that are not text, and text beyond
  the chunk budget, are listed as unread; such an update is only partly
  read and still merges, after `unread_age_days`. For a bundled file over
  256 KB only the lines that occur nowhere in the old file are shown.
- A forged npm provenance statement: the gate reads the statement the
  registry serves and does not verify its signature.
- A broken update. The gate does not look at CI; the default branch's
  required checks are the only thing between a failing update and a
  merge, which is why ChecksConfigured is a fact.
- Who may push to `dependabot/` branches beyond what GitHub's rules say:
  the ruleset's bypass list is not visible to the gate.
- A wrong answer from a source the gate trusts: the Go checksum database
  and index, the npm registry, Docker Hub, GCR, GitHub's API and its
  Advisory Database.

## Trust boundaries

- **Default-branch code only.** `workflow_run` and `schedule` run the
  caller's workflow from the default branch, and every job runs the gate
  built from the commit the caller pinned. Nothing from a pull request is
  executed: the change set is read from git objects, and artifacts are
  downloaded, verified against the pinned hash and diffed.
- **Checksums between jobs.** Anything holding a run's runtime token can
  replace the run's artifacts, so every job checks the gate binary and
  every artifact it uses against sha256 sums that their producers passed
  as job outputs.
- **Secrets.** classify, fetch and refresh hold a read-only token and no
  secret. review holds only the OIDC token it exchanges for a short-lived
  Claude token, and no access to the repository; the model gets text in a
  request and has no tools. publish alone holds the gate app's token, in
  the `dep-review` environment, and parses no untrusted text in a shell.
- **What a job can assert.** The model can only veto: no answer of its
  makes a decision more permissive than "no veto". The facts file has no
  member that says an update was read; that comes only from the verdicts
  file, matched by content hash. publish believes the facts of an event's
  run only about the pull request and head that classify proved. The
  policy file never comes from the pull request.
- **Third-party text.** Everything a registry, a dependency or the model
  wrote reaches the comment only through one sanitiser, in code spans,
  with a length cap; it reaches logs only through a logger that escapes
  control characters and workflow commands. Notifications and commit
  statuses carry only the gate's own words.
- **The scheduled path** has no model and no credential to ask one with.
  Its one unprivileged job runs both the identity proof and the fetch, so
  there publish has no second job's word to check the facts against.
- **One app per owner.** The gate app's private key sits in the
  `dep-review` environment of every repository the app is installed on.
  Anyone who can get a workflow change onto one such repository's default
  branch can mint the app's token for all of them.
- **Caches** are outside the checksum chain. The gate uses none.

## Layout

| Path | What |
|---|---|
| `.github/workflows/gate.yml` | the reusable workflow |
| `cmd/dep-review` | one subcommand per job, and `replay`; flags, files, exit codes |
| `internal/classify` | the identity proof |
| `internal/gather` | the fetch and review jobs |
| `internal/facts/{gomod,npm,actions,docker}` | each ecosystem's facts |
| `internal/advisory` | GitHub's Advisory Database |
| `internal/artifact` | download, verify, extract, diff, chunk |
| `internal/veto` | the model request and its credentials |
| `internal/wire` | the files the jobs hand each other |
| `internal/allow` | the decision: a pure function of facts, policy and time |
| `internal/config` | the built-in settings and a repository's file |
| `internal/land` | the publish job: comment, status, merge, notification |
| `internal/replay` | the decision over recorded pull requests, offline |
| `internal/gh` | the GitHub REST client |

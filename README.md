# dep-review

A merge gate for Dependabot pull requests, as a reusable GitHub Actions
workflow. It merges an update without a person when a short list of facts
about it holds, quickly for security fixes in Go modules and npm, and
hands everything else to a person with the one fact that failed.

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
failing is a wait, and so is GitHub's "Base branch was modified" (another
merge landed at the same moment; the next scheduled run asks again). Any
other refusal is reported (status `error`) and not retried.

A run that cannot decide is not silent. When the fetch job leaves no
facts, or deciding fails, publish still runs: it sets the status to
`error`, writes the comment ("the run failed", with the workflow run to
re-run) and notifies once per head commit. When the review job fails or
leaves a prepared read without a verdict, the pull request waits as
before and the owner is told once, because the scheduled run asks no
model and would not end that wait. A classify job that fails leaves only
the failed workflow run: nothing is written on a pull request that was
not classified.

To run the gate again, re-run all jobs of the workflow run, which is
what the comment and the notification say. Publish decides only on facts
gathered in the last 4 hours, by the fetch job's clock and its own.
GitHub's "re-run failed jobs" hands a job that runs again the artifacts
of the first attempt, so a publish or review job run again by itself
would decide on what the registries said then with the clock of now.
Such a run is reported as one that could not decide. The 4 hours are the
timeouts of fetch, review and publish (2 h 35 min) and the time a job
may wait for a runner or for the publishes ahead of it.

Waiting for an age has no deadline. Waiting for a retry (a model read, a
source that did not answer, a superseded Docker digest, required checks)
ends `wait_deadline_days` after the latest time the update could have
merged, or after the pull request was opened if that is later; then it is
a person's. While neither time is known (GitHub and the registry's clock
both went unanswered) there is no deadline, and the pull request waits.

## Facts

For the pull request:

| Fact | Meaning | Source |
|---|---|---|
| Identity | Dependabot's alone, on the default branch, at its current head | `internal/classify`: author, signed commits, the branch's activity log, the pull request's timeline, GitHub's rules for the branch |
| Shape | only that ecosystem's manifest and lock files changed, each a plain file (mode 100644) at both commits, and only version or hash tokens | the real tool's reading of base and head, or exact line shapes |
| ChecksConfigured | the default branch has an active rule requiring a status check other than `dep-review` | GitHub `rules/branches` |

For every update, computed from the base and head manifests and never
from the pull request's title, body, labels or Dependabot's metadata:

| Fact | Meaning |
|---|---|
| Known | the name is a dependency at the base commit, or is on the list (Docker: on the list only) |
| Listed | the name is on the owner's list |
| NewName | the name is absent at base |
| Increase | `to` is a plain release above `from` (Go: a listed module may also move to a higher pseudo-version) |
| Major | the leading version component changed (for an image, the tag's: a refresh under an unchanged tag is never a major, also when the tag is `latest` or another name that is not a version and nothing could be compared) |
| Indirect | the repository's own manifest shows it does not declare the dependency: `// indirect` in `go.mod`, or in none of the root package's dependency maps in `package-lock.json` (Go and npm only) |
| Bound | the pinned hash, commit or digest is what the registry reports now |
| FirstSeen | when the version became public, by a clock the publisher cannot set; where the registry has none, when the gate first evaluated that exact pin (name, version and hash) on the pull request, which its comment remembers |
| NameCreated | when the package name first appeared (new names only) |
| Clean | still published; not retracted, yanked or deprecated; no malware advisory; no advisory on `to` that `from` did not have (an action used from a directory, `owner/repo/path`, is asked about under the repository's name and its own) |
| NoRegress | no new or changed install script; npm: in the tarball the install scripts (each hook's command as written), `gypfile` and `binding.gyp` beside every `package.json` are the old tarball's, none new, changed or gone, while the files those commands and a `binding.gyp` run are not compared, since the model reads them; provenance not lost; Actions: the new commit descends from the old one, is on the default branch or `releases/v<major>`, and is what the tag resolves to |
| SecurityFix | GitHub's Advisory Database has a reviewed advisory that affects `from`, not `to`, and names `to` as first patched version (Go and npm only: never an image, and never an action, whose tag can be moved after the advisory was reviewed) |
| Read | how much of the changed code the model was shown and answered for: full, partial, none, refused, or not applicable (Docker). Two artifacts that hold the same files are full with no model asked, and the comment says so |
| Veto | none, or a category and the lines the model quoted |

A fact is in one of four states, and only the first contributes to a
merge: it holds; it does not hold (person); its source was asked and did
not answer (wait, then person at the deadline); it was never gathered
(person). One outage does not wait: when the registry or GitHub does not
answer for Bound of a Go, npm or Actions update, there is no verified
hash to read the code against, nothing is read, and an update that was
not read is a person's at once (`read_unknown`; re-run the gate after
the outage). A Docker update waits, because nothing of an image is read.
Identity waits like any other fact: when the branch's activity log has
not caught up with the push, or GitHub does not answer for the log, the
timeline or the branch's rules, the proof is unfinished, the other facts
are gathered all the same, and the scheduled run tries the proof again.
An answer that is not proof (someone else pushed, no ruleset, a 403 or a
404) is a person's at once.

With every fact holding, an update needs an age, measured from FirstSeen:

| Case | Required age (default) |
|---|---|
| read in full, security fix | none |
| read in full | `min_age_hours` (72 h) |
| read in part, security fix | `min_age_hours` (72 h) |
| read in part | `unread_age_days` (14 d) |
| Docker (nothing is read) | `min_age_hours` (72 h) |
| major update of a listed name, or of an indirect dependency | at least `major_age_days` (14 d) |
| major update of an unlisted name the repository declares itself | person |
| new name, unlisted | person unless read in full and the name is `new_name_age_days` (365 d) old |

In a pull request that carries a fully read security fix, the other
updates that are known, not new, not major and fully read need no age
either (`fast_path_companions: ride-along`).

The two security-fix rows are for Go modules and npm. An action's
security fix waits like any other update of an action, 72 h when read in
full: the advisory vouches for a tag, and a tag can be moved after the
advisory was reviewed. The comment still names the advisory, so the fix
can be merged by hand. An image has no advisory source at all.

Where a registry has no such clock (an Action release that is not
immutable, most of all, and every gcr.io image: GCR dates the upload of
a manifest, not the moment a tag was pointed at it), the age runs from
the gate's first evaluation of the pin, not from the day the pull request
was opened: Dependabot rewrites a grouped pull request in place, and a
version it adds today is new today. A rebase keeps the pin's time;
another version or hash starts again.

For Go the registry's clock has a limit of its own. The index has no
lookup by module: it is read forward from the version's commit time, 50
pages for one version and 150 for one run. A tag that was cut days after
its commit is not in those pages, and each such version costs 50 of the
run's 150, so in a grouped pull request the updates looked up after them
can get no lookup at all. All of these are dated from the gate's first
evaluation and wait their age from there. A fully read security fix
needs no age and is not held up.

## Ecosystems

| Ecosystem | Shape and change set | Bound | FirstSeen | Read |
|---|---|---|---|---|
| Go modules | `golang.org/x/mod/modfile` on base and head `go.mod`; `go.sum` lines by exact shape; only `require` lines and the `go` line change, and no requirement is removed | `go mod download -json` in an empty module, checksum database on | index.golang.org | the module zips, from proxy.golang.org, checked against the `go.sum` hash |
| npm | `npm ls --package-lock-only --ignore-scripts --offline` at base and head; lockfile v2 and v3 only; every lock entry has only the members npm writes, and a new version replaces one old version at the same lock paths and is not marked as bringing an `npm-shrinkwrap.json` | lock `integrity` equals the registry's and the downloaded bytes | registry `time[version]` | the tarballs, whose `package.json` and `binding.gyp` files are also checked for install steps: npm's NoRegress holds only once they were |
| GitHub Actions | changed lines must be tag pin lines in a workflow (`uses: owner/repo@vX.Y.Z`) and the `actions.lock` entries that record them (lock schema `v0.0.3`), each tag line through its own workflow's list in the lock | the tag resolves to the pinned commit; repository and owner IDs unchanged | the release's `published_at` when the release is immutable | the action repository's tarball, `dist/` included, for an action that runs its repository's own files (`using: nodeNN` or `composite` where the workflows use it from) |
| Docker | changed lines must be `FROM` lines that name an official Docker Hub image by its bare name (`golang`) or a gcr.io image, differing only in tag and digest | the registry resolves the tag to the new digest now | Docker Hub `tag_last_pushed`; for a gcr.io image the gate's first evaluation of the pin | nothing |

Limits that send real pull requests to a person:

- uv, OpenTofu, submodules and every other ecosystem have no rule.
- An Actions update needs a tag pin (`@vX.Y.Z`) and `actions.lock`:
  without the lock entry there is no recorded repository and owner ID to
  compare with. The lock must list the workflow the line is in, and that
  workflow's list must move to the new tag with it: an entry that only
  another workflow's list names does not count. A line that pins a
  commit (`@<40 hex> # vX.Y.Z`) and a local `action.yml` are not read. A
  pin update replaces lines in place: one that adds or removes a line of
  a workflow or of `actions.lock` (an action that starts or stops using
  another) goes to a person.
- A changed `uses:` line that points at a reusable workflow never merges.
  That includes a caller's pin of this gate.
- A container action: `runs.using: docker` in its `action.yml`, with an
  image by reference or built from a Dockerfile, or a composite action
  with a `docker://` step. It runs an image, and nothing of an image is
  read. The gate looks at the `action.yml` (or `action.yaml`) in the
  directory the workflows use the action from, and takes one line there,
  `using: nodeNN` or `using: composite`; a file that says it any other
  way, or no file, goes to a person too.
- Docker images merge only from the list, and only when written as an
  official Docker Hub image by its bare name or as a gcr.io image. Any
  other spelling (`library/golang`, `grafana/grafana`, another registry)
  is not read, whatever the list says.
- A Go update that removes a requirement (a move from `example.com/m/v2`
  to `/v3` does) or changes the `toolchain` line.
- An npm update whose tarball adds, changes or drops an install script, a
  `gypfile` or a `binding.gyp`, or whose lock has an entry with a member
  npm 9 to 11 do not write.
- An npm update whose lock changes what it says of a package that keeps
  its version (its `bin`, `os`, `cpu`, `libc` or dependency ranges, like
  its source and hash). Only `dev`, `optional`, `devOptional`, `peer`,
  `deprecated`, `license`, `funding` and `engines` may differ there.
- An npm update to a version whose lock entry has `hasShrinkwrap`: the
  package ships an `npm-shrinkwrap.json`, npm installs what is below it
  as that file says, scripts included, and the gate does not read it.
- An npm update whose lock at the base commit npm itself reports a
  problem for (a missing or invalid entry, as two lock edits merged
  without a rebase leave behind). The pull request that repairs the lock
  is the one that goes to a person.
- A Go, npm or Actions update whose registry did not answer when its
  pinned hash was checked (see the four states above).
- An update that changes, adds or removes a file whose path has anything
  but ASCII letters, digits and `._/@+-` in it (a space, a parenthesis,
  another script). A path stands on lines the model is told the gate
  wrote, so one that can read as a sentence is not written there.
- An update in which nothing that changed can be shown to the model:
  only files that are not text changed (a prebuilt object, an image), or
  nothing of the change fits the chunk budget. No model is asked, so it
  is not a read in part.
- The gate runs on github.com only.
- A pre-release is never an increase. A Go pseudo-version (a commit, not
  a release) is one only for a listed module, and can then merge like a
  release: `google.golang.org/genproto` publishes nothing else. For it
  the retraction check is the go command's word alone, since no version
  list carries a pseudo-version. A module that is not listed never moves
  to one; from one to a release it moves like any other update. The
  advisory database is asked about a pseudo-version only in the two forms
  it was seen to read, `vX.0.0-TIME-COMMIT` and, after a release,
  `vX.Y.Z-0.TIME-COMMIT`. An update to or from any other, such as one
  that follows a pre-release (`v1.2.0-rc.1.0.TIME-COMMIT`), goes to a
  person.

## Configuration

The settings are built into the gate, in
[internal/config/policy/defaults.json](internal/config/policy/defaults.json),
and they are the only ones. A repository has no settings file, and
nothing in a repository or a pull request changes a value. What differs
between repositories is in the caller's workflow (`app_slug`,
`ignore_ecosystems`, the Anthropic IDs) and in `dependabot.yml`.

| Key | Value |
|---|---|
| `min_age_hours` | 72 |
| `unread_age_days` | 14 |
| `major_age_days` | 14 |
| `new_name_age_days` | 365 |
| `wait_deadline_days` | 7 |
| `fast_path` | true |
| `fast_path_companions` | `ride-along` |
| `listed` | see below |
| `chunk_bytes`, `max_chunks` | 400000, 12 |
| `model`, `effort`, `context_tokens`, `max_output_tokens`, `request_timeout_seconds`, `attempts` | `claude-opus-5-5`, `high`, ... |

The list names the publishers whose major updates and new packages may
merge, and the only Docker images that may. A major update of a
dependency the repository does not declare itself (one that a parent
pulls in) needs no entry. An entry ending in `/` is a
namespace; any other entry is a name and everything below it. Matching is
exact and case-sensitive, with no wildcards. A Docker entry is matched
against `docker.io/library/<name>` for an official image and
`gcr.io/<repository>` for a gcr.io image; no other image is read, so an
entry for one (`docker.io/your-org/`) never matches.

To list a publisher, add the entry to `defaults.json` and to the block in
section 5 of [the spec](docs/v0.2-spec.md) (a test holds the two
together), measure it with the replay below, release the gate and move
the caller's pin of `gate.yml`. Until the pin has moved, the pull request
is merged by hand. Every entry is public here, also one that only a
private repository uses.

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
person. `--policy` takes a complete file in the form of `defaults.json`.
It may be wider or narrower than the built-in one, and the replay is the
only thing that reads a policy from a file (`replay.ReadPolicy`).
`--name-created` is the one stand-in with a choice: without it the
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
            publish   the identity proof once more, then decide,   (gate app)
                      comment, status, merge
```

Publish jobs run one at a time in a repository and wait for each other
in order (`queue: max`), so two merges never reach the base branch at the
same moment. fetch and refresh run npm from a pinned Node major, not the
runner image's.

A verdict is remembered in the gate's comment by a hash of what was read
and of the question (prompt, answer schema, model, effort). That is for
the scheduled run, which has no model and decides on what was read
before. An event's run (a push, a rebase, a re-run) always asks the
model, whatever the comment remembers.

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
   pull request as not Dependabot's alone without all three. An update
   rule that lets anyone pull the base branch in
   (`update_allows_fetch_and_merge`) does not count. It cannot see the
   bypass list, so keeping that list to Dependabot is the owner's job.
5. Give the default branch a ruleset rule that requires at least one
   status check besides `dep-review`. Classic branch protection does not
   count.
6. Pin actions by tag and onboard the workflows to
   `.github/workflows/actions.lock` if Actions updates should merge.
7. Give the Anthropic workspace a workload identity federation rule that
   admits the review job: the repository's immutable OIDC subject, event
   `workflow_run`, and a `job_workflow_ref` of this repository's
   `gate.yml`. The workflow uses no API key.

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
- What an action or an install script downloads when it runs: a tool, an
  installer, a prebuilt binary. The model sees the lines that fetch it.
- Code the model was not shown. Files that are not text, and text beyond
  the chunk budget, are listed as unread; such an update is only partly
  read and still merges, after `unread_age_days`, as long as the model
  was shown at least some of the change. For a bundled file over
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
  member that says a model read an update; that comes only from the
  verdicts file, matched by content hash. The one read that counts
  without a verdict is of two artifacts that hold the same files, where
  there is nothing to show a model and the facts file says so. publish
  believes the facts only about the pull request and head that classify
  proved: the classify job on an event, its own run of the proof on a
  schedule. The policy is built into the gate: no file of a repository
  or a pull request changes it.
- **Third-party text.** Everything a registry, a dependency or the model
  wrote reaches the comment only through one sanitiser, in code spans,
  with a length cap; it reaches logs only through a logger that escapes
  control characters and workflow commands. Notifications and commit
  statuses carry only the gate's own words.
- **The scheduled path** has no model and no credential to ask one with.
  Its one unprivileged job runs both the identity proof and the fetch, so
  publish takes neither on its word: it runs the proof again itself for
  every refreshed pull request and believes the facts only as far as that
  goes.
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
| `internal/model` | classify's answer as a file, and Dependabot's names for the ecosystems |
| `internal/gather` | the fetch and review jobs |
| `internal/facts` | what a gatherer is given and hands back |
| `internal/facts/{gomod,npm,actions,docker}` | each ecosystem's facts |
| `internal/advisory` | GitHub's Advisory Database |
| `internal/artifact` | download, verify, extract, diff, chunk |
| `internal/veto` | the model request and its credentials |
| `internal/wire` | the files the jobs hand each other |
| `internal/allow` | the decision: a pure function of facts, policy and time |
| `internal/config` | the built-in settings |
| `internal/land` | the publish job: comment, status, merge, notification |
| `internal/replay` | the decision over recorded pull requests, offline |
| `internal/gh` | the GitHub REST client |

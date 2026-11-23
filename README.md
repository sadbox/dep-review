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
One kind of update merges with nothing read: a reusable workflow of the
gate owner's own repositories (see "The owner's own workflows" below).

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
| merge | every fact holds, no veto, the default branch has not changed a file of the pull request, and GitHub accepts the merge | squash merge of exactly the head commit the facts are about |
| wait | only time, CI, or a retry is missing | status `pending`; the scheduled run looks again |
| person | a fact is false or was never established, or the model raised a veto | status `failure`, one comment, one notification |

The gate writes one comment per pull request, which leads with the
outcome and, for wait and person, the fact that failed and the cheapest
way out. It sets the commit status `dep-review` and, when a person is
needed and Pushover is configured, notifies once per head commit. A
status that says what the gate last set on that head is not set again
(GitHub keeps 1000 for a commit), and one that cannot be set does not
stop the comment or the notification.

The gate does not judge CI. It asks GitHub to merge with `sha=<head>`, and
GitHub's rules decide; a refusal because required checks are pending or
failing is a wait, and so is GitHub's "Base branch was modified" (another
merge landed at the same moment; the next scheduled run asks again). Any
other refusal is reported (status `error`) and not retried.

Before it asks, the gate looks at what the default branch has changed
since the commit the pull request branches from. If that includes a file
the pull request changes, it does not ask: the facts are about the head
on the base it had, and two edits of one lock file can merge without a
conflict into a lock nobody proposed. The pull request waits
(`base_changed`). Dependabot usually rebuilds it within minutes, and the
new head gets a run of its own; if not, the owner is told, once for the
head: at once for a security fix, otherwise at the first scheduled run a
day after the hold began. The notification names the file and the
comment that has Dependabot rebase. At the wait deadline it needs a
person (`base_changed_deadline`). A pull request
that is only behind merges as it is. The gate never rebases, updates or
comments to bring a pull request up to date.

A run that cannot decide is not silent. When the fetch job leaves no
facts, or deciding fails, publish still runs: it sets the status to
`error`, writes the comment ("the run failed", with the workflow run to
re-run) and notifies once per head commit. A classify job that fails
leaves only the failed workflow run: nothing is written on a pull
request that was not classified.

When the model leaves a prepared read without a verdict (it did not
answer, the review job failed, the token exchange was denied), the pull
request waits and the scheduled run asks again by itself: at its next
run, then 30 minutes after that ask, then after 1 hour, 2 hours and so
on, each gap twice the one before, until the wait deadline. One miss
needs nobody. When the second scheduled ask also gets no answer the
owner is told once per head commit, and the gate goes on asking.

To run the gate again, re-run all jobs of the workflow run, which is
what the comment and the notification say. Publish decides only on facts
gathered in the last 4 hours, by the fetch job's clock and its own.
GitHub's "re-run failed jobs" hands a job that runs again the artifacts
of the first attempt, so a publish or review job run again by itself
would decide on what the registries said then with the clock of now.
Such a run is reported as one that could not decide. The 4 hours are the
timeouts of fetch, review and publish (2 h 35 min; a scheduled run's
refresh, reread and publish have 2 h 45 min) and the time a job may wait
for a runner or for the publishes ahead of it.

Waiting for an age has no deadline. Waiting for a retry (a model read, a
source that did not answer, a superseded Docker digest, required checks,
a merge held because the default branch changed a file of the pull request)
ends `wait_deadline_days` after the latest time the update could have
merged, or after the pull request was opened if that is later; then it is
a person's. While neither time is known (GitHub and the registry's clock
both went unanswered) there is no deadline, and the pull request waits.
A wait the scheduled run cannot evaluate again (gathering its facts
keeps failing) is a person's at the deadline of its last decision all
the same: publish says so on the pull request and notifies.

The scheduled run also takes up a Dependabot pull request the gate has
nothing for at its head: the event's run died before it could write
anything, or the comment is one this version cannot read, as on every
pull request left open by v0.1. It waits until the pull request has not
changed for 4 hours, so as not to race the event's run, evaluates at
most five such pull requests in a run, from scratch and without the
model, and asks the model at the run after. If it cannot evaluate one,
publish reports that once (status `error`, the comment, a notification)
and the schedule does not try that head again.

A notification that could not be sent is sent by the next scheduled run.
Without Pushover configured there is nobody to tell, and nothing is
owed.

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
| Bound | the pinned hash, commit or digest is what the registry reports now; for an action also that the repository has the IDs `actions.lock` records, or for an own workflow the IDs the policy records |
| FirstSeen | when the version became public, by a clock the publisher cannot set; where the registry has none, when the gate first evaluated that exact pin (name, version and hash) on the pull request, which its comment remembers |
| NameCreated | when the package name first appeared (new names only) |
| Clean | still published; not retracted, yanked or deprecated; no malware advisory; no advisory on `to` that `from` did not have (an action used from a directory, `owner/repo/path`, is asked about under the repository's name and its own; an own workflow needs no published release) |
| NoRegress | no new or changed install script; npm: in the tarball the install scripts (each hook's command as written), `gypfile` and `binding.gyp` beside every `package.json`, and every `.gypi` file, are the old tarball's, none new, changed or gone, while the other files those commands and a `binding.gyp` run are not compared, since the model reads them (none of this is asked where the repository turns install scripts off, see below); provenance not lost; Actions: the new commit descends from the old one, is on the default branch or `releases/v<major>` (an own workflow: the default branch only), and is what the tag resolves to |
| SecurityFix | GitHub's Advisory Database has a reviewed advisory that affects `from`, not `to`, and names `to` as first patched version (Go and npm only: never an image, and never an action, whose tag can be moved after the advisory was reviewed) |
| Own | Actions only: the update moves the commit pin of a reusable workflow in one of the gate owner's own repositories (`own_workflows`) |
| Read | how much of the changed code the model was shown and answered for: full, partial, none, refused, or not applicable (Docker, and an own workflow). Two artifacts that hold the same files are full with no model asked, and the comment says so |
| Veto | none, or a category and the lines the model quoted |

A fact is in one of four states, and only the first contributes to a
merge: it holds; it does not hold (person); its source was asked and did
not answer (wait, then person at the deadline); it was never gathered
(person). That goes for Bound too. When the registry or GitHub does not
answer for the pin of a Go, npm or Actions update, there is no verified
hash to read the code against yet, so nothing is fetched and the update
waits (`source_unavailable`, `read_pending`); the scheduled run gathers
again, and reads the code once the pin is bound. A pin the registry
answered "no" for is a person's at once.
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
| the owner's own workflow (nothing is read) | none |
| major update of the owner's own workflow | person |
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
lookup by module: it is read forward from a point in time. The gate
starts where proxy.golang.org says it stored the version (the
`Last-Modified` header of its answer for the version's `.mod` file),
which is where the index has it; the date is the one on the index's own
line. When the header is missing or leads to no line, the index is read
from the version's commit time, 50 pages for one version, and a tag that
was cut days after its commit is not in those pages. One run reads 150
pages in all. A version found neither way is dated from the gate's first
evaluation and waits its age from there. A fully read security fix needs
no age and is not held up.

## Ecosystems

| Ecosystem | Shape and change set | Bound | FirstSeen | Read |
|---|---|---|---|---|
| Go modules | `golang.org/x/mod/modfile` on base and head `go.mod`; `go.sum` lines by exact shape; only `require` lines and the `go` line change, and no requirement is removed | `go mod download -json` in an empty module, checksum database on | index.golang.org | the module zips, from proxy.golang.org, checked against the `go.sum` hash |
| npm | `npm ls --package-lock-only --ignore-scripts --offline` at base and head; lockfile v2 and v3 only; every lock entry has only the members npm writes, and a new version replaces one old version at the same lock paths and is not marked as bringing an `npm-shrinkwrap.json` | lock `integrity` equals the registry's and the downloaded bytes | registry `time[version]` | the tarballs, whose `package.json`, `binding.gyp` and `.gypi` files are also checked for install steps: npm's NoRegress holds only once they were, or where the repository turns install scripts off |
| GitHub Actions | changed lines must be tag pin lines in a workflow (`uses: owner/repo@vX.Y.Z`) and the `actions.lock` entries that record them (lock schema `v0.0.3`), each tag line through its own workflow's list in the lock; or the commit pin line of the owner's own reusable workflow (`uses: owner/repo/.github/workflows/<file>.yml@<40 hex> # vX.Y.Z`) | the tag resolves to the pinned commit; repository and owner IDs unchanged | the release's `published_at` when the release is immutable; not asked for an own workflow | the action repository's tarball, `dist/` included, for an action that runs its repository's own files (`using: nodeNN` or `composite` where the workflows use it from); nothing of an own workflow |
| Docker | changed lines must be `FROM` lines that name an official Docker Hub image by its bare name (`golang`) or a gcr.io image, differing only in tag and digest | the registry resolves the tag to the new digest now | Docker Hub `tag_last_pushed`; for a gcr.io image the gate's first evaluation of the pin | nothing |

Limits that send real pull requests to a person:

- uv, OpenTofu, submodules and every other ecosystem have no rule.
- An Actions update needs a tag pin (`@vX.Y.Z`) and `actions.lock`:
  without the lock entry there is no recorded repository and owner ID to
  compare with. The lock must list the workflow the line is in, and that
  workflow's list must move to the new tag with it: an entry that only
  another workflow's list names does not count. A line that pins an
  action by commit (`@<40 hex> # vX.Y.Z`) and a local `action.yml` are
  not read. A pin update replaces lines in place: one that adds or
  removes a line of a workflow or of `actions.lock` (an action that
  starts or stops using another) goes to a person.
- A changed `uses:` line that points at a reusable workflow never
  merges, unless the workflow is one of the owner's own (next section).
- A container action: `runs.using: docker` in its `action.yml`, with an
  image by reference or built from a Dockerfile, or a composite action
  with a `docker://` step. It runs an image, and nothing of an image is
  read. The gate looks at the `action.yml` (or `action.yaml`) in the
  directory the workflows use the action from, and takes one line there,
  `using: nodeNN` or `using: composite`, under a bare `runs:`, in a
  file written in YAML's plain block form (plain keys, no flow style,
  quoted keys, anchors, aliases or second document); a file that says it
  any other way, or no file, goes to a person too. A composite action
  can run other actions of its repository, so when one is used every
  `action.yml` of the repository is held to this.
- Docker images merge only from the list, and only when written as an
  official Docker Hub image by its bare name or as a gcr.io image. Any
  other spelling (`library/golang`, `grafana/grafana`, another registry)
  is not read, whatever the list says.
- A Go update that removes a requirement (a move from `example.com/m/v2`
  to `/v3` does) or changes the `toolchain` line.
- An npm update whose tarball adds, changes or drops an install script, a
  `gypfile`, a `binding.gyp` or a `.gypi` file, unless the repository
  turns install scripts off (below), or whose lock has an entry with a
  member npm 9 to 11 do not write.
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

## The owner's own workflows

A caller pins this gate, and the shared CI workflows, as reusable
workflows by commit:

```
    uses: sadbox/dep-review/.github/workflows/gate.yml@<40 hex> # vX.Y.Z
```

The gate's owner publishes those, and ruled that the gate trusts them. A
Dependabot pull request that moves such a line merges at the gate's
first look at it, once the required checks pass, with **nothing of the
update read and no age**. The comment says so in those words.

It applies to the repositories in `own_workflows` in `defaults.json` and
to no other: `sadbox/ci` and `sadbox/dep-review`, each named whole and
with the repository ID and owner ID GitHub gave it. There is no prefix
and no entry for an owner or an organisation. What must hold:

- Identity, Shape and ChecksConfigured, as for every pull request. The
  line keeps its repository and its workflow file; only the commit and
  the version in the comment move, and no other line changes with it.
  A tag pin of such a workflow is not read.
- Increase, from the two versions.
- Bound: the tag of the new version, in the repository with exactly
  those two IDs, resolves to the new commit. A look-alike name, a
  repository that was renamed away, and a name someone else registered
  again fail here or in Shape.
- NoRegress: the new commit descends from the old pin and is on the
  repository's default branch. A release branch does not count, and a
  commit that only a fork has is on no branch.
- Clean: no advisory names it. A release is not asked for.
- Not a major. A major version of an own workflow always goes to a
  person, listed or not: that is how a release says that callers may
  have to change with it.

An action in the same (grouped) pull request is read and aged by its own
rules. Everything about a reusable workflow of any other repository is
as before: a person.

What this trusts and does not check: that only the owner can put a
version tag on those two default branches. A gate release reaches every
caller unread, and no pull request runs the new gate before it merges
(a new CI workflow is run by the caller's required checks). So a gate
release that changes `gate.yml`'s inputs or secrets has to be a new
major. While both repositories are on v0 there are no majors, and that
safeguard does nothing.

## Configuration

The settings are built into the gate, in
[internal/config/policy/defaults.json](internal/config/policy/defaults.json),
and they are the only ones. A repository has no settings file, and
nothing in a repository or a pull request changes a value. What differs
between repositories is in the caller's workflow (`app_slug`,
`ignore_ecosystems`, the Anthropic IDs) and in `dependabot.yml`. One
file of a repository is read for a fact, and it is no setting: a root
`.npmrc` that turns npm's install scripts off (see "npm: turning install
scripts off").

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
| `own_workflows` | `sadbox/ci`, `sadbox/dep-review`, with their IDs (see above) |
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
  "github_actions": ["actions/", "github/", "docker/", "astral-sh/"],
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
            refresh   for every PR left waiting, and every one     (read-only token)
                      the gate has nothing for at its head: the
                      identity proof and the facts again, and which
                      reads the model need not be asked about now
            reread    one tool-less model request per chunk of     (OIDC token only)
                      a read that has no answer yet; not on a
                      manual dispatch
            publish   the identity proof once more, then decide    (gate app)
                      on the facts, reread's verdicts and what
                      its own comment remembers; then its own look
                      at the open PRs for a wait past its deadline
                      and a notification that was not sent
```

Publish jobs run one at a time in a repository and wait for each other
in order (`queue: max`), so two merges never reach the base branch at the
same moment. fetch and refresh run npm from a pinned Node major, not the
runner image's.

A verdict is remembered in the gate's comment by a hash of what was read
and of the question (prompt, answer schema, model, effort). The
scheduled run asks the model only about a read the comment has no
answer for, and only when an ask is due; for the rest it decides on what
was read before. An event's run (a push, a rebase, a re-run) always asks
the model about every read, whatever the comment remembers. A verdict
remembered under an older prompt or model is no answer: the scheduled
run asks again.

A veto is remembered for good. Once the model has objected to an
update's code, that veto stands for the same code under the same
question in every later run, on an event and on the schedule, whatever
the model answers when it is asked again and also when it does not
answer. A rebase does not clear it and neither does running the gate
again. A person does, by merging or closing the pull request; so does
other code (a new version) and a changed prompt or model. A run that
could not write its decision keeps the veto in what it does write. The comment
keeps a veto's quotes only while there is room, and the veto without
them after that; a pull request with more vetoes than the comment can
remember at all needs a person for good (`vetoes_forgotten`).

## Using it in a repository

1. Copy `examples/dep-review-trigger.yaml` and `examples/dep-review.yaml`
   into `.github/workflows/`. Pin `gate.yml` by the commit of a release
   tag, with the version in the comment as the example has it
   (`@<40 hex> # vX.Y.Z`): that is the line the gate reads when
   Dependabot moves it. Set `app_slug` and the Anthropic IDs.
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
   admits the two review jobs: the repository's immutable OIDC subject,
   the default branch as `ref`, an event that is `workflow_run` or
   `schedule` (`claims.event_name in ["workflow_run", "schedule"]`), and
   a `job_workflow_ref` of this repository's `gate.yml`. No other event:
   the gate asks no model on a manual dispatch. The workflow uses no API
   key. While the rule does not admit `schedule`, a scheduled ask is
   denied, counts as a miss and is tried again later; nothing merges
   unread. An owner with more than one rule changes each: every
   repository passes the ID of its own as `anthropic_federation_rule_id`.
8. For npm, optionally turn install scripts off (next section).

### npm: turning install scripts off

npm runs a dependency's `preinstall`, `install` and `postinstall`
scripts, and builds a `binding.gyp`, when it installs. The gate
otherwise sends every update that adds or changes one of these to a
person. A repository that needs none of them can turn them off, and the
gate then asks nothing about them:

- a root `.npmrc` whose whole content is `ignore-scripts=true` and one
  newline. The gate compares the file's git entry with the one it knows,
  so a comment, a space or a second setting is not this file;
- wherever npm installs from the lock, the file beside `package.json`:
  in a Dockerfile, `COPY package.json package-lock.json .npmrc ./`
  before `npm ci`. Without the copy the scripts run;
- a guard before the install, because a flag or an environment variable
  overrides the file: `RUN test "$(npm config get ignore-scripts)" = true`.

The gate sees only the file. That it is copied and that nothing
overrides it is the repository's to keep, so all three go in together,
and before the repository runs a gate that has this rule. It covers the
root's `package-lock.json` only, a pull request that changes `.npmrc`
goes to a person, and the tarballs are still verified and read by the
model. Provenance is still compared. Removing the line later turns on
every install script in the lock at once, and none of them was compared
while it was there. The gate reads the file at the commit the pull
request records, which GitHub moves only when Dependabot rebuilds the
pull request, so before a merge that rests on it, publish reads the
default branch's root `.npmrc` as it is now; when it is not the same
file, the pull request waits (`scripts_off_changed`) until Dependabot
rebuilds it and the new head is evaluated on its own.

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
- Anything in the owner's own reusable workflows (`sadbox/ci`,
  `sadbox/dep-review`): a release of one merges unread and at once.
  That covers what the owner wrote and whatever third-party update the
  owner merged there by hand before tagging; neither repository runs the
  gate on itself, and the gate's jobs run with the gate app's key.
- What an action or an install script downloads when it runs: a tool, an
  installer, a prebuilt binary. The model sees the lines that fetch it.
- An install script in a repository whose `.npmrc` turns scripts off, when
  npm runs somewhere that does not read that file or is told otherwise by
  a flag or an environment variable. The gate reads the file's bytes at
  the base commit, and its git entry on the default branch before a
  merge, and nothing about how npm is run.
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
  secret. review and reread hold only the OIDC token they exchange for a
  short-lived Claude token, and no access to the repository; the model
  gets text in a request and has no tools. publish alone holds the gate
  app's token, in the `dep-review` environment, and parses no untrusted
  text in a shell.
- **What a job can assert.** The model can only veto: no answer of its
  makes a decision more permissive than "no veto", and none takes back a
  veto the gate's comment remembers. The facts file has no
  member that says a model read an update; that comes only from the
  verdicts file, matched by content hash. The one read that counts
  without a verdict is of two artifacts that hold the same files, where
  there is nothing to show a model and the facts file says so. The one
  update that merges with no read at all is the owner's own workflow:
  the facts file says `own`, and publish takes that only for a name on
  the list built into its own binary. publish
  believes the facts only about the pull request and head that classify
  proved: the classify job on an event, its own run of the proof on a
  schedule. The policy is built into the gate: no file of a repository
  or a pull request changes it. One file of the repository changes what
  a fact asks: the root `.npmrc` at the base branch's commit, by which
  npm's install inputs are not compared, and which must still be the
  default branch's for a merge that rests on it. A pull request that
  changes that file has no Shape.
- **Third-party text.** Everything a registry, a dependency or the model
  wrote reaches the comment only through one sanitiser, in code spans,
  with a length cap; it reaches logs only through a logger that escapes
  control characters and workflow commands. Commit statuses carry only
  the gate's own words, and so do notifications but for one thing: the
  name of the file a held merge is held for, through the same sanitiser.
- **The scheduled path.** refresh runs both the identity proof and the
  fetch in one unprivileged job, so publish takes neither on its word:
  it runs the proof again itself for every refreshed pull request and
  believes the facts only as far as that goes; when its proof says the
  pull request is not Dependabot's alone, that is the decision's
  Identity whatever the facts say. refresh also reads the
  gate's comment, and its copy of what the comment remembers goes to
  reread only, as a list of reads to skip in which no entry says a read
  was read. publish takes a verdict from reread's own artifact or from
  the comment, which it reads itself. A wrong list makes the model answer
  twice or leaves a read waiting; it cannot make a read count.
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

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
| review | patch/minor/digest updates whose deterministic checks all passed, or flagged only items the reviewer assesses one by one (see below) | model review; merge only on `pass` with every flagged item assessed `benign` |
| human | majors (0.x minors are reviewed like any minor), anything a check routes to a person (including an `actions.lock` change that neither a bump nor an analyzed transitive pair explains), truncated evidence, more than 200 flagged items, model `fail`/`unsure` or a `pass` that does not assess every flagged item `benign` or list every required diff as examined, a Dependabot PR someone else pushed or merged into, or whose branch history cannot be read | comment + notification, no merge |
| refuse | the PR is malformed (no updates, tag instead of SHA pin outside a workflow onboarded to `actions.lock`, a lockfile the gate cannot read strictly or that disagrees with the `uses:` lines, change set disagrees with Dependabot's metadata in a way that matters) | comment + notification |

### Flagged items (Go modules)

The Go checks flag code that runs on import (a new or changed `func init`,
a package-level initializer that calls code, any changed declaration that
init code reaches by name within its package), code the compiler does not
check (cgo and its preamble, C/C++/assembly sources, `//go:linkname`), new
risky or blank imports, every `//go:linkname`, `//go:cgo_*` and
`//go:generate` directive in a changed file, newly embedded files,
binaries and long encoded literals. These route to the model review, not to
a person: `evidence.json` lists every flagged item (`flagged`, capped at
200, past which a person decides), and a `.flagged.md` evidence file per
module shows exactly what changed for each one. For binaries and decoded
blobs the gate renders, with Go's own parsers only (run in a child
process of the gate under a 2 GiB address-space limit on Linux, which
leaves its Go heap roughly 360 to 515 MB, and a timeout; with a
per-module budget of bytes parsed and decompressed and a 10-minute
rendering clock per fetch that starts with the first rendering), the type, structure
(ELF/Mach-O/PE sections, imported libraries and symbols, Go build info;
zip/tar/gzip entries), a hexdump, printable strings, a comparison with the
previous version, and where the module refers to the file (linked `.syso`,
`//go:embed`, test-only mentions). The verdict must assess every flagged
item (`items`: `benign`, `suspicious` or `unclear`); `publish` compares that
list with the evidence's, and merges only when every flagged item, and
nothing else, is `benign`.

The default is a person, and only text can stay on the review route:
valid UTF-8 with no control characters but tab, newline and carriage
return, quoted in full. That is the whole new text of every file with a
flagged Go item, and of every C, assembly or cgo file (always as text,
controls and invisible letters shown as escapes), the whole declaration
for an init callee, and a literal that decodes to such text (decoded again,
up to three times, if the text looks encoded itself; for a person if that
fails), when it fits an evidence file.

Every flagged binary goes to a person; the AI never clears one. So do
cgo, C, C++, Objective-C, Fortran, SWIG and assembly sources (`gomod.cgo`,
`gomod.cgo-source-changed`, `gomod.assembly-changed`), as on main: what
they compile, include or link is beyond what the gate shows. Their full
text is still in the focused evidence, and when a person is needed only
for such items (and binaries and other items not shown in full: no
refusal, truncation, major or unknown version, or other reason), the
review still runs as **triage**: `fetch` outputs `review=true`, and the PR
comment shows the model's per-item notes under "Triage for the person
deciding". The decision stays a person's whatever the model answers;
`publish` never merges from triage.

What is flagged:

- a binary added or changed outside `testdata/` (as on main);
- a changed binary under `testdata/` (never built by itself) when the new
  tree embeds it, or when the module has cgo, C or assembly sources or a
  `.syso` (which can link or include any file without naming it);
- a file the new tree newly embeds, changed or not: what each package
  embeds is `go list`'s `EmbedFiles` in both trees (the union over every
  `go tool dist list` platform, cgo on and off), compared per package. An
  unchanged file newly embedded is quoted in full under the package's
  embed item if it is not binary (escapes show any control bytes), and
  goes to a person otherwise. A package `go list` gives no answer for, a
  file with `//go:embed` that only a `-tags` build builds (when anything
  under its directory changed), or any
  non-ASCII path element in either tree puts the embed item in front of a
  person (and counts every binary it could reach as embedded). A `.go`
  file that some configuration builds in the new tree and did not in the
  old (go/build's answer, compared per configuration and for `-tags`
  builds) is checked as a new file throughout (init code,
  imports, the declarations init reaches);
- an assembly (`.s`, `.S`, `.sx`) or `.syso` file, changed or not, that
  some configuration newly assembles or links: one the toolchain lists
  (`SFiles`, `SysoFiles`) in a package that builds there and did not
  before. Assembly goes to a person with its full text, a `.syso` as a
  binary;
- every binary, when the module's link sources change (new cgo, C or
  assembly, or a new `.syso` or library).

The gate still renders every flagged binary and every literal that
decodes to bytes that are not text (ELF, PE/COFF, Mach-O, tar, zip, gzip;
parsed in the isolated child process), labelled "for the person deciding;
the gate does not clear binaries by their content", with how it can reach
the build. Module text in that evidence, reasons included, is always
quoted, with controls and default-ignorable characters shown as escapes.
Unparseable Go files, truncated evidence and a module with more flagged
items than a review can take also go to a person. Module diffs do not
detect renames.

#### Navigable diffs

A Go module's diff is split per file, and each file's diff is its own
evidence file. The parts have caps of their own: 2 MB each, 50 MB
together. A gate-written `diffs.md` index lists every changed file with an
ID. Every file is required reading unless the go command's own rules say
no consumer build reads it: a `_test.go` file that nothing embeds, in a
module with no assembly or cgo that could include it, or, with declared
builds, a file none of them compiles. The verdict's `examined` must list every
required ID, or a person decides. A person also decides when:
- more than 500 files are required;
- the required diffs and flagged items together pass 4 MB, the most one
  review is asked to read;
- a part is cut by the caps;
- git stopped reading the diff;
- the diffs' paths don't match the files that changed (a path git can't
  write unambiguously); every diff is then required.

Parts are named by ID. The fetch job ships the evidence's checksums as a
`SHA256SUMS` manifest inside the artifact and outputs only that file's
sum, which review and publish verify first.
The flagged-items file uses the same caps. Other ecosystems keep the
single-file limits (400 KB a file, 4 MB in all).

#### Split reviews

When the required reading passes about 900 KB, one reviewer run doesn't
finish it. homelab-configs#127 read 37 of about 90 required diffs in 80
turns. Such a review is split into passes, each a full sandboxed run with
its own budget:
- pass 1 assesses every flagged item and reads as many required diffs as
  fit;
- each later pass reads the next share of required diffs;
- a final pass, given every pass's report as data, decides on the whole.

The merged verdict is the worst of them all, with every flag, pass 1's
items, every reading pass's `examined` and the final pass's summary.
Publish checks it like a single verdict. A pass with no verdict leaves no
verdict at all, and a person decides. There are at most six reading
passes; the 4 MB reading limit keeps reviews inside them.

#### Upstream commits

For an update with flagged items, the gate also fetches the module's
upstream history between the two versions and attaches, per item, the
commits that touched its files (`.upstream.md`). Go's own tooling makes
those commits the change. `go mod download -json` reports the proxy's
`Origin` for each version: repository, subdirectory and commit.
`x/mod/zip.CreateFromVCS` rebuilds each module zip from the repository at
that commit, as the go command does, and `dirhash` must give the go.sum
hash. A mismatch is `gomod.upstream-mismatch`, which goes to a person.
When upstream history is verified, a benign item that has commits listed
counts only if the verdict cites at least one of them and nothing else.
The reviewer is told to read each message against the diff, since the
repository's owner wrote it. A message that doesn't fit makes the item
unclear.

Nothing is attached, and the review runs as without it, when any of
these hold:
- the update is a new module;
- the proxy recorded no origin, or the repository isn't git;
- the host isn't github.com, go.googlesource.com or gitlab.com;
- the two versions share no history within 1000 commits;
- more than 150 commits lie between them;
- the attachment would pass its size budget;
- the fetch fails.

git runs in its own memory-limited child, killed after four minutes. Its
configuration is the gate's alone: https only, no system or global
config, no credential helper or hooks, and objects are fsck'd on fetch.
It makes a blob-less shallow fetch and a sparse checkout of the module's
directory.

#### Well-known modules

For `golang.org/x/*`, `google.golang.org/*` and `cloud.google.com/go` (and
below it), and only when the update's upstream history is verified, some
person-routed items are reviewed instead:
- cgo, C and assembly source;
- binaries under testdata/ that nothing embeds and that only link lines
  could reach, other than files the linker takes by name (.syso and
  libraries);
- embeds the gate could not resolve.

The per-item accounting and the commit citations still apply. Every
other binary, a decoded blob that is not text, an unparseable file and an
unanalyzable module still go to a person. The list is the gate's, with no
per-repository input. `github.com/google/*` is not on it.

### GitHub workflow lockfiles

In a workflow onboarded to `.github/workflows/actions.lock`, a step names
an exact tag (`uses: owner/repo@v1.2.3`) and the runner runs the commit
the lockfile records. The actions fetcher takes both commits from the base
and head lockfiles and runs the usual upstream checks on them. The named
tag must dereference to the locked commit, and the locked owner/repo IDs
must be upstream's. The lockfile is read only in the exact form
`gh actions-lock` writes (schema v0.0.3, no `hostname`); anything else
refuses.

A bumped composite can change its own pinned actions. Each transitive
entry that moves to another key and commit of the same repository, under
the same parent, at a subpath the parent's old version ran, is analyzed
as a bump of its own (`Direct: false`, evidence under
`actions/transitive/`), with the same identity checks; the old exact tag
must still name the old commit. A nested `uses:` change that such a pair
explains no longer forces a human; the PR's route is the worst of all
pairs. A transitive pair's old version comes from its old ref: an exact
tag, the highest tag under a floating `vN`/`vN.M` ref, or for any other
ref the old commit's only vX.Y.Z tag. These go to a human: a moved tag
(the same key at another commit, or one exact ref recorded at two
commits), an old version the old ref does not anchor, a subpath the
parent did not run before, a transitive action from a repository the old
version did not use, two pins of one repository under one parent, more
than 8 transitive pairs, a step of any onboarded workflow whose pin the
new lockfile does not lock (or a workflow whose steps the gate cannot
read in full), and any other lockfile change. Job-level reusable workflows and workflows not in the lockfile
keep SHA pins.

## Design rules

**Don't re-implement Go toolchain behaviour.** Where Go's own tooling
(`go/build`, `go list`, `go/parser`, `go/scanner`, `go/build/constraint`)
gives an authoritative answer, the gate uses it. For every platform of `go
tool dist list`, cgo on and off, with each target's own tool tags (GOARCH
feature levels, default GOEXPERIMENTs) read from the toolchain: which
files are built, and what a package embeds, is `go list -e -json`
(`GoFiles`, `CgoFiles`, `EmbedFiles`) for every package with a
`//go:embed` comment, run offline in isolated children with a clean
environment, and `build.Context.ImportDir` over the module tree for the
other packages. Where the tooling gives no answer, the gate
over-approximates in the direction that flags more (for the new tree, a
directory the tooling fails on counts as built everywhere; for the old
tree, nowhere), and it never credits the old side with a hand-ported
rule: directives go/build does not report (`//go:linkname`, `//go:cgo_*`,
`//go:generate`) are flagged in every changed or newly built file whether
or not they were there before.

Why: every differential review rounds 8 to 10 (and the later scans) found
came from cmd/go logic re-implemented in the gate (constraint headers,
block comments, a BOM, `package documentation`, default release tags,
embed pattern matching, directive placement). Each port was close, and
each gap was a way to bring old or unseen text into the build.

What varies between consumers has no authoritative answer: tags set with
`-tags` (`purego`, `netgo`, even `ignore`), `go1.N` (older and newer
toolchains), `gccgo`, GOARCH feature levels (`GOAMD64`) and
`goexperiment.*` (`GOEXPERIMENT`); only exact GOOS/GOARCH values, `unix`,
`cgo` and `gc` are fixed by a platform (`arm.7`, `arm64.v9.0`,
`foo_windows` vary). A changed file whose constraint
consults a varying tag in either tree (go/build's `AllTags` for the file)
gets no old text credited, and nothing its `//go:embed` patterns match is
credited. A file no default configuration builds counts as possibly built
when go/build builds it, alone in its directory, with exactly some subset
of the tags it consults turned on (default release and tool tags such as
`go1.27`, a default GOEXPERIMENT or `arm.7` off unless the subset turns
them on); its embeds go to a person when its directory changes.
A byte-identical file keeps its credit only when every configuration that
builds it now built it before (a sibling's fixed package clause can bring
it into a build). Every old file a build newly includes is quoted
in full under `gomod.newly-built`: its diff can be a constraint line, or
nothing. Past a work or time budget, nothing is credited and a
person decides.

An old `EmbedFiles` answer is credited only where every file the package
takes `//go:embed` patterns from (the files go list builds there with a
`//go:embed` comment, per configuration) is byte-identical and built as
before: go list also reports patterns the compiler rejects, and this needs
no rule about where a directive may stand. A pattern with a backslash (an
escape on Linux, a separator on Windows) or a byte a module file path
cannot hold, other than the glob characters, goes to a person.

One rule is the gate's own, because go/build has no answer for it: a
package-level var initializer such as `var _ I = (*T)(nil)`, `T(nil)` or
`G[int](nil)` is a conversion, not a call, when `T` or `G` is a type
declared in that same file. That follows from Go's scoping: wherever the
file compiles, any other package-level declaration of the name, in a
sibling file or imported into this one, is a redeclaration error. So it
holds under every build constraint, including files only a `-tags` or
newer-toolchain build compiles (x/net's `http2` files at go1.27). It
yields to every doubt: a func, var or const of that name in any `.go`
file of the directory, a dot import, an import of that name, or a file
that does not parse make it a call. A type declared in another file
counts only when that file is built in every configuration. Each version
of a file is classified in the scope of its own tree.

Known limits:

- go/build is compiled into the gate and `go list` is the runner's `go`
  (the fetch summary records both versions).
- Under a non-default build tag, an old package that did not build at all
  in that configuration (a package-consistency error, such as two package
  clauses among the files that tag selects) and that a sibling's fix makes
  buildable keeps credit for its unchanged files. The `-tags` search
  looks at each file alone, so it does not see the old package fail. The
  gap is narrow: no build using that tag could have used the old package,
  so nothing of it ran before. A repository that declares its builds
  (below) does not have this limit for the tags it declares.

### Declared Go builds

A caller can set `go_platforms`, the GOOS/GOARCH pairs it builds Go for,
and `go_tags`, tag sets its builds also use: sets separated by spaces,
tags within a set by commas, such as `race` for `go test -race`. Go module
checks then evaluate each platform, cgo off and on, with no tags and with
each tag set, using go/build and go list. That replaces every platform
with `-tags` over-approximated. Tags the toolchain sets still vary between
consumers whatever they declare: `go1.N`, GOARCH feature levels such as
`amd64.v3`, `gccgo` and GOEXPERIMENT. A file whose constraint consults one
is still treated as possibly built, and checked as new when it changes.

The checks then skip:
- `.go` and `.syso` files that none of those builds compile;
- C and other cgo sources, when no package builds cgo or SWIG files in
  them and the module has no assembly.

Nothing else is skipped:
- assembly, since a built `.s` can include another under any spelling;
- anything go list embeds;
- anything in a package whose embeds go list could not resolve.

The list must cover every build the repository uses: CI, releases and
developer machines. A build missing from it is not checked.

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
   The repository must use immutable OIDC subjects (see "Model
   credential").
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

### Ignoring an ecosystem

`ignore_ecosystems` (comma-separated, default empty) is for an ecosystem
whose Dependabot PRs another trusted process already owns, e.g. a routine
that opens its own PR for every submodule bump and closes Dependabot's as
superseded. Use it only then: an ignored PR is never reviewed, merged or
reported. Names are the ones in Dependabot's branch names
(`dependabot/<ecosystem>/...`): `docker`, `github_actions`, `go_modules`,
`npm_and_yarn`, `submodules`, `uv`, not the `package-ecosystem` names in
`dependabot.yml` (`gitsubmodule`, `gomod`, ...). An unknown name fails the
run.

classify still runs every check above. Only a PR that passes them all
(kind `dependabot`) and whose branch ecosystem and every declared update
are in the list becomes `dependabot-ignored`: fetch, review and publish
do not run, so it gets no status, comment or notification, and the
classify log says why. An unverified PR, or an update set that mixes an
ignored ecosystem with another, is gated as usual. Dependabot's
`updated-dependencies` metadata names no ecosystem, so in practice the
branch name decides. Sweep cannot classify, so it skips every open
Dependabot PR whose branch names an ignored ecosystem; such a PR is
therefore never reported as stuck either (publish has already marked an
unverified one `failure`).

### Trust boundaries

Each owner has one gate GitHub App: sadbox uses app 5855685 (installed on
sadbox.org, homelab-configs, towngear, oncall-sync), Espresso-Aficionados
uses app 5855747 (sprobot, linkclean). Its private key sits in the
`dep-review` environment of every repository it is installed on. So
anyone who can run a job in one repository's `dep-review` environment, in
practice anyone who can get a workflow change onto its default branch,
can mint contents- and workflows-write tokens for every repository that
app is installed on, and can forge the `dep-review` status that sweep
merges on.

Accepted: write access on those repositories is limited to trusted
people (the owner, plus sprobot's collaborators), so write on one of an
owner's gated repositories already means write on all of them. Revisit,
by moving to one app per repository, if a gated repository gains
collaborators who should not have write on the others.

Caches are outside the sha256 chain that protects the gate's artifacts.
The fetch job and the review job's host steps still hold the run's
runtime token, so code execution in either could write cache entries
scoped to the default branch, which the caller's other workflows would
then restore. The gate itself uses no cache.

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
tokens live about ten minutes; a review can take twenty). No API key is
stored anywhere.

Every gated repository uses GitHub's immutable OIDC subjects, which carry
numeric IDs (e.g.
`repo:Espresso-Aficionados@76916743/linkclean@1420833610:ref:refs/heads/main`),
so each owner's federation rule matches `repo:<owner>@<owner_id>/*`:
`repo:sadbox@2502941/*` and `repo:Espresso-Aficionados@76916743/*`. Before
adding a repository to the gate, make sure it has immutable subjects
enabled: `GET`/`PUT repos/{owner}/{repo}/actions/oidc/customization/sub`,
`use_immutable_subject: true` (new repositories get it by default). The
rule's CEL checks on `repository_id` add rename safety on top. The rule
also pins `event_name == "workflow_run"`, the default branch and
`job_workflow_ref` starting with this repository's `gate.yml`. Its scope
is `workspace:developer`, the narrowest the Claude Console offers (the
other is `org:admin`), in a workspace that has a spend limit. That scope
allows more than inference, but the token never enters the sandbox and
the proxy forwards only `POST /v1/messages`, so the rest is reachable
only from the host side. Inputs: `anthropic_federation_rule_id`,
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
result, at most 2 MB, whose `structured_output` must pass the verdict
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

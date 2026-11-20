# Project baseline

What every project follows, so projects don't drift apart. New projects
start from this; existing ones are brought in line. A deliberate deviation
is recorded under [Deviations](#deviations) by PR, with the reason, never
left to drift. Change this file by PR, then update the projects.

## Services

Every long-running service:

- **Health check in the binary, as a flag.** `<binary> -healthcheck`
  exits 0 when the service is healthy and non-zero otherwise, by calling
  the running process (e.g. its `/healthz` on loopback) with a short
  timeout. It is the only health check: the Quadlet unit's `HealthCmd`
  runs it (Podman ignores an image's `HEALTHCHECK`), with
  `Notify=healthy` so a unit is only started once healthy and
  podman-auto-update rolls back an image that never is. No `wget`, `curl`
  or shell from a base image.
- **Configuration from files and environment, secrets from 1Password.**
  Each service receives only its own secrets, rendered per service on the
  host (`quadlet/render-env.sh`, `op inject`) into an env file the unit
  reads. No service gets the host's 1Password service-account token.
- **Shared Go code lives in the shared module** (see [Go](#go)), not copied
  between repositories and not imported from another service's repository.
- **Logs:** `log/slog` text handler to stdout.

## Go

- **One Go version, from the build image.** The Dockerfile's
  `golang:X.Y.Z@sha256:<digest>` is the source of truth; CI runs the tests
  inside that build stage (as sprobot's `test` target does), so a
  Dependabot Docker bump moves the compiler and the tests together. No
  floating minor tags (`golang:1.27`); `go.mod`'s `go`/`toolchain` lines
  must not be newer than the image.
- **Static builds:** `CGO_ENABLED=0`, `-trimpath`. Prefer pure-Go libraries
  over cgo (e.g. `modernc.org/sqlite`, not `mattn/go-sqlite3`).
- **Checks in CI, on linux/amd64 and linux/arm64 natively:** `gofmt`,
  `go vet`, `go test -race`, `golangci-lint`, `govulncheck`.

## Other languages

Every language a repository uses gets a linter and a vulnerability check
in CI:

| Language / file type | Lint | Vulnerabilities |
|---|---|---|
| Go | gofmt, go vet, golangci-lint | govulncheck |
| JavaScript / npm | eslint where there is first-party JS | `npm audit --omit=dev` (production deps) and `npm audit signatures` |
| Python (uv) | ruff | `uv` + osv-scanner against `uv.lock` |
| Shell | shellcheck | – |
| GitHub Actions | actionlint, zizmor | zizmor (known-vulnerable actions) |
| Dockerfiles | hadolint | the image's packages via the dep-review gate |
| Ansible | ansible-lint, `--syntax-check` | – |

## Container images

- **Runtime: distroless.** `gcr.io/distroless/static-debian12:nonroot`
  for static binaries. No shell, no package manager in a runtime image.
  Pinned `tag@sha256:<index digest>`.
- **Build stages: Debian, not Alpine.** Node stages use `node:<major>-slim`
  (glibc; nodejs.org publishes and signs the binaries for every
  architecture we build). Go stages use the official `golang` image.
- **Architectures: linux/amd64 and linux/arm64**, built and tested natively
  on `ubuntu-26.04` and `ubuntu-26.04-arm` (no QEMU), so local development
  on the Mac and production on bonnet run the same image.
- **Tags:** `:latest` plus one immutable tag, `sha-<7-char commit>`, on
  every publish; labels `org.opencontainers.image.source` and
  `org.opencontainers.image.revision`. BuildKit provenance and SBOM
  attestations on every image (`provenance: mode=max`, `sbom: true`), and
  GitHub artifact attestations where the plan allows (public repositories).
- **`.dockerignore`** in every repository with a Dockerfile (at least
  `.git` and local data).
- **Non-root.** Every image runs as a non-root user (`nonroot` in
  distroless).

## Quadlet units (bonnet)

- `UserNS=auto`, volumes mounted `:idmap`, `ReadOnly=true`,
  `DropCapability=ALL`, `NoNewPrivileges=true` (add back only what a
  service needs, with a comment saying why).
- `Memory=` and `PidsLimit=` on every unit, sized from observed peak usage
  with headroom, plus `StopTimeout=`.
- Data under `/var/lib/<service>`, created by ansible with the ownership
  the container expects; nothing under `/root`.
- Ports below 1024 are published by Quadlet (`PublishPort=80:8080`);
  processes inside listen on high ports.
- `HealthCmd=["/<binary>", "-healthcheck"]` (see [Services](#services)).
- Image policy: services deployed by the deploy tool use the `prod` tag it
  moves; the others use `:latest` with `AutoUpdate=registry`.

## GitHub Actions

- Every `uses:` pinned by full commit SHA with a full `# vX.Y.Z` comment.
- Top-level `permissions: contents: read` (or `{}`); jobs ask for more only
  where needed (`packages: write` only on the publish job).
- Untrusted event fields reach shells only through `env:`, never `${{ }}`
  inside `run:`.
- No `pull_request_target`; `workflow_run` only for the dep-review gate.
- Runners pinned to `ubuntu-26.04` / `ubuntu-26.04-arm`.
- `timeout-minutes` on every job.
- Default workflow token read-only (repository setting); "Allow GitHub
  Actions to create and approve pull requests" off.

## Dependabot

- `version: 2`, daily, for every ecosystem the repo has, including
  `github-actions` and `docker`.
- `cooldown: default-days: 3` set explicitly on every ecosystem, Docker
  included (it is Dependabot's default anyway, measured from the tag's last
  push); security updates skip it.
- Docker images grouped into one PR per directory.
- Reviewed and merged by the dep-review gate (this repository).

## Repository settings

- Default branch ruleset: no deletion, no force-push, linear history, pull
  requests required, required status checks for CI (only checks that run on
  every PR, never path-filtered ones), and **signed commits required**.
- Dependabot alerts and security updates on; on public repositories also
  secret scanning and push protection.
- No unused secrets.

## Deviations

- **sadbox/sadbox.org:** default branch is `master`.
- **Espresso-Aficionados/linkclean:** a library, no image; tests against a
  Go version matrix (1.26.x and stable) rather than a build image.
- **sadbox/homelab-configs deploy tool:** built on the Mac at deploy time,
  never published as an image.
- **sadbox/claude-routines:** no package ecosystems.
- Being brought in line (remove each entry when done): root containers
  (rproxy, sadbox-web), amd64-only tests (towngear, sadbox.org, oncall-sync,
  linkclean), shared host 1Password token (sprobot bots, oncall-sync),
  `sprobot/pkg/opsecrets` imported by towngear and oncall-sync.

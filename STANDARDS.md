# Project baseline

What every project follows, so projects don't drift apart. New projects
start from this; existing ones are brought in line (deviations are listed
at the end, with the reason). Change this file by PR, then update the
projects.

## Container images

- **Runtime: distroless.** `gcr.io/distroless/static-debian12` for static
  binaries (Go with `CGO_ENABLED=0`). No shell, no package manager in a
  runtime image. Pinned `tag@sha256:<index digest>`.
- **Go builds are static.** `CGO_ENABLED=0`, `-trimpath`. Prefer pure-Go
  libraries over cgo (e.g. `modernc.org/sqlite`, not `mattn/go-sqlite3`).
- **Health checks live in the binary.** A `-healthcheck` flag (or a
  subcommand) that the container's health check runs; never `wget`, `curl`
  or a shell from the base image.
- **Build stages: Debian, not Alpine.** Node stages use `node:<major>-slim`
  (glibc; nodejs.org publishes and signs the binaries for every
  architecture we build). Go stages use the official `golang` image.
- **Architectures: linux/amd64 and linux/arm64**, built natively on
  `ubuntu-26.04` and `ubuntu-26.04-arm` runners (no QEMU), so local
  development on the Mac and production on bonnet run the same image.
- **Non-root.** Every image runs as a non-root user (`nonroot` in
  distroless). On bonnet, Quadlet units add user namespaces
  (`UserNS=auto`) with idmapped volumes (`:idmap`), plus
  `ReadOnly=true`, `DropCapability=ALL`, `NoNewPrivileges=true` (adding back
  only what a service needs, and saying why).
- **Ports below 1024** are published by Quadlet (`PublishPort=80:8080`);
  processes inside listen on high ports.

## GitHub Actions

- Every `uses:` pinned by full commit SHA with a `# vX.Y.Z` comment.
- Top-level `permissions: contents: read` (or `{}`); jobs ask for more
  only where needed.
- Untrusted event fields reach shells only through `env:`, never
  `${{ }}` inside `run:`.
- No `pull_request_target`; `workflow_run` only for the dep-review gate.
- Runners pinned to `ubuntu-26.04` / `ubuntu-26.04-arm`.
- Default workflow token: read-only (repository setting); "Allow GitHub
  Actions to create and approve pull requests": off.

## Dependabot

- `version: 2`, daily, for every ecosystem the repo has, including
  `github-actions` and `docker`.
- Cooldown: Dependabot's default 3 days applies to every ecosystem
  (Docker included); security updates skip it.
- Docker images grouped into one PR per directory.
- Reviewed and merged by the dep-review gate (this repository).

## Repository settings

- Default branch protected: PRs required, no force-push, linear history,
  required status checks for CI.
- Commits signed.
- Dependabot alerts and security updates on.
- No unused secrets.

## Deviations

None recorded yet; the first cross-project audit fills this in.

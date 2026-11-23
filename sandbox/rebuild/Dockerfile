# The rebuild job's build images: one stage per Node major an action may
# run on (runs.using: node20/22/24), each the official image unchanged.
# gate.yml builds each stage as dep-review-node<major>:local; the job
# runs them under gVisor (internal/rebuild). Pinned by index digest and
# bumped by Dependabot (docker, /sandbox/rebuild). A new major needs a
# stage here, rebuild.Nodes, and gate.yml's --images.

FROM node:20-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0 AS node20

FROM node:22-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee AS node22

FROM node:24-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS node24

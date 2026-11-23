# The rebuild job's build images: one stage per Node major an action may
# run on (runs.using: node20/22/24), each the official image unchanged.
# gate.yml builds each stage as dep-review-node<major>:local; the job
# runs them under gVisor (internal/rebuild). Pinned by index digest and
# bumped by Dependabot (docker, /sandbox/rebuild). A new major needs a
# stage here, rebuild.Nodes, and gate.yml's --images.

FROM node:26-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc AS node20

FROM node:26-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc AS node22

FROM node:26-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc AS node24

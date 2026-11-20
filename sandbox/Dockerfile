# The reviewer sandbox image: the Claude Code CLI and nothing else of ours.
# It holds no credentials; the gate runs it under gVisor, read-only, on an
# internal network whose only peer is the credential proxy. See README.md
# ("Sandbox") and internal/sandbox.
#
# The CLI comes from its native platform package, pinned by
# package-lock.json (sha512 integrity). The wrapper package
# @anthropic-ai/claude-code only copies that same binary into place from a
# postinstall script, which --ignore-scripts would skip.

FROM node:26-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc AS install
WORKDIR /opt/claude
COPY package.json package-lock.json ./
# Both platform packages are optional dependencies, so npm skips the one
# for the other architecture; the test below fails the build if it also
# skipped ours.
RUN npm ci --ignore-scripts --no-audit --no-fund \
 && pkg="node_modules/@anthropic-ai/claude-code-linux-$(node -p process.arch)" \
 && test -x "$pkg/claude" \
 && cp "$pkg/claude" /opt/claude/claude

# The credential proxy runs the gate's own static binary (bind-mounted at
# run time) on distroless; this stage only pins the base.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS proxy

# The reviewer (the default target).
FROM node:26-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc
COPY --from=install /opt/claude/claude /usr/local/bin/claude
# /work holds exactly ./evidence and ./repo (read-only bind mounts); $HOME
# and /tmp are tmpfs at run time. Nothing in the image is writable by the
# reviewer user.
RUN mkdir /work /home/reviewer
WORKDIR /work
USER 65532:65532
ENV HOME=/home/reviewer
ENTRYPOINT ["/usr/local/bin/claude"]

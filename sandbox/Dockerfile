# The reviewer sandbox image: the Claude Code CLI and nothing else. It
# holds no credentials; the gate runs it under gVisor, read-only, on an
# internal network whose only peer is the credential proxy. See README.md
# ("Sandbox") and internal/sandbox.
#
# The CLI comes from its native platform package, pinned by
# package-lock.json (sha512 integrity). The wrapper package
# @anthropic-ai/claude-code only copies that same binary into place from a
# postinstall script, which --ignore-scripts would skip.

FROM node:26-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc AS install
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
WORKDIR /opt/claude
COPY package.json package-lock.json ./
# Both platform packages are optional dependencies, so npm skips the one
# for the other architecture; the test below fails the build if it also
# skipped ours. The binary links only against glibc's own libraries
# (libc, libm, libdl, librt, libpthread), which the distroless cc runtime
# has; the ldd check fails the build if a new CLI version needs more.
RUN npm ci --ignore-scripts --no-audit --no-fund \
 && pkg="node_modules/@anthropic-ai/claude-code-linux-$(node -p process.arch)" \
 && test -x "$pkg/claude" \
 && mkdir -p /out/usr/local/bin /out/work /out/home/reviewer \
 && cp "$pkg/claude" /out/usr/local/bin/claude \
 && ldd /out/usr/local/bin/claude \
 && ! ldd /out/usr/local/bin/claude | grep -vE '^\s*(linux-vdso\.so\.1|/lib/ld-linux[^ ]*|(libc|libm|libdl|librt|libpthread)\.so\.[0-9]+ => )'

# The credential proxy runs the gate's own static binary (bind-mounted at
# run time) on distroless; this stage only pins the base.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS proxy

# The reviewer (the default target): distroless with glibc. No shell, no
# package manager, no Node; only the CLI binary. /work holds exactly
# ./evidence and ./repo (read-only bind mounts); $HOME and /tmp are tmpfs
# at run time. Nothing in the image is writable by the reviewer user.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=install /out/ /
WORKDIR /work
USER 65532:65532
ENV HOME=/home/reviewer
ENTRYPOINT ["/usr/local/bin/claude"]

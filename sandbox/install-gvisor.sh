#!/usr/bin/env bash
# Installs gVisor (runsc) on a GitHub-hosted runner from gVisor's official
# release bucket and registers it with Docker as the runtime "runsc".
# Used by gate.yml (review) and ci.yml (sandbox).
#
# The release is pinned, and so is the sha512 of each architecture's
# tarball: the download must match the pinned sum, and the bucket's
# published .sha512 must say the same thing, before anything is extracted.
# Install steps: https://gvisor.dev/docs/user_guide/install/
set -euo pipefail

release=20261109.0
case "$(uname -m)" in
  x86_64) sum=0a0041fd862f4ea3042a9db8d41c742f48a01f909699adc2a0256e46d85e53f97b82b9fd154b3dce636f62b8d557677639f91c77d13f3f875ff9fa535275393c ;;
  aarch64) sum=a0b5d911512ef5fe70e833821e653a90c4d06c7027246ee49423f1d2fe2b2a509389a637797248958b90e49a069bb079ecde860efe1871b1d980ec0fe17e18ac ;;
  *) echo "install-gvisor: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
url="https://storage.googleapis.com/gvisor/releases/release/$release/$(uname -m)"
dest=/usr/local/lib/gvisor

dl=$(mktemp -d)
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$dl/gvisor.tar.zstd" "$url/gvisor.tar.zstd"
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$dl/gvisor.tar.zstd.sha512" "$url/gvisor.tar.zstd.sha512"
published=$(cut -d' ' -f1 "$dl/gvisor.tar.zstd.sha512")
if [ "$published" != "$sum" ]; then
  echo "install-gvisor: the bucket's published sha512 differs from the pinned one" >&2
  exit 1
fi
echo "$sum  $dl/gvisor.tar.zstd" | sha512sum --check --strict -

sudo install -d -m 0755 -o root -g root "$dest"
sudo tar --zstd -xf "$dl/gvisor.tar.zstd" -C "$dest" --no-same-owner --no-same-permissions
sudo chown -R root:root "$dest"
sudo chmod -R go-w "$dest"
"$dest/runsc" --version

cfg=$(sudo cat /etc/docker/daemon.json 2>/dev/null || echo '{}')
jq --arg p "$dest/runsc" '.runtimes.runsc = {path: $p}' <<<"$cfg" | sudo tee /etc/docker/daemon.json >/dev/null
sudo systemctl restart docker
docker info --format '{{json .Runtimes}}' | jq -e --arg p "$dest/runsc" '.runsc.path == $p' >/dev/null
echo "install-gvisor: runsc $release registered with Docker"

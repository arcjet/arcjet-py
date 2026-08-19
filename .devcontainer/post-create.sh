#!/usr/bin/env bash
set -euo pipefail

# Install wasm-tools (needed by witgen to extract WIT from WASM binaries).
# Pin to a specific version for reproducibility; bump manually when needed.
ARCH=$(uname -m)
TAG="v1.245.1"
VER=${TAG#v}
TARBALL="wasm-tools-${VER}-${ARCH}-linux.tar.gz"
curl -sL "https://github.com/bytecodealliance/wasm-tools/releases/download/${TAG}/${TARBALL}" \
  | sudo tar xz -C /usr/local/bin --strip-components=1 "wasm-tools-${VER}-${ARCH}-linux/wasm-tools"

echo "Installed wasm-tools ${VER} (${ARCH})"

# Install just (the command runner: `just --list`). Pinned like wasm-tools above.
JUST_VER="1.58.0"
curl -sL "https://github.com/casey/just/releases/download/${JUST_VER}/just-${JUST_VER}-${ARCH}-unknown-linux-musl.tar.gz" \
  | sudo tar xz -C /usr/local/bin just

echo "Installed just ${JUST_VER} (${ARCH})"

# Install project dependencies
just install

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

# Install project dependencies
uv sync

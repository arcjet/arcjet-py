#!/usr/bin/env bash
set -euo pipefail

# Install wasm-tools (needed by witgen to extract WIT from WASM binaries)
ARCH=$(uname -m)
TAG=$(curl -sL https://api.github.com/repos/bytecodealliance/wasm-tools/releases/latest \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])')
VER=${TAG#v}
TARBALL="wasm-tools-${VER}-${ARCH}-linux.tar.gz"
curl -sL "https://github.com/bytecodealliance/wasm-tools/releases/download/${TAG}/${TARBALL}" \
  | sudo tar xz -C /usr/local/bin --strip-components=1 "wasm-tools-${VER}-${ARCH}-linux/wasm-tools"

echo "Installed wasm-tools ${VER} (${ARCH})"

# Install project dependencies
uv sync

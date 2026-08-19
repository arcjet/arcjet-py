#!/usr/bin/env bash
set -euo pipefail

ARCH=$(uname -m)

TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT

# Download an archive into $TMP and check it against a pinned SHA256, so an
# unverified archive is never extracted into /usr/local/bin.
# Usage: fetch_verified <url> <sha256> <filename>
fetch_verified() {
  local url="$1" sha256="$2" name="$3"
  curl -fsSL "$url" -o "${TMP}/${name}"
  echo "${sha256}  ${TMP}/${name}" | sha256sum --check --quiet
}

# Install wasm-tools (needed by witgen to extract WIT from WASM binaries).
# Pin the version and the SHA256 of each release archive; bump them together
# when needed. Upstream publishes no checksum file, so these digests are those
# of the published assets, whose GitHub build provenance was verified with
# `gh attestation verify --owner bytecodealliance`.
WASM_TOOLS_VER="1.245.1"
WASM_TOOLS_DIR="wasm-tools-${WASM_TOOLS_VER}-${ARCH}-linux"
case "$ARCH" in
  x86_64) WASM_TOOLS_SHA256="b171e20fd107e63e89ef6c936b5581597666a086af677d7818de92b7cdd5a86d" ;;
  aarch64) WASM_TOOLS_SHA256="e01ef74b8e7b4a819d91122fdd87084fb25a938e4bfa4179cc5524b961468c85" ;;
  *)
    echo "No pinned wasm-tools ${WASM_TOOLS_VER} checksum for ${ARCH}" >&2
    exit 1
    ;;
esac

fetch_verified \
  "https://github.com/bytecodealliance/wasm-tools/releases/download/v${WASM_TOOLS_VER}/${WASM_TOOLS_DIR}.tar.gz" \
  "$WASM_TOOLS_SHA256" "${WASM_TOOLS_DIR}.tar.gz"
sudo tar xz -C /usr/local/bin --strip-components=1 \
  -f "${TMP}/${WASM_TOOLS_DIR}.tar.gz" "${WASM_TOOLS_DIR}/wasm-tools"

echo "Installed wasm-tools ${WASM_TOOLS_VER} (${ARCH})"

# Install just (the command runner: `just --list`). Same pinning rules as
# wasm-tools above; these digests come from the SHA256SUMS asset of the release.
JUST_VER="1.58.0"
JUST_TARBALL="just-${JUST_VER}-${ARCH}-unknown-linux-musl.tar.gz"
case "$ARCH" in
  x86_64) JUST_SHA256="4a5cc2f53e6f0f8c59092a6cc38291eb729d46a7dd95d3ae582008881b84931d" ;;
  aarch64) JUST_SHA256="748237128c4c40cbdabc65e841d05ceba13cc23a91eaba395495894c1d9764df" ;;
  *)
    echo "No pinned just ${JUST_VER} checksum for ${ARCH}" >&2
    exit 1
    ;;
esac

fetch_verified \
  "https://github.com/casey/just/releases/download/${JUST_VER}/${JUST_TARBALL}" \
  "$JUST_SHA256" "$JUST_TARBALL"
sudo tar xz -C /usr/local/bin -f "${TMP}/${JUST_TARBALL}" just

echo "Installed just ${JUST_VER} (${ARCH})"

# Install project dependencies
just install

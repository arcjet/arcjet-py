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

# Install just (the command runner: `just --list`). Pin the version and the
# SHA256 of each release archive; bump both manually when needed. The digests
# come from the SHA256SUMS asset of the release. Verify the archive before
# extraction so an unverified binary never reaches /usr/local/bin.
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

JUST_TMP=$(mktemp -d)
trap 'rm -rf "${JUST_TMP}"' EXIT
curl -fsSL "https://github.com/casey/just/releases/download/${JUST_VER}/${JUST_TARBALL}" \
  -o "${JUST_TMP}/${JUST_TARBALL}"
echo "${JUST_SHA256}  ${JUST_TMP}/${JUST_TARBALL}" | sha256sum --check --quiet
sudo tar xz -C /usr/local/bin -f "${JUST_TMP}/${JUST_TARBALL}" just

echo "Installed just ${JUST_VER} (${ARCH})"

# Install project dependencies
just install

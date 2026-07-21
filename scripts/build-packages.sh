#!/usr/bin/env bash
#
# Build the deb, rpm, apk and Arch packages for one architecture.
#
#   scripts/build-packages.sh --version 0.2.1 --arch amd64 --binary target/release/nmdns
#
# nfpm reads nfpm.yaml at the repo root and renders all four formats from it.
# The binary and man page are staged at fixed paths under dist/stage/ because
# nfpm does not expand environment variables inside contents[].src.
set -euo pipefail

version=""
arch=""
binary=""
outdir="dist/pkg"

while [ $# -gt 0 ]; do
  case "$1" in
    --version) version="$2"; shift 2 ;;
    --arch)    arch="$2";    shift 2 ;;
    --binary)  binary="$2";  shift 2 ;;
    --outdir)  outdir="$2";  shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

for required in version arch binary; do
  if [ -z "${!required}" ]; then
    echo "missing --${required}" >&2
    exit 2
  fi
done

case "$arch" in
  amd64|arm64) ;;
  *) echo "unsupported --arch '$arch' (expected amd64 or arm64)" >&2; exit 2 ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [ ! -f "$binary" ]; then
  echo "binary not found: $binary" >&2
  exit 1
fi

rm -rf dist/stage
mkdir -p dist/stage "$outdir"
install -m 0755 "$binary" dist/stage/nmdns
# -n so the gzip header carries no timestamp, keeping packages reproducible.
gzip -9nc man/nmdns.8 > dist/stage/nmdns.8.gz

export NMDNS_VERSION="$version" NMDNS_ARCH="$arch"
for packager in deb rpm apk archlinux; do
  nfpm package --packager "$packager" --target "$outdir/"
done

rm -rf dist/stage

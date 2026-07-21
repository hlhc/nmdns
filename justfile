# Build and packaging tasks for nmdns. Run `just` to list them.
#
# `just packages` reproduces what the release workflow does: static musl
# binaries for every shipped architecture, then deb, rpm, apk and Arch
# packages for each. Needs `cross` (which needs Docker) and `nfpm`.

set shell := ["bash", "-euo", "pipefail", "-c"]

# nfpm's architecture names paired with the Rust target that produces them.
targets := "amd64=x86_64-unknown-linux-musl arm64=aarch64-unknown-linux-musl"
version := `sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1`
outdir := "dist/pkg"

# List available recipes.
default:
    @just --list

# Build static musl binaries for every shipped architecture.
binaries: require-cross
    for entry in {{ targets }}; do \
      triple="${entry#*=}"; \
      echo ">> building $triple"; \
      cross build --release --locked --target "$triple"; \
    done

# Build deb, rpm, apk and Arch packages for every architecture.
packages: require-nfpm binaries
    rm -rf {{ outdir }}
    for entry in {{ targets }}; do \
      arch="${entry%%=*}"; \
      triple="${entry#*=}"; \
      scripts/build-packages.sh --version "{{ version }}" --arch "$arch" \
        --binary "target/$triple/release/nmdns" --outdir "{{ outdir }}"; \
    done
    @just checksums

# Package one architecture from a binary you already have. Handy for
# iterating on nfpm.yaml without a full cross-build:
#   just package amd64 target/release/nmdns
package arch binary: require-nfpm
    scripts/build-packages.sh --version "{{ version }}" --arch "{{ arch }}" \
      --binary "{{ binary }}" --outdir "{{ outdir }}"

# Write a .sha256 beside every artifact.
checksums:
    @cd {{ outdir }} && for f in *; do \
      case "$f" in *.sha256) continue ;; esac; \
      if command -v sha256sum >/dev/null 2>&1; then \
        sha256sum "$f" > "$f.sha256"; \
      else \
        shasum -a 256 "$f" > "$f.sha256"; \
      fi; \
    done
    @ls -1 {{ outdir }}

# List the files each built package installs.
inspect:
    @for p in {{ outdir }}/*.deb; do echo "== $p"; dpkg-deb -c "$p" | awk '{print $NF}'; done
    @for p in {{ outdir }}/*.rpm; do echo "== $p"; rpm -qlp "$p"; done
    @for p in {{ outdir }}/*.apk; do echo "== $p"; tar -tzf "$p" | grep -v '^\.'; done
    @for p in {{ outdir }}/*.pkg.tar.zst; do echo "== $p"; tar --use-compress-program=unzstd -tf "$p" | grep -v '^\.'; done

# Install the deb in a Debian container and run it, as CI does.
smoke:
    docker run --rm -v "$PWD/{{ outdir }}:/pkg:ro" debian:stable bash -eux -c '\
      apt-get update -qq; \
      apt-get install -yqq /pkg/nmdns_*_amd64.deb; \
      nmdns --help; \
      nmdns -c /etc/nmdns.toml --check'

# fmt, clippy and tests -- the same gates CI enforces.
check:
    cargo fmt --check
    cargo clippy --locked --all-targets -- -D warnings
    cargo test --locked

# Remove build output.
clean:
    rm -rf dist

[private]
require-cross:
    @command -v cross >/dev/null 2>&1 || { \
      echo "cross not found: cargo install cross --locked (needs Docker)" >&2; exit 1; }

[private]
require-nfpm:
    @command -v nfpm >/dev/null 2>&1 || { \
      echo "nfpm not found: brew install nfpm" >&2; exit 1; }

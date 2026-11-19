#!/usr/bin/env bash
# Tests et clippy de impl/core avec la feature `vdf` (chiavdf) dans un
# conteneur Linux — voir impl/TECH_STACK.md, « Environnement de build ».
# Usage, depuis la racine du dépôt :  bash impl/docker-test.sh [args cargo test…]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd -W 2>/dev/null || pwd)"
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "$here:/w" -v p2p-cargo:/usr/local/cargo/registry -v p2p-target:/target \
  -e CARGO_TARGET_DIR=/target -w /w/core rust:1-bookworm bash -c "
    set -e
    apt-get update -qq >/dev/null && apt-get install -y -qq cmake libgmp-dev libclang-dev >/dev/null
    rustup component add clippy >/dev/null 2>&1
    cargo test -q --features vdf $* 2>&1 | grep -E '^test result|^error|FAILED|panicked' || true
    cargo clippy -q --features vdf --all-targets -- -D warnings && echo 'clippy vdf: ok'
  "

#!/usr/bin/env bash
# Exécutables Windows (deploiement.packaging) : Nœud et Connecteur en
# release, preuve VDF (feature `vdf`) et lecteur WinFsp (feature `mount`),
# avec les DLL MPIR de chiavdf à côté des binaires (chargées au démarrage).
# Prérequis : Visual Studio (MSVC), CMake, LLVM ; WinFsp pour monter le
# lecteur. Usage, depuis la racine du dépôt :  bash impl/package-windows.sh
# Licence de MPIR à faire valider avant toute distribution (TECH_STACK.md).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
export LIBCLANG_PATH="${LIBCLANG_PATH:-C:/Program Files/LLVM/bin}"
if ! command -v cmake >/dev/null; then
  cm="$(ls -d "$HOME"/AppData/Local/Microsoft/WinGet/Packages/Kitware.CMake_*/cmake-*/bin 2>/dev/null | head -1)"
  [ -n "$cm" ] && export PATH="$cm:$PATH"
fi
(cd "$here/node" && cargo build --release --features vdf --bin s3m-node)
(cd "$here/connector" && cargo build --release --features "vdf mount" --bin s3m-connector)
(cd "$here/connector" && cargo build --release --features "vdf tray" --bin S3m)
dist="$here/dist/windows"
rm -rf "$dist" && mkdir -p "$dist"
cp "$here/node/target/release/s3m-node.exe" "$here/connector/target/release/s3m-connector.exe"    "$here/connector/target/release/S3m.exe" "$dist/"
mpir="$(cargo metadata --format-version 1 --manifest-path "$here/core/Cargo.toml" --features vdf 2>/dev/null \
  | python -c "import json,sys,os; m=json.load(sys.stdin); print(next(os.path.dirname(p['manifest_path']) for p in m['packages'] if p['name']=='chiavdf'))")/mpir_gc_x64"
cp "$mpir"/*.dll "$dist/"
echo "Exécutables et DLL dans $dist"

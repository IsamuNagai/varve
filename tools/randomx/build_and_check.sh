#!/bin/sh
# Build the pinned, Varve-patched RandomX and verify test-vectors/pow.json.
# Fails if the upstream source, the patch result, or any hash differs.
# Usage: sh tools/randomx/build_and_check.sh [workdir]
set -eu

RANDOMX_REPO="https://github.com/tevador/RandomX.git"
RANDOMX_COMMIT="ff6daa17fde3bb9032bbad15db16cad908deaee0"
CONFIG_SHA256_BEFORE="2eea9777204fd25fcd95225474dbec299e56bf56bd5915d4cf0e223ccc7be833"
CONFIG_SHA256_AFTER="61d71e8d86610e3e7ce89dc8ca5b8733077783ded901fa9f4802167f4d52a791"

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WORK="${1:-$ROOT/.build/randomx}"

rm -rf "$WORK"
mkdir -p "$WORK"
git -C "$WORK" init -q
git -C "$WORK" remote add origin "$RANDOMX_REPO"
git -C "$WORK" fetch -q --depth 1 origin "$RANDOMX_COMMIT"
git -C "$WORK" checkout -q FETCH_HEAD
test "$(git -C "$WORK" rev-parse HEAD)" = "$RANDOMX_COMMIT" || { echo "FAIL: wrong RandomX commit"; exit 1; }

echo "$CONFIG_SHA256_BEFORE  $WORK/src/configuration.h" | sha256sum -c -
git -C "$WORK" apply --check "$HERE/varve-salt.patch"
git -C "$WORK" apply "$HERE/varve-salt.patch"
echo "$CONFIG_SHA256_AFTER  $WORK/src/configuration.h" | sha256sum -c -

cmake -S "$WORK" -B "$WORK/build" -DCMAKE_BUILD_TYPE=Release > "$WORK/cmake.log"
cmake --build "$WORK/build" --target randomx -j 2 > "$WORK/build.log"
c++ -O2 -o "$WORK/pow_vectors" "$ROOT/tools/pow_vectors.c" -I"$WORK/src" "$WORK/build/librandomx.a" -lpthread

for mode in portable fast; do
  "$WORK/pow_vectors" "$mode" > "$WORK/out-$mode.txt"
  python3 -I "$ROOT/tools/randomx/compare_pow.py" "$ROOT/test-vectors/pow.json" "$WORK/out-$mode.txt" "$mode"
done
echo "OK: RandomX ($RANDOMX_COMMIT + Varve salt) matches test-vectors/pow.json in portable and fast modes on $(uname -m)."

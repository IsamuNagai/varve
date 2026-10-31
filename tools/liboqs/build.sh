#!/bin/sh
# Build the pinned liboqs (ML-DSA-65 and SLH-DSA-SHA2-128s only) as a shared library.
# Fails if the fetched source is not the pinned commit.
# Usage: sh tools/liboqs/build.sh [workdir]    -> prints the path of liboqs.so
set -eu

LIBOQS_REPO="https://github.com/open-quantum-safe/liboqs.git"
LIBOQS_COMMIT="87576461b457a17f806aae463a7c223e45029813"   # OQS 0.16.0 line; used for the benchmarks

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WORK="${1:-$ROOT/.build/liboqs}"

rm -rf "$WORK"
mkdir -p "$WORK"
git -C "$WORK" init -q
git -C "$WORK" remote add origin "$LIBOQS_REPO"
git -C "$WORK" fetch -q --depth 1 origin "$LIBOQS_COMMIT"
git -C "$WORK" checkout -q FETCH_HEAD
test "$(git -C "$WORK" rev-parse HEAD)" = "$LIBOQS_COMMIT" || { echo "FAIL: wrong liboqs commit" >&2; exit 1; }

cmake -S "$WORK" -B "$WORK/build" -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_MINIMAL_BUILD="SIG_ml_dsa_65;SIG_slh_dsa_pure_sha2_128s" -DCMAKE_BUILD_TYPE=Release > "$WORK/cmake.log"
cmake --build "$WORK/build" -j 2 > "$WORK/build.log"
ls "$WORK/build/lib/liboqs.so"

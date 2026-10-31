#!/bin/sh
# Build the node's two C dependencies as static libraries, from pinned sources:
#   liboqs  (ML-DSA-65, SLH-DSA-SHA2-128s, SHA3/SHAKE/SHA-256)
#   RandomX (with the Varve salt patch, verified before and after patching)
# Usage: sh tools/build-deps.sh <prefix>
# Result: <prefix>/lib/{liboqs.a,librandomx.a}, <prefix>/include/{oqs/,randomx.h}
set -eu

LIBOQS_REPO="https://github.com/open-quantum-safe/liboqs.git"
LIBOQS_COMMIT="87576461b457a17f806aae463a7c223e45029813"
RANDOMX_REPO="https://github.com/tevador/RandomX.git"
RANDOMX_COMMIT="ff6daa17fde3bb9032bbad15db16cad908deaee0"
RX_CONFIG_SHA256_BEFORE="2eea9777204fd25fcd95225474dbec299e56bf56bd5915d4cf0e223ccc7be833"
RX_CONFIG_SHA256_AFTER="61d71e8d86610e3e7ce89dc8ca5b8733077783ded901fa9f4802167f4d52a791"

HERE="$(cd "$(dirname "$0")" && pwd)"
PREFIX="${1:?usage: build-deps.sh <prefix>}"
JOBS="${JOBS:-2}"
mkdir -p "$PREFIX/src" "$PREFIX/lib" "$PREFIX/include"
# Windows (Git Bash / MSYS with the MSVC toolchain): Visual Studio generator, .lib outputs,
# and the dynamic C runtime (/MD) that Rust's MSVC target links against.
WIN=0
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) WIN=1 ;; esac
if [ "$WIN" = 1 ]; then
  CM_EXTRA="-A x64 -DCMAKE_POLICY_DEFAULT_CMP0091=NEW -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL"
  BUILD_CFG="--config Release"
else
  CM_EXTRA="-DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_BUILD_TYPE=Release"
  BUILD_CFG=""
fi
copy_lib() {  # $1 = build dir, $2 = unix name (liboqs.a), $3 = windows name (oqs.lib)
  if [ "$WIN" = 1 ]; then
    f=$(find "$1" -name "$3" | head -1); [ -n "$f" ] || { echo "FAIL: $3 not built" >&2; exit 1; }
    cp "$f" "$PREFIX/lib/$3"
  else
    f=$(find "$1" -name "$2" | head -1); [ -n "$f" ] || { echo "FAIL: $2 not built" >&2; exit 1; }
    cp "$f" "$PREFIX/lib/$2"
  fi
}
PREFIX="$(cd "$PREFIX" && pwd)"

sha256_check() {  # $1 = expected, $2 = file
  if command -v sha256sum >/dev/null 2>&1; then got=$(sha256sum "$2" | cut -d' ' -f1)
  else got=$(shasum -a 256 "$2" | cut -d' ' -f1); fi
  [ "$got" = "$1" ] || { echo "FAIL: sha256 of $2 is $got, expected $1" >&2; exit 1; }
}

fetch() {  # $1 = repo, $2 = commit, $3 = dir
  rm -rf "$3"; mkdir -p "$3"
  git -C "$3" init -q
  git -C "$3" config core.autocrlf false   # exact bytes: checksums and patches depend on them
  git -C "$3" remote add origin "$1"
  git -C "$3" fetch -q --depth 1 origin "$2"
  git -C "$3" checkout -q FETCH_HEAD
  [ "$(git -C "$3" rev-parse HEAD)" = "$2" ] || { echo "FAIL: $1 is not at $2" >&2; exit 1; }
}

# liboqs ---------------------------------------------------------------------
fetch "$LIBOQS_REPO" "$LIBOQS_COMMIT" "$PREFIX/src/liboqs"
# shellcheck disable=SC2086
cmake -S "$PREFIX/src/liboqs" -B "$PREFIX/src/liboqs/build" -DBUILD_SHARED_LIBS=OFF -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_MINIMAL_BUILD="SIG_ml_dsa_65;SIG_slh_dsa_pure_sha2_128s" -DOQS_USE_OPENSSL=OFF \
  $CM_EXTRA > "$PREFIX/src/liboqs.cmake.log"
# shellcheck disable=SC2086
cmake --build "$PREFIX/src/liboqs/build" $BUILD_CFG -j "$JOBS" > "$PREFIX/src/liboqs.build.log"
copy_lib "$PREFIX/src/liboqs/build" liboqs.a oqs.lib
rm -rf "$PREFIX/include/oqs"; cp -R "$PREFIX/src/liboqs/build/include/oqs" "$PREFIX/include/"

# RandomX --------------------------------------------------------------------
fetch "$RANDOMX_REPO" "$RANDOMX_COMMIT" "$PREFIX/src/randomx"
sha256_check "$RX_CONFIG_SHA256_BEFORE" "$PREFIX/src/randomx/src/configuration.h"
git -C "$PREFIX/src/randomx" apply "$HERE/randomx/varve-salt.patch"
sha256_check "$RX_CONFIG_SHA256_AFTER" "$PREFIX/src/randomx/src/configuration.h"
# shellcheck disable=SC2086
cmake -S "$PREFIX/src/randomx" -B "$PREFIX/src/randomx/build" $CM_EXTRA > "$PREFIX/src/randomx.cmake.log"
# shellcheck disable=SC2086
cmake --build "$PREFIX/src/randomx/build" $BUILD_CFG --target randomx -j "$JOBS" > "$PREFIX/src/randomx.build.log"
copy_lib "$PREFIX/src/randomx/build" librandomx.a randomx.lib
cp "$PREFIX/src/randomx/src/randomx.h" "$PREFIX/include/"

echo "$LIBOQS_COMMIT $RANDOMX_COMMIT" > "$PREFIX/PINS"
echo "OK: static liboqs and patched RandomX in $PREFIX"

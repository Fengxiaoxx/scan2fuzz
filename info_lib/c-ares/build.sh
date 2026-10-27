#!/bin/bash
set -euo pipefail

MODE=${1:-analysis}
BUILD_DIR="build_${MODE}"
SOURCE_DIR=$PWD
SAN_FLAGS="-O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=fuzzer-no-link,address,undefined -fsanitize-address-use-after-scope"
COVERAGE_FLAGS="-O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=fuzzer-no-link -fprofile-instr-generate -fcoverage-mapping"

export CC=clang
export CXX=clang++
export AR=llvm-ar

case "$MODE" in
  analysis)
    export CFLAGS=""
    export CXXFLAGS=""
    ;;
  sanitize)
    export CFLAGS="${SAN_FLAGS}"
    export CXXFLAGS="${SAN_FLAGS}"
    ;;
  coverage)
    export CFLAGS="${COVERAGE_FLAGS}"
    export CXXFLAGS="${COVERAGE_FLAGS}"
    ;;
  aflpp)
    source "$(dirname "${BASH_SOURCE[0]}")/../common_aflpp.sh"
    comparison_aflpp_environment
    ;;
  *)
    echo "Usage: $0 [analysis|sanitize|coverage|aflpp]"
    exit 1
    ;;
esac

cleanup_bootstrap_outputs() {
  rm -f -- "$SOURCE_DIR/aminclude_static.am" \
    "$SOURCE_DIR/src/lib/ares_config.h.in" "$SOURCE_DIR/configure~"
}
trap cleanup_bootstrap_outputs EXIT

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Use the checked-in configure script when available. We only need the library
# build for analysis/sanitize/coverage, so tests and their googletest dependency are
# unnecessary here.
if [ ! -x ../configure ] || [ ! -f ../src/lib/ares_config.h.in ]; then
  (cd .. && autoreconf -fi)
fi

# Enable shared only for analysis (API extraction); sanitize/coverage use static.
if [ "$MODE" = "analysis" ]; then SHARED_FLAG="--enable-shared"; else SHARED_FLAG="--disable-shared"; fi
CONFIGURE_ARGS=(--enable-debug --disable-tests --enable-static "${SHARED_FLAG}")
if [ "$MODE" = "analysis" ] && [ -n "${INSTALL_PREFIX:-}" ]; then
  CONFIGURE_ARGS+=("--prefix=${INSTALL_PREFIX}")
fi
../configure "${CONFIGURE_ARGS[@]}"

if [ "$MODE" = "analysis" ]; then
  bear -- make clean
  bear -- make -j"$(nproc)" V=1 all
else
  make clean
  make -j"$(nproc)" V=1 all
fi

if [ "$MODE" = "analysis" ] && [ -n "${INSTALL_PREFIX:-}" ]; then
  make install
fi

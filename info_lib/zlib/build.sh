#!/bin/bash
set -euo pipefail

MODE=${1:-analysis}
BUILD_DIR="build_${MODE}"
SAN_FLAGS="-O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=fuzzer-no-link,address,undefined -fsanitize-address-use-after-scope"
COVERAGE_FLAGS="-O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=fuzzer-no-link -fprofile-instr-generate -fcoverage-mapping"

export CC=clang
export CXX=clang++
export AR=llvm-ar

case "$MODE" in
  analysis)
    # The scan's provenance pass needs one compiler depfile per linked object.
    export CFLAGS="-MMD"
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

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# analysis: build both shared and static (shared used for API extraction).
# sanitize/coverage: static only to avoid issues with instrumented shared objects.
if [ "$MODE" = "analysis" ]; then
  STATIC_FLAG=""
else
  STATIC_FLAG="--static"
fi
CONFIGURE_ARGS=()
if [ -n "$STATIC_FLAG" ]; then
  CONFIGURE_ARGS+=("$STATIC_FLAG")
fi
if [ "$MODE" = "analysis" ] && [ -n "${INSTALL_PREFIX:-}" ]; then
  CONFIGURE_ARGS+=("--prefix=${INSTALL_PREFIX}")
fi
if ! ../configure "${CONFIGURE_ARGS[@]}"; then
  cat configure.log
  exit 1
fi

if [ "$MODE" = "analysis" ]; then
  bear -- make -j"$(nproc)" all
else
  make -j"$(nproc)" all
fi

if [ "$MODE" = "analysis" ] && [ -n "${INSTALL_PREFIX:-}" ]; then
  make install
fi

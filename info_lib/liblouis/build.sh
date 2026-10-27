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
    export CFLAGS=""
    export CXXFLAGS=""
    ;;
  sanitize)
    export CFLAGS="${SAN_FLAGS}"
    export CXXFLAGS="${SAN_FLAGS}"
    # Keep Clang 15 ASan configure probes stable without changing library objects.
    export LDFLAGS="-no-pie"
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

if [ ! -x ../configure ]; then
  (cd .. && ./autogen.sh)
fi

# Configure flags aligned with OSS-Fuzz liblouis tests/fuzzing/build.sh.
# Enable shared only for analysis (API extraction); sanitize/coverage use static.
if [ "$MODE" = "analysis" ]; then
  SHARED_FLAG="--enable-shared"
  PREFIX_FLAG="--prefix=${INSTALL_PREFIX:?}"
else
  SHARED_FLAG="--disable-shared"
  PREFIX_FLAG=""
fi
../configure ${SHARED_FLAG} ${PREFIX_FLAG} --enable-macros

if [ "$MODE" = "analysis" ]; then
  bear -- make -j"$(nproc)" V=1
  make install
else
  make -j"$(nproc)" V=1
  if [ "$MODE" != "aflpp" ]; then
    install -d /usr/local/share/liblouis/tables
    cp -a ../tables/. /usr/local/share/liblouis/tables/
  fi
fi

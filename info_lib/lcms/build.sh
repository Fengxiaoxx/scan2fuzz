#!/bin/bash
set -euo pipefail

MODE=${1:-analysis}
BUILD_DIR="build_${MODE}"
SAN_FLAGS="-O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=fuzzer-no-link,address,undefined -fsanitize-address-use-after-scope"
COVERAGE_FLAGS="-O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=fuzzer-no-link -fprofile-instr-generate -fcoverage-mapping"
BUILD_JOBS="${LCMS_BUILD_JOBS:-$(nproc)}"

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
  short_wchar_sanitize)
    # Reproduce defects that require a 16-bit wchar_t, such as lcms #607.
    export CFLAGS="${SAN_FLAGS} -fshort-wchar"
    export CXXFLAGS="${SAN_FLAGS} -fshort-wchar"
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
    echo "Usage: $0 [analysis|sanitize|short_wchar_sanitize|coverage|aflpp]"
    exit 1
    ;;
esac

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

if [ ! -x ../configure ]; then
  (cd .. && autoreconf -fi)
fi

# Configure flags aligned with OSS-Fuzz lcms/build.sh.
# Enable shared only for analysis (API extraction); sanitize/coverage use static.
if [ "$MODE" = "analysis" ]; then
  SHARED_FLAG="yes"
else
  SHARED_FLAG="no"
fi
CONFIGURE_ARGS=("--enable-shared=${SHARED_FLAG}")
if [ "$MODE" = "analysis" ] && [ -n "${INSTALL_PREFIX:-}" ]; then
  CONFIGURE_ARGS+=("--prefix=${INSTALL_PREFIX}")
fi
if [ "$MODE" = "short_wchar_sanitize" ]; then
  # LeakSanitizer cannot run Autoconf's probes in ptrace-restricted containers.
  ASAN_OPTIONS="${ASAN_OPTIONS:+${ASAN_OPTIONS}:}detect_leaks=0" ../configure "${CONFIGURE_ARGS[@]}"
else
  ../configure "${CONFIGURE_ARGS[@]}"
fi

if [ "$MODE" = "analysis" ]; then
  bear -- make -j"${BUILD_JOBS}" all
else
  make -j"${BUILD_JOBS}" all
fi

if [ "$MODE" = "analysis" ] && [ -n "${INSTALL_PREFIX:-}" ]; then
  make -C include install-includeHEADERS
fi

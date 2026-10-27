#!/usr/bin/env bash
set -euo pipefail

MODE=${1:-analysis}
BUILD_DIR="build_${MODE}"
SAN_FLAGS="-O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=fuzzer-no-link,address,undefined -fsanitize-address-use-after-scope"
COVERAGE_FLAGS="-O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=fuzzer-no-link -fprofile-instr-generate -fcoverage-mapping"

export CC=clang
export CXX=clang++
export AR=llvm-ar
export RANLIB=llvm-ranlib

INSTALL_ARGS=()
case "$MODE" in
  analysis)
    CFLAGS="-O0 -g -fno-omit-frame-pointer"
    BUILD_SHARED=ON
    BUILD_STATIC=OFF
    LIBRARY_TARGET=nghttp2
    if [ -n "${INSTALL_PREFIX:-}" ]; then
      INSTALL_ARGS+=("-DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX}")
    fi
    ;;
  sanitize)
    CFLAGS="$SAN_FLAGS"
    BUILD_SHARED=OFF
    BUILD_STATIC=ON
    LIBRARY_TARGET=nghttp2_static
    ;;
  coverage)
    CFLAGS="$COVERAGE_FLAGS"
    BUILD_SHARED=OFF
    BUILD_STATIC=ON
    LIBRARY_TARGET=nghttp2_static
    ;;
  aflpp)
    source "$(dirname "${BASH_SOURCE[0]}")/../common_aflpp.sh"
    comparison_aflpp_environment
    BUILD_SHARED=OFF
    BUILD_STATIC=ON
    LIBRARY_TARGET=nghttp2_static
    ;;
  *)
    echo "Usage: $0 [analysis|sanitize|coverage|aflpp]" >&2
    exit 1
    ;;
esac
export CFLAGS
if [ "$MODE" != "aflpp" ]; then
  export CXXFLAGS="$CFLAGS"
fi

# The pipeline invokes this script from test_lib/nghttp2. CMake supplies the
# compilation database; clang on PATH preserves the scan stage's build hooks.
test -f CMakeLists.txt
test -f lib/includes/nghttp2/nghttp2.h
rm -rf "$BUILD_DIR"
cmake -S . -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_AR="$(command -v "$AR")" \
  -DCMAKE_RANLIB="$(command -v "$RANLIB")" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_C_FLAGS_RELWITHDEBINFO='' \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DENABLE_LIB_ONLY=ON \
  -DENABLE_DOC=OFF \
  -DENABLE_FAILMALLOC=OFF \
  -DBUILD_TESTING=OFF \
  -DBUILD_SHARED_LIBS="$BUILD_SHARED" \
  -DBUILD_STATIC_LIBS="$BUILD_STATIC" \
  "${INSTALL_ARGS[@]}"

cmake --build "$BUILD_DIR" --target "$LIBRARY_TARGET" \
  --parallel "${BUILD_JOBS:-$(nproc)}" --verbose
if [ "$MODE" = "analysis" ] && [ -n "${INSTALL_PREFIX:-}" ]; then
  cmake --install "$BUILD_DIR"
fi

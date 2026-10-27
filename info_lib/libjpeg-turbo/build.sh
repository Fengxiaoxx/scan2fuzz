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
    export CFLAGS="-g"
    export CXXFLAGS="-g"
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

# cmake flags aligned with the upstream libjpeg-turbo fuzzing build.
# WITH_FUZZ/FUZZ_BINDIR/FUZZ_LIBRARY are omitted because only the library is needed.
# Enable shared only for analysis (API extraction); sanitize/coverage use static.
if [ "$MODE" = "analysis" ]; then ENABLE_SHARED=1; else ENABLE_SHARED=0; fi
CMAKE_ARGS=()
if [ "$MODE" = "analysis" ] && [ -n "${INSTALL_PREFIX:-}" ]; then
  CMAKE_ARGS+=("-DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX}")
fi
cmake .. \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DENABLE_STATIC=1 \
  -DENABLE_SHARED=${ENABLE_SHARED} \
  -DCMAKE_C_FLAGS='' \
  -DCMAKE_CXX_FLAGS='' \
  -DCMAKE_C_FLAGS_RELWITHDEBINFO="${CFLAGS} -DNDEBUG" \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="${CXXFLAGS} -DNDEBUG" \
  "${CMAKE_ARGS[@]}"

if [ "$MODE" = "analysis" ]; then
  bear -- make -j"$(nproc)"
elif [ "$MODE" = "aflpp" ]; then
  # Final fuzz links libjpeg.a only. Avoid building the duplicate turbojpeg
  # archive and command-line tools, which recompile large source files.
  cmake --build . --target jpeg-static --parallel "${BUILD_JOBS:-$(nproc)}"
else
  make -j"$(nproc)"
fi

if [ "$MODE" = "analysis" ] && [ -n "${INSTALL_PREFIX:-}" ]; then
  cmake --install . --component include
fi

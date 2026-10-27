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

extra_c_flags='-DAOM_MAX_ALLOCABLE_MEMORY=1073741824'
extra_c_flags+=' -DDO_RANGE_CHECK_CLAMP=1'

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
rm -rf ./*

# Enable shared only for analysis (API extraction); sanitize/coverage use static.
if [ "$MODE" = "analysis" ]; then
  BUILD_SHARED=ON
  INSTALL_ARGS=(-DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX:?}")
else
  BUILD_SHARED=OFF
  INSTALL_ARGS=()
fi
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="${CFLAGS}" \
  -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
  -DCMAKE_C_FLAGS_RELEASE='-O3 -g' \
  -DCMAKE_CXX_FLAGS_RELEASE='-O3 -g' \
  -DCONFIG_PIC=1 \
  -DCONFIG_LOWBITDEPTH=1 \
  -DCONFIG_AV1_ENCODER=0 \
  -DENABLE_EXAMPLES=0 \
  -DENABLE_DOCS=0 \
  -DENABLE_TESTS=0 \
  -DCONFIG_SIZE_LIMIT=1 \
  -DDECODE_HEIGHT_LIMIT=12288 \
  -DDECODE_WIDTH_LIMIT=12288 \
  -DAOM_EXTRA_C_FLAGS="${extra_c_flags}" \
  -DENABLE_TOOLS=0 \
  -DAOM_EXTRA_CXX_FLAGS="${extra_c_flags}" \
  -DBUILD_SHARED_LIBS=${BUILD_SHARED} \
  "${INSTALL_ARGS[@]}"

if [ "$MODE" = "analysis" ]; then
  bear -- make -j"$(nproc)"
  cmake --install .
else
  make -j"$(nproc)"
fi

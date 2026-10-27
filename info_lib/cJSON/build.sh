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

case "$MODE" in
  analysis)
    CFLAGS="-O0 -g -fno-omit-frame-pointer"
    BUILD_SHARED=ON
    ;;
  sanitize)
    CFLAGS="$SAN_FLAGS"
    BUILD_SHARED=OFF
    ;;
  coverage)
    CFLAGS="$COVERAGE_FLAGS"
    BUILD_SHARED=OFF
    ;;
  aflpp)
    source "$(dirname "${BASH_SOURCE[0]}")/../common_aflpp.sh"
    BUILD_SHARED=OFF
    comparison_aflpp_environment
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

# The pipeline invokes this script from test_lib/cJSON. CMake supplies the
# compilation database; clang on PATH preserves the scan stage's build hooks.
# cJSON and cJSON_Utils are combined into one library so a single analysis
# target carries both public headers.
test -f CMakeLists.txt
test -f cJSON.c
test -f cJSON_Utils.c
rm -rf "$BUILD_DIR"

INSTALL_ARGS=()
if [ "$MODE" = "analysis" ] && [ -n "${INSTALL_PREFIX:-}" ]; then
  INSTALL_ARGS+=("-DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX}")
fi

cmake -S . -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_AR="$(command -v "$AR")" \
  -DCMAKE_RANLIB="$(command -v "$RANLIB")" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_C_FLAGS_RELWITHDEBINFO='' \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DENABLE_CJSON_TEST=OFF \
  -DENABLE_CJSON_UTILS=ON \
  -DENABLE_TARGET_EXPORT=OFF \
  -DBUILD_SHARED_LIBS="$BUILD_SHARED" \
  "${INSTALL_ARGS[@]}"

cmake --build "$BUILD_DIR" --parallel "${BUILD_JOBS:-$(nproc)}"

if [ "$MODE" = "analysis" ]; then
  mapfile -t ANALYSIS_OBJECTS < <(
    find \
      "$BUILD_DIR/CMakeFiles/cjson.dir" \
      "$BUILD_DIR/CMakeFiles/cjson_utils.dir" \
      -type f -name '*.o' -print | sort
  )
  if [ "${#ANALYSIS_OBJECTS[@]}" -eq 0 ]; then
    echo "No cJSON analysis objects found" >&2
    exit 1
  fi
  "$CC" -shared -o "$BUILD_DIR/libcjson_trace2fuzz.so" \
    "${ANALYSIS_OBJECTS[@]}" -lm
  if [ -n "${INSTALL_PREFIX:-}" ]; then
    cmake --install "$BUILD_DIR"
  fi
else
  COMPLETE_LIBRARY="$BUILD_DIR/libcjson_trace2fuzz.a"
  {
    printf 'create %s\n' "$COMPLETE_LIBRARY"
    find "$BUILD_DIR" -type f -name 'libcjson*.a' -print \
      | sort \
      | while read -r library; do printf 'addlib %s\n' "$library"; done
    printf 'save\nend\n'
  } | "$AR" -M
fi

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
    export CFLAGS="-O2 -g"
    export CXXFLAGS="-O2 -g"
    BUILD_SHARED=ON
    ;;
  sanitize)
    export CFLAGS="$SAN_FLAGS"
    export CXXFLAGS="$SAN_FLAGS"
    BUILD_SHARED=OFF
    ;;
  coverage)
    export CFLAGS="$COVERAGE_FLAGS"
    export CXXFLAGS="$COVERAGE_FLAGS"
    BUILD_SHARED=OFF
    ;;
  aflpp)
    source "$(dirname "${BASH_SOURCE[0]}")/../common_aflpp.sh"
    comparison_aflpp_environment
    BUILD_SHARED=OFF
    ;;
  *)
    echo "Usage: $0 [analysis|sanitize|coverage|aflpp]" >&2
    exit 1
    ;;
esac

rm -rf "$BUILD_DIR"

cmake -S . -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_CXX_FLAGS='' \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="$CXXFLAGS" \
  -DCMAKE_CXX_STANDARD=17 \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX:-$PWD/$BUILD_DIR/install}" \
  -DBUILD_SHARED_LIBS="$BUILD_SHARED" \
  -DABSL_ENABLE_INSTALL=ON \
  -DABSL_BUILD_TESTING=OFF \
  -DBUILD_TESTING=OFF

cmake --build "$BUILD_DIR" --parallel "$(nproc)"

if [ "$MODE" = "analysis" ]; then
  cmake --install "$BUILD_DIR"

  # Whole-library analysis scope: every object built from absl sources, so the
  # scan audits (and can slice) the entire library rather than a subset.
  mapfile -t ANALYSIS_OBJECTS < <(
    find "$BUILD_DIR/absl" -type f -path '*/CMakeFiles/*' -name '*.o' -print | sort
  )
  if [ "${#ANALYSIS_OBJECTS[@]}" -eq 0 ]; then
    echo "No Abseil analysis objects found" >&2
    exit 1
  fi
  "$CXX" -shared \
    -o "$BUILD_DIR/libabsl_trace2fuzz.so" \
    "${ANALYSIS_OBJECTS[@]}"
else
  COMPLETE_LIBRARY="$BUILD_DIR/libabsl_strings_complete.a"
  {
    printf 'create %s\n' "$COMPLETE_LIBRARY"
    find "$BUILD_DIR" -type f -name 'libabsl_*.a' -print \
      | sort \
      | while read -r library; do printf 'addlib %s\n' "$library"; done
    printf 'save\nend\n'
  } | "$AR" -M
fi

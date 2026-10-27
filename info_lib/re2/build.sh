#!/bin/bash
set -euo pipefail

MODE=${1:-analysis}
BUILD_DIR="build_${MODE}"
BUILD_JOBS=${BUILD_JOBS:-$(nproc)}
SAN_FLAGS="-O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=fuzzer-no-link,address,undefined -fsanitize-address-use-after-scope"
COVERAGE_FLAGS="-O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=fuzzer-no-link -fprofile-instr-generate -fcoverage-mapping"

if [ "$MODE" = "analysis" ]; then
  INSTALL_ARGS=(
    -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX:?}"
    -DRE2_INSTALL=ON
  )
else
  INSTALL_ARGS=(-DRE2_INSTALL=OFF)
fi

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
    export CFLAGS="${SAN_FLAGS}"
    export CXXFLAGS="${SAN_FLAGS} -O2"
    BUILD_SHARED=OFF
    ;;
  coverage)
    export CFLAGS="${COVERAGE_FLAGS}"
    export CXXFLAGS="${COVERAGE_FLAGS} -O2"
    BUILD_SHARED=OFF
    ;;
  aflpp)
    source "$(dirname "${BASH_SOURCE[0]}")/../common_aflpp.sh"
    comparison_aflpp_environment
    BUILD_SHARED=OFF
    ;;
  *)
    echo "Usage: $0 [analysis|sanitize|coverage|aflpp]"
    exit 1
    ;;
esac

if [ ! -d ../abseil-cpp ]; then
  echo "Missing ../abseil-cpp required by OSS-Fuzz re2 build"
  exit 1
fi

rm -rf "$BUILD_DIR"
ABSL_BUILD_DIR="$BUILD_DIR/abseil"
ABSL_INSTALL_DIR="$BUILD_DIR/abseil-install"

cmake -S ../abseil-cpp -B "$ABSL_BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_CXX_COMPILER="${CXX:-c++}" \
  -DCMAKE_CXX_FLAGS='' \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="${CXXFLAGS}" \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DCMAKE_CXX_STANDARD=17 \
  -DCMAKE_INSTALL_PREFIX="$ABSL_INSTALL_DIR" \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_TESTING=OFF \
  -DABSL_BUILD_TESTING=OFF
cmake --build "$ABSL_BUILD_DIR" --parallel "$BUILD_JOBS"
cmake --install "$ABSL_BUILD_DIR"

cmake -S . -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_CXX_COMPILER="${CXX:-c++}" \
  -DCMAKE_CXX_FLAGS='' \
  -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="${CXXFLAGS}" \
  -DCMAKE_PREFIX_PATH="$ABSL_INSTALL_DIR" \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DBUILD_SHARED_LIBS="$BUILD_SHARED" \
  -DRE2_BUILD_TESTING=OFF \
  -DRE2_TEST=OFF \
  -DRE2_BENCHMARK=OFF \
  "${INSTALL_ARGS[@]}"
cmake --build "$BUILD_DIR" --target re2 --parallel "$BUILD_JOBS"

if [ "$MODE" = "analysis" ]; then
  cmake --install "$BUILD_DIR"
  # re2's public headers include Abseil's; drivers compile against this tree.
  cp -a "$ABSL_INSTALL_DIR/include/absl" "$INSTALL_PREFIX/include/"
fi

if [ "$MODE" != "analysis" ]; then
  ln -sfn abseil-install/include/absl "$BUILD_DIR/absl"
  COMPLETE_LIBRARY="$BUILD_DIR/libre2_complete.a"
  {
    printf 'create %s\n' "$COMPLETE_LIBRARY"
    printf 'addlib %s\n' "$BUILD_DIR/libre2.a"
    find "$ABSL_INSTALL_DIR/lib" -type f -name '*.a' -print \
      | sort \
      | while read -r library; do printf 'addlib %s\n' "$library"; done
    printf 'save\nend\n'
  } | "$AR" -M
fi

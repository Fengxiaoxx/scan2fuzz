#!/bin/bash
set -euo pipefail

MODE=${1:-analysis}
BUILD_DIR="build_${MODE}"
BUILD_JOBS=${BUILD_JOBS:-$(nproc)}
SAN_FLAGS="-O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=fuzzer-no-link,address,undefined -fsanitize-address-use-after-scope"
COVERAGE_FLAGS="-O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=fuzzer-no-link -fprofile-instr-generate -fcoverage-mapping"

export CC=clang
export CXX=clang++
export AR=llvm-ar
export RANLIB=llvm-ranlib

# Aligned with OSS-Fuzz sqlite3/build.sh compile definitions.
SQLITE_DEFINES="-DSQLITE_MAX_LENGTH=128000000 \
  -DSQLITE_MAX_SQL_LENGTH=128000000 \
  -DSQLITE_MAX_MEMORY=25000000 \
  -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
  -DSQLITE_DEBUG=1 \
  -DSQLITE_MAX_PAGE_COUNT=16384"

case "$MODE" in
  analysis)
    export CFLAGS="${SQLITE_DEFINES} -O0 -g -fno-omit-frame-pointer"
    export CXXFLAGS=""
    ;;
  sanitize)
    export CFLAGS="${SQLITE_DEFINES} ${SAN_FLAGS}"
    export CXXFLAGS="${SAN_FLAGS}"
    export ASAN_OPTIONS="${ASAN_OPTIONS:+$ASAN_OPTIONS:}detect_leaks=0"
    ;;
  coverage)
    export CFLAGS="${SQLITE_DEFINES} ${COVERAGE_FLAGS}"
    export CXXFLAGS="${COVERAGE_FLAGS}"
    ;;
  aflpp)
    source "$(dirname "${BASH_SOURCE[0]}")/../common_aflpp.sh"
    comparison_aflpp_environment
    export CFLAGS="${SQLITE_DEFINES} ${CFLAGS}"
    ;;
  *)
    echo "Usage: $0 [analysis|sanitize|coverage|aflpp]"
    exit 1
    ;;
esac

# Run from the source root (the scan/preprocess build contract).
test -f src/sqlite.h.in
test -f main.mk
if [ "$MODE" = "analysis" ]; then
  : "${INSTALL_PREFIX:?analysis requires a public header install prefix}"
fi

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Compile core source files separately so the scanner keeps their original
# paths. SQLite still generates a combined FTS5 source file. Enable extensions
# exposed through sqlite3.h without additional consumer-side feature macros.
# Keep these feature choices consistent across analysis and sanitizer builds.
CONFIGURE_ARGS=(--disable-amalgamation --fts4 --fts5 --rtree --geopoly
  --dbpage --dbstat --column-metadata --disable-tcl)
if [ "$MODE" = "analysis" ]; then
  CONFIGURE_ARGS+=(--shared --static)
else
  CONFIGURE_ARGS+=(--disable-shared --static)
fi

../configure "${CONFIGURE_ARGS[@]}"
if [ "$MODE" = "analysis" ]; then
  # The scanner uses object depfiles to recover all linked source/header inputs.
  # SQLite's make rules omit -o for individual .c files; the build-trace
  # parser requires explicit object outputs to match each link input.
  # T.link must be overridden separately so link commands do not inherit
  # the compile-only -MD/-MF/-o options.
  bear -- make -j"$BUILD_JOBS" BCC=clang \
    'T.compile=$(T.cc) -MD -MF $@.d -o $@' \
    'T.link=$(T.cc)' lib so
else
  make -j"$BUILD_JOBS" BCC=clang lib
fi

test -s libsqlite3.a

if [ "$MODE" = "analysis" ]; then
  test -s libsqlite3.so
  test -s compile_commands.json
  install -d "${INSTALL_PREFIX:?}/include"
  install -m 0644 sqlite3.h ../src/sqlite3ext.h \
    "$INSTALL_PREFIX/include/"
fi

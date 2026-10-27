#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/.local/aflpp/4.33c"
mkdir -p "$(dirname "$DEST")"

if [[ -d "$DEST" ]]; then
  if [[ ! -f "$DEST/GNUmakefile" ]] ||
     ! grep -q '^#define VERSION "++4\.33c"' "$DEST/include/config.h"; then
    echo "Unexpected AFL++ installation at $DEST" >&2
    exit 1
  fi
  VERSION_OUTPUT="$("$DEST/afl-fuzz" -V x 2>&1 || true)"
  if [[ "$VERSION_OUTPUT" != *'afl-fuzz++4.33c'* ]]; then
    # A copied build may link against a Python library absent in this container.
    make -C "$DEST" -f GNUmakefile -B NO_PYTHON=1 afl-fuzz
  fi
  VERSION_OUTPUT="$("$DEST/afl-fuzz" -V x 2>&1 || true)"
  if [[ "$VERSION_OUTPUT" != *'afl-fuzz++4.33c'* ]] ||
     [[ ! -x "$DEST/afl-clang-fast++" ]] ||
     [[ ! -f "$DEST/libAFLDriver.a" ]]; then
    echo "Incomplete AFL++ 4.33c installation at $DEST" >&2
    exit 1
  fi
  echo "AFL++ 4.33c is available at $DEST"
  exit 0
fi
if [[ -e "$DEST" ]]; then
  echo "Unexpected AFL++ installation at $DEST" >&2
  exit 1
fi

STAGE="$(mktemp -d "$(dirname "$DEST")/.setup-XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
if [[ -n "${AFLPP_SOURCE_ARCHIVE:-}" ]]; then
  ARCHIVE="$AFLPP_SOURCE_ARCHIVE"
else
  ARCHIVE="$STAGE/aflpp.tar.gz"
  curl -fsSL \
    https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/v4.33c.tar.gz \
    -o "$ARCHIVE"
fi
mkdir "$STAGE/source"
tar -xf "$ARCHIVE" -C "$STAGE/source" --strip-components=1
if ! grep -q '^#define VERSION "++4\.33c"' "$STAGE/source/include/config.h"; then
  echo "Source archive is not AFL++ 4.33c" >&2
  exit 1
fi
make -C "$STAGE/source" -j"${AFLPP_BUILD_JOBS:-4}" NO_PYTHON=1 all
mv "$STAGE/source" "$DEST"
test -f "$DEST/libAFLDriver.a"
VERSION_OUTPUT="$("$DEST/afl-fuzz" -V x 2>&1 || true)"
[[ "$VERSION_OUTPUT" == *'afl-fuzz++4.33c'* ]]
echo "Built AFL++ 4.33c at $DEST"

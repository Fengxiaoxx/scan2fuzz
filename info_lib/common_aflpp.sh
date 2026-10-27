#!/usr/bin/env bash
# AFL++ ASan+UBSan environment for final comparison campaigns.

comparison_aflpp_environment() {
  local repository_root
  repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  local aflpp_dir="${repository_root}/.local/aflpp/4.33c"
  export CC="${TRACE2FUZZ_AFL_C:-${aflpp_dir}/afl-clang-fast}"
  export CXX="${TRACE2FUZZ_AFL_CXX:-${aflpp_dir}/afl-clang-fast++}"
  local compiler version_output
  for compiler in "$CC" "$CXX"; do
    if [[ ! -x "$compiler" ]]; then
      echo "Final fuzz library build requires AFL++ 4.33c compiler: $compiler" >&2
      return 1
    fi
    version_output="$("$compiler" -h 2>&1 || true)"
    if [[ "$version_output" != *4.33c* ]]; then
      echo "Final fuzz library build requires AFL++ 4.33c compiler: $compiler" >&2
      return 1
    fi
  done
  export AFL_LLVM_USE_TRACE_PC=1
  export AFL_DONT_OPTIMIZE=1
  export CFLAGS="-O1 -g -fno-omit-frame-pointer -fPIC"
  export CXXFLAGS="$CFLAGS"
  export AFL_USE_ASAN=1
  export AFL_USE_UBSAN=1
  unset AFL_USE_MSAN MSAN_OPTIONS
  # Autoconf executes instrumented probes while configuring static libraries.
  export ASAN_OPTIONS="${ASAN_OPTIONS:+${ASAN_OPTIONS}:}detect_leaks=0"
}

#!/bin/bash
set -euo pipefail

MODE=${1:-analysis}
SOURCE_DIR="$PWD"
BUILD_DIR="$SOURCE_DIR/build_${MODE}"
LOCAL_CMAKE="$SOURCE_DIR/../../.local/cmake-wheel/cmake/data/bin"
if [ "$MODE" = "aflpp" ] && [ -x "$LOCAL_CMAKE/cmake" ]; then
  export PATH="$LOCAL_CMAKE:$PATH"
fi
OSS_FUZZ_DIR="$(dirname "$SOURCE_DIR")/curl-fuzzer"
OSS_BUILD_DIR="$BUILD_DIR/ossfuzz"
SAN_FLAGS="-O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=fuzzer-no-link,address,undefined -fsanitize-address-use-after-scope"
COVERAGE_BASE_FLAGS="-O1 -g -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=fuzzer-no-link"

export CC=clang
export CXX=clang++
export AR=llvm-ar
export CURL_SOURCE_DIR="$SOURCE_DIR"
export ARCHITECTURE=x86_64
export SANITIZER=address

case "$MODE" in
  analysis)
    export CFLAGS="-fPIC"
    export CXXFLAGS="-fPIC"
    ENABLE_COVERAGE=OFF
    ;;
  sanitize)
    export CFLAGS="$SAN_FLAGS"
    export CXXFLAGS="$SAN_FLAGS"
    export LDFLAGS="-no-pie"
    ENABLE_COVERAGE=OFF
    ;;
  coverage)
    export CFLAGS="$COVERAGE_BASE_FLAGS"
    export CXXFLAGS="$COVERAGE_BASE_FLAGS"
    ENABLE_COVERAGE=ON
    ;;
  aflpp)
    source "$(dirname "${BASH_SOURCE[0]}")/../common_aflpp.sh"
    comparison_aflpp_environment
    ENABLE_COVERAGE=OFF
    ;;
  *)
    echo "Usage: $0 [analysis|sanitize|coverage|aflpp]"
    exit 1
    ;;
esac

if [ ! -f "$OSS_FUZZ_DIR/CMakeLists.txt" ]; then
  echo "Missing ../curl-fuzzer required by the OSS-Fuzz curl build"
  exit 1
fi

# Preserve the downloaded/built third-party dependencies across rebuilds so a
# transient network failure cannot force re-downloading everything.
DEPS_KEEP="${BUILD_DIR}.deps-keep"
if [ -d "$OSS_BUILD_DIR" ]; then
  rm -rf "$DEPS_KEEP"
  mv "$OSS_BUILD_DIR" "$DEPS_KEEP"
fi
rm -rf "$BUILD_DIR"
if [ -d "$DEPS_KEEP" ]; then
  mkdir -p "$BUILD_DIR"
  mv "$DEPS_KEEP" "$OSS_BUILD_DIR"
fi
# The source tree is also mounted at /Trace2Fuzz inside Docker. Reconfigure
# CMake for the current path while retaining downloaded dependency archives.
rm -rf "$OSS_BUILD_DIR/CMakeCache.txt" "$OSS_BUILD_DIR/CMakeFiles"
# ExternalProject does not track changes in a local SOURCE_DIR. Its completed
# stamps can therefore reuse libcurl.a from an older curl checkout even after
# CMake reconfigures the outer project. Clear only curl's own build/install
# state; keep downloaded and built third-party dependencies in ossfuzz.
for variant in curl_external curl_gnutls_external curl_mbedtls_external curl_http3_external; do
  rm -rf "$OSS_BUILD_DIR/${variant}-prefix"
  rm -f "$OSS_BUILD_DIR/CMakeFiles/${variant}-complete"
done
for install in curl-install curl-gnutls-install curl-mbedtls-install curl-http3-install; do
  rm -rf "$OSS_BUILD_DIR/$install"
done
cmake -S "$OSS_FUZZ_DIR" -B "$OSS_BUILD_DIR" \
  -DENABLE_COVERAGE="$ENABLE_COVERAGE"
cmake --build "$OSS_BUILD_DIR" --target curl_external --parallel "$(nproc)"

find_one() {
  local label="$1"
  local pattern="$2"
  local matches=()
  mapfile -t matches < <(find "$OSS_BUILD_DIR" -type f -path "$pattern" -print)
  if [ "${#matches[@]}" -ne 1 ]; then
    echo "Expected one $label archive, found ${#matches[@]}"
    exit 1
  fi
  printf '%s\n' "${matches[0]}"
}

CURL_A="$(find_one libcurl '*/curl-install/lib/libcurl.a')"
ZLIB_A="$(find_one zlib '*/zlib-*-install/lib/libz.a')"
ZSTD_A="$(find_one zstd '*/zstd-*-install/lib/libzstd.a')"
BROTLIDEC_A="$(find_one libbrotlidec '*/brotli-*-install/lib/libbrotlidec.a')"
BROTLICOMMON_A="$(find_one libbrotlicommon '*/brotli-*-install/lib/libbrotlicommon.a')"
SSL_A="$(find_one libssl '*/openssl-*-install/lib/libssl.a')"
CRYPTO_A="$(find_one libcrypto '*/openssl-*-install/lib/libcrypto.a')"
NGHTTP2_A="$(find_one nghttp2 '*/nghttp2-*-install/lib/libnghttp2.a')"
IDN2_A="$(find_one libidn2 '*/libidn2-*-install/lib/libidn2.a')"
LDAP_A="$(find_one libldap '*/openldap-*-install/lib/libldap.a')"
LBER_A="$(find_one liblber '*/openldap-*-install/lib/liblber.a')"

if [ "$MODE" = "analysis" ]; then
  SHARED_BUILD_DIR="$BUILD_DIR/shared"
  cmake -S "$SOURCE_DIR" -B "$SHARED_BUILD_DIR" \
    -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX:?}" \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_C_FLAGS="-fPIC -DUNITTESTS" \
    -DCMAKE_CXX_FLAGS="-fPIC -DUNITTESTS" \
    -DCMAKE_INSTALL_LIBDIR=lib \
    -DBUILD_SHARED_LIBS=ON \
    -DBUILD_STATIC_LIBS=OFF \
    -DENABLE_DEBUG=ON \
    -DCURL_HIDDEN_SYMBOLS=OFF \
    -DBUILD_CURL_EXE=OFF \
    -DBUILD_LIBCURL_DOCS=OFF \
    -DBUILD_MISC_DOCS=OFF \
    -DENABLE_CURL_MANUAL=OFF \
    -DCURL_USE_LIBPSL=OFF \
    -DCURL_USE_OPENSSL=ON \
    -DOPENSSL_ROOT_DIR="$(dirname "$(dirname "$SSL_A")")" \
    -DZLIB_INCLUDE_DIR="$(dirname "$(dirname "$ZLIB_A")")/include" \
    -DZLIB_LIBRARY="$ZLIB_A" \
    -DNGHTTP2_INCLUDE_DIR="$(dirname "$(dirname "$NGHTTP2_A")")/include" \
    -DNGHTTP2_LIBRARY="$NGHTTP2_A" \
    -DZSTD_INCLUDE_DIR="$(dirname "$(dirname "$ZSTD_A")")/include" \
    -DZSTD_LIBRARY="$ZSTD_A" \
    -DCURL_BROTLI=ON \
    -DBROTLI_INCLUDE_DIR="$(dirname "$(dirname "$BROTLIDEC_A")")/include" \
    -DBROTLIDEC_LIBRARY="$BROTLIDEC_A" \
    -DBROTLICOMMON_LIBRARY="$BROTLICOMMON_A" \
    -DBROTLI_USE_STATIC_LIBS=ON \
    -DLIBIDN2_INCLUDE_DIR="$(dirname "$(dirname "$IDN2_A")")/include" \
    -DLIBIDN2_LIBRARY="$IDN2_A" \
    -DLDAP_INCLUDE_DIR="$(dirname "$(dirname "$LDAP_A")")/include" \
    -DLDAP_LIBRARY="$LDAP_A" \
    -DLDAP_LBER_LIBRARY="$LBER_A"
  pushd "$BUILD_DIR" >/dev/null
  bear -- cmake --build "$SHARED_BUILD_DIR" --target libcurl_shared --parallel "$(nproc)"
  popd >/dev/null
  cmake --install "$SHARED_BUILD_DIR"
else
  COMPLETE_LIBRARY="$BUILD_DIR/libcurl_complete.a"
  {
    printf 'create %s\n' "$COMPLETE_LIBRARY"
    for library in \
      "$CURL_A" "$NGHTTP2_A" "$SSL_A" "$CRYPTO_A" "$ZLIB_A" \
      "$ZSTD_A" "$BROTLIDEC_A" "$BROTLICOMMON_A" \
      "$IDN2_A" "$LDAP_A" "$LBER_A"; do
      printf 'addlib %s\n' "$library"
    done
    printf 'save\nend\n'
  } | "$AR" -M
fi

"""Regression coverage for the curl build wrapper's ExternalProject cache."""

import os
import subprocess
from pathlib import Path


BUILD_SCRIPT = Path(__file__).resolve().parents[1] / "info_lib/curl/build.sh"


def test_curl_build_discards_stale_curl_artifacts_but_keeps_dependencies(tmp_path):
    source = tmp_path / "curl"
    source.mkdir()
    fuzzer = tmp_path / "curl-fuzzer"
    fuzzer.mkdir()
    (fuzzer / "CMakeLists.txt").write_text("# fake project\n")
    oss_build = source / "build_coverage/ossfuzz"
    oss_build.mkdir(parents=True)

    variants = (
        "curl_external",
        "curl_gnutls_external",
        "curl_mbedtls_external",
        "curl_http3_external",
    )
    installs = (
        "curl-install",
        "curl-gnutls-install",
        "curl-mbedtls-install",
        "curl-http3-install",
    )
    for variant in variants:
        (oss_build / f"{variant}-prefix").mkdir()
        (oss_build / f"{variant}-prefix/stale").touch()
        marker = oss_build / "CMakeFiles" / f"{variant}-complete"
        marker.parent.mkdir(exist_ok=True)
        marker.touch()
    for install in installs:
        (oss_build / install).mkdir()
        (oss_build / install / "stale").touch()

    archives = {
        "zlib-1.3.2-install/lib/libz.a": "zlib",
        "zstd-1.5.7-install/lib/libzstd.a": "zstd",
        "brotli-1.2.0-install/lib/libbrotlidec.a": "brotli",
        "brotli-1.2.0-install/lib/libbrotlicommon.a": "brotli",
        "openssl-4.0.3-install/lib/libssl.a": "openssl",
        "openssl-4.0.3-install/lib/libcrypto.a": "openssl",
        "nghttp2-1.70.0-install/lib/libnghttp2.a": "nghttp2",
        "libidn2-2.3.8-install/lib/libidn2.a": "libidn2",
        "openldap-2.6.13-install/lib/libldap.a": "openldap",
        "openldap-2.6.13-install/lib/liblber.a": "openldap",
    }
    for relative, content in archives.items():
        archive = oss_build / relative
        archive.parent.mkdir(parents=True, exist_ok=True)
        archive.write_text(content)

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    cmake = bin_dir / "cmake"
    cmake.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        'root="$TEST_OSS_BUILD_DIR"\n'
        'if [ "$1" = "-S" ]; then\n'
        '  for name in curl_external curl_gnutls_external curl_mbedtls_external curl_http3_external; do\n'
        '    test ! -e "$root/${name}-prefix"\n'
        '    test ! -e "$root/CMakeFiles/${name}-complete"\n'
        '  done\n'
        '  for name in curl-install curl-gnutls-install curl-mbedtls-install curl-http3-install; do\n'
        '    test ! -e "$root/$name"\n'
        '  done\n'
        '  test -f "$root/zlib-1.3.2-install/lib/libz.a"\n'
        'elif [ "$1" = "--build" ]; then\n'
        '  mkdir -p "$root/curl-install/lib"\n'
        '  printf fresh > "$root/curl-install/lib/libcurl.a"\n'
        'else\n'
        '  exit 1\n'
        'fi\n'
    )
    cmake.chmod(0o755)
    llvm_ar = bin_dir / "llvm-ar"
    llvm_ar.write_text(
        "#!/usr/bin/env bash\n"
        'read -r command destination\n'
        'test "$command" = create\n'
        ': > "$destination"\n'
        'cat > /dev/null\n'
    )
    llvm_ar.chmod(0o755)

    env = os.environ | {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "TEST_OSS_BUILD_DIR": str(oss_build),
    }
    subprocess.run(
        ["bash", str(BUILD_SCRIPT), "coverage"],
        cwd=source,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    assert (oss_build / "curl-install/lib/libcurl.a").read_text() == "fresh"
    assert (source / "build_coverage/libcurl_complete.a").is_file()
    for relative, content in archives.items():
        assert (oss_build / relative).read_text() == content

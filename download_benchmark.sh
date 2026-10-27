#!/bin/bash
set -euo pipefail

mkdir -p test_lib

# ---------------------------------------------------------------------------
# Pinned versions for the libraries whose reported findings are reproducible
# only on a specific revision (2026-10-17).  Everything else tracks the
# default branch.  Alternatives verified by the same materials are in the
# comments; the pin covers the reported issues of that library.
# ---------------------------------------------------------------------------
declare -A PINNED_REFS=(
    ["abseil-cpp"]="15ea57c38713eff81d29d2d780b6a56f241a16a0"   # 2026-09-15  #2167/#2168/#2174
    ["curl"]="cdbe4eb55609e2096e296faf86552f27514d6a01"         # 2026-09-15 master #22963/#22971 (release curl-8_22_0 also verified)
    ["lcms"]="8105f59f3204be8b3e9931f92d98dc2bbc3f9cff"         # 2026-09-14 pre-fix tree for #606/#607/#611 (#611 recheck baseline: b760fb1)
    ["exiv2"]="8bdd99813a6bef6fc14551592d12f7db54971b48"        # 2026-09-18 #9509 (release v0.28.9 also verified)
    ["liblouis"]="011cfb3b5868f9e0a63092d5cfa39b0caf57fe21"     # 2026-09-18 #2112/#2115/#2117/#2120/#2127
    ["libjpeg-turbo"]="c85e6b905bf237038faa936dab160ebfc5da0344" # 3.2.0, 2026-06-30 #923 (main 03c9a9d also verified)
)

LIBRARIES=(
    abseil-cpp
    aom
    c-ares
    cJSON
    curl
    exiv2
    ffjpeg
    file
    giflib
    lcms
    libjpeg-turbo
    liblouis
    libpcap
    libpng
    libsndfile
    libtiff
    libvpx
    libxml2
    loguru
    lua
    nghttp2
    openssl
    pugixml
    re2
    sqlite3
    tinygltf
    zlib
)

if [ $# -gt 1 ]; then
    echo "Usage: $0 [library_name]"
    exit 1
fi

prepare_target() {
    rm -rf "test_lib/$1"
}

download_git() {
    local name="$1"
    local url="$2"
    local ref="${3:-${PINNED_REFS[$1]:-}}"

    prepare_target "$name"
    if [ -n "$ref" ]; then
        # Pin to an exact revision.  GitHub serves "fetch by SHA"; when that is
        # refused, fall back to a full fetch and check out the object directly.
        git init -q "test_lib/$name"
        git -C "test_lib/$name" remote add origin "$url"
        if git -C "test_lib/$name" fetch --depth 1 origin "$ref" >/dev/null 2>&1; then
            git -C "test_lib/$name" checkout -q --detach FETCH_HEAD
        else
            git -C "test_lib/$name" fetch --tags origin >/dev/null 2>&1 || true
            git -C "test_lib/$name" fetch origin >/dev/null 2>&1 || true
            git -C "test_lib/$name" checkout -q --detach "$ref"
        fi
        echo "[pinned] $name @ $(git -C "test_lib/$name" rev-parse --short HEAD)"
    else
        git clone --depth 1 "$url" "test_lib/$name"
    fi
}

download_git_dependency() {
    local name="$1"
    local url="$2"

    if [ ! -d "test_lib/$name" ]; then
        download_git "$name" "$url"
    elif [ -n "${PINNED_REFS[$name]:-}" ]; then
        # present already: keep it on the pinned revision
        git -C "test_lib/$name" checkout -q --detach "${PINNED_REFS[$name]}" 2>/dev/null || true
    fi
}

download_tarball() {
    local name="$1"
    local url="$2"
    local tmpdir
    local archive
    local topdir

    prepare_target "$name"
    tmpdir="$(mktemp -d)"

    curl -LJO --output-dir "$tmpdir" "$url"
    archive="$(find "$tmpdir" -maxdepth 1 -type f | head -n 1)"

    case "$archive" in
        *.tar.gz|*.tgz)
            tar -xzf "$archive" -C "$tmpdir"
            ;;
        *.tar.xz)
            tar -xJf "$archive" -C "$tmpdir"
            ;;
        *.tar.bz2)
            tar -xjf "$archive" -C "$tmpdir"
            ;;
        *.zip)
            unzip -q "$archive" -d "$tmpdir"
            ;;
        *)
            echo "Unsupported archive format: $archive"
            rm -rf "$tmpdir"
            exit 1
            ;;
    esac

    topdir="$(find "$tmpdir" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
    mv "$topdir" "test_lib/$name"
    rm -rf "$tmpdir"
}

download_library() {
    case "$1" in
        abseil-cpp)
            download_git "abseil-cpp" "https://github.com/abseil/abseil-cpp.git"
            ;;
        aom|libaom)
            download_git "libaom" "https://aomedia.googlesource.com/aom"
            ;;
        c-ares)
            download_git "c-ares" "https://github.com/c-ares/c-ares.git"
            ;;
        cJSON|cjson)
            download_git "cJSON" "https://github.com/DaveGamble/cJSON.git"
            ;;
        curl)
            download_git_dependency "curl-fuzzer" "https://github.com/curl/curl-fuzzer.git"
            download_git "curl" "https://github.com/curl/curl.git"
            ;;
        exiv2)
            download_git "exiv2" "https://github.com/Exiv2/exiv2.git"
            ;;
        ffjpeg)
            download_git "ffjpeg" "https://github.com/rockcarry/ffjpeg.git"
            ;;
        file|libmagic)
            download_git "file" "https://github.com/file/file.git"
            ;;
        giflib)
            download_tarball "giflib" "https://sourceforge.net/projects/giflib/files/latest/download"
            ;;
        lcms)
            download_git "lcms" "https://github.com/mm2/Little-CMS.git"
            ;;
        libjpeg-turbo)
            download_git "libjpeg-turbo" "https://github.com/libjpeg-turbo/libjpeg-turbo.git"
            ;;
        liblouis)
            download_git "liblouis" "https://github.com/liblouis/liblouis.git"
            ;;
        libpcap)
            download_git "libpcap" "https://github.com/the-tcpdump-group/libpcap.git"
            ;;
        libpng)
            download_tarball "libpng" "https://sourceforge.net/projects/libpng/files/latest/download"
            ;;
        libsndfile)
            download_git "libsndfile" "https://github.com/libsndfile/libsndfile.git"
            ;;
        libtiff)
            download_git_dependency "zlib" "https://github.com/madler/zlib.git"
            download_git_dependency "libjpeg-turbo" "https://github.com/libjpeg-turbo/libjpeg-turbo.git"
            download_git_dependency "jbigkit" "https://www.cl.cam.ac.uk/~mgk25/git/jbigkit"
            download_git "libtiff" "https://gitlab.com/libtiff/libtiff.git"
            ;;
        libvpx)
            download_git "libvpx" "https://github.com/webmproject/libvpx.git"
            ;;
        libxml2)
            download_git "libxml2" "https://gitlab.gnome.org/GNOME/libxml2.git"
            ;;
        loguru)
            download_git "loguru" "https://github.com/emilk/loguru.git"
            ;;
        lua)
            download_git "lua" "https://github.com/lua/lua.git"
            ;;
        nghttp2)
            download_git "nghttp2" "https://github.com/nghttp2/nghttp2.git"
            git -C test_lib/nghttp2 submodule update --init --recursive --depth 1
            ;;
        openssl)
            download_git "openssl" "https://github.com/openssl/openssl.git"
            ;;
        pugixml)
            download_git "pugixml" "https://github.com/zeux/pugixml.git"
            ;;
        re2)
            download_git_dependency "abseil-cpp" "https://github.com/abseil/abseil-cpp.git"
            download_git "re2" "https://github.com/google/re2.git"
            ;;
        sqlite3)
            download_git "sqlite3" "https://github.com/sqlite/sqlite.git"
            ;;
        tinygltf)
            download_git "tinygltf" "https://github.com/syoyo/tinygltf.git"
            ;;
        zlib)
            download_git "zlib" "https://github.com/madler/zlib.git"
            ;;
        *)
            echo "Supported libraries: ${LIBRARIES[*]}"
            exit 1
            ;;
    esac
}

if [ $# -eq 0 ]; then
    for lib in "${LIBRARIES[@]}"; do
        download_library "$lib"
    done
else
    download_library "$1"
fi

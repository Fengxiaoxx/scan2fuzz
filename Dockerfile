FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

ARG CODEQL_VERSION=2.25.4
ARG CODEQL_CPP_QUERIES_VERSION=1.6.2
ARG INFER_VERSION=1.2.0
ARG LLVM_ANALYSIS_VERSION=18
ARG CLANGD_VERSION=20.1.8
ARG CLANGD_SHA256=98493005e2c7532e69827987d909c46295e2ee997a48228606e7777547994490

# LLVM 15 remains the default compiler/coverage toolchain. LLVM 18 is kept
# versioned and is used only to link bitcode and build the matching readers.
RUN apt-get update && apt-get install -y --no-install-recommends \
    software-properties-common \
    ca-certificates \
    gnupg \
    wget \
    && wget -q https://apt.llvm.org/llvm-snapshot.gpg.key \
        -O /tmp/llvm-snapshot.gpg.key \
    && gpg --dearmor --yes \
        -o /usr/share/keyrings/apt.llvm.org.gpg \
        /tmp/llvm-snapshot.gpg.key \
    && rm /tmp/llvm-snapshot.gpg.key \
    && printf 'deb [signed-by=/usr/share/keyrings/apt.llvm.org.gpg] https://apt.llvm.org/jammy/ llvm-toolchain-jammy-%s main\n' \
        "${LLVM_ANALYSIS_VERSION}" \
        > /etc/apt/sources.list.d/llvm-${LLVM_ANALYSIS_VERSION}.list \
    && add-apt-repository ppa:deadsnakes/ppa -y \
    && apt-get update && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    bear \
    bison \
    build-essential \
    clang-15 \
    clang-${LLVM_ANALYSIS_VERSION} \
    curl \
    flex \
    git \
    ripgrep \
    libasound2-dev \
    libbrotli-dev \
    libbz2-dev \
    libexpat1-dev \
    libflac-dev \
    libfmt-dev \
    libicu-dev \
    libjpeg-dev \
    liblz4-dev \
    liblzma-dev \
    libmp3lame-dev \
    libmpg123-dev \
    libogg-dev \
    libopenjp2-7-dev \
    libopus-dev \
    libpng-dev \
    libsqlite3-dev \
    libtool \
    libvorbis-dev \
    libxml2-dev \
    libzstd-dev \
    llvm-15 \
    llvm-15-dev \
    llvm-15-tools \
    llvm-${LLVM_ANALYSIS_VERSION} \
    llvm-${LLVM_ANALYSIS_VERSION}-dev \
    lld-15 \
    ninja-build \
    pkg-config \
    python3.11 \
    python3.11-dev \
    python3-pip \
    unzip \
    xz-utils \
    yasm \
    zlib1g-dev \
    && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 100 \
    && update-alternatives --install /usr/bin/clang clang /usr/bin/clang-15 100 \
    && update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-15 100 \
    && update-alternatives --install /usr/bin/llvm-ar llvm-ar /usr/bin/llvm-ar-15 100 \
    && update-alternatives --install /usr/bin/llvm-ranlib llvm-ranlib /usr/bin/llvm-ranlib-15 100 \
    && update-alternatives --install /usr/bin/llvm-link llvm-link /usr/bin/llvm-link-15 100 \
    && update-alternatives --install /usr/bin/llvm-cov llvm-cov /usr/bin/llvm-cov-15 100 \
    && update-alternatives --install /usr/bin/llvm-profdata llvm-profdata /usr/bin/llvm-profdata-15 100 \
    && update-alternatives --install /usr/bin/lld lld /usr/bin/lld-15 100 \
    && update-alternatives --install /usr/bin/ld.lld ld.lld /usr/bin/ld.lld-15 100 \
    && llvm-link-${LLVM_ANALYSIS_VERSION} --version \
    && rm -rf /var/lib/apt/lists/*

# clangd is independent of the compilation, coverage and bitcode-analysis
# toolchains installed above.
RUN curl --fail --location --retry 2 --connect-timeout 20 --max-time 600 \
        "https://github.com/clangd/clangd/releases/download/${CLANGD_VERSION}/clangd-linux-${CLANGD_VERSION}.zip" \
        -o /tmp/clangd.zip \
    && printf '%s  %s\n' "${CLANGD_SHA256}" /tmp/clangd.zip | sha256sum --check --status \
    && unzip -q /tmp/clangd.zip -d /opt \
    && ln -s "/opt/clangd_${CLANGD_VERSION}/bin/clangd" /usr/local/bin/clangd \
    && rm /tmp/clangd.zip \
    && clangd --version

# Declared here rather than with the other versions: every RUN after an ARG sees it, so a
# bump at the top would rebuild the system packages too. 1.18.35 offers the gpt-6 models
# (gpt-6-luna and others) to a ChatGPT login; 1.18.29 does not.
ARG OPENCODE_VERSION=1.18.35
RUN cd /tmp \
    && wget -q "https://registry.npmjs.org/opencode-linux-x64-baseline/-/opencode-linux-x64-baseline-${OPENCODE_VERSION}.tgz" -O opencode.tgz \
    && tar -xzf opencode.tgz \
    && install -m 0755 package/bin/opencode /usr/local/bin/opencode \
    && rm -rf package opencode.tgz \
    && opencode --version

RUN cd /tmp \
    && wget -q "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip" \
    && unzip -q codeql-linux64.zip \
    && mv codeql /opt/codeql \
    && rm codeql-linux64.zip

RUN cd /tmp \
    && wget -q "https://github.com/facebook/infer/releases/download/v${INFER_VERSION}/infer-linux-x86_64-v${INFER_VERSION}.tar.xz" \
    && tar -xf "infer-linux-x86_64-v${INFER_VERSION}.tar.xz" \
    && mv "infer-linux-x86_64-v${INFER_VERSION}" /opt/infer \
    && rm "infer-linux-x86_64-v${INFER_VERSION}.tar.xz"

ENV PATH="/opt/codeql:/opt/infer/bin:${PATH}"
ENV PYTHONPATH=/Trace2Fuzz

# The mounted checkouts belong to the host user, so git inside the container
# calls them "dubious ownership" and refuses to report their state. The scan
# stage reads that state: the cutoff date and the clean-tree check both come
# from git.
RUN git config --global --add safe.directory '*'

WORKDIR /Trace2Fuzz

COPY requirements.txt /Trace2Fuzz/requirements.txt
RUN python3 -m pip install --no-cache-dir -r requirements.txt

COPY . /Trace2Fuzz/

RUN codeql pack ci src/preprocess/reachability/queries \
    && codeql pack download "codeql/cpp-queries@${CODEQL_CPP_QUERIES_VERSION}" \
    && codeql resolve extractor --language=cpp --just-check

RUN clang++-${LLVM_ANALYSIS_VERSION} \
        $(llvm-config-${LLVM_ANALYSIS_VERSION} --cxxflags) -std=c++17 -O2 \
        src/preprocess/reachability/native/extract_direct_calls.cpp \
        -o /usr/local/bin/trace2fuzz-direct-calls \
        $(llvm-config-${LLVM_ANALYSIS_VERSION} \
            --ldflags --system-libs --libs core irreader support) \
    && clang++-${LLVM_ANALYSIS_VERSION} \
        $(llvm-config-${LLVM_ANALYSIS_VERSION} --cxxflags) -std=c++17 -O2 \
        src/preprocess/reachability/native/extract_function_locations.cpp \
        -o /usr/local/bin/trace2fuzz-function-locations \
        $(llvm-config-${LLVM_ANALYSIS_VERSION} \
            --ldflags --system-libs --libs core irreader support)

CMD ["/bin/bash"]

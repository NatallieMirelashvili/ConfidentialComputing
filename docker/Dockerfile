FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin

RUN apt-get update && apt-get install -y --no-install-recommends \
    adb \
    bc \
    bison \
    build-essential \
    ca-certificates \
    ccache \
    cpio \
    curl \
    device-tree-compiler \
    expect \
    file \
    flex \
    gawk \
    gcc \
    gcc-aarch64-linux-gnu \
    gcc-arm-linux-gnueabi \
    gcc-arm-linux-gnueabihf \
    git \
    gnupg \
    libattr1-dev \
    libcap-dev \
    libfdt-dev \
    libftdi-dev \
    libglib2.0-dev \
    libgmp3-dev \
    libgnutls28-dev \
    libhidapi-dev \
    libmpc-dev \
    libncurses5-dev \
    libpixman-1-dev \
    libssl-dev \
    libtool \
    locales \
    make \
    mtools \
    netcat-openbsd \
    ninja-build \
    python3 \
    python3-cryptography \
    python3-pip \
    python3-pyelftools \
    python3-serial \
    python3-tomli \
    rsync \
    sudo \
    tmux \
    unzip \
    uuid-dev \
    vim-tiny \
    wget \
    xxd \
    zlib1g-dev \
    && locale-gen C.UTF-8 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash optee \
    && mkdir -p /workspace \
    && chown -R optee:optee /workspace

RUN curl -fsSL https://storage.googleapis.com/git-repo-downloads/repo -o /usr/local/bin/repo \
    && chmod a+x /usr/local/bin/repo

USER optee
WORKDIR /workspace/ConfidentialComputing

CMD ["/bin/bash"]

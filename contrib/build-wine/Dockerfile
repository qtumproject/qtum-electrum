FROM debian:bullseye@sha256:43ef0c6c3585d5b406caa7a0f232ff5a19c1402aeb415f68bcd1cf9d10180af8

# need ca-certificates before using snapshot packages
RUN apt update -qq > /dev/null && apt install -qq --yes --no-install-recommends \
    ca-certificates

# pin the distro packages.
COPY apt.sources.list /etc/apt/sources.list
COPY apt.preferences /etc/apt/preferences.d/snapshot

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive

RUN dpkg --add-architecture i386 && \
    apt-get update -q && \
    apt-get install -qy --allow-downgrades \
        wget \
        gnupg2 \
        dirmngr \
        python3-software-properties \
        software-properties-common \
        git \
        p7zip-full \
        make \
        mingw-w64 \
        mingw-w64-tools \
        autotools-dev \
        autoconf \
        autopoint \
        libtool \
        gettext \
        sudo \
        nsis \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean

RUN wget -nc https://dl.winehq.org/wine-builds/Release.key && \
        echo "c51bcb8cc4a12abfbd7c7660eaf90f49674d15e222c262f27e6c96429111b822 Release.key" | sha256sum -c - && \
        apt-key add Release.key && \
        rm Release.key && \
    wget -nc https://dl.winehq.org/wine-builds/winehq.key && \
        echo "78b185fabdb323971d13bd329fefc8038e08559aa51c4996de18db0639a51df6 winehq.key" | sha256sum -c - && \
        apt-key add winehq.key && \
        rm winehq.key && \
    apt-add-repository https://dl.winehq.org/wine-builds/debian/ && \
    apt-get update -q && \
    apt-get install -qy --allow-downgrades \
        wine-stable-amd64:amd64=8.0.1~bullseye-1 \
        wine-stable-i386:i386=8.0.1~bullseye-1 \
        wine-stable:amd64=8.0.1~bullseye-1 \
        winehq-stable:amd64=8.0.1~bullseye-1 \
        libvkd3d1:amd64=1.3~bullseye-1 \
        libvkd3d1:i386=1.3~bullseye-1 \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean

RUN mkdir --parents "/opt/wine64/drive_c/electrum"

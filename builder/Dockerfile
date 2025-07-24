FROM ghcr.io/goreleaser/goreleaser-cross:v1.24.5

# remove s390x and ppc64el since its not in the repos and causes apt to fail
RUN dpkg --remove-architecture s390x && \
    dpkg --remove-architecture ppc64el && \
    dpkg --add-architecture arm64 && \
    dpkg --add-architecture armhf && \
    apt-get update && \
    apt-get install -y wget unzip flex bison \
    libpcap-dev libpcap-dev:arm64 libpcap-dev:armhf \
    mingw-w64 gcc-mingw-w64-x86-64 \
    gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf

# Install musl cross compiler for OpenWRT compatibility
RUN wget https://musl.cc/aarch64-linux-musl-cross.tgz && \
    tar -xzf aarch64-linux-musl-cross.tgz -C /opt && \
    rm aarch64-linux-musl-cross.tgz
ENV PATH="/opt/aarch64-linux-musl-cross/bin:${PATH}"

# Build libpcap for musl
RUN wget https://www.tcpdump.org/release/libpcap-1.10.4.tar.gz && \
    tar -xzf libpcap-1.10.4.tar.gz && \
    cd libpcap-1.10.4 && \
    CC=aarch64-linux-musl-gcc ./configure --host=aarch64-linux-musl --prefix=/opt/aarch64-linux-musl-cross/aarch64-linux-musl --disable-shared --enable-static && \
    make && make install && \
    cd .. && rm -rf libpcap-1.10.4 libpcap-1.10.4.tar.gz

# install windows npcap sdk
RUN wget -O /tmp/npcap-sdk.zip https://npcap.com/dist/npcap-sdk-1.13.zip && \
    unzip /tmp/npcap-sdk.zip -d /opt/npcap-sdk && \
    rm /tmp/npcap-sdk.zip

FROM ghcr.io/goreleaser/goreleaser-cross:v1.24.5

# remove s390x since its not in the repos and causes apt to fail
RUN dpkg --remove-architecture s390x && \
    dpkg --add-architecture arm64 && \
    dpkg --add-architecture armhf && \
    apt-get update && \
    apt-get install -y wget unzip \
    libpcap-dev libpcap-dev:arm64 libpcap-dev:armhf \
    mingw-w64 gcc-mingw-w64-x86-64 \
    gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf

# install windows npcap sdk
RUN wget -O /tmp/npcap-sdk.zip https://npcap.com/dist/npcap-sdk-1.13.zip && \
    unzip /tmp/npcap-sdk.zip -d /opt/npcap-sdk && \
    rm /tmp/npcap-sdk.zip

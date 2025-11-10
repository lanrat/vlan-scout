#!/bin/bash
set -e

LIBPCAP_VERSION="1.10.4"
NPCAP_VERSION="1.13"
LIBS_DIR="$PWD/.libs"
LIBPCAP_SRC="$LIBS_DIR/libpcap-src"
NPCAP_DIR="$LIBS_DIR/npcap-sdk"

# Build targets: (target-name, zig-target, configure-host)
declare -a TARGETS=(
    "x86_64-linux-gnu x86_64-linux-gnu x86_64-linux-gnu"
    "aarch64-linux-gnu aarch64-linux-gnu aarch64-linux-gnu"
    "arm-linux-gnueabihf arm-linux-gnueabihf arm-linux-gnueabihf"
    "aarch64-linux-musl aarch64-linux-musl aarch64-linux-musl"
    #"x86_64-macos x86_64-macos x86_64-apple-darwin"
    #"aarch64-macos aarch64-macos aarch64-apple-darwin"
)

echo "Setting up build dependencies..."

# Download libpcap source
if [ ! -d "$LIBPCAP_SRC" ]; then
    echo "Downloading libpcap $LIBPCAP_VERSION..."
    mkdir -p "$LIBS_DIR"
    cd "$LIBS_DIR"
    wget -q "https://www.tcpdump.org/release/libpcap-$LIBPCAP_VERSION.tar.gz"
    tar -xzf "libpcap-$LIBPCAP_VERSION.tar.gz"
    mv "libpcap-$LIBPCAP_VERSION" libpcap-src
    rm "libpcap-$LIBPCAP_VERSION.tar.gz"
    cd -
    echo "✓ libpcap source downloaded"
else
    echo "✓ libpcap source already present"
fi

# Build static libpcap for each target
for target_info in "${TARGETS[@]}"; do
    read -r name zig_target configure_host <<< "$target_info"
    BUILD_DIR="$LIBS_DIR/libpcap-$name"

    if [ ! -f "$BUILD_DIR/libpcap.a" ]; then
        echo "Building libpcap for $name..."
        mkdir -p "$BUILD_DIR"

        # Copy source to build directory
        cp -r "$LIBPCAP_SRC"/* "$BUILD_DIR/"
        cd "$BUILD_DIR"

        # Configure and build with Zig as CC
        CC="zig cc -target $zig_target" \
        AR="zig ar" \
        RANLIB="zig ranlib" \
        CFLAGS="-O2" \
        ./configure \
            --host="$configure_host" \
            --disable-shared \
            --enable-static \
            --disable-dbus \
            --without-libnl \
            --prefix="$BUILD_DIR"

        # # Remove macOS-specific arch flags that conflict with Zig cross-compilation
        # if [[ "$configure_host" == *"darwin"* ]]; then
        #     sed -i 's/-arch [a-z0-9_]*//g' Makefile
        # fi

        make -j"$(nproc 2>/dev/null || echo 2)"

        cd - >/dev/null
        echo "✓ libpcap built for $name"
    else
        echo "✓ libpcap for $name already built"
    fi
done

# Download Npcap SDK for Windows
if [ ! -d "$NPCAP_DIR" ]; then
    echo "Downloading Npcap SDK $NPCAP_VERSION..."
    mkdir -p "$LIBS_DIR"
    cd "$LIBS_DIR"
    wget -q -O npcap-sdk.zip "https://npcap.com/dist/npcap-sdk-$NPCAP_VERSION.zip"
    unzip -q npcap-sdk.zip -d npcap-sdk
    rm npcap-sdk.zip
    cd -
    echo "✓ Npcap SDK downloaded"
else
    echo "✓ Npcap SDK already present"
fi

echo ""
echo "✓ Build dependencies ready"

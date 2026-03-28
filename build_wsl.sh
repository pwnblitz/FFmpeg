#!/bin/bash
set -e

# FFmpeg WSL Static Build Script (Ubuntu/Debian)
# Produces standalone ffmpeg/ffplay/ffprobe binaries with zero runtime dependencies.
#
# Usage:
#   chmod +x build_wsl.sh
#   ./build_wsl.sh              # full build (install deps + compile)
#   ./build_wsl.sh --no-deps    # skip apt install
#   ./build_wsl.sh --prefix=DIR # change output directory (default: ./build)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NPROC=$(nproc 2>/dev/null || echo 4)
PREFIX="$SCRIPT_DIR/build"
SKIP_DEPS=0

for arg in "$@"; do
    case "$arg" in
        --no-deps)  SKIP_DEPS=1 ;;
        --prefix=*) PREFIX="${arg#--prefix=}" ;;
        -h|--help)
            echo "Usage: $0 [--no-deps] [--prefix=./build]"
            exit 0
            ;;
    esac
done

echo "=== FFmpeg WSL Static Build ==="
echo "  Source:  $SCRIPT_DIR"
echo "  Output:  $PREFIX/bin/"
echo "  Jobs:    $NPROC"
echo ""

########################################
# 1. Install build dependencies
########################################
if [ "$SKIP_DEPS" -eq 0 ]; then
    echo ">>> Installing build dependencies..."
    sudo apt-get update -qq
    sudo apt-get install -y --no-install-recommends \
        build-essential \
        nasm \
        yasm \
        pkg-config \
        git \
        libssl-dev \
        libx264-dev \
        libx265-dev \
        libvpx-dev \
        libfdk-aac-dev \
        libmp3lame-dev \
        libopus-dev \
        libass-dev \
        libfreetype-dev \
        libfontconfig-dev \
        libfribidi-dev \
        libharfbuzz-dev \
        libsdl2-dev \
        libva-dev \
        libvdpau-dev \
        libxcb1-dev \
        libxcb-shm0-dev \
        libxcb-xfixes0-dev \
        zlib1g-dev \
        libgnutls28-dev \
        libunistring-dev \
        libdrm-dev \
        libpulse-dev \
        libasound2-dev \
        libsrt-gnutls-dev \
        libgmp-dev \
        libtasn1-6-dev \
        libp11-kit-dev \
        nettle-dev \
        libbz2-dev \
        liblzma-dev \
        libxml2-dev
    echo ">>> Dependencies installed."
else
    echo ">>> Skipping dependency install (--no-deps)"
fi

########################################
# 2. Configure (static)
########################################
echo ""
echo ">>> Configuring FFmpeg (static)..."
cd "$SCRIPT_DIR"

# pkg-config must find .a files
export PKG_CONFIG="pkg-config --static"

./configure \
    --prefix="$PREFIX" \
    --pkg-config-flags="--static" \
    --extra-cflags="-static" \
    --extra-ldflags="-static" \
    --extra-libs="-lpthread -lm" \
    --enable-static \
    --disable-shared \
    --enable-gpl \
    --enable-nonfree \
    --enable-openssl \
    --enable-libx264 \
    --enable-libx265 \
    --enable-libvpx \
    --enable-libfdk-aac \
    --enable-libmp3lame \
    --enable-libopus \
    --enable-libass \
    --enable-libfreetype \
    --enable-sdl2 \
    --enable-libpulse \
    --enable-vaapi \
    --enable-vdpau \
    --enable-libdrm

echo ">>> Configure done."

########################################
# 3. Build
########################################
echo ""
echo ">>> Building FFmpeg (jobs=$NPROC)..."
make -j"$NPROC"
echo ">>> Build complete."

########################################
# 4. Install to prefix
########################################
echo ""
echo ">>> Installing to $PREFIX ..."
make install
echo ">>> Install complete."

########################################
# 5. Verify
########################################
echo ""
echo "=== Verification ==="
FFMPEG="$PREFIX/bin/ffmpeg"
FFPLAY="$PREFIX/bin/ffplay"
FFPROBE="$PREFIX/bin/ffprobe"

for bin in "$FFMPEG" "$FFPLAY" "$FFPROBE"; do
    if [ -f "$bin" ]; then
        name=$(basename "$bin")
        size=$(du -sh "$bin" | cut -f1)
        printf "  %-8s %s  %s\n" "$name" "$size" "$("$bin" -version 2>/dev/null | head -1)"
        # Show it's truly static (no dynamic deps)
        if ldd "$bin" 2>&1 | grep -q "not a dynamic"; then
            echo "           -> fully static binary"
        else
            echo "           -> dynamically linked (some libs may not have static .a)"
        fi
    fi
done

echo ""
echo "=== Output binaries ==="
echo "  $PREFIX/bin/ffmpeg"
echo "  $PREFIX/bin/ffplay"
echo "  $PREFIX/bin/ffprobe"
echo ""
echo "Copy these files anywhere and run without installing dependencies."
echo ""
echo "=== TLS keylog usage ==="
echo "  $FFPLAY -keylog_file /tmp/keys.log rtsps://host/stream"
echo "  SSLKEYLOGFILE=/tmp/keys.log $FFPLAY rtsps://host/stream"
echo ""
echo "Done!"

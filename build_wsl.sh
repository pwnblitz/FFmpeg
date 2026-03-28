#!/bin/bash
set -e

# FFmpeg WSL Build Script (Ubuntu/Debian)
# SHA-256/SHA-512-256 digest auth + SSL keylog support
#
# Usage:
#   chmod +x build_wsl.sh
#   ./build_wsl.sh          # full build (install deps + compile)
#   ./build_wsl.sh --no-deps  # skip apt install (deps already installed)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NPROC=$(nproc 2>/dev/null || echo 4)
PREFIX="/usr/local"
SKIP_DEPS=0

for arg in "$@"; do
    case "$arg" in
        --no-deps) SKIP_DEPS=1 ;;
        --prefix=*) PREFIX="${arg#--prefix=}" ;;
        -h|--help)
            echo "Usage: $0 [--no-deps] [--prefix=/usr/local]"
            exit 0
            ;;
    esac
done

echo "=== FFmpeg WSL Build ==="
echo "  Source:  $SCRIPT_DIR"
echo "  Prefix:  $PREFIX"
echo "  Jobs:    $NPROC"
echo ""

########################################
# 1. Install dependencies
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
        libasound2-dev
    echo ">>> Dependencies installed."
else
    echo ">>> Skipping dependency install (--no-deps)"
fi

########################################
# 2. Configure
########################################
echo ""
echo ">>> Configuring FFmpeg..."
cd "$SCRIPT_DIR"

./configure \
    --prefix="$PREFIX" \
    --enable-gpl \
    --enable-nonfree \
    --enable-openssl \
    --enable-gnutls \
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
# 4. Install (optional)
########################################
echo ""
echo ">>> Installing to $PREFIX ..."
sudo make install
sudo ldconfig
echo ">>> Install complete."

########################################
# 5. Verify
########################################
echo ""
echo "=== Verification ==="
echo -n "ffmpeg:  "; ffmpeg -version 2>/dev/null | head -1 || echo "(not in PATH)"
echo -n "ffplay:  "; ffplay -version 2>/dev/null | head -1 || echo "(not in PATH)"
echo -n "ffprobe: "; ffprobe -version 2>/dev/null | head -1 || echo "(not in PATH)"

echo ""
echo "=== TLS keylog test ==="
echo "  ffplay -keylog_file /tmp/keys.log rtsps://host/stream"
echo "  SSLKEYLOGFILE=/tmp/keys.log ffplay rtsps://host/stream"
echo ""
echo "Done!"

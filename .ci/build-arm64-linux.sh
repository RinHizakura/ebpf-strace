#!/usr/bin/env bash
#
# Build Linux for aarch64 cross-compilation using the Arm GNU toolchain.
#
# Usage:
#   .ci/build-arm64-linux.sh                        # full setup (default kernel)
#   KERNEL_VER=6.1.100 .ci/build-arm64-linux.sh     # specific kernel version
#

set -euox pipefail

TOOLCHAIN_DIR=/usr/local/aarch64-none-linux-gnu
KERNEL_VER=${KERNEL_VER:-7.0.1}
KERNEL_MAJOR=${KERNEL_VER%%.*}
KERNEL_DIR=linux-${KERNEL_VER}
KERNEL_TARBALL=${KERNEL_DIR}.tar.xz
KERNEL_URL=https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_MAJOR}.x/${KERNEL_TARBALL}

export PATH="$PATH:$TOOLCHAIN_DIR/bin"

step() { printf '\n=== %s ===\n' "$1"; }

step "arm64 kernel ${KERNEL_VER} (vmlinux for BTF)"
if [ ! -f "$KERNEL_DIR/vmlinux" ]; then
    [ -f "$KERNEL_TARBALL" ] || wget -q "$KERNEL_URL"
    [ -d "$KERNEL_DIR" ]     || tar xf "$KERNEL_TARBALL"
    cp .ci/materials/config-arm64 "$KERNEL_DIR/.config"
fi

cd "$KERNEL_DIR" && make ARCH=arm64 \
    CROSS_COMPILE=aarch64-none-linux-gnu- -j"$(nproc)"

#!/usr/bin/env bash
#
# Prepare the local environment for an aarch64 cross build.
#
# Usage:
#   .ci/install-arm64-toolchains.sh
#
# Requires sudo for installing the toolchain/sysroot under
# /usr/local/aarch64-none-linux-gnu.

set -euo pipefail

TOOLCHAIN_DIR=/usr/local/aarch64-none-linux-gnu
SYSROOT="$TOOLCHAIN_DIR/aarch64-none-linux-gnu"
ARM_TOOLCHAIN_VER=15.2.rel1
ARM_DIR=arm-gnu-toolchain-${ARM_TOOLCHAIN_VER}-x86_64-aarch64-none-linux-gnu
ARM_TARBALL=${ARM_DIR}.tar.xz
ARM_URL=https://developer.arm.com/-/media/Files/downloads/gnu/${ARM_TOOLCHAIN_VER}/binrel/${ARM_TARBALL}

step() { printf '\n=== %s ===\n' "$1"; }

step "Arm GNU toolchain ($TOOLCHAIN_DIR)"
if [ ! -x "$TOOLCHAIN_DIR/bin/aarch64-none-linux-gnu-gcc" ]; then
    [ -f "$ARM_TARBALL" ] || wget -q "$ARM_URL"
    [ -d "$ARM_DIR" ]    || tar xf "$ARM_TARBALL"
    sudo mkdir -p "$TOOLCHAIN_DIR"
    sudo cp -a "$ARM_DIR"/. "$TOOLCHAIN_DIR"/
else
    echo "Arm GNU toolchain already installed at $TOOLCHAIN_DIR, skipping."
fi

step "arm64 zlib (sysroot)"
if [ ! -f "$SYSROOT/lib/libz.a" ] && [ ! -f "$SYSROOT/lib/libz.so" ]; then
    [ -d zlib ] || git clone -q https://github.com/madler/zlib.git
    (
        cd zlib
        git clean -fdx -q
        CHOST=aarch64 \
            CC=aarch64-none-linux-gnu-gcc \
            AR=aarch64-none-linux-gnu-ar \
            ./configure --prefix="$SYSROOT"
        make -j"$(nproc)"
        sudo make install
    )
else
    echo "arm64 zlib already installed in sysroot, skipping."
fi

step "arm64 libelf (sysroot)"
if [ ! -f "$SYSROOT/lib/libelf.a" ] && [ ! -f "$SYSROOT/lib/libelf.so" ]; then
    [ -d elfutils ] || git clone -q git://sourceware.org/git/elfutils.git
    (
        cd elfutils
        autoreconf -i -f
        ./configure \
            --host=aarch64-none-linux-gnu \
            --prefix="$SYSROOT" \
            --enable-maintainer-mode \
            --disable-libdebuginfod --disable-debuginfod
        (cd lib && make -j"$(nproc)")
        (cd libelf && make -j"$(nproc)" \
            && sudo PATH="$TOOLCHAIN_DIR/bin:${PATH}" make install)
    )
else
    echo "arm64 libelf already installed in sysroot, skipping."
fi

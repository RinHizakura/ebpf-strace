#!/usr/bin/env bash
#
# Prepare an aarch64 chroot used by vng/QEMU when running ebpf-strace tests
# from an x86_64 host.
#
# Pulls the Ubuntu cloud-image rootfs tarball, unpacks it, and pre-creates
# the mount point that .ci/strace-test-arm64-vm.sh bind-mounts the project
# tree into (vng's 9p root is read-only, so the directory must exist before
# boot).
#
# Usage:
#   .ci/build-arm64-rootfs.sh                  # fetch + unpack (idempotent)
#   ROOTFS_DIR=/tmp/r .ci/build-arm64-rootfs.sh
#
# Env knobs:
#   BUILD_DIR        cache/output root, default build
#   ROOTFS_DIR       chroot location, default $BUILD_DIR/arm64-chroot
#   ROOTFS_TARBALL   downloaded tarball path, default $BUILD_DIR/arm64-rootfs.tar.xz
#   ROOTFS_URL       tarball URL, default Ubuntu jammy arm64 cloud image
#   GUEST_MOUNT      mount point to pre-create inside chroot, default /mnt/proj
#
set -euo pipefail

BUILD_DIR=${BUILD_DIR:-build}
ROOTFS_DIR=${ROOTFS_DIR:-$BUILD_DIR/arm64-chroot}
ROOTFS_TARBALL=${ROOTFS_TARBALL:-$BUILD_DIR/arm64-rootfs.tar.xz}
ROOTFS_URL=${ROOTFS_URL:-https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-arm64-root.tar.xz}
GUEST_MOUNT=${GUEST_MOUNT:-/mnt/proj}

step() { printf '\n=== %s ===\n' "$1"; }

mkdir -p "$(dirname "$ROOTFS_TARBALL")"

step "fetch rootfs tarball"
if [ ! -f "$ROOTFS_TARBALL" ]; then
    echo "downloading $ROOTFS_URL"
    curl -sSL -o "$ROOTFS_TARBALL" "$ROOTFS_URL"
else
    echo "tarball already present: $ROOTFS_TARBALL"
fi

step "unpack rootfs"
if [ ! -d "$ROOTFS_DIR/bin" ]; then
    sudo mkdir -p "$ROOTFS_DIR"
    sudo tar -xJf "$ROOTFS_TARBALL" -C "$ROOTFS_DIR"
else
    echo "chroot already populated: $ROOTFS_DIR"
fi

step "pre-create guest mount point"
if [ ! -d "$ROOTFS_DIR$GUEST_MOUNT" ]; then
    sudo mkdir -p "$ROOTFS_DIR$GUEST_MOUNT"
fi
echo "ready: $ROOTFS_DIR$GUEST_MOUNT"

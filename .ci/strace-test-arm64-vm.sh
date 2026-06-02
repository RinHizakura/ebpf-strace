#!/usr/bin/env bash
#
# Boot the cross-built aarch64 kernel under virtme-ng on an x86_64 host and run
# .ci/strace-test.sh inside the guest against the aarch64 ebpf-strace binary.
#
# Prereqs (installed locally, not by this script):
#   * vng / virtme-ng              (pip install virtme-ng)
#   * qemu-system-aarch64
#   * Arm GNU toolchain at /usr/local/aarch64-none-linux-gnu/...
#   * Cross-built kernel:    KERNEL_VER=... .ci/build-arm64-linux.sh
#     -> produces linux-<ver>/arch/arm64/boot/Image with BTF + virtio drivers.
#   * Cross-built userspace: VMLINUX=... make ARCH=aarch64 \
#         CROSS_COMPILE=aarch64-none-linux-gnu-
#   * Aarch64 chroot:        .ci/build-arm64-rootfs.sh
#
# Usage:
#   .ci/strace-test-arm64-vm.sh                 # run full suite
#   .ci/strace-test-arm64-vm.sh openat read     # run specific tests
#
# Env knobs:
#   KERNEL_VER   kernel directory suffix, default 7.0.1
#   BUILD_DIR    where kernel + chroot live, default build
#   ROOTFS_DIR   chroot location, default $BUILD_DIR/arm64-chroot
#
set -euo pipefail

KERNEL_VER=${KERNEL_VER:-7.0.1}
BUILD_DIR=${BUILD_DIR:-build}
KERNEL_IMG="${BUILD_DIR}/linux-${KERNEL_VER}/arch/arm64/boot/Image"
ROOTFS_DIR=${ROOTFS_DIR:-$BUILD_DIR/arm64-chroot}
PROJECT_DIR=$(cd "$(dirname "$0")/.." && pwd)
GUEST_MOUNT=/mnt/proj

if [ ! -f "$KERNEL_IMG" ]; then
    echo "error: missing $KERNEL_IMG — run .ci/build-arm64-linux.sh first" >&2
    exit 1
fi
if [ ! -x target/aarch64-unknown-linux-gnu/debug/ebpf-strace ]; then
    echo "error: missing arm64 ebpf-strace binary — cross-build first" >&2
    exit 1
fi
if [ ! -d "$ROOTFS_DIR/bin" ] || [ ! -d "$ROOTFS_DIR$GUEST_MOUNT" ]; then
    echo "error: missing aarch64 chroot at $ROOTFS_DIR — run .ci/build-arm64-rootfs.sh first" >&2
    exit 1
fi

TEST_ARGS="$*"

# vng flags:
#   --arch arm64             tell vng to spin an aarch64 guest via qemu
#   --run <Image>            kernel binary to boot
#   --root <dir>             aarch64 chroot (Ubuntu cloud image)
#   --rwdir guest=host       expose project tree under /mnt/proj in guest
#   --user root              strace-test.sh uses sudo; start as root inside
# Guest env:
#   STRACE_LOG / OUTPUT_LOG are redirected to /var/tmp because vng leaves /tmp
#   on the read-only 9p root, while /var/tmp is mounted tmpfs by virtme-init.
exec vng \
    --arch arm64 \
    --run "$KERNEL_IMG" \
    --root "$ROOTFS_DIR" \
    --rwdir="${GUEST_MOUNT}=${PROJECT_DIR}" \
    --user root \
    --memory 2G \
    --cpus "$(( $(nproc) < 8 ? $(nproc) : 8 ))" \
    --exec "cd $GUEST_MOUNT && \
            STRACE_LOG=/var/tmp/strace.log \
            OUTPUT_LOG=/var/tmp/output.log \
            BIN=target/aarch64-unknown-linux-gnu/debug/ebpf-strace \
            OUT_DIR=target/aarch64-unknown-linux-gnu/debug/tests \
            .ci/strace-test.sh $TEST_ARGS"

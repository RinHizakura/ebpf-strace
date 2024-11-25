# ebpf-strace

## Overview

The `ebpf-strace` is an experimental tool to trace system calls like
[strace](https://github.com/strace/strace), but achieving by
[eBPF](https://en.wikipedia.org/wiki/EBPF) instead of
[ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

The tool can be run on x86_64 or aarch64, but most of the
validation only done on x86_64 currently. Besides, only a few syscalls's
arguments can be traced. Please feel free to report for any unusual output
or implement arguments tracing for more system calls.

## Usage

### Build

These dependencies are required to build ebpf-strace.

```
$ sudo apt install clang llvm libelf1 libelf-dev zlib1g-dev
```

You will also need `bpftool` for the generating of `vmlinux.h`.

```
$ git clone https://github.com/libbpf/bpftool.git
$ cd bpftool
$ git submodule update --init
$ cd src
$ make
$ sudo make install
```

After the installations, you can build `ebpf-strace` now.
```
$ make
```

### Execute

To know the detail for how to use ebpf-strace, you can try `-h` for the direction.

```
$ sudo ./ebpf -h
Usage: ebpf-strace [OPTIONS] [CMD]...

Arguments:
  [CMD]...  command to run for trace

Options:
  -T, --syscall-times  whether to show on the time cost of syscall
  -h, --help           Print help
```

For example, we can trace which system calls are run during the execution
of `echo hello` with the following command:
```
$ sudo ./ebpf-strace echo hello
```

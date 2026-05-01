# ebpf-strace

## Overview

The `ebpf-strace` is an experimental tool to trace system calls like
[strace](https://github.com/strace/strace), but achieving by
[eBPF](https://en.wikipedia.org/wiki/EBPF) instead of
[ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

The tool can be run on x86_64 or aarch64, but most of the
validation only done on x86_64 currently. Besides, not every syscalls's
arguments can be traced.

## Syscall Support

See [Documents/support.md](Documents/support.md) for the full syscall support and test coverage tables.

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
$ sudo ./ebpf-strace -h
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

## Testing

The test suite lives in `tests/` — one C program per syscall. Each program
exercises the syscall and prints its arguments and return value in strace
format to stdout. The CI script `.ci/strace-test.sh` runs every test binary
under `ebpf-strace`, then checks that each stdout line appears verbatim in
ebpf-strace's output.

### Run all tests

Build everything first, then run the full suite:

```
$ make
$ .ci/strace-test.sh
```

A passing run prints `pass` for every test. A failure prints the offending
line and the relevant ebpf-strace output to help diagnose the mismatch.

### Run a specific syscall

Pass one or more syscall names (without the `.out` suffix) as arguments:

```
$ .ci/strace-test.sh fstat
$ .ci/strace-test.sh read write open
```

### Verify against strace

The `BIN` environment variable controls which tracer is used. Setting it to
`strace -v` runs the tests against the real strace instead of ebpf-strace,
which lets you confirm that a test's expected output actually matches what
strace produces:

```
$ BIN="strace -v" .ci/strace-test.sh
$ BIN="strace -v" .ci/strace-test.sh getrandom
```

`strace -v` disables abbreviation of struct fields so the output is fully
expanded, matching the verbose format that the tests expect.

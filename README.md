# ebpf-strace

A tiny tool to trace syscalls by eBPF

> WARNING: Currently, the tool can only be run on x86_64. Besides,
> only a few syscalls's arguments can be traced.

## Usage

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

For example, we can trace which system calls are run during the execution
of `echo hello` with the following command:
```
$ sudo ./ebpf-strace echo hello
```

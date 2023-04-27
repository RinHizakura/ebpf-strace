# ebpf-strace

A tiny tool to trace syscalls by eBPF

> WARNING: It could only be run on x86_64 architecture currently

## Usage

These dependencies are required to build ebpf-strace.
```
$ apt install clang llvm libelf1 libelf-dev zlib1g-dev
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

After those installation, you should be able to build `ebpf-strace` now.
For example, we can trace which system calls are run during the execution
of `echo hello` with the following command:
```
$ make
$ sudo target/debug/ebpf-strace echo hello
```

Note that the result doesn't perfectly match the output of `strace` because
this project is still work in process.

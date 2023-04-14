OUT = target/debug
BIN = $(OUT)/ebpf-strace
VMLINUX_H = vmlinux.h

SRCS = $(shell find ./src -name '*.c')
SRCS += $(shell find ./src -name '*.rs')

all: $(BIN) $(GIT_HOOKS)

$(GIT_HOOKS):
	@scripts/install-git-hooks
	@echo

$(BIN): $(SRCS) $(VMLINUX_H)
	cargo build

$(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

run: $(BIN)
	sudo $(BIN) cat README.md 1>/dev/null

check:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	cargo clean
	$(RM) bpf/syscall/syscall_tbl.h
	$(RM) bpf/syscall/syscall_nr.h
	$(RM) src/syscall/syscall_tbl.rs
	$(RM) src/syscall/syscall_nr.rs

OUT = target/debug
BIN = $(OUT)/ebpf-strace

SRCS = $(shell find ./src -name '*.c')
SRCS += $(shell find ./src -name '*.rs')

all: $(BIN) $(GIT_HOOKS)

$(GIT_HOOKS):
	@scripts/install-git-hooks
	@echo

$(BIN): $(SRCS)
	cargo build

run: $(BIN)
	sudo $(BIN) echo hello 1>/dev/null

check:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	cargo clean
	$(RM) src/bpf/syscall/syscall_tbl.h
	$(RM) src/bpf/syscall/syscall.h
	$(RM) src/syscall_tbl.rs

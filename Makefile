OUT = target/debug
BIN = $(OUT)/ebpf-strace

all: $(BIN) $(GIT_HOOKS)

$(GIT_HOOKS):
	@scripts/install-git-hooks
	@echo

$(BIN):
	cargo build

run: $(BIN)
	sudo $(BIN) echo hello 1>/dev/null

clean:
	cargo clean
	$(RM) src/bpf/syscall_tbl.h
	$(RM) src/bpf/syscall.h
	$(RM) src/syscall.rs

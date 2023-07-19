OUT = target/debug

BIN = $(OUT)/ebpf-strace
VMLINUX_H = vmlinux.h
GIT_HOOKS := .git/hooks/applied
SRCS = $(shell find ./bpf -name '*.c')
SRCS += $(shell find ./src -name '*.rs')

TEST_OUT = build
SHELL_HACK := $(shell mkdir -p $(TEST_OUT))
TEST_SRCS = $(shell find ./tests -name '*.c')
_TEST_OBJ =  $(notdir $(TEST_SRCS))
TEST_OBJ = $(_TEST_OBJ:%.c=$(TEST_OUT)/%.out)

vpath %.c $(sort $(dir $(TEST_SRCS)))

all: $(BIN) $(GIT_HOOKS) $(TEST_OBJ)

$(GIT_HOOKS):
	@scripts/install-git-hooks
	@echo

$(BIN): $(SRCS) $(VMLINUX_H)
	cargo build

$(TEST_OUT)/%.out: %.c
	gcc $< -o $@

$(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

test:
	scripts/strace-test.sh

check:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	cargo clean
	$(RM) $(TEST_OBJ) $(TEST)
	$(RM) bpf/syscall/syscall_tbl.h
	$(RM) bpf/syscall/syscall_nr.h
	$(RM) src/syscall/syscall_tbl.rs
	$(RM) src/syscall/syscall_nr.rs

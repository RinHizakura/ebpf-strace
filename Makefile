ARCH =

# AARCH64 build
ifeq ($(ARCH), aarch64)
	LINKER = CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER
	CROSS_COMPILE = aarch64-unknown-linux-gnu
	EXPORT_PATH = $(LINKER)=$(CROSS_COMPILE)-gcc
	CARGO_OPT = --target $(CROSS_COMPILE)
	CC = $(CROSS_COMPILE)-gcc
endif

# Host build
ifeq ($(ARCH), )
	CROSS_COMPILE =
	EXPORT_PATH =
	CARGO_OPT =
endif

OUT = target/$(CROSS_COMPILE)/debug
SHELL_HACK := $(shell mkdir -p $(OUT))

BIN = $(OUT)/ebpf-strace
GIT_HOOKS := .git/hooks/applied
SRCS = $(shell find ./bpf -name '*.c')
SRCS += $(shell find ./src -name '*.rs')

TEST_OUT = build
TEST_SRCS = $(shell find ./tests -name '*.c')
_TEST_OBJ =  $(notdir $(TEST_SRCS))
TEST_OBJ = $(_TEST_OBJ:%.c=$(TEST_OUT)/%.out)
TET_SHELL_HACK := $(shell mkdir -p $(TEST_OUT))

CFLAGS = -Wall -Wextra -Werror

vpath %.c $(sort $(dir $(TEST_SRCS)))

all: build $(GIT_HOOKS) $(TEST_OBJ)

build: $(BIN)

$(GIT_HOOKS):
	@scripts/install-git-hooks
	@echo

$(BIN): $(SRCS)
	$(EXPORT_PATH) cargo build $(CARGO_OPT)

$(TEST_OUT)/%.out: %.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	cargo clean
	$(RM) $(TEST_OBJ) $(TEST)
	$(RM) bpf/arch/*/syscall_tbl.h
	$(RM) bpf/arch/*/syscall_nr.h
	$(RM) src/arch/*/syscall_tbl.rs
	$(RM) src/arch/*/syscall_nr.rs

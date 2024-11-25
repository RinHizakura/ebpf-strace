HOSTARCH := $(shell uname -m)
ARCH ?=

NOTEST = 'TestEveryThing'
AARCH64_NOTEST = 'select|stat|pipe|open'

# AARCH64 cross build
ifeq ($(ARCH), aarch64)
	LINKER = CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER
	TARGET = aarch64-unknown-linux-gnu
	CROSS_COMPILE ?= aarch64-unknown-linux-gnu-
	EXPORT_PATH = $(LINKER)=$(CROSS_COMPILE)gcc
	CARGO_OPT = --target $(TARGET)
	CC = $(CROSS_COMPILE)gcc
	NOTEST = $(AARCH64_NOTEST)
endif

# Host build
ifeq ($(ARCH), )
	CROSS_COMPILE =
	EXPORT_PATH =
	CARGO_OPT =
ifeq ($(HOSTARCH), aarch64)
	NOTEST = $(AARCH64_NOTEST)
endif
endif

OUT = target/$(TARGET)/debug
TEST_OUT = $(OUT)/tests
SHELL_HACK := $(shell mkdir -p $(TEST_OUT))

GIT_HOOKS := .git/hooks/applied

BIN = $(OUT)/ebpf-strace
SRCS = $(shell find bpf -name '*.c')
SRCS += $(shell find src -name '*.rs')

TEST_SRCS := $(shell find tests -name '*.c' | grep -vE $(NOTEST))
_TEST_OBJ =  $(notdir $(TEST_SRCS))
TEST_OBJ = $(_TEST_OBJ:%.c=$(TEST_OUT)/%.out)

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

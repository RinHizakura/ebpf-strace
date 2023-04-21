#ifndef __TARGET_ARCH_x86
#error "only x86_64 architecture is supported for ebpf-strace"
#endif

/* clang-format off */
// We must include this
#include "vmlinux.h"
/* clang-format on */
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "syscall/syscall_ent.h"
#include "syscall/syscall_nr.h"
#include "utils.h"

// We limit the iteration of loop by this definition to pass eBPF verifier
#define LOOP_MAX 1024

pid_t select_pid = 0;
/* The key to access the single entry BPF_MAP in array type. */
u32 INDEX_0 = 0;

DEFINE_BPF_MAP(g_buf_addr, BPF_MAP_TYPE_ARRAY, u32, void *, 1);

/* FIXME: The instance allow us to store some information
 * at sys_enter and collect the remaining information at sys_exit.
 * It assumes that the sys_exit of a system call will always come
 * right after its sys_enter. Is this always correct? */
DEFINE_BPF_MAP(g_ent, BPF_MAP_TYPE_ARRAY, u32, syscall_ent_t, 1);

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} syscall_record SEC(".maps");

#include "bpf/execve.c"
#include "bpf/exit.c"
#include "bpf/io.c"

static void sys_enter_default(syscall_ent_t *ent, u64 id)
{
    ent->basic.id = id;
}

SEC("raw_tracepoint/sys_enter")
int sys_enter(struct bpf_raw_tracepoint_args *args)
{
    /* We'll only hook the pid which is specified by BPF loader.
     * Note that the return value of "bpf_get_current_pid_tgid" will
     * be "(u64) task->tgid << 32 | task->pid" */
    u64 cur_pid = (bpf_get_current_pid_tgid() >> 32);
    if (select_pid == 0 || select_pid != cur_pid)
        return 0;

    /* Reference to the TP_PROTO macro for sys_enter under
     * https://elixir.bootlin.com/linux/latest/source/include/trace/events/syscalls.h
     */
    u64 id = args->args[1];
    syscall_ent_t *ent = bpf_g_ent_lookup_elem(&INDEX_0);
    if (!ent)
        return -1;

    sys_enter_default(ent, id);

    /* According to x86_64 abi:  User-level applications use as integer
     * registers for passing the sequence %rdi, %rsi, %rdx, %rcx, %r8 and %r9.
     * The kernel interface uses %rdi, %rsi, %rdx, %r10, %r8 and %r9. */
    struct pt_regs *pt_regs = (struct pt_regs *) args->args[0];
    u64 di = BPF_CORE_READ(pt_regs, di);
    u64 si = BPF_CORE_READ(pt_regs, si);
    u64 dx = BPF_CORE_READ(pt_regs, dx);
    u64 r10 = BPF_CORE_READ(pt_regs, r10);
    u64 r8 = BPF_CORE_READ(pt_regs, r8);
    u64 r9 = BPF_CORE_READ(pt_regs, r9);
    switch (id) {
    case SYS_READ:
        sys_read_enter(ent, id, di, (void *) si, dx);
        break;
    case SYS_WRITE:
        sys_write_enter(ent, id, di, (void *) si, dx);
        break;
    case SYS_EXECVE:
        sys_execve_enter(ent, id, (char *) di, (void *) si, (void *) dx);
        break;
    case SYS_EXIT_GROUP:
        sys_exit_group_enter(id, di);
        break;
    default:
        break;
    }

    return 0;
}

static void sys_exit_default(syscall_ent_t *ent, u64 ret)
{
    ent->basic.ret = ret;
}

static void submit_syscall(syscall_ent_t *ent, size_t args_size)
{
    size_t total_size = sizeof(basic_t) + args_size;
    syscall_ent_t *ringbuf_ent =
        bpf_ringbuf_reserve(&syscall_record, total_size, 0);
    if (!ringbuf_ent) {
        /* FIXME: Drop the syscall directly. Any better approach to guarantee
         * to record the syscall on ring buffer?*/
        return;
    }
    memcpy(ringbuf_ent, ent, total_size);
    bpf_ringbuf_submit(ringbuf_ent, 0);
}

SEC("raw_tracepoint/sys_exit")
int sys_exit(struct bpf_raw_tracepoint_args *args)
{
    u64 cur_pid = (bpf_get_current_pid_tgid() >> 32);
    if (select_pid == 0 || select_pid != cur_pid)
        return 0;

    struct pt_regs *pt_regs = (struct pt_regs *) args->args[0];
    long ret = args->args[1];

    u64 id = BPF_CORE_READ(pt_regs, orig_ax);
    syscall_ent_t *ent = bpf_g_ent_lookup_elem(&INDEX_0);
    if (!ent || (ent->basic.id != id))
        return -1;

    sys_exit_default(ent, ret);

    switch (id) {
    case SYS_READ:
        sys_read_exit(ent, ret);
        break;
    default:
        break;
    }

    switch (id) {
#define __SYSCALL(nr, call)                         \
    case nr:                                        \
        submit_syscall(ent, sizeof(call##_args_t)); \
        break;
#include "syscall/syscall_tbl.h"
#undef __SYSCALL
    default:
        break;
    }

    return 0;
}
char LICENSE[] SEC("license") = "GPL";

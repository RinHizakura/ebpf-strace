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

pid_t select_pid = 0;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} syscall_record SEC(".maps");

/* Generate the default syscall enter handler */
#define __SYSCALL(nr, call)            \
    static void call##_enter()         \
    {                                  \
        bpf_printk("enter/%s", #call); \
    }                                  \
    static void call##_exit()          \
    {                                  \
        bpf_printk("exit/%s", #call);  \
    }
#include "syscall/syscall_tbl.h"
#undef __SYSCALL

SEC("raw_tracepoint/sys_enter")
int sys_enter(struct bpf_raw_tracepoint_args *args)
{
    /* We'll only hook the pid which is specified by BPF loader.
     * Note that the return value of "bpf_get_current_pid_tgid" will
     * be "(u64) task->tgid << 32 | task->pid" */
    __u64 cur_pid = (bpf_get_current_pid_tgid() >> 32);
    if (select_pid == 0 || select_pid != cur_pid)
        return 0;

    /* Reference to the TP_PROTO macro for sys_enter under
     * https://elixir.bootlin.com/linux/latest/source/include/trace/events/syscalls.h
     */
    __u64 id = args->args[1];
    switch (id) {
#define __SYSCALL(nr, call) \
    case nr:                \
        call##_enter();     \
        break;
#include "syscall/syscall_tbl.h"
#undef __SYSCALL
    default:
        break;
    }

    syscall_ent_t *ent =
        bpf_ringbuf_reserve(&syscall_record, sizeof(syscall_ent_t), 0);
    if (!ent) {
        /* FIXME: Drop the syscall directly. Any better approach to guarantee
         * to record the syscall on ring buffer?*/
        return 0;
    }
    ent->id = id;
    bpf_ringbuf_submit(ent, 0);

    return 0;
}

SEC("raw_tracepoint/sys_exit")
int sys_exit(struct bpf_raw_tracepoint_args *args)
{
    __u64 cur_pid = (bpf_get_current_pid_tgid() >> 32);
    if (select_pid == 0 || select_pid != cur_pid)
        return 0;

    struct pt_regs *pt_regs = (struct pt_regs *) args->args[0];
    long ret = args->args[1];

    __u64 id = BPF_CORE_READ(pt_regs, orig_ax);
    switch (id) {
#define __SYSCALL(nr, call) \
    case nr:                \
        call##_exit();      \
        break;
#include "syscall/syscall_tbl.h"
#undef __SYSCALL
    default:
        break;
    }

    return 0;
}
char LICENSE[] SEC("license") = "GPL";

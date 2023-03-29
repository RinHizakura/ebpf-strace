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
/* FIXME: The instance allow us to store some information
 * at sys_enter and collect the remaining information at sys_exit.
 * It assumes that the sys_exit of a system call will always come
 * right after its sys_enter. Is this always correct? */
DEFINE_BPF_MAP(g_ent, BPF_MAP_TYPE_ARRAY, u32, syscall_ent_t, 1);

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} syscall_record SEC(".maps");

/* Generate the default syscall enter handler */
#define __SYSCALL(nr, call)            \
    static void call##_enter_debug()   \
    {                                  \
        bpf_printk("enter/%s", #call); \
    }                                  \
    static void call##_exit_debug()    \
    {                                  \
        bpf_printk("exit/%s", #call);  \
    }
#include "syscall/syscall_tbl.h"
#undef __SYSCALL

static void sys_enter_default(syscall_ent_t *ent, __u64 id)
{
    ent->id = id;
}

static void sys_enter_read(syscall_ent_t *ent,
                           __u64 id,
                           int fd,
                           void *buf,
                           size_t count)
{
    sys_enter_default(ent, id);

    read_args_t *read = &ent->read;
    read->fd = fd;
    memset(read->buf, 0, sizeof(read->buf));
    read->count = count;
}

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
#define __SYSCALL(nr, call)   \
    case nr:                  \
        call##_enter_debug(); \
        break;
#include "syscall/syscall_tbl.h"
#undef __SYSCALL
    default:
        break;
    }

    u32 index = 0;
    syscall_ent_t *ent = bpf_g_ent_lookup_elem(&index);
    if (!ent)
        return -1;

    /* TODO: take the arguements from register */
    switch (id) {
    case SYS_READ:
        sys_enter_read(ent, id, 0, NULL, 0);
        break;
    default:
        sys_enter_default(ent, id);
        break;
    }

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
#define __SYSCALL(nr, call)  \
    case nr:                 \
        call##_exit_debug(); \
        break;
#include "syscall/syscall_tbl.h"
#undef __SYSCALL
    default:
        break;
    }

    u32 index = 0;
    syscall_ent_t *ent = bpf_g_ent_lookup_elem(&index);
    if (!ent || (ent->id != id))
        return -1;
    ent->ret = ret;

    syscall_ent_t *ringbuf_ent =
        bpf_ringbuf_reserve(&syscall_record, sizeof(syscall_ent_t), 0);
    if (!ringbuf_ent) {
        /* FIXME: Drop the syscall directly. Any better approach to guarantee
         * to record the syscall on ring buffer?*/
        return 0;
    }
    memcpy(ringbuf_ent, ent, sizeof(syscall_ent_t));
    bpf_ringbuf_submit(ringbuf_ent, 0);

    return 0;
}
char LICENSE[] SEC("license") = "GPL";

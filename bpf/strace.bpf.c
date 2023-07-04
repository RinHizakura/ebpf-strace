/* clang-format off */

/* These header file should be included first and in sequence,
 * because our following included file may depend on these. Turn
 * off clang-format to achieve this purpose. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
/* clang-format on */

#ifdef __TARGET_ARCH_x86
#include "arch/x86_64/syscall.h"
#else
#error "only x86_64 architecture is supported for ebpf-strace now"
#endif

#include "msg_ent.h"
#include "syscall/syscall_nr.h"
#include "utils.h"

// We limit the iteration of loop by this definition to pass eBPF verifier
#define LOOP_MAX 1024

pid_t select_pid = 0;
/* The key to access the single entry BPF_MAP in array type. */
u32 INDEX_0 = 0;
u32 INDEX_1 = 1;

/* FIXME: For some reason, we may not able to read the content under the
 * address at sys_enter. To solve the problem, we store the address first
 * and read it until sys_exit.
 *
 * Are we guaranteed to get the syscall arguments from
 * ABI-defined register at sys_exit? If so we are able to do most
 * of the works at sys_exit directly, instead of passing the address
 * by BPF map like this. */
DEFINE_BPF_MAP(g_buf_addr, BPF_MAP_TYPE_ARRAY, u32, void *, 2);

/* FIXME: The instance allow us to store some information
 * at sys_enter and collect the remaining information at sys_exit.
 * It assumes that the sys_exit of a system call will always come
 * right after its sys_enter. Is this always correct? */
DEFINE_BPF_MAP(g_ent, BPF_MAP_TYPE_ARRAY, u32, syscall_ent_t, 1);

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} msg_ringbuf SEC(".maps");

#include "bpf/execve.c"
#include "bpf/exit.c"
#include "bpf/io.c"
#include "bpf/ioctl.c"
#include "bpf/lseek.c"
#include "bpf/mem.c"
#include "bpf/open_close.c"
#include "bpf/poll.c"
#include "bpf/rt_sigreturn.c"
#include "bpf/signal.c"
#include "bpf/stat.c"

static void submit_syscall(syscall_ent_t *ent, size_t args_size)
{
    size_t syscall_ent_size = sizeof(basic_t) + args_size;
    size_t total_size = sizeof(msg_ent_t) + syscall_ent_size;
    msg_ent_t *ringbuf_ent = bpf_ringbuf_reserve(&msg_ringbuf, total_size, 0);
    if (!ringbuf_ent) {
        /* FIXME: Drop the syscall directly. Any better approach to guarantee
         * to record the syscall on ring buffer?*/
        return;
    }
    ringbuf_ent->msg_type = MSG_SYSCALL;
    memcpy(ringbuf_ent->inner, ent, syscall_ent_size);
    bpf_ringbuf_submit(ringbuf_ent, 0);
}

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
    pid_t cur_pid = (bpf_get_current_pid_tgid() >> 32);
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

    struct pt_regs *pt_regs = (struct pt_regs *) args->args[0];
    u64 parm1 = PT_REGS_PARM1_CORE_SYSCALL(pt_regs);
    u64 parm2 = PT_REGS_PARM2_CORE_SYSCALL(pt_regs);
    u64 parm3 = PT_REGS_PARM3_CORE_SYSCALL(pt_regs);
    u64 parm4 = PT_REGS_PARM4_CORE_SYSCALL(pt_regs);
    u64 parm5 = PT_REGS_PARM5_CORE_SYSCALL(pt_regs);
    u64 parm6 = PT_REGS_PARM6_CORE_SYSCALL(pt_regs);
    switch (id) {
    case SYS_READ:
        sys_read_enter(ent, parm1, (void *) parm2, parm3);
        break;
    case SYS_WRITE:
        sys_write_enter(ent, parm1, (void *) parm2, parm3);
        break;
    case SYS_OPEN:
        sys_open_enter(ent, (char *) parm1, parm2);
        break;
    case SYS_CLOSE:
        sys_close_enter(ent, parm1);
        break;
    case SYS_STAT:
        sys_stat_enter(ent, (void *) parm1, (void *) parm2);
        break;
    case SYS_FSTAT:
        sys_fstat_enter(ent, parm1, (void *) parm2);
        break;
    case SYS_LSTAT:
        sys_lstat_enter(ent, (void *) parm1, (void *) parm2);
        break;
    case SYS_POLL:
        sys_poll_enter(ent, (void *) parm1, parm2, parm3);
        break;
    case SYS_LSEEK:
        sys_lseek_enter(ent, parm1, parm2, parm3);
        break;
    case SYS_MMAP:
        sys_mmap_enter(ent, (void *) parm1, parm2, parm3, parm4, parm5, parm6);
        break;
    case SYS_MPROTECT:
        sys_mprotect_enter(ent, (void *) parm1, parm2, parm3);
        break;
    case SYS_MUNMAP:
        sys_munmap_enter(ent, (void *) parm1, parm2);
        break;
    case SYS_BRK:
        sys_brk_enter(ent, (void *) parm1);
        break;
    case SYS_RT_SIGACTION:
        sys_rt_sigaction_enter(ent, parm1, (void *) parm2, (void *) parm3,
                               parm4);
        break;
    case SYS_IOCTL:
        sys_ioctl_enter(ent, parm1, parm2, (void *) parm3);
        break;
    case SYS_PREAD64:
        sys_pread_enter(ent, parm1, (void *) parm2, parm3, parm4);
        break;
    case SYS_RT_SIGPROCMASK:
        sys_rt_sigprocmask_enter(ent, parm1, (void *) parm2, (void *) parm3,
                                 parm4);
        break;
    case SYS_RT_SIGRETURN:
        sys_rt_sigreturn_enter(ent, pt_regs);
        break;
    case SYS_NEWFSTATAT:
        sys_newfstatat_enter(ent, parm1, (void *) parm2, (void *) parm3, parm4);
        break;
    case SYS_EXECVE:
        sys_execve_enter(ent, (char *) parm1, (void *) parm2, (void *) parm3);
        break;
    case SYS_EXIT_GROUP:
        sys_exit_group_enter(ent, parm1);
        break;
    case SYS_OPENAT:
        sys_openat_enter(ent, parm1, (char *) parm2, parm3);
        break;
    default:
        break;
    }

    /* Unlike most system call which can be traced to one sys_enter
     * and a pairing sys_exit, these call can only be traced
     * to one sys_enter only. Because of the reason, we submit the event
     * here directly. Note that we therefore don't know the return value */
    switch (id) {
    case SYS_RT_SIGRETURN:
        submit_syscall(ent, sizeof(rt_sigreturn_args_t));
        break;
    case SYS_EXIT_GROUP:
        submit_syscall(ent, sizeof(exit_group_args_t));
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

SEC("raw_tracepoint/sys_exit")
int sys_exit(struct bpf_raw_tracepoint_args *args)
{
    pid_t cur_pid = (bpf_get_current_pid_tgid() >> 32);
    if (select_pid == 0 || select_pid != cur_pid)
        return 0;

    struct pt_regs *pt_regs = (struct pt_regs *) args->args[0];
    long ret = args->args[1];

    u64 id = get_syscall_nr(pt_regs);
    syscall_ent_t *ent = bpf_g_ent_lookup_elem(&INDEX_0);
    if (!ent || (ent->basic.id != id))
        return -1;

    sys_exit_default(ent, ret);

    switch (id) {
    case SYS_READ:
        sys_read_exit(ent);
        break;
    case SYS_OPEN:
        sys_open_exit(ent);
        break;
    case SYS_STAT:
        sys_stat_exit(ent);
        break;
    case SYS_FSTAT:
        sys_fstat_exit(ent);
        break;
    case SYS_LSTAT:
        sys_lstat_exit(ent);
        break;
    case SYS_RT_SIGACTION:
        sys_rt_sigaction_exit(ent);
        break;
    case SYS_RT_SIGPROCMASK:
        sys_rt_sigprocmask_exit(ent);
        break;
    case SYS_IOCTL:
        sys_ioctl_exit(ent);
        break;
    case SYS_PREAD64:
        sys_pread_exit(ent);
        break;
    case SYS_NEWFSTATAT:
        sys_newfstatat_exit(ent);
        break;
    case SYS_OPENAT:
        sys_openat_exit(ent);
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

SEC("raw_tracepoint/signal_deliver")
int signal_deliver(struct bpf_raw_tracepoint_args *args)
{
    pid_t cur_pid = (bpf_get_current_pid_tgid() >> 32);
    if (select_pid == 0 || select_pid != cur_pid)
        return 0;

    size_t total_size = sizeof(msg_ent_t) + sizeof(signal_ent_t);
    msg_ent_t *ringbuf_ent = bpf_ringbuf_reserve(&msg_ringbuf, total_size, 0);
    if (!ringbuf_ent) {
        /* FIXME: Drop the syscall directly. Any better approach to guarantee
         * to record the syscall on ring buffer?*/
        return 0;
    }
    ringbuf_ent->msg_type = MSG_SIGNAL;

    /* FIXME: We simply assume that kernel_siginfo is the subset of siginfo,
     * but is this always correct? */
    int signo = args->args[0];
    struct kernel_siginfo *ksiginfo = (struct kernel_siginfo *) args->args[1];
    signal_ent_t *ent = (signal_ent_t *) ringbuf_ent->inner;
    ent->signo = signo;
    if (ksiginfo) {
        bpf_core_read(&ent->siginfo, sizeof(struct kernel_siginfo), ksiginfo);
    }
    bpf_ringbuf_submit(ringbuf_ent, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

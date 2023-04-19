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

/* FIXME: The instance allow us to store some information
 * at sys_enter and collect the remaining information at sys_exit.
 * It assumes that the sys_exit of a system call will always come
 * right after its sys_enter. Is this always correct? */
DEFINE_BPF_MAP(g_ent, BPF_MAP_TYPE_ARRAY, u32, syscall_ent_t, 1);

DEFINE_BPF_MAP(g_buf_addr, BPF_MAP_TYPE_ARRAY, u32, void *, 1);

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} syscall_record SEC(".maps");

/* Generate the default syscall enter and exit debug function */
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

static void sys_enter_default(syscall_ent_t *ent, u64 id)
{
    ent->id = id;
}

static void sys_enter_read(syscall_ent_t *ent,
                           u64 id,
                           int fd,
                           void *buf,
                           size_t count)
{
    sys_enter_default(ent, id);

    read_args_t *read = &ent->read;
    read->fd = fd;
    read->count = count;

    /* Record the address of buffer first but don't read the
     * content directly. Because the read syscall hasn't
     * fill the buffer yet when entering syscall. */
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = buf;
}

static void sys_enter_write(syscall_ent_t *ent,
                            u64 id,
                            int fd,
                            void *buf,
                            size_t count)
{
    sys_enter_default(ent, id);

    write_args_t *write = &ent->write;
    write->fd = fd;
    write->count = count;

    memset(write->buf, 0, sizeof(write->buf));
    size_t cpy_count = count > BUF_SIZE ? BUF_SIZE : count;
    bpf_core_read_user(write->buf, cpy_count, buf);
}

static void sys_enter_execve(syscall_ent_t *ent,
                             u64 id,
                             char *pathname,
                             char *argv[],
                             char *envp[])
{
    sys_enter_default(ent, id);

    execve_args_t *execve = &ent->execve;

    size_t idx = 0;
    if (argv != NULL) {
        for (;idx < LOOP_MAX; idx++) {
            char *env_var = NULL;
            bpf_core_read_user(&env_var, sizeof(env_var), &argv[idx]);
            if (!env_var)
                break;

            char c;
            bpf_core_read_user(&c, sizeof(c), env_var);
            if (c == '0')
                break;
        }
    }

    execve->argv = (size_t) argv;
    execve->argc = idx;

    execve->envp = (size_t) envp;
    execve->envp_cnt = 0;

    memset(execve->pathname, 0, sizeof(execve->pathname));
    bpf_core_read_user_str(execve->pathname, sizeof(execve->pathname),
                           pathname);
}

static void sys_enter_exit_group(u64 id, int status)
{
    /* Unlike most system call which can be traced to one sys_enter
     * and a pairing sys_exit, the 'exit_group' can only be traced
     * to one sys_enter only. Because of the reason, we submit the event
     * here directly. Note thati we therefore don't know the return value */
    syscall_ent_t *ringbuf_ent =
        bpf_ringbuf_reserve(&syscall_record, sizeof(syscall_ent_t), 0);
    if (!ringbuf_ent) {
        /* FIXME: Drop the syscall directly. Any better approach to guarantee
         * to record the syscall on ring buffer?*/
        return;
    }
    ringbuf_ent->id = id;
    // ringbuf_ent->ret = ?;

    exit_group_args_t *exit_group = &ringbuf_ent->exit_group;
    exit_group->status = status;
    bpf_ringbuf_submit(ringbuf_ent, 0);
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

    syscall_ent_t *ent = bpf_g_ent_lookup_elem(&INDEX_0);
    if (!ent)
        return -1;

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
        sys_enter_read(ent, id, di, (void *) si, dx);
        break;
    case SYS_WRITE:
        sys_enter_write(ent, id, di, (void *) si, dx);
        break;
    case SYS_EXECVE:
        sys_enter_execve(ent, id, (char *) di, (void *) si, (void *) dx);
        break;
    case SYS_EXIT_GROUP:
        sys_enter_exit_group(id, di);
        break;
    default:
        sys_enter_default(ent, id);
        break;
    }

    return 0;
}

static void sys_exit_default(syscall_ent_t *ent, u64 ret)
{
    ent->ret = ret;
}

static void sys_exit_read(syscall_ent_t *ent, u64 ret)
{
    sys_exit_default(ent, ret);

    read_args_t *read = &ent->read;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    size_t count = read->count;

    memset(read->buf, 0, sizeof(read->buf));
    /* minus 1 for the tail '\0' */
    size_t cpy_count = count > BUF_SIZE ? BUF_SIZE : count;
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(read->buf, cpy_count, *buf_addr_ptr);
}

static void submit_syscall(syscall_ent_t *ent)
{
    syscall_ent_t *ringbuf_ent =
        bpf_ringbuf_reserve(&syscall_record, sizeof(syscall_ent_t), 0);
    if (!ringbuf_ent) {
        /* FIXME: Drop the syscall directly. Any better approach to guarantee
         * to record the syscall on ring buffer?*/
        return;
    }
    memcpy(ringbuf_ent, ent, sizeof(syscall_ent_t));
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

    syscall_ent_t *ent = bpf_g_ent_lookup_elem(&INDEX_0);
    if (!ent || (ent->id != id))
        return -1;

    switch (id) {
    case SYS_READ:
        sys_exit_read(ent, ret);
        break;
    default:
        sys_exit_default(ent, ret);
        break;
    }

    submit_syscall(ent);
    return 0;
}
char LICENSE[] SEC("license") = "GPL";

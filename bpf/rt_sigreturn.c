#define OFFSETOF_SIGMASK_IN_RT_SIGFRAME \
    offsetof(struct rt_sigframe, uc.uc_sigmask)
static void sys_rt_sigreturn_enter(u64 id, struct pt_regs *pt_regs)
{
    /* Unlike most system call which can be traced to one sys_enter
     * and a pairing sys_exit, the 'rt_sigreturn' can only be traced
     * to one sys_enter only. Because of the reason, we submit the event
     * here directly. */
    syscall_ent_t *ringbuf_ent = bpf_ringbuf_reserve(
        &syscall_record, sizeof(basic_t) + sizeof(rt_sigreturn_args_t), 0);
    if (!ringbuf_ent) {
        /* FIXME: Drop the syscall directly. Any better approach to guarantee
         * to record the syscall on ring buffer?*/
        return;
    }
    ringbuf_ent->basic.id = id;
    // ringbuf_ent->ret = ?;

    rt_sigreturn_args_t *rt_sigreturn =
        (rt_sigreturn_args_t *) ringbuf_ent->bytes;
    size_t sf_addr = get_rt_sigframe_addr(pt_regs);

    if (sf_addr != 0) {
        size_t sm_addr = sf_addr + OFFSETOF_SIGMASK_IN_RT_SIGFRAME;
        bpf_core_read_user(&rt_sigreturn->set, sizeof(sigset_t),
                           (void *) sm_addr);
    }

    bpf_ringbuf_submit(ringbuf_ent, 0);
}

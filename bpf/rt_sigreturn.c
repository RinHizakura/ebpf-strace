static void sys_rt_sigreturn_enter(u64 id)
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

    bpf_ringbuf_submit(ringbuf_ent, 0);
}

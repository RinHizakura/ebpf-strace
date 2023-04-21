static void sys_exit_group_enter(u64 id, int status)
{
    /* Unlike most system call which can be traced to one sys_enter
     * and a pairing sys_exit, the 'exit_group' can only be traced
     * to one sys_enter only. Because of the reason, we submit the event
     * here directly. Note thati we therefore don't know the return value */
    syscall_ent_t *ringbuf_ent = bpf_ringbuf_reserve(
        &syscall_record, sizeof(basic_t) + sizeof(exit_group_args_t), 0);
    if (!ringbuf_ent) {
        /* FIXME: Drop the syscall directly. Any better approach to guarantee
         * to record the syscall on ring buffer?*/
        return;
    }
    ringbuf_ent->basic.id = id;
    // ringbuf_ent->ret = ?;

    exit_group_args_t *exit_group = (exit_group_args_t *) ringbuf_ent->bytes;
    exit_group->status = status;
    bpf_ringbuf_submit(ringbuf_ent, 0);
}

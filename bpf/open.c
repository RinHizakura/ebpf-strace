static void sys_open_enter(syscall_ent_t *ent,
                           u64 id,
                           char *pathname,
                           int flags)
{
    open_args_t *open = (open_args_t *) ent->bytes;
    memset(open->pathname, 0, sizeof(open->pathname));
    /* FIXME: Possibly error when pathname comes from a string literal
     * in the userspace? */
    bpf_core_read_user_str(open->pathname, sizeof(open->pathname), pathname);
    open->flags = flags;
}

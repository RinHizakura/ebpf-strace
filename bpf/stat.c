static void sys_stat_enter(syscall_ent_t *ent,
                           char *pathname,
                           struct stat *statbuf)
{
    __attribute__((unused)) stat_args_t *stat = (stat_args_t *) ent->bytes;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = pathname;

    buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_1);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = statbuf;
}

static void sys_stat_exit(syscall_ent_t *ent)
{
    stat_args_t *stat = (stat_args_t *) ent->bytes;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    memset(&stat->pathname, 0, sizeof(stat->pathname));
    if (buf_addr_ptr != NULL)
        bpf_core_read_user_str(&stat->pathname, sizeof(stat->pathname),
                               *buf_addr_ptr);

    buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_1);
    memset(&stat->statbuf, 0, sizeof(struct stat));
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(&stat->statbuf, sizeof(struct stat), *buf_addr_ptr);
}

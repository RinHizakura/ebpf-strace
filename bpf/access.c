static void sys_access_enter(syscall_ent_t *ent, char *pathname, int mode)
{
    access_args_t *access = (access_args_t *) ent->bytes;
    access->mode = mode;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = pathname;
}

static void sys_access_exit(syscall_ent_t *ent)
{
    access_args_t *access = (access_args_t *) ent->bytes;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    memset(access->pathname, 0, sizeof(access->pathname));
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(access->pathname, sizeof(access->pathname),
                           *buf_addr_ptr);
}

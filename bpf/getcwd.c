static void sys_getcwd_enter(syscall_ent_t *ent, struct input_parms parms)
{
    char *buf = (char *) parms.parm1;
    size_t size = (size_t) parms.parm2;

    getcwd_args_t *getcwd = (getcwd_args_t *) ent->bytes;
    getcwd->size = size;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = buf;
}

static void sys_getcwd_exit(syscall_ent_t *ent)
{
    getcwd_args_t *getcwd = (getcwd_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    memset(getcwd->buf, 0, sizeof(getcwd->buf));
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(getcwd->buf, sizeof(getcwd->buf), *buf_addr_ptr);
}

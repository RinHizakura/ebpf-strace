static void sys_getdents64_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int fd = (int) parms.parm1;
    void *dirp = (void *) parms.parm2;
    size_t count = (size_t) parms.parm3;

    getdents64_args_t *getdents64 = (getdents64_args_t *) ent->bytes;
    getdents64->fd = fd;
    getdents64->count = count;
    getdents64->buf_used = 0;

    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf0 != NULL)
        *buf0 = dirp;
}

static void sys_getdents64_exit(syscall_ent_t *ent)
{
    getdents64_args_t *g = (getdents64_args_t *) ent->bytes;
    long ret = (long) ent->basic.ret;

    if (ret <= 0)
        return;

    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf0 == NULL || *buf0 == NULL)
        return;

    u32 cpy_len = (u32) ret > sizeof(g->buf) ? sizeof(g->buf) : (u32) ret;
    g->buf_used = cpy_len;
    bpf_core_read_user(g->buf, cpy_len, *buf0);
}

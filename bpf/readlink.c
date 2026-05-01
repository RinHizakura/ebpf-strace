static void sys_readlink_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    char *path = (char *) parms->parm1;
    char *buf = (char *) parms->parm2;
    size_t bufsiz = (size_t) parms->parm3;

    readlink_args_t *readlink = (readlink_args_t *) ent->bytes;
    readlink->bufsiz = bufsiz;

    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf0 != NULL)
        *buf0 = path;
    void **buf1 = bpf_g_buf_addr_lookup_elem(&INDEX_1);
    if (buf1 != NULL)
        *buf1 = buf;
}

static void sys_readlink_exit(syscall_ent_t *ent)
{
    readlink_args_t *readlink = (readlink_args_t *) ent->bytes;
    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    void **buf1 = bpf_g_buf_addr_lookup_elem(&INDEX_1);

    memset(readlink->path, 0, sizeof(readlink->path));
    memset(readlink->buf, 0, sizeof(readlink->buf));
    if (buf0 != NULL)
        bpf_core_read_user(readlink->path, sizeof(readlink->path), *buf0);
    if (buf1 != NULL)
        bpf_core_read_user(readlink->buf, sizeof(readlink->buf), *buf1);
}

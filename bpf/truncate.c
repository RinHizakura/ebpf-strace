static void sys_truncate_enter(syscall_ent_t *ent, struct input_parms parms)
{
    char *path = (char *) parms.parm1;
    off_t length = (off_t) parms.parm2;

    truncate_args_t *truncate = (truncate_args_t *) ent->bytes;
    truncate->length = length;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = path;
}

static void sys_truncate_exit(syscall_ent_t *ent)
{
    truncate_args_t *truncate = (truncate_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    memset(truncate->path, 0, sizeof(truncate->path));
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(truncate->path, sizeof(truncate->path),
                           *buf_addr_ptr);
}

static void sys_ftruncate_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int fd = (int) parms.parm1;
    off_t length = (off_t) parms.parm2;

    ftruncate_args_t *ftruncate = (ftruncate_args_t *) ent->bytes;
    ftruncate->fd = fd;
    ftruncate->length = length;
}

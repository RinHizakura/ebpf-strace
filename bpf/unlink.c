static void sys_unlink_enter(syscall_ent_t *ent, struct input_parms parms)
{
    char *path = (char *) parms.parm1;

    __attribute__((unused)) unlink_args_t *unlink =
        (unlink_args_t *) ent->bytes;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = path;
}

static void sys_unlink_exit(syscall_ent_t *ent)
{
    unlink_args_t *unlink = (unlink_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    memset(unlink->path, 0, sizeof(unlink->path));
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(unlink->path, sizeof(unlink->path), *buf_addr_ptr);
}

static void sys_unlinkat_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int dirfd = (int) parms.parm1;
    char *path = (char *) parms.parm2;
    int flags = (int) parms.parm3;

    unlinkat_args_t *unlinkat = (unlinkat_args_t *) ent->bytes;
    unlinkat->dirfd = dirfd;
    unlinkat->flags = flags;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = path;
}

static void sys_unlinkat_exit(syscall_ent_t *ent)
{
    unlinkat_args_t *unlinkat = (unlinkat_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    memset(unlinkat->path, 0, sizeof(unlinkat->path));
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(unlinkat->path, sizeof(unlinkat->path),
                           *buf_addr_ptr);
}

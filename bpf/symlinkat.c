static void sys_symlink_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    char *target = (char *) parms->parm1;
    char *linkpath = (char *) parms->parm2;

    __attribute__((unused)) symlink_args_t *symlink =
        (symlink_args_t *) ent->bytes;

    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf0 != NULL)
        *buf0 = target;
    void **buf1 = bpf_g_buf_addr_lookup_elem(&INDEX_1);
    if (buf1 != NULL)
        *buf1 = linkpath;
}

static void sys_symlink_exit(syscall_ent_t *ent)
{
    symlink_args_t *symlink = (symlink_args_t *) ent->bytes;
    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    void **buf1 = bpf_g_buf_addr_lookup_elem(&INDEX_1);

    memset(symlink->target, 0, sizeof(symlink->target));
    memset(symlink->linkpath, 0, sizeof(symlink->linkpath));
    if (buf0 != NULL)
        bpf_core_read_user(symlink->target, sizeof(symlink->target), *buf0);
    if (buf1 != NULL)
        bpf_core_read_user(symlink->linkpath, sizeof(symlink->linkpath), *buf1);
}

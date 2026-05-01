static void sys_rmdir_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    char *path = (char *) parms->parm1;

    __attribute__((unused)) rmdir_args_t *rmdir = (rmdir_args_t *) ent->bytes;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = path;
}

static void sys_rmdir_exit(syscall_ent_t *ent)
{
    rmdir_args_t *rmdir = (rmdir_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    memset(rmdir->path, 0, sizeof(rmdir->path));
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(rmdir->path, sizeof(rmdir->path), *buf_addr_ptr);
}

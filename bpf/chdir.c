static void sys_chdir_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    char *path = (char *) parms->parm1;

    __attribute__((unused)) chdir_args_t *chdir = (chdir_args_t *) ent->bytes;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = path;
}

static void sys_chdir_exit(syscall_ent_t *ent)
{
    chdir_args_t *chdir = (chdir_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    memset(chdir->path, 0, sizeof(chdir->path));
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(chdir->path, sizeof(chdir->path), *buf_addr_ptr);
}

static void sys_fchdir_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    int fd = (int) parms->parm1;

    fchdir_args_t *fchdir = (fchdir_args_t *) ent->bytes;
    fchdir->fd = fd;
}

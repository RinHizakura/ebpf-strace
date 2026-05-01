static void sys_chmod_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    char *path = (char *) parms->parm1;
    mode_t mode = (mode_t) parms->parm2;

    chmod_args_t *chmod = (chmod_args_t *) ent->bytes;
    chmod->mode = mode;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = path;
}

static void sys_chmod_exit(syscall_ent_t *ent)
{
    chmod_args_t *chmod = (chmod_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    memset(chmod->path, 0, sizeof(chmod->path));
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(chmod->path, sizeof(chmod->path), *buf_addr_ptr);
}

static void sys_fchmod_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    int fd = (int) parms->parm1;
    mode_t mode = (mode_t) parms->parm2;

    fchmod_args_t *fchmod = (fchmod_args_t *) ent->bytes;
    fchmod->fd = fd;
    fchmod->mode = mode;
}

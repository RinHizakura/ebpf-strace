static void sys_mkdir_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    char *path = (char *) parms->parm1;
    mode_t mode = (mode_t) parms->parm2;

    mkdir_args_t *mkdir = (mkdir_args_t *) ent->bytes;
    mkdir->mode = mode;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = path;
}

static void sys_mkdir_exit(syscall_ent_t *ent)
{
    mkdir_args_t *mkdir = (mkdir_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    memset(mkdir->path, 0, sizeof(mkdir->path));
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(mkdir->path, sizeof(mkdir->path), *buf_addr_ptr);
}

static void sys_mkdirat_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    int dirfd = (int) parms->parm1;
    char *path = (char *) parms->parm2;
    mode_t mode = (mode_t) parms->parm3;

    mkdirat_args_t *mkdirat = (mkdirat_args_t *) ent->bytes;
    mkdirat->dirfd = dirfd;
    mkdirat->mode = mode;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = path;
}

static void sys_mkdirat_exit(syscall_ent_t *ent)
{
    mkdirat_args_t *mkdirat = (mkdirat_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    memset(mkdirat->path, 0, sizeof(mkdirat->path));
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(mkdirat->path, sizeof(mkdirat->path), *buf_addr_ptr);
}

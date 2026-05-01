static void sys_rename_enter(syscall_ent_t *ent, struct input_parms parms)
{
    char *old_path = (char *) parms.parm1;
    char *new_path = (char *) parms.parm2;

    __attribute__((unused)) rename_args_t *rename =
        (rename_args_t *) ent->bytes;

    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf0 != NULL)
        *buf0 = old_path;
    void **buf1 = bpf_g_buf_addr_lookup_elem(&INDEX_1);
    if (buf1 != NULL)
        *buf1 = new_path;
}

static void sys_rename_exit(syscall_ent_t *ent)
{
    rename_args_t *rename = (rename_args_t *) ent->bytes;
    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    void **buf1 = bpf_g_buf_addr_lookup_elem(&INDEX_1);

    memset(rename->old_path, 0, sizeof(rename->old_path));
    memset(rename->new_path, 0, sizeof(rename->new_path));
    if (buf0 != NULL)
        bpf_core_read_user(rename->old_path, sizeof(rename->old_path), *buf0);
    if (buf1 != NULL)
        bpf_core_read_user(rename->new_path, sizeof(rename->new_path), *buf1);
}

static void sys_renameat_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int olddirfd = (int) parms.parm1;
    char *old_path = (char *) parms.parm2;
    int newdirfd = (int) parms.parm3;
    char *new_path = (char *) parms.parm4;

    renameat_args_t *renameat = (renameat_args_t *) ent->bytes;
    renameat->olddirfd = olddirfd;
    renameat->newdirfd = newdirfd;

    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf0 != NULL)
        *buf0 = old_path;
    void **buf1 = bpf_g_buf_addr_lookup_elem(&INDEX_1);
    if (buf1 != NULL)
        *buf1 = new_path;
}

static void sys_renameat_exit(syscall_ent_t *ent)
{
    renameat_args_t *renameat = (renameat_args_t *) ent->bytes;
    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    void **buf1 = bpf_g_buf_addr_lookup_elem(&INDEX_1);

    memset(renameat->old_path, 0, sizeof(renameat->old_path));
    memset(renameat->new_path, 0, sizeof(renameat->new_path));
    if (buf0 != NULL)
        bpf_core_read_user(renameat->old_path, sizeof(renameat->old_path),
                           *buf0);
    if (buf1 != NULL)
        bpf_core_read_user(renameat->new_path, sizeof(renameat->new_path),
                           *buf1);
}

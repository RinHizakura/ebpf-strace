static void sys_link_enter(syscall_ent_t *ent, struct input_parms parms)
{
    char *old_path = (char *) parms.parm1;
    char *new_path = (char *) parms.parm2;

    __attribute__((unused)) link_args_t *link = (link_args_t *) ent->bytes;

    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf0 != NULL)
        *buf0 = old_path;
    void **buf1 = bpf_g_buf_addr_lookup_elem(&INDEX_1);
    if (buf1 != NULL)
        *buf1 = new_path;
}

static void sys_link_exit(syscall_ent_t *ent)
{
    link_args_t *link = (link_args_t *) ent->bytes;
    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    void **buf1 = bpf_g_buf_addr_lookup_elem(&INDEX_1);

    memset(link->old_path, 0, sizeof(link->old_path));
    memset(link->new_path, 0, sizeof(link->new_path));
    if (buf0 != NULL)
        bpf_core_read_user(link->old_path, sizeof(link->old_path), *buf0);
    if (buf1 != NULL)
        bpf_core_read_user(link->new_path, sizeof(link->new_path), *buf1);
}

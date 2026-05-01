static void sys_chown_enter(syscall_ent_t *ent, struct input_parms parms)
{
    char *path = (char *) parms.parm1;
    uid_t uid = (uid_t) parms.parm2;
    gid_t gid = (gid_t) parms.parm3;

    chown_args_t *chown = (chown_args_t *) ent->bytes;
    chown->uid = uid;
    chown->gid = gid;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = path;
}

static void sys_chown_exit(syscall_ent_t *ent)
{
    chown_args_t *chown = (chown_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    memset(chown->path, 0, sizeof(chown->path));
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(chown->path, sizeof(chown->path), *buf_addr_ptr);
}

static void sys_fchown_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int fd = (int) parms.parm1;
    uid_t uid = (uid_t) parms.parm2;
    gid_t gid = (gid_t) parms.parm3;

    fchown_args_t *fchown = (fchown_args_t *) ent->bytes;
    fchown->fd = fd;
    fchown->uid = uid;
    fchown->gid = gid;
}

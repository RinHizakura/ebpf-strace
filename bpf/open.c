static void sys_open_enter(syscall_ent_t *ent, struct input_parms parms)
{
    char *pathname = (char *) parms.parm1;
    int flags = parms.parm2;
    mode_t mode = parms.parm3;

    open_args_t *open = (open_args_t *) ent->bytes;
    open->flags = flags;
    open->mode = mode;

    /* FIXME: It looks like we should read this until sys_exit.
     * But what's the reason for us to do this? How about
     * the timing to read the pathname at execve?
     *
     * There could have some hint at
     * https://research.nccgroup.com/2021/08/06/some-musings-on-common-ebpf-linux-tracing-bugs/
     */
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = pathname;
}

static void sys_open_exit(syscall_ent_t *ent)
{
    open_args_t *open = (open_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    memset(open->pathname, 0, sizeof(open->pathname));
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(open->pathname, sizeof(open->pathname),
                           *buf_addr_ptr);
}

static void sys_openat_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int dirfd = parms.parm1;
    char *pathname = (char *) parms.parm2;
    int flags = parms.parm3;
    mode_t mode = parms.parm4;

    openat_args_t *openat = (openat_args_t *) ent->bytes;
    openat->dirfd = dirfd;
    openat->flags = flags;
    openat->mode = mode;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = pathname;
}

static void sys_openat_exit(syscall_ent_t *ent)
{
    openat_args_t *openat = (openat_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    memset(openat->pathname, 0, sizeof(openat->pathname));
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(openat->pathname, sizeof(openat->pathname),
                           *buf_addr_ptr);
}

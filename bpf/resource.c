static void sys_prlimit64_enter(syscall_ent_t *ent, struct input_parms parms)
{
    pid_t pid = (pid_t) parms.parm1;
    int resource = (int) parms.parm2;
    void *new_rlim = (void *) parms.parm3;
    void *old_rlim = (void *) parms.parm4;

    prlimit64_args_t *pr = (prlimit64_args_t *) ent->bytes;
    pr->pid = pid;
    pr->resource = resource;
    pr->is_new_exist = (new_rlim != NULL);

    memset(&pr->new_rlim, 0, sizeof(pr->new_rlim));
    if (new_rlim)
        bpf_core_read_user(&pr->new_rlim, sizeof(pr->new_rlim), new_rlim);

    memset(&pr->old_rlim, 0, sizeof(pr->old_rlim));
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = old_rlim;
}

static void sys_prlimit64_exit(syscall_ent_t *ent)
{
    prlimit64_args_t *pr = (prlimit64_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    if (buf_addr_ptr != NULL && *buf_addr_ptr != NULL)
        bpf_core_read_user(&pr->old_rlim, sizeof(pr->old_rlim), *buf_addr_ptr);
}

static void sys_setrlimit_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int resource = (int) parms.parm1;
    void *rlim = (void *) parms.parm2;

    setrlimit_args_t *sr = (setrlimit_args_t *) ent->bytes;
    sr->resource = resource;
    memset(&sr->rlim, 0, sizeof(sr->rlim));
    if (rlim)
        bpf_core_read_user(&sr->rlim, sizeof(sr->rlim), rlim);
}

static void sys_getrlimit_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int resource = (int) parms.parm1;
    void *rlim = (void *) parms.parm2;

    getrlimit_args_t *gr = (getrlimit_args_t *) ent->bytes;
    gr->resource = resource;
    memset(&gr->rlim, 0, sizeof(gr->rlim));

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = rlim;
}

static void sys_getrlimit_exit(syscall_ent_t *ent)
{
    getrlimit_args_t *gr = (getrlimit_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    if (buf_addr_ptr != NULL && *buf_addr_ptr != NULL)
        bpf_core_read_user(&gr->rlim, sizeof(gr->rlim), *buf_addr_ptr);
}

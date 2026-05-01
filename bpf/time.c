/* nanosleep: req is input timespec, rem is output (only valid on EINTR)
 * Read req at sys_enter directly; defer rem to sys_exit. */
static void sys_nanosleep_enter(syscall_ent_t *ent, struct input_parms parms)
{
    void *req = (void *) parms.parm1;
    void *rem = (void *) parms.parm2;

    nanosleep_args_t *nanosleep = (nanosleep_args_t *) ent->bytes;
    nanosleep->is_rem_exist = (rem != NULL);

    memset(&nanosleep->req, 0, sizeof(nanosleep->req));
    if (req)
        bpf_core_read_user(&nanosleep->req, sizeof(nanosleep->req), req);

    memset(&nanosleep->rem, 0, sizeof(nanosleep->rem));
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = rem;
}

static void sys_nanosleep_exit(syscall_ent_t *ent)
{
    nanosleep_args_t *nanosleep = (nanosleep_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    if (buf_addr_ptr != NULL && *buf_addr_ptr != NULL)
        bpf_core_read_user(&nanosleep->rem, sizeof(nanosleep->rem),
                           *buf_addr_ptr);
}

static void sys_clock_gettime_enter(syscall_ent_t *ent,
                                    struct input_parms parms)
{
    int clockid = (int) parms.parm1;
    void *tp = (void *) parms.parm2;

    clock_gettime_args_t *cgt = (clock_gettime_args_t *) ent->bytes;
    cgt->clockid = clockid;
    memset(&cgt->tp, 0, sizeof(cgt->tp));

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = tp;
}

static void sys_clock_gettime_exit(syscall_ent_t *ent)
{
    clock_gettime_args_t *cgt = (clock_gettime_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    if (buf_addr_ptr != NULL && *buf_addr_ptr != NULL)
        bpf_core_read_user(&cgt->tp, sizeof(cgt->tp), *buf_addr_ptr);
}

static void sys_clock_getres_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int clockid = (int) parms.parm1;
    void *res = (void *) parms.parm2;

    clock_getres_args_t *cgr = (clock_getres_args_t *) ent->bytes;
    cgr->clockid = clockid;
    cgr->is_res_exist = (res != NULL);
    memset(&cgr->res, 0, sizeof(cgr->res));

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = res;
}

static void sys_clock_getres_exit(syscall_ent_t *ent)
{
    clock_getres_args_t *cgr = (clock_getres_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    if (buf_addr_ptr != NULL && *buf_addr_ptr != NULL)
        bpf_core_read_user(&cgr->res, sizeof(cgr->res), *buf_addr_ptr);
}

static void sys_gettimeofday_enter(syscall_ent_t *ent, struct input_parms parms)
{
    void *tv = (void *) parms.parm1;

    gettimeofday_args_t *gtod = (gettimeofday_args_t *) ent->bytes;
    gtod->is_tv_exist = (tv != NULL);
    memset(&gtod->tv, 0, sizeof(gtod->tv));

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = tv;
}

static void sys_gettimeofday_exit(syscall_ent_t *ent)
{
    gettimeofday_args_t *gtod = (gettimeofday_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    if (buf_addr_ptr != NULL && *buf_addr_ptr != NULL)
        bpf_core_read_user(&gtod->tv, sizeof(gtod->tv), *buf_addr_ptr);
}

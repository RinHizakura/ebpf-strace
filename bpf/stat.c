static void save_pathname(char *pathname)
{
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = pathname;
}

static void save_statbuf(struct stat *statbuf)
{
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_1);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = statbuf;
}

static void load_pathname(u8 *pathname)
{
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    memset(pathname, 0, BUF_SIZE);
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(pathname, BUF_SIZE, *buf_addr_ptr);
}

static void load_statbuf(struct stat *statbuf)
{
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_1);
    memset(statbuf, 0, sizeof(struct stat));
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(statbuf, sizeof(struct stat), *buf_addr_ptr);
}

static void sys_stat_enter(syscall_ent_t *ent, struct input_parms parms)
{
    char *pathname = (char *) parms.parm1;
    struct stat *statbuf = (struct stat *) parms.parm2;

    __attribute__((unused)) stat_args_t *stat = (stat_args_t *) ent->bytes;
    save_pathname(pathname);
    save_statbuf(statbuf);
}

static void sys_stat_exit(syscall_ent_t *ent)
{
    stat_args_t *stat = (stat_args_t *) ent->bytes;
    load_pathname(stat->pathname);
    load_statbuf(&stat->statbuf);
}

static void sys_fstat_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int fd = parms.parm1;
    struct stat *statbuf = (struct stat *) parms.parm2;

    fstat_args_t *fstat = (fstat_args_t *) ent->bytes;
    fstat->fd = fd;
    save_statbuf(statbuf);
}


static void sys_fstat_exit(syscall_ent_t *ent)
{
    fstat_args_t *fstat = (fstat_args_t *) ent->bytes;
    load_statbuf(&fstat->statbuf);
}

static void sys_lstat_enter(syscall_ent_t *ent, struct input_parms parms)
{
    char *pathname = (char *) parms.parm1;
    struct stat *statbuf = (struct stat *) parms.parm2;

    __attribute__((unused)) lstat_args_t *lstat = (lstat_args_t *) ent->bytes;
    save_pathname(pathname);
    save_statbuf(statbuf);
}

static void sys_lstat_exit(syscall_ent_t *ent)
{
    lstat_args_t *lstat = (lstat_args_t *) ent->bytes;
    load_pathname(lstat->pathname);
    load_statbuf(&lstat->statbuf);
}

static void sys_newfstatat_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int dirfd = parms.parm1;
    char *pathname = (char *) parms.parm2;
    struct stat *statbuf = (struct stat *) parms.parm3;
    int flags = parms.parm4;

    newfstatat_args_t *newfstatat = (newfstatat_args_t *) ent->bytes;
    newfstatat->dirfd = dirfd;
    newfstatat->flags = flags;
    save_pathname(pathname);
    save_statbuf(statbuf);
}

static void sys_newfstatat_exit(syscall_ent_t *ent)
{
    newfstatat_args_t *newfstatat = (newfstatat_args_t *) ent->bytes;
    load_pathname(newfstatat->pathname);
    load_statbuf(&newfstatat->statbuf);
}

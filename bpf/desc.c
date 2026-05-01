static void sys_close_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    int fd = parms->parm1;

    close_args_t *close = (close_args_t *) ent->bytes;
    close->fd = fd;
}

static void sys_select_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    int nfds = parms->parm1;
    fd_set *readfds = (fd_set *) parms->parm2;
    fd_set *writefds = (fd_set *) parms->parm3;
    fd_set *exceptfds = (fd_set *) parms->parm4;
    struct timeval *timeout = (struct timeval *) parms->parm5;

    select_args_t *select = (select_args_t *) ent->bytes;

    select->nfds = nfds;

    if (readfds) {
        bpf_core_read_user(&select->readfds, sizeof(fd_set), readfds);
        select->is_readfds_exist = true;
    } else {
        select->is_readfds_exist = false;
    }

    if (writefds) {
        bpf_core_read_user(&select->writefds, sizeof(fd_set), writefds);
        select->is_writefds_exist = true;
    } else {
        select->is_writefds_exist = false;
    }

    if (exceptfds) {
        bpf_core_read_user(&select->exceptfds, sizeof(fd_set), exceptfds);
        select->is_exceptfds_exist = true;
    } else {
        select->is_exceptfds_exist = false;
    }

    if (timeout) {
        bpf_core_read_user(&select->timeout, sizeof(struct timeval), timeout);
        select->is_timeout_exist = true;
    } else {
        select->is_timeout_exist = false;
    }

    select->is_readfds_out = false;
    select->is_timeout_left = false;

    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    void **buf1 = bpf_g_buf_addr_lookup_elem(&INDEX_1);
    if (buf0)
        *buf0 = readfds;
    if (buf1)
        *buf1 = timeout;
}

static void sys_select_exit(syscall_ent_t *ent)
{
    select_args_t *select = (select_args_t *) ent->bytes;
    long ret = (long) ent->basic.ret;
    if (ret <= 0)
        return;

    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf0 && *buf0) {
        bpf_core_read_user(&select->readfds_out, sizeof(fd_set), *buf0);
        select->is_readfds_out = true;
    }

    void **buf1 = bpf_g_buf_addr_lookup_elem(&INDEX_1);
    if (buf1 && *buf1) {
        bpf_core_read_user(&select->timeout_left, sizeof(struct timeval),
                           *buf1);
        select->is_timeout_left = true;
    }
}

static void sys_pipe_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    int *pipefd = (int *) parms->parm1;

    __attribute__((unused)) pipe_args_t *pipe = (pipe_args_t *) ent->bytes;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = pipefd;
}

static void sys_pipe_exit(syscall_ent_t *ent)
{
    pipe_args_t *pipe = (pipe_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    memset(pipe->pipefd, 0, sizeof(pipe->pipefd));
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(pipe->pipefd, sizeof(pipe->pipefd), *buf_addr_ptr);
}

static void sys_pipe2_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    int *pipefd = (int *) parms->parm1;
    int flags = (int) parms->parm2;

    pipe2_args_t *pipe2 = (pipe2_args_t *) ent->bytes;
    pipe2->flags = flags;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = pipefd;
}

static void sys_pipe2_exit(syscall_ent_t *ent)
{
    pipe2_args_t *pipe2 = (pipe2_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    memset(pipe2->pipefd, 0, sizeof(pipe2->pipefd));
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(pipe2->pipefd, sizeof(pipe2->pipefd), *buf_addr_ptr);
}

static void sys_fsync_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    int fd = (int) parms->parm1;

    fsync_args_t *fsync = (fsync_args_t *) ent->bytes;
    fsync->fd = fd;
}

static void sys_fdatasync_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    int fd = (int) parms->parm1;

    fdatasync_args_t *fdatasync = (fdatasync_args_t *) ent->bytes;
    fdatasync->fd = fd;
}

static void sys_syncfs_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    int fd = (int) parms->parm1;

    syncfs_args_t *syncfs = (syncfs_args_t *) ent->bytes;
    syncfs->fd = fd;
}

static void sys_close_range_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    unsigned int fd = (unsigned int) parms->parm1;
    unsigned int max_fd = (unsigned int) parms->parm2;
    unsigned int flags = (unsigned int) parms->parm3;

    close_range_args_t *cr = (close_range_args_t *) ent->bytes;
    cr->fd = fd;
    cr->max_fd = max_fd;
    cr->flags = flags;
}

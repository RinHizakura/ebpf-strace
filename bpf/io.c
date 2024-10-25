static void sys_read_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int fd = parms.parm1;
    void *buf = (void *) parms.parm2;
    size_t count = parms.parm3;

    read_args_t *read = (read_args_t *) ent->bytes;
    read->fd = fd;
    read->count = count;

    /* Record the address of buffer first but don't read the
     * content directly. Because the read syscall hasn't
     * fill the buffer yet when entering syscall. */
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = buf;
}

static void sys_read_exit(syscall_ent_t *ent)
{
    read_args_t *read = (read_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    size_t count = read->count;

    memset(read->buf, 0, sizeof(read->buf));
    /* minus 1 for the tail '\0' */
    size_t cpy_count = count > BUF_SIZE ? BUF_SIZE : count;
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(read->buf, cpy_count, *buf_addr_ptr);
}

static void sys_write_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int fd = parms.parm1;
    void *buf = (void *) parms.parm2;
    size_t count = parms.parm3;

    write_args_t *write = (write_args_t *) ent->bytes;
    write->fd = fd;
    write->count = count;

    memset(write->buf, 0, sizeof(write->buf));
    size_t cpy_count = count > BUF_SIZE ? BUF_SIZE : count;
    bpf_core_read_user(write->buf, cpy_count, buf);
}

static void sys_pread_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int fd = parms.parm1;
    void *buf = (void *) parms.parm2;
    size_t count = parms.parm3;
    off_t offset = parms.parm4;

    pread64_args_t *pread = (pread64_args_t *) ent->bytes;
    pread->fd = fd;
    pread->count = count;
    pread->offset = offset;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = buf;
}

static void sys_pread_exit(syscall_ent_t *ent)
{
    pread64_args_t *pread = (pread64_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    size_t count = pread->count;

    memset(pread->buf, 0, sizeof(pread->buf));
    size_t cpy_count = count > BUF_SIZE ? BUF_SIZE : count;
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(pread->buf, cpy_count, *buf_addr_ptr);
}

static void sys_pwrite_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int fd = parms.parm1;
    void *buf = (void *) parms.parm2;
    size_t count = parms.parm3;
    off_t offset = parms.parm4;

    pwrite64_args_t *pwrite = (pwrite64_args_t *) ent->bytes;
    pwrite->fd = fd;
    pwrite->count = count;
    pwrite->offset = offset;

    memset(pwrite->buf, 0, sizeof(pwrite->buf));
    size_t cpy_count = count > BUF_SIZE ? BUF_SIZE : count;
    bpf_core_read_user(pwrite->buf, cpy_count, buf);
}

static void sys_readv_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int fd = parms.parm1;
    struct iovec *iov = (struct iovec *) parms.parm2;
    int iovcnt = parms.parm3;

    readv_args_t *readv = (readv_args_t *) ent->bytes;
    readv->fd = fd;
    readv->iovcnt = iovcnt;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = iov;
}

static void sys_readv_exit(syscall_ent_t *ent)
{
    readv_args_t *readv = (readv_args_t *) ent->bytes;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (!buf_addr_ptr)
        return;

    struct iovec *iov = *buf_addr_ptr;
    for (int i = 0; (i < ARR_ENT_SIZE) && (i < readv->iovcnt); i++) {
        struct iovec iov_tmp;
        bpf_core_read_user(&iov_tmp, sizeof(struct iovec), iov + i);

        void *iov_base = iov_tmp.iov_base;
        size_t iov_len = iov_tmp.iov_len;

        memset(readv->iov[i].iov_base, 0, BUF_SIZE);
        if (iov_base) {
            size_t len = iov_len > BUF_SIZE ? BUF_SIZE : iov_len;
            bpf_core_read_user(readv->iov[i].iov_base, len, iov_base);
        }
        readv->iov[i].iov_len = iov_len;
    }
}

static void sys_writev_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int fd = parms.parm1;
    struct iovec *iov = (struct iovec *) parms.parm2;
    int iovcnt = parms.parm3;

    writev_args_t *writev = (writev_args_t *) ent->bytes;
    writev->fd = fd;
    writev->iovcnt = iovcnt;

    for (int i = 0; (i < ARR_ENT_SIZE) && (i < iovcnt); i++) {
        struct iovec iov_tmp;
        bpf_core_read_user(&iov_tmp, sizeof(struct iovec), iov + i);

        void *iov_base = iov_tmp.iov_base;
        size_t iov_len = iov_tmp.iov_len;

        memset(writev->iov[i].iov_base, 0, BUF_SIZE);
        if (iov_base) {
            size_t len = iov_len > BUF_SIZE ? BUF_SIZE : iov_len;
            bpf_core_read_user(writev->iov[i].iov_base, len, iov_base);
        }
        writev->iov[i].iov_len = iov_len;
    }
}

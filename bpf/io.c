static void sys_read_enter(syscall_ent_t *ent, int fd, void *buf, size_t count)
{
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

static void sys_write_enter(syscall_ent_t *ent, int fd, void *buf, size_t count)
{
    write_args_t *write = (write_args_t *) ent->bytes;
    write->fd = fd;
    write->count = count;

    memset(write->buf, 0, sizeof(write->buf));
    size_t cpy_count = count > BUF_SIZE ? BUF_SIZE : count;
    bpf_core_read_user(write->buf, cpy_count, buf);
}

static void sys_pread_enter(syscall_ent_t *ent,
                            int fd,
                            void *buf,
                            size_t count,
                            off_t offset)
{
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

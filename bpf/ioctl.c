static void sys_ioctl_enter(syscall_ent_t *ent,
                            int fd,
                            unsigned long request,
                            void *arg)
{
    ioctl_args_t *ioctl = (ioctl_args_t *) ent->bytes;
    ioctl->fd = fd;
    ioctl->request = request;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = arg;
}

static void sys_ioctl_exit(syscall_ent_t *ent)
{
    ioctl_args_t *ioctl = (ioctl_args_t *) ent->bytes;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(&ioctl->arg, sizeof(unsigned long), *buf_addr_ptr);
}

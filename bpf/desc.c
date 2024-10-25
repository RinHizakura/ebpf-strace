static void sys_close_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int fd = parms.parm1;

    close_args_t *close = (close_args_t *) ent->bytes;
    close->fd = fd;
}

static void sys_select_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int nfds = parms.parm1;
    fd_set *readfds = (fd_set *) parms.parm2;
    fd_set *writefds = (fd_set *) parms.parm3;
    fd_set *exceptfds = (fd_set *) parms.parm4;
    struct timeval *timeout = (struct timeval *) parms.parm5;

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
}

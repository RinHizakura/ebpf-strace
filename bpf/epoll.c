static void sys_epoll_create1_enter(syscall_ent_t *ent,
                                    struct input_parms parms)
{
    int flags = (int) parms.parm1;

    epoll_create1_args_t *epc1 = (epoll_create1_args_t *) ent->bytes;
    epc1->flags = flags;
}

static void sys_epoll_ctl_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int epfd = (int) parms.parm1;
    int op = (int) parms.parm2;
    int fd = (int) parms.parm3;
    void *event = (void *) parms.parm4;

    epoll_ctl_args_t *ec = (epoll_ctl_args_t *) ent->bytes;
    ec->epfd = epfd;
    ec->op = op;
    ec->fd = fd;
    ec->is_event_exist = (event != NULL);
    ec->events = 0;
    ec->data = 0;

    if (event) {
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        bpf_core_read_user(&ev, sizeof(ev), event);
        ec->events = ev.events;
        ec->data = ev.data;
    }
}

static void sys_epoll_wait_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int epfd = (int) parms.parm1;
    int maxevents = (int) parms.parm3;
    int timeout = (int) parms.parm4;

    epoll_wait_args_t *ew = (epoll_wait_args_t *) ent->bytes;
    ew->epfd = epfd;
    ew->maxevents = maxevents;
    ew->timeout = timeout;
}

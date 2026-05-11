/* The arm64 vmlinux.h generated from BTF for this kernel does not carry
 * struct epoll_event, even though the kernel UAPI defines it. BTF only
 * preserves types reachable from anchored kernel symbols, and on arm64
 * pahole pruned this one (the kernel only touches it through __user
 * pointers). Declare it manually here so SYS_EPOLL_CTL keeps working.
 *
 * Layout note: EPOLL_PACKED is applied only on x86_64 — on arm64 the
 * struct is naturally aligned (12B on x86_64 packed vs 16B on arm64). */
#ifdef __TARGET_ARCH_arm64
struct epoll_event {
    u32 events;
    u64 data;
};
#endif

static void sys_epoll_create1_enter(syscall_ent_t *ent,
                                    struct input_parms *parms)
{
    int flags = (int) parms->parm1;

    epoll_create1_args_t *epc1 = (epoll_create1_args_t *) ent->bytes;
    epc1->flags = flags;
}

static void sys_epoll_ctl_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    int epfd = (int) parms->parm1;
    int op = (int) parms->parm2;
    int fd = (int) parms->parm3;
    void *event = (void *) parms->parm4;

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

#ifdef __TARGET_ARCH_x86
static void sys_epoll_wait_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    int epfd = (int) parms->parm1;
    void *events = (void *) parms->parm2;
    int maxevents = (int) parms->parm3;
    int timeout = (int) parms->parm4;

    epoll_wait_args_t *ew = (epoll_wait_args_t *) ent->bytes;
    ew->epfd = epfd;
    ew->maxevents = maxevents;
    ew->timeout = timeout;
    ew->ev_events = 0;
    ew->ev_data = 0;

    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf0 != NULL)
        *buf0 = events;
}

static void sys_epoll_wait_exit(syscall_ent_t *ent)
{
    epoll_wait_args_t *ew = (epoll_wait_args_t *) ent->bytes;
    long ret = (long) ent->basic.ret;
    if (ret <= 0)
        return;

    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf0 != NULL && *buf0 != NULL) {
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        bpf_core_read_user(&ev, sizeof(ev), *buf0);
        ew->ev_events = ev.events;
        ew->ev_data = ev.data;
    }
}
#endif

static void sys_poll_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    struct pollfd *fds = (struct pollfd *) parms->parm1;
    u32 nfds = parms->parm2;
    int timeout = parms->parm3;

    poll_args_t *poll = (poll_args_t *) ent->bytes;

    poll->nfds = nfds;
    poll->timeout = timeout;
    memset(poll->fds, 0, ARR_ENT_SIZE * sizeof(struct pollfd));
    memset(poll->revents, 0, ARR_ENT_SIZE * sizeof(short));
    if (nfds != 0 && fds != NULL)
        bpf_core_read_user(poll->fds, sizeof(struct pollfd) * ARR_ENT_SIZE,
                           fds);

    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf0 != NULL)
        *buf0 = fds;
}

static void sys_poll_exit(syscall_ent_t *ent)
{
    poll_args_t *poll = (poll_args_t *) ent->bytes;
    long ret = (long) ent->basic.ret;
    if (ret <= 0)
        return;

    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf0 == NULL || *buf0 == NULL)
        return;

    bpf_core_read_user(poll->fds, sizeof(struct pollfd) * ARR_ENT_SIZE, *buf0);
    for (int i = 0; i < ARR_ENT_SIZE; i++)
        poll->revents[i] = poll->fds[i].revents;
}

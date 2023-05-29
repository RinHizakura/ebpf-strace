static void sys_poll_enter(syscall_ent_t *ent,
                           struct pollfd *fds,
                           u32 nfds,
                           int timeout)
{
    poll_args_t *poll = (poll_args_t *) ent->bytes;

    poll->nfds = nfds;
    poll->timeout = timeout;
    memset(poll->fds, 0, ARR_ENT_SIZE * sizeof(struct pollfd));
    if (nfds != 0 && fds != NULL)
        bpf_core_read_user(poll->fds, sizeof(struct pollfd) * ARR_ENT_SIZE,
                           fds);
}

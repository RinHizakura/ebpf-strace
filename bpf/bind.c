static void sys_bind_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int sockfd = (int) parms.parm1;
    void *addr = (void *) parms.parm2;
    u32 addrlen = (u32) parms.parm3;

    bind_args_t *bind = (bind_args_t *) ent->bytes;
    bind->sockfd = sockfd;
    bind->addrlen = addrlen;

    memset(bind->addr, 0, sizeof(bind->addr));
    if (addr) {
        u32 cpy_len =
            addrlen > sizeof(bind->addr) ? sizeof(bind->addr) : addrlen;
        bpf_core_read_user(bind->addr, cpy_len, addr);
    }
}

static void sys_getrandom_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    void *buf = (void *) parms->parm1;
    size_t buflen = (size_t) parms->parm2;
    unsigned int flags = (unsigned int) parms->parm3;

    getrandom_args_t *gr = (getrandom_args_t *) ent->bytes;
    gr->buflen = buflen;
    gr->flags = flags;

    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf0 != NULL)
        *buf0 = buf;
}

static void sys_getrandom_exit(syscall_ent_t *ent)
{
    getrandom_args_t *gr = (getrandom_args_t *) ent->bytes;
    long ret = (long) ent->basic.ret;

    memset(gr->buf, 0, sizeof(gr->buf));
    if (ret <= 0)
        return;

    void **buf0 = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf0 != NULL && *buf0 != NULL) {
        u32 cpy_len = (u32) ret > sizeof(gr->buf) ? sizeof(gr->buf) : (u32) ret;
        bpf_core_read_user(gr->buf, cpy_len, *buf0);
    }
}

static void sys_wait4_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    pid_t upid = (pid_t) parms->parm1;
    int *wstatus = (int *) parms->parm2;
    int options = (int) parms->parm3;

    wait4_args_t *wait4 = (wait4_args_t *) ent->bytes;
    wait4->upid = upid;
    wait4->options = options;
    wait4->wstatus = 0;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = wstatus;
}

static void sys_wait4_exit(syscall_ent_t *ent)
{
    wait4_args_t *wait4 = (wait4_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    if (buf_addr_ptr != NULL && *buf_addr_ptr != NULL)
        bpf_core_read_user(&wait4->wstatus, sizeof(wait4->wstatus),
                           *buf_addr_ptr);
}

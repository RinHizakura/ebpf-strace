
static void sys_pipe_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int *pipefd = (int *) parms.parm1;

    __attribute__((unused)) pipe_args_t *pipe = (pipe_args_t *) ent->bytes;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = pipefd;
}

static void sys_pipe_exit(syscall_ent_t *ent)
{
    pipe_args_t *pipe = (pipe_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    memset(pipe->pipefd, 0, sizeof(pipe->pipefd));
    if (buf_addr_ptr != NULL)
        bpf_core_read_user(pipe->pipefd, sizeof(pipe->pipefd), *buf_addr_ptr);
}

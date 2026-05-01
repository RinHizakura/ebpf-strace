static void sys_fcntl_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    int fd = (int) parms->parm1;
    int cmd = (int) parms->parm2;
    unsigned long arg = parms->parm3;

    fcntl_args_t *fcntl = (fcntl_args_t *) ent->bytes;
    fcntl->fd = fd;
    fcntl->cmd = cmd;
    fcntl->arg = arg;
}

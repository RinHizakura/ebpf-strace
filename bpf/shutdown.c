static void sys_shutdown_enter(syscall_ent_t *ent, struct input_parms *parms)
{
    int sockfd = (int) parms->parm1;
    int how = (int) parms->parm2;

    shutdown_args_t *shutdown = (shutdown_args_t *) ent->bytes;
    shutdown->sockfd = sockfd;
    shutdown->how = how;
}

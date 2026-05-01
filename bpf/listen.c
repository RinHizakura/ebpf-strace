static void sys_listen_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int sockfd = (int) parms.parm1;
    int backlog = (int) parms.parm2;

    listen_args_t *listen = (listen_args_t *) ent->bytes;
    listen->sockfd = sockfd;
    listen->backlog = backlog;
}

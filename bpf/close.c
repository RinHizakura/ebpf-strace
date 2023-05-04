static void sys_close_enter(syscall_ent_t *ent, int fd)
{
    close_arg_t *close = (close_args_t *) ent->bytes;
    close->fd = fd;
}

static void sys_lseek_enter(syscall_ent_t *ent,
                            int fd,
                            off_t offset,
                            int whence)
{
    lseek_args_t *lseek = (lseek_args_t *) ent->bytes;

    lseek->fd = fd;
    lseek->offset = offset;
    lseek->whence = whence;
}

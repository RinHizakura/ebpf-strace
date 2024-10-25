static void sys_lseek_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int fd = parms.parm1;
    off_t offset = parms.parm2;
    int whence = parms.parm3;

    lseek_args_t *lseek = (lseek_args_t *) ent->bytes;

    lseek->fd = fd;
    lseek->offset = offset;
    lseek->whence = whence;
}

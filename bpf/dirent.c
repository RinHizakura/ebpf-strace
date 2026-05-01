static void sys_getdents64_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int fd = (int) parms.parm1;
    size_t count = (size_t) parms.parm3;

    getdents64_args_t *getdents64 = (getdents64_args_t *) ent->bytes;
    getdents64->fd = fd;
    getdents64->count = count;
}

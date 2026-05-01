static void sys_getrandom_enter(syscall_ent_t *ent, struct input_parms parms)
{
    size_t buflen = (size_t) parms.parm2;
    unsigned int flags = (unsigned int) parms.parm3;

    getrandom_args_t *gr = (getrandom_args_t *) ent->bytes;
    gr->buflen = buflen;
    gr->flags = flags;
}

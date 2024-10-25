static void sys_dup_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int oldfd = parms.parm1;

    dup_args_t *dup = (dup_args_t *) ent->bytes;
    dup->oldfd = oldfd;
}

static void sys_dup2_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int oldfd = parms.parm1;
    int newfd = parms.parm2;

    dup2_args_t *dup2 = (dup2_args_t *) ent->bytes;
    dup2->oldfd = oldfd;
    dup2->newfd = newfd;
}

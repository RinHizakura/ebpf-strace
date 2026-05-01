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

static void sys_dup3_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int oldfd = (int) parms.parm1;
    int newfd = (int) parms.parm2;
    int flags = (int) parms.parm3;

    dup3_args_t *dup3 = (dup3_args_t *) ent->bytes;
    dup3->oldfd = oldfd;
    dup3->newfd = newfd;
    dup3->flags = flags;
}

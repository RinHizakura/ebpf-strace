static void sys_prctl_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int option = (int) parms.parm1;
    unsigned long arg2 = parms.parm2;

    prctl_args_t *prctl = (prctl_args_t *) ent->bytes;
    prctl->option = option;
    prctl->arg2 = arg2;
}

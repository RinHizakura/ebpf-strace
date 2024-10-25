static void sys_exit_group_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int status = parms.parm1;

    exit_group_args_t *exit_group = (exit_group_args_t *) ent->bytes;
    exit_group->status = status;
}

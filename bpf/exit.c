static void sys_exit_group_enter(syscall_ent_t *ent, int status)
{
    exit_group_args_t *exit_group = (exit_group_args_t *) ent->bytes;
    exit_group->status = status;
}

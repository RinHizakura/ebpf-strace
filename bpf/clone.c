static void sys_clone_enter(syscall_ent_t *ent, struct input_parms parms)
{
    unsigned long flags = parms.parm1;
    unsigned long child_stack = parms.parm2;

    clone_args_t *clone = (clone_args_t *) ent->bytes;
    clone->flags = flags;
    clone->child_stack = child_stack;
}

static void sys_dup_enter(syscall_ent_t *ent, int oldfd)
{
    dup_args_t *dup = (dup_args_t *) ent->bytes;
    dup->oldfd = oldfd;
}

static void sys_dup2_enter(syscall_ent_t *ent, int oldfd, int newfd)
{
    dup2_args_t *dup2 = (dup2_args_t *) ent->bytes;
    dup2->oldfd = oldfd;
    dup2->newfd = newfd;
}

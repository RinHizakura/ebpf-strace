static void sys_rt_sigaction_enter(syscall_ent_t *ent,
                                   int signum,
                                   struct sigaction *act,
                                   struct sigaction *oldact,
                                   size_t sigsetsize)
{
    rt_sigaction_args_t *rt_sigaction = (rt_sigaction_args_t *) ent->bytes;

    memset(&rt_sigaction->act, 0, sizeof(struct sigaction));
    memset(&rt_sigaction->oldact, 0, sizeof(struct sigaction));

    if (act) {
        bpf_core_read_user(&rt_sigaction->act, sizeof(struct sigaction), act);
        rt_sigaction->is_act_exist = true;
    }

    if (oldact) {
        bpf_core_read_user(&rt_sigaction->oldact, sizeof(struct sigaction),
                           oldact);
        rt_sigaction->is_oldact_exist = true;
    }

    rt_sigaction->signum = signum;
    rt_sigaction->sigsetsize = sigsetsize;
}

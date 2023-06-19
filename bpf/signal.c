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
    } else {
        rt_sigaction->is_act_exist = false;
    }

    if (oldact) {
        bpf_core_read_user(&rt_sigaction->oldact, sizeof(struct sigaction),
                           oldact);
        rt_sigaction->is_oldact_exist = true;
    } else {
        rt_sigaction->is_oldact_exist = false;
    }

    rt_sigaction->signum = signum;
    rt_sigaction->sigsetsize = sigsetsize;
}

static void sys_rt_sigprocmask_enter(syscall_ent_t *ent,
                                     int how,
                                     sigset_t *set,
                                     sigset_t *oldset,
                                     size_t sigsetsize)
{
    rt_sigprocmask_args_t *rt_sigprocmask =
        (rt_sigprocmask_args_t *) ent->bytes;

    memset(&rt_sigprocmask->set, 0, sizeof(rt_sigprocmask_args_t));
    memset(&rt_sigprocmask->oldset, 0, sizeof(rt_sigprocmask_args_t));

    if (set) {
        bpf_core_read_user(&rt_sigprocmask->set, sizeof(sigset_t), set);
        rt_sigprocmask->is_set_exist = true;
    } else {
        rt_sigprocmask->is_set_exist = false;
    }

    if (oldset) {
        bpf_core_read_user(&rt_sigprocmask->oldset, sizeof(sigset_t), oldset);
        rt_sigprocmask->is_oldset_exist = true;
    } else {
        rt_sigprocmask->is_oldset_exist = false;
    }

    rt_sigprocmask->how = how;
    rt_sigprocmask->sigsetsize = sigsetsize;
}

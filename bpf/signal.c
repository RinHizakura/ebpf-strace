static void sys_rt_sigaction_enter(syscall_ent_t *ent, struct input_parms parms)
{
    int signum = parms.parm1;
    struct sigaction *act = (struct sigaction *) parms.parm2;
    struct sigaction *oldact = (struct sigaction *) parms.parm3;
    size_t sigsetsize = parms.parm4;

    rt_sigaction_args_t *rt_sigaction = (rt_sigaction_args_t *) ent->bytes;

    memset(&rt_sigaction->act, 0, sizeof(struct sigaction));
    if (act) {
        bpf_core_read_user(&rt_sigaction->act, sizeof(struct sigaction), act);
        rt_sigaction->is_act_exist = true;
    } else {
        rt_sigaction->is_act_exist = false;
    }
    rt_sigaction->signum = signum;
    rt_sigaction->sigsetsize = sigsetsize;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = oldact;
}

static void sys_rt_sigaction_exit(syscall_ent_t *ent)
{
    /* For oldact as an returned structure, it should be updated
     * during exit stage. */
    rt_sigaction_args_t *rt_sigaction = (rt_sigaction_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    memset(&rt_sigaction->oldact, 0, sizeof(struct sigaction));
    if (buf_addr_ptr != NULL) {
        if (*buf_addr_ptr != NULL) {
            bpf_core_read_user(&rt_sigaction->oldact, sizeof(struct sigaction),
                               *buf_addr_ptr);
            rt_sigaction->is_oldact_exist = true;
        } else {
            rt_sigaction->is_oldact_exist = false;
        }
    }
}

static void sys_rt_sigprocmask_enter(syscall_ent_t *ent,
                                     struct input_parms parms)
{
    int how = parms.parm1;
    sigset_t *set = (sigset_t *) parms.parm2;
    sigset_t *oldset = (sigset_t *) parms.parm3;
    size_t sigsetsize = parms.parm4;

    rt_sigprocmask_args_t *rt_sigprocmask =
        (rt_sigprocmask_args_t *) ent->bytes;

    memset(&rt_sigprocmask->set, 0, sizeof(sigset_t));
    if (set) {
        bpf_core_read_user(&rt_sigprocmask->set, sizeof(sigset_t), set);
        rt_sigprocmask->is_set_exist = true;
    } else {
        rt_sigprocmask->is_set_exist = false;
    }
    rt_sigprocmask->how = how;
    rt_sigprocmask->sigsetsize = sigsetsize;

    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);
    if (buf_addr_ptr != NULL)
        *buf_addr_ptr = oldset;
}

static void sys_rt_sigprocmask_exit(syscall_ent_t *ent)
{
    rt_sigprocmask_args_t *rt_sigprocmask =
        (rt_sigprocmask_args_t *) ent->bytes;
    void **buf_addr_ptr = bpf_g_buf_addr_lookup_elem(&INDEX_0);

    memset(&rt_sigprocmask->oldset, 0, sizeof(sigset_t));
    if (buf_addr_ptr != NULL) {
        if (*buf_addr_ptr != NULL) {
            bpf_core_read_user(&rt_sigprocmask->oldset, sizeof(sigset_t),
                               *buf_addr_ptr);
            rt_sigprocmask->is_oldset_exist = true;
        } else {
            rt_sigprocmask->is_oldset_exist = false;
        }
    }
}

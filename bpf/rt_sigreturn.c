#define OFFSETOF_SIGMASK_IN_RT_SIGFRAME \
    offsetof(struct rt_sigframe, uc.uc_sigmask)
static void sys_rt_sigreturn_enter(syscall_ent_t *ent, struct pt_regs *pt_regs)
{
    rt_sigreturn_args_t *rt_sigreturn = (rt_sigreturn_args_t *) ent->bytes;
    size_t sf_addr = get_rt_sigframe_addr(pt_regs);

    if (sf_addr != 0) {
        size_t sm_addr = sf_addr + OFFSETOF_SIGMASK_IN_RT_SIGFRAME;
        bpf_core_read_user(&rt_sigreturn->set, sizeof(sigset_t),
                           (void *) sm_addr);
    }
}

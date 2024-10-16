#ifndef ARCH_SYSCALL_H
#define ARCH_SYSCALL_H

static inline u64 get_syscall_nr(struct pt_regs *pt_regs)
{
    return BPF_CORE_READ(pt_regs, orig_ax);
}

static inline size_t get_rt_sigframe_addr(struct pt_regs *pt_regs)
{
    size_t sp = BPF_CORE_READ(pt_regs, sp);
    return (sp != 0) ? sp - 8 : 0;
}

#endif

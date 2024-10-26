#ifndef ARCH_SYSCALL_H
#define ARCH_SYSCALL_H

static inline u64 get_syscall_nr(
    __attribute__((unused)) struct pt_regs *pt_regs)
{
    /* TODO */
    return 0;
}

static inline size_t get_rt_sigframe_addr(
    __attribute__((unused)) struct pt_regs *pt_regs)
{
    /* TODO */
    return 0;
}

#endif

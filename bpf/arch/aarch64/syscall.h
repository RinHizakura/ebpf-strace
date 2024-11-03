#ifndef ARCH_SYSCALL_H
#define ARCH_SYSCALL_H

#ifndef
#define PT_REGS_PARM6_CORE_SYSCALL(pt_regs) BPF_CORE_READ(pt_regs, regs[5])
#endif

/* Ref:
 * https://elixir.bootlin.com/linux/v6.11.6/source/arch/arm64/include/asm/syscall.h
 */
static inline u64 get_syscall_nr(struct pt_regs *pt_regs)
{
    return BPF_CORE_READ(pt_regs, syscallno);
}

/* Ref:
 * https://github.com/strace/strace/blob/master/src/linux/generic/arch_rt_sigframe.c
 */
static inline size_t get_rt_sigframe_addr(struct pt_regs *pt_regs)
{
    size_t sp = BPF_CORE_READ(pt_regs, sp);
    return (sp != 0) ? sp : 0;
}

#endif

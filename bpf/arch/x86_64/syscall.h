#ifndef ARCH_SYSCALL_H
#define ARCH_SYSCALL_H

/* Ref:
 * https://elixir.bootlin.com/linux/v6.11.6/source/arch/x86/include/asm/syscall.h
 */
static inline u64 get_syscall_nr(struct pt_regs *pt_regs)
{
    return BPF_CORE_READ(pt_regs, orig_ax);
}

/* Ref:
 * https://github.com/strace/strace/blob/master/src/linux/i386/arch_rt_sigframe.c
 */
static inline size_t get_rt_sigframe_addr(struct pt_regs *pt_regs)
{
    size_t sp = BPF_CORE_READ(pt_regs, sp);
    return (sp != 0) ? sp - 8 : 0;
}

#endif

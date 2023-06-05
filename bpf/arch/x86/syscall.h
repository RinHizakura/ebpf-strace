#ifndef ARCH_SYSCALL_H
#define ARCH_SYSCALL_H

/* FIXME: Remove this once the library have the macro natively */
#define PT_REGS_PARM6_CORE_SYSCALL(pt_regs) BPF_CORE_READ(pt_regs, r9)

static inline u64 get_syscall_nr(struct pt_regs *pt_regs)
{
    return BPF_CORE_READ(pt_regs, orig_ax);
}

#endif

use crate::common::*;
use libc::{
    SA_NOCLDSTOP, SA_NOCLDWAIT, SA_NODEFER, SA_ONSTACK, SA_RESETHAND, SA_RESTART, SA_SIGINFO,
    SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK,
};
use std::ffi::{c_int, c_long};

/* FIXME: We define this ourself because it is not contained in
 * libc, but it could be architecture-dependent? */
const SA_RESTORER: c_int = 0x04000000;

/* Note that the struct sigaction between kernel and userspace is not the same, see:
 * https://elixir.bootlin.com/glibc/latest/source/sysdeps/unix/sysv/linux/libc_sigaction.c#L42 */
#[repr(C)]
struct Sigaction {
    sa_handler: libc::sighandler_t,
    sa_flags: c_long,
    sa_restorer: usize,
    sa_mask: KernlSigset,
}
unsafe impl plain::Plain for Sigaction {}

#[repr(C)]
struct RtSigactionArgs {
    act: Sigaction,
    oldact: Sigaction,
    sigsetsize: usize,
    signum: c_int,
    is_act_exist: bool,
    is_oldact_exist: bool,
}
unsafe impl plain::Plain for RtSigactionArgs {}

const SIGACT_FLAGS_DESCS: &[Desc] = &[
    desc!(SA_RESTORER),
    desc!(SA_ONSTACK),
    desc!(SA_RESTART),
    desc!(SA_NODEFER),
    desc!(SA_RESETHAND),
    desc!(SA_SIGINFO),
    desc!(SA_RESETHAND),
    desc!(SA_ONSTACK),
    desc!(SA_NODEFER),
    desc!(SA_NOCLDSTOP),
    desc!(SA_NOCLDWAIT),
];

fn format_sigaction(act: &Sigaction) -> String {
    let sa_mask = format_sigset(&act.sa_mask);
    let sa_flags = format_flags(act.sa_flags as u64, '|', SIGACT_FLAGS_DESCS);
    let sa_restorer = if act.sa_restorer != 0 {
        format!("0x{:x}", act.sa_restorer)
    } else {
        "NULL".to_string()
    };

    return format!(
        "{{sa_handler=0x{:x}, sa_mask={}, sa_flags={}, sa_restorer={}}}",
        act.sa_handler, sa_mask, sa_flags, sa_restorer
    );
}

pub(super) fn handle_rt_sigaction_args(args: &[u8]) -> String {
    let rt_sigaction = get_args::<RtSigactionArgs>(args);

    let signum = format_signum(rt_sigaction.signum);
    let act = if rt_sigaction.is_act_exist {
        format_sigaction(&rt_sigaction.act)
    } else {
        "NULL".to_string()
    };
    let oldact = if rt_sigaction.is_oldact_exist {
        format_sigaction(&rt_sigaction.oldact)
    } else {
        "NULL".to_string()
    };

    return format!(
        "{}, {}, {}, {}",
        signum, act, oldact, rt_sigaction.sigsetsize
    );
}

#[repr(C)]
struct RtSigprocmaskArgs {
    set: KernlSigset,
    oldset: KernlSigset,
    sigsetsize: usize,
    how: c_int,
    is_set_exist: bool,
    is_oldset_exist: bool,
}
unsafe impl plain::Plain for RtSigprocmaskArgs {}

const SIGPROCMASK_HOW_DESCS: &[Desc] = &[desc!(SIG_BLOCK), desc!(SIG_UNBLOCK), desc!(SIG_SETMASK)];

pub(super) fn handle_rt_sigprocmask_args(args: &[u8]) -> String {
    let rt_sigprocmask = get_args::<RtSigprocmaskArgs>(args);

    let how = format_value(rt_sigprocmask.how as u64, "SIG_???", &SIGPROCMASK_HOW_DESCS);
    let set = if rt_sigprocmask.is_set_exist {
        format_sigset(&rt_sigprocmask.set)
    } else {
        "NULL".to_string()
    };

    let oldset = if rt_sigprocmask.is_oldset_exist {
        format_sigset(&rt_sigprocmask.oldset)
    } else {
        "NULL".to_string()
    };
    return format!(
        "{}, {}, {}, {}",
        how, set, oldset, rt_sigprocmask.sigsetsize
    );
}

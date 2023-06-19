use crate::syscall::common::*;
use libc::{
    SA_NOCLDSTOP, SA_NOCLDWAIT, SA_NODEFER, SA_ONSTACK, SA_RESETHAND, SA_RESTART, SA_SIGINFO,
};
use std::ffi::{c_int, c_long};

/* FIXME: We define this ourself because it is not contained in
 * libc, but it could be architecture-dependent? */
const SA_RESTORER: c_int = 0x04000000;

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[repr(C)]
struct KernlSigset {
    sig: [c_long; 1],
}

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

/* FIXME: This could not correct for some architecture */
const SIGNUM_TOTAL: usize = 33;
const SIGNAL_NAME: &[&'static str; SIGNUM_TOTAL] = &[
    "0",         /* 0 */
    "SIGHUP",    /* 1 */
    "SIGINT",    /* 2 */
    "SIGQUIT",   /* 3 */
    "SIGILL",    /* 4 */
    "SIGTRAP",   /* 5 */
    "SIGABRT",   /* 6 */
    "SIGBUS",    /* 7 */
    "SIGFPE",    /* 8 */
    "SIGKILL",   /* 9 */
    "SIGUSR1",   /* 10 */
    "SIGSEGV",   /* 11 */
    "SIGUSR2",   /* 12 */
    "SIGPIPE",   /* 13 */
    "SIGALRM",   /* 14 */
    "SIGTERM",   /* 15 */
    "SIGSTKFLT", /* 16 */
    "SIGCHLD",   /* 17 */
    "SIGCONT",   /* 18 */
    "SIGSTOP",   /* 19 */
    "SIGTSTP",   /* 20 */
    "SIGTTIN",   /* 21 */
    "SIGTTOU",   /* 22 */
    "SIGURG",    /* 23 */
    "SIGXCPU",   /* 24 */
    "SIGXFSZ",   /* 25 */
    "SIGVTALRM", /* 26 */
    "SIGPROF",   /* 27 */
    "SIGWINCH",  /* 28 */
    "SIGIO",     /* 29 */
    "SIGPWR",    /* 30 */
    "SIGSYS",    /* 31 */
    "SIGRTMIN",  /* 32 */
];

fn format_signum(signum: c_int) -> String {
    if signum < 0 || signum >= SIGNUM_TOTAL as c_int {
        return signum.to_string();
    }

    return SIGNAL_NAME[signum as usize].to_string();
}

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

fn next_set_bit(sig_mask: &[c_long], mut cur_bit: c_int) -> c_int {
    /* FIXME: Just simply implement this for correctness. Consider
     * https://github.com/strace/strace/blob/master/src/util.c#LL274C1-L274C74
     * if we want some optimization */
    let ent_bitsize = std::mem::size_of::<c_long>() as c_int * 8;
    let total_bitsize = sig_mask.len() as c_int * ent_bitsize;

    while cur_bit < total_bitsize {
        let slot = (cur_bit / ent_bitsize) as usize;
        let pos = cur_bit % ent_bitsize;

        if ((sig_mask[slot] >> pos) & 1) == 1 {
            return cur_bit;
        }

        cur_bit += 1;
    }
    return -1;
}

fn format_sigset(sig_mask: &KernlSigset) -> String {
    let mut s = String::new();
    s.push('[');

    let mut i = next_set_bit(&sig_mask.sig, 0);
    while i >= 0 {
        i += 1;
        s.push_str(&SIGNAL_NAME[i as usize][3..]);
        s.push(' ');
        i = next_set_bit(&sig_mask.sig, i);
    }
    /* It means we don't just put the first '[' in the string. Pop
     * the last space. */
    if s.len() != 1 {
        s.pop();
    }
    s.push(']');
    return s;
}

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

pub(super) fn handle_rt_sigprocmask_args(args: &[u8]) -> String {
    let rt_sigprocmask = get_args::<RtSigprocmaskArgs>(args);

    return format!("{}", rt_sigprocmask.sigsetsize);
}

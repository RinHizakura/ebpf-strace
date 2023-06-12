use std::ffi::{c_int, c_long};

use crate::syscall::common::*;

/* FIXME: We use own defined sigaction. This could only work on
 * x86_64 architecture. What's the problem of mismatch between Rust's
 * libc::sigaction and C's sigaction? */
#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct Sigaction {
    sa_handler: libc::sighandler_t,
    sa_flags: c_long,
    sa_restorer: Option<extern "C" fn()>,
    sa_mask: c_int,
}
unsafe impl plain::Plain for Sigaction {}

#[repr(C)]
struct RtSigactionArgs {
    act: Sigaction,
    oldact: Sigaction,
    sigsetsize: usize,
    signum: c_int,
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

pub(super) fn handle_rt_sigaction_args(args: &[u8]) -> String {
    let rt_sigaction = get_args::<RtSigactionArgs>(args);

    let signum = format_signum(rt_sigaction.signum);
    return format!(
        "{}, {}, {}",
        signum, rt_sigaction.signum, rt_sigaction.sigsetsize
    );
}

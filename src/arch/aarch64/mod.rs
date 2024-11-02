pub mod syscall_nr;
pub mod syscall_tbl;

use std::ffi::c_long;

#[repr(C)]
pub struct KernlSigset {
    pub sig: [c_long; 1],
}

pub const SIGRTMIN: usize = 32;
pub const SIGRTMAX: usize = 64;
pub const SIGNAL_NAME: &[&'static str; SIGRTMIN + 1] = &[
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

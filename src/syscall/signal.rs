use crate::syscall::common::*;

/* FIXME: What's the problem of libc::sigaction? */
#[repr(C)]
struct Sigaction {
    sa_handler: libc::sighandler_t,
    sa_flags: i32,
    sa_restorer: Option<extern "C" fn()>,
    sa_mask: i32,
}
unsafe impl plain::Plain for Sigaction {}

#[repr(C)]
struct RtSigactionArgs {
    act: Sigaction,
    oldact: Sigaction,
    sigsetsize: usize,
    signum: i32,
}
unsafe impl plain::Plain for RtSigactionArgs {}

pub(super) fn handle_rt_sigaction_args(args: &[u8]) -> String {
    let rt_sigaction = get_args::<RtSigactionArgs>(args);

    return format!("{}, {}", rt_sigaction.signum, rt_sigaction.sigsetsize);
}

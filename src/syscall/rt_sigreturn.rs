use crate::syscall::common::*;

#[repr(C)]
struct RtSigreturnArgs {
    set: KernlSigset,
}
unsafe impl plain::Plain for RtSigreturnArgs {}

pub(super) fn handle_rt_sigreturn_args(args: &[u8]) -> String {
    let rt_sigreturn = get_args::<RtSigreturnArgs>(args);

    let mask = format_sigset(&rt_sigreturn.set);
    return format!("{}", mask);
}

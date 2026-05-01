use crate::common::*;
use libc::pid_t;

#[repr(C)]
struct SetpgidArgs {
    pid: pid_t,
    pgid: pid_t,
}
unsafe impl plain::Plain for SetpgidArgs {}

pub(super) fn handle_setpgid_args(args: &[u8]) -> String {
    let setpgid = get_args::<SetpgidArgs>(args);
    format!("{}, {}", setpgid.pid, setpgid.pgid)
}

#[repr(C)]
struct GetpgidArgs {
    pid: pid_t,
}
unsafe impl plain::Plain for GetpgidArgs {}

pub(super) fn handle_getpgid_args(args: &[u8]) -> String {
    let getpgid = get_args::<GetpgidArgs>(args);
    format!("{}", getpgid.pid)
}

#[repr(C)]
struct GetsidArgs {
    pid: pid_t,
}
unsafe impl plain::Plain for GetsidArgs {}

pub(super) fn handle_getsid_args(args: &[u8]) -> String {
    let getsid = get_args::<GetsidArgs>(args);
    format!("{}", getsid.pid)
}

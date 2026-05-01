use crate::common::*;
use libc::{pid_t, WCONTINUED, WNOHANG, WUNTRACED};

#[repr(C)]
struct Wait4Args {
    upid: pid_t,
    wstatus: c_int,
    options: c_int,
}
unsafe impl plain::Plain for Wait4Args {}

const WAIT_OPTIONS_DESCS: &[Desc] = &[desc!(WNOHANG), desc!(WUNTRACED), desc!(WCONTINUED)];

pub(super) fn handle_wait4_args(args: &[u8], ret: u64) -> String {
    let wait4 = get_args::<Wait4Args>(args);
    let opts = format_flags(wait4.options as u64, '|', WAIT_OPTIONS_DESCS, Format::Hex);
    let ret_pid = ret as i64;
    let wstatus_str = if ret_pid > 0 {
        format!("[{{wstatus={}}}]", wait4.wstatus)
    } else {
        NULL_STR.to_owned()
    };
    format!("{}, {}, {}, NULL", wait4.upid, wstatus_str, opts)
}

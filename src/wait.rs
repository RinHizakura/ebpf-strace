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

fn format_wstatus(wstatus: c_int) -> String {
    let low7 = (wstatus & 0x7f) as u8;
    if low7 == 0 {
        let exit_code = (wstatus >> 8) & 0xff;
        format!("WIFEXITED(s) && WEXITSTATUS(s) == {}", exit_code)
    } else if low7 != 0x7f {
        let sig = low7;
        format!("WIFSIGNALED(s) && WTERMSIG(s) == {}", sig)
    } else {
        let stop_sig = (wstatus >> 8) & 0xff;
        format!("WIFSTOPPED(s) && WSTOPSIG(s) == {}", stop_sig)
    }
}

pub(super) fn handle_wait4_args(args: &[u8], ret: u64) -> String {
    let wait4 = get_args::<Wait4Args>(args);
    let opts = format_flags(wait4.options as u64, '|', WAIT_OPTIONS_DESCS, Format::Hex);
    let ret_pid = ret as i64;
    let wstatus_str = if ret_pid > 0 {
        format!("[{{{}}}]", format_wstatus(wait4.wstatus))
    } else {
        NULL_STR.to_owned()
    };
    format!("{}, {}, {}, NULL", wait4.upid, wstatus_str, opts)
}

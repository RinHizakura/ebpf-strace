use crate::common::*;
use libc::off_t;

#[repr(C)]
struct TruncateArgs {
    path: [u8; BUF_SIZE],
    length: off_t,
}
unsafe impl plain::Plain for TruncateArgs {}

pub(super) fn handle_truncate_args(args: &[u8]) -> String {
    let t = get_args::<TruncateArgs>(args);
    format!("{}, {}", format_str(&t.path), t.length)
}

#[repr(C)]
struct FtruncateArgs {
    fd: c_int,
    length: off_t,
}
unsafe impl plain::Plain for FtruncateArgs {}

pub(super) fn handle_ftruncate_args(args: &[u8]) -> String {
    let f = get_args::<FtruncateArgs>(args);
    format!("{}, {}", f.fd, f.length)
}

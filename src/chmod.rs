use crate::common::*;
use libc::mode_t;

#[repr(C)]
struct ChmodArgs {
    path: [u8; BUF_SIZE],
    mode: mode_t,
}
unsafe impl plain::Plain for ChmodArgs {}

pub(super) fn handle_chmod_args(args: &[u8]) -> String {
    let c = get_args::<ChmodArgs>(args);
    format!("{}, 0{:o}", format_str(&c.path), c.mode)
}

#[repr(C)]
struct FchmodArgs {
    fd: c_int,
    mode: mode_t,
}
unsafe impl plain::Plain for FchmodArgs {}

pub(super) fn handle_fchmod_args(args: &[u8]) -> String {
    let f = get_args::<FchmodArgs>(args);
    format!("{}, 0{:o}", f.fd, f.mode)
}

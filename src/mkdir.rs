use crate::common::*;
use libc::mode_t;

#[repr(C)]
struct MkdirArgs {
    path: [u8; BUF_SIZE],
    mode: mode_t,
}
unsafe impl plain::Plain for MkdirArgs {}

pub(super) fn handle_mkdir_args(args: &[u8]) -> String {
    let m = get_args::<MkdirArgs>(args);
    format!("{}, 0{:o}", format_str(&m.path), m.mode)
}

#[repr(C)]
struct MkdiratArgs {
    dirfd: c_int,
    path: [u8; BUF_SIZE],
    mode: mode_t,
}
unsafe impl plain::Plain for MkdiratArgs {}

pub(super) fn handle_mkdirat_args(args: &[u8]) -> String {
    let m = get_args::<MkdiratArgs>(args);
    format!(
        "{}, {}, 0{:o}",
        format_dirfd(m.dirfd),
        format_str(&m.path),
        m.mode
    )
}
